//! Reentrancy-risk: an external contract call after a storage write without a re-read.
//!
//! External calls are `env.invoke_contract` / `invoke_contract_check` /
//! `try_invoke_contract`, and any method called on a contract client: a binding or
//! expression built with `<X>Client::new(..)` (`token::Client`, `TokenClient`, a
//! `contractimport!` / `#[contractclient]`-generated `FooClient`, or a `use … as` alias of
//! one).

use crate::util::{
    collect_use_renames, contractimpl_functions_excluding_test, ctor_type_name,
    is_invoke_contract_method_name, pat_ident_name, receiver_chain_contains_storage,
};
use crate::{Check, Finding, Severity};
use std::collections::HashSet;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{ExprMethodCall, File};

const CHECK_NAME: &str = "reentrancy-risk";

/// Flags `#[contractimpl]` methods that make an external contract call after a storage
/// write (`set`, `remove`, `append`) without reading state again first.
pub struct ReentrancyRiskCheck;

impl Check for ReentrancyRiskCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let client_aliases = collect_use_renames(file, |name| name.ends_with("Client"));
        let mut out = Vec::new();
        for method in contractimpl_functions_excluding_test(file) {
            let fn_name = method.sig.ident.to_string();
            let mut v = ReentrancyVisitor {
                client_aliases: client_aliases.clone(),
                ..ReentrancyVisitor::default()
            };
            v.visit_block(&method.block);
            if let Some(line) = v.invoke_after_write_line {
                out.push(Finding {
                    check_name: CHECK_NAME.to_string(),
                    severity: Severity::High,
                    file_path: String::new(),
                    line,
                    function_name: fn_name.clone(),
                    description: format!(
                        "Method `{fn_name}` makes an external contract call after a storage write. \
                         The callee is an untrusted contract that may re-enter this contract \
                         before state is finalised. Perform all external calls before writing \
                         storage (checks-effects-interactions) or re-read state after the call."
                    ),
                    rule_url: Some(
                        "https://github.com/SorobanGuard/Guard-CLI/blob/main/docs/checks.md#reentrancy-risk-high"
                            .to_string(),
                    ),
                    suggestion: Some(format!(
                        "Move all `env.storage().*.set(…)` calls in `{fn_name}` to \
                         *after* the external call (checks-effects-interactions \
                         pattern), or re-read and re-validate state immediately after \
                         the external call returns."
                    )),
                });
            }
        }
        out
    }
}

fn is_storage_write(m: &ExprMethodCall) -> bool {
    let name = m.method.to_string();
    // `extend_ttl`/`bump` only change a storage entry's expiration, not its stored
    // value, so they cannot open a checks-effects-interactions hazard on their own.
    if !matches!(name.as_str(), "set" | "remove" | "append") {
        return false;
    }
    receiver_chain_contains_storage(&m.receiver)
}

fn is_storage_read(m: &ExprMethodCall) -> bool {
    let name = m.method.to_string();
    // `get_unchecked` is not a soroban-sdk storage method (#1055).
    if !matches!(name.as_str(), "get" | "has") {
        return false;
    }
    receiver_chain_contains_storage(&m.receiver)
}

/// Client methods that only configure test authorisation and never call the contract.
const CLIENT_NON_CALL_METHODS: &[&str] = &[
    "mock_auths",
    "mock_all_auths",
    "mock_all_auths_allowing_non_root_auth",
    "set_auths",
];

#[derive(Default)]
struct ReentrancyVisitor {
    wrote: bool,
    re_read_after_write: bool,
    invoke_after_write_line: Option<usize>,
    /// `use … as X` renames of `*Client` types.
    client_aliases: HashSet<String>,
    /// Local bindings holding a contract client.
    client_bindings: HashSet<String>,
}

impl ReentrancyVisitor {
    fn branch(&self) -> Self {
        ReentrancyVisitor {
            wrote: self.wrote,
            re_read_after_write: self.re_read_after_write,
            invoke_after_write_line: self.invoke_after_write_line,
            client_aliases: self.client_aliases.clone(),
            client_bindings: self.client_bindings.clone(),
        }
    }

    fn is_client_ctor(&self, expr: &syn::Expr) -> bool {
        ctor_type_name(expr)
            .is_some_and(|ty| ty.ends_with("Client") || self.client_aliases.contains(&ty))
    }

    fn is_client_expr(&self, expr: &syn::Expr) -> bool {
        match expr {
            syn::Expr::Path(p) => p
                .path
                .get_ident()
                .is_some_and(|i| self.client_bindings.contains(&i.to_string())),
            syn::Expr::Reference(r) => self.is_client_expr(&r.expr),
            syn::Expr::Paren(p) => self.is_client_expr(&p.expr),
            other => self.is_client_ctor(other),
        }
    }

    /// `env.invoke_contract(..)` and friends, or any call on a contract client.
    fn is_external_call(&self, m: &ExprMethodCall) -> bool {
        let name = m.method.to_string();
        is_invoke_contract_method_name(&name)
            || (self.is_client_expr(&m.receiver)
                && !CLIENT_NON_CALL_METHODS.contains(&name.as_str()))
    }
}

impl<'ast> Visit<'ast> for ReentrancyVisitor {
    fn visit_local(&mut self, i: &'ast syn::Local) {
        visit::visit_local(self, i);
        if let Some(name) = pat_ident_name(&i.pat) {
            if i.init
                .as_ref()
                .is_some_and(|init| self.is_client_ctor(&init.expr))
            {
                self.client_bindings.insert(name);
            } else {
                // Shadowed by a non-client value.
                self.client_bindings.remove(&name);
            }
        }
    }

    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        if is_storage_write(i) {
            self.wrote = true;
            self.re_read_after_write = false;
        } else if self.wrote && is_storage_read(i) {
            self.re_read_after_write = true;
        } else if self.wrote
            && !self.re_read_after_write
            && self.is_external_call(i)
            && self.invoke_after_write_line.is_none()
        {
            self.invoke_after_write_line = Some(i.span().start().line);
        }
        visit::visit_expr_method_call(self, i);
    }

    /// Evaluate each branch of an `if`/`else if`/`else` independently.
    ///
    /// A write in one branch and an invoke in a mutually-exclusive branch are
    /// **not** a checks-effects-interactions violation — those two statements can
    /// never execute together in the same invocation.  Only flag if a *single*
    /// branch contains both a write and a subsequent invoke.
    fn visit_expr_if(&mut self, expr_if: &'ast syn::ExprIf) {
        // The condition always runs, before either branch: an external call or a storage
        // re-read in it (`if client.try_transfer(..).is_err()`,
        // `if let Some(v) = env.storage().persistent().get(&k)`) counts (#1057).
        self.visit_expr(&expr_if.cond);

        // Each branch starts from the state after the condition.
        // Evaluate the `then` branch in isolation.
        let mut then_visitor = self.branch();
        then_visitor.visit_block(&expr_if.then_branch);

        // Evaluate the `else` branch (if present) in isolation, starting from
        // the *same* pre-if state, not the then-branch's exit state.
        let mut else_visitor = self.branch();
        if let Some((_, else_expr)) = &expr_if.else_branch {
            else_visitor.visit_expr(else_expr);
        }

        // Propagate any new findings from either branch back to self.
        if self.invoke_after_write_line.is_none() {
            if then_visitor.invoke_after_write_line.is_some() {
                self.invoke_after_write_line = then_visitor.invoke_after_write_line;
            } else if else_visitor.invoke_after_write_line.is_some() {
                self.invoke_after_write_line = else_visitor.invoke_after_write_line;
            }
        }

        // After the if expression, state is the union of both branches (conservative).
        self.wrote = then_visitor.wrote || else_visitor.wrote;
        self.re_read_after_write = then_visitor.re_read_after_write && else_visitor.re_read_after_write;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Check;
    use syn::parse_file;

    fn run(src: &str) -> Vec<Finding> {
        let file = parse_file(src).expect("parse");
        ReentrancyRiskCheck.run(&file, src)
    }

    #[test]
    fn flags_invoke_after_write() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env, Address};

pub struct C;

#[contractimpl]
impl C {
    pub fn transfer(env: Env, to: Address, amount: i128) {
        env.storage().persistent().set(&to, &amount);
        env.invoke_contract::<()>(&to, &soroban_sdk::symbol_short!("cb"), soroban_sdk::vec![&env]);
    }
}
"#);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::High);
    }

    #[test]
    fn passes_invoke_before_write() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env, Address};

pub struct C;

#[contractimpl]
impl C {
    pub fn transfer(env: Env, to: Address, amount: i128) {
        env.invoke_contract::<()>(&to, &soroban_sdk::symbol_short!("cb"), soroban_sdk::vec![&env]);
        env.storage().persistent().set(&to, &amount);
    }
}
"#);
        assert!(hits.is_empty());
    }

    #[test]
    fn passes_re_read_before_invoke() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env, Address};

pub struct C;

#[contractimpl]
impl C {
    pub fn transfer(env: Env, to: Address) {
        env.storage().persistent().set(&to, &42i128);
        let _v: i128 = env.storage().persistent().get(&to).unwrap();
        env.invoke_contract::<()>(&to, &soroban_sdk::symbol_short!("cb"), soroban_sdk::vec![&env]);
    }
}
"#);
        assert!(hits.is_empty());
    }

    #[test]
    fn passes_ttl_bump_before_invoke() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env, Address};

pub struct C;

#[contractimpl]
impl C {
    pub fn ping(env: Env, peer: Address) {
        env.storage().persistent().extend_ttl(&peer, 100, 1000);
        env.invoke_contract::<()>(&peer, &soroban_sdk::symbol_short!("cb"), soroban_sdk::vec![&env]);
    }
}
"#);
        assert!(hits.is_empty());
    }

    #[test]
    fn passes_bump_before_invoke() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env, Address};

pub struct C;

#[contractimpl]
impl C {
    pub fn ping(env: Env, peer: Address) {
        env.storage().persistent().bump(&peer, 100, 1000);
        env.invoke_contract::<()>(&peer, &soroban_sdk::symbol_short!("cb"), soroban_sdk::vec![&env]);
    }
}
"#);
        assert!(hits.is_empty());
    }

    #[test]
    fn ignores_non_contractimpl() {
        let hits = run(r#"
use soroban_sdk::{Env, Address};

pub struct C;

impl C {
    pub fn transfer(env: Env, to: Address, amount: i128) {
        env.storage().persistent().set(&to, &amount);
        env.invoke_contract::<()>(&to, &soroban_sdk::symbol_short!("cb"), soroban_sdk::vec![&env]);
    }
}
"#);
        assert!(hits.is_empty());
    }

    /// Regression test for issue #696: a storage write in the `if` branch and an
    /// `invoke_contract` in the mutually-exclusive `else` branch must NOT be
    /// flagged — they can never execute together in the same invocation.
    #[test]
    fn passes_write_in_if_invoke_in_else_are_disjoint() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env, Address};

pub struct C;

#[contractimpl]
impl C {
    pub fn dispatch(env: Env, cond: bool, to: Address, amount: i128) {
        if cond {
            env.storage().persistent().set(&to, &amount);
        } else {
            env.invoke_contract::<()>(&to, &soroban_sdk::symbol_short!("cb"), soroban_sdk::vec![&env]);
        }
    }
}
"#);
        assert!(
            hits.is_empty(),
            "write in if-branch and invoke in else-branch are disjoint paths — no reentrancy risk; got: {hits:#?}"
        );
    }

    /// Confirm that a write followed by an invoke *within the same branch* is still
    /// flagged after the branch-scoping change.
    #[test]
    fn flags_write_then_invoke_in_same_branch() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env, Address};

pub struct C;

#[contractimpl]
impl C {
    pub fn dispatch(env: Env, cond: bool, to: Address, amount: i128) {
        if cond {
            env.storage().persistent().set(&to, &amount);
            env.invoke_contract::<()>(&to, &soroban_sdk::symbol_short!("cb"), soroban_sdk::vec![&env]);
        }
    }
}
"#);
        assert_eq!(
            hits.len(),
            1,
            "write then invoke in same branch should still be flagged; got: {hits:#?}"
        );
    }

    /// #1056: a token client transfer after a write is an external call.
    #[test]
    fn flags_token_client_transfer_after_write() {
        let hits = run(r#"
use soroban_sdk::{contract, contractimpl, contracttype, token, Address, Env};

#[contracttype]
pub enum DataKey { Bal(Address) }

#[contract]
pub struct C;

#[contractimpl]
impl C {
    pub fn withdraw(env: Env, tok: Address, user: Address, amt: i128) {
        env.storage().persistent().set(&DataKey::Bal(user.clone()), &0i128);
        token::Client::new(&env, &tok).transfer(&env.current_contract_address(), &user, &amt);
    }

    pub fn withdraw_bound(env: Env, tok: Address, user: Address, amt: i128) {
        env.storage().persistent().set(&DataKey::Bal(user.clone()), &0i128);
        let client = token::Client::new(&env, &tok);
        client.transfer(&env.current_contract_address(), &user, &amt);
    }
}
"#);
        assert_eq!(hits.len(), 2, "{hits:?}");
    }

    #[test]
    fn flags_token_client_alias_and_token_client_type() {
        let hits = run(r#"
use soroban_sdk::token::TokenClient;
use soroban_sdk::token::Client as Tok;
use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct C;

#[contractimpl]
impl C {
    pub fn a(env: Env, tok: Address, user: Address, amt: i128) {
        env.storage().persistent().set(&user, &0i128);
        TokenClient::new(&env, &tok).transfer(&env.current_contract_address(), &user, &amt);
    }

    pub fn b(env: Env, tok: Address, user: Address, amt: i128) {
        env.storage().persistent().set(&user, &0i128);
        let t = Tok::new(&env, &tok);
        t.transfer(&env.current_contract_address(), &user, &amt);
    }
}
"#);
        assert_eq!(hits.len(), 2, "{hits:?}");
    }

    /// #1056: a `contractimport!` / `#[contractclient]`-generated client.
    #[test]
    fn flags_generated_client_call_after_write() {
        let hits = run(r#"
use soroban_sdk::{contract, contractclient, contractimpl, Address, Env};

#[contractclient(name = "VaultClient")]
pub trait Vault {
    fn deposit(env: Env, from: Address, amount: i128);
}

#[contract]
pub struct C;

#[contractimpl]
impl C {
    pub fn route(env: Env, vault: Address, user: Address, amt: i128) {
        env.storage().persistent().set(&user, &amt);
        let v = VaultClient::new(&env, &vault);
        v.deposit(&user, &amt);
    }
}
"#);
        assert_eq!(hits.len(), 1, "{hits:?}");
    }

    /// #1056: `try_invoke_contract` is a cross-contract call too.
    #[test]
    fn flags_try_invoke_contract_after_write() {
        let hits = run(r#"
use soroban_sdk::{contract, contractimpl, symbol_short, vec, Address, Env, Val, InvokeError};

#[contract]
pub struct C;

#[contractimpl]
impl C {
    pub fn ping(env: Env, to: Address, amount: i128) {
        env.storage().persistent().set(&to, &amount);
        let _ = env.try_invoke_contract::<Val, InvokeError>(&to, &symbol_short!("cb"), vec![&env]);
    }
}
"#);
        assert_eq!(hits.len(), 1, "{hits:?}");
    }

    /// #1056: client calls before the write, and test-only auth helpers, are fine.
    #[test]
    fn passes_client_call_before_write() {
        let hits = run(r#"
use soroban_sdk::{contract, contractimpl, token, Address, Env};

#[contract]
pub struct C;

#[contractimpl]
impl C {
    pub fn deposit(env: Env, tok: Address, user: Address, amt: i128) {
        let client = token::Client::new(&env, &tok);
        client.transfer(&user, &env.current_contract_address(), &amt);
        env.storage().persistent().set(&user, &amt);
    }
}
"#);
        assert!(hits.is_empty(), "{hits:?}");
    }

    /// #1057: an external call in an `if` condition after a write is flagged.
    #[test]
    fn flags_invoke_in_if_condition_after_write() {
        let hits = run(r#"
use soroban_sdk::{contract, contractimpl, token, Address, Env};

#[contract]
pub struct C;

#[contractimpl]
impl C {
    pub fn pay(env: Env, tok: Address, user: Address, amt: i128) {
        env.storage().persistent().set(&user, &0i128);
        let client = token::Client::new(&env, &tok);
        if client.try_transfer(&env.current_contract_address(), &user, &amt).is_err() {
            panic!("transfer failed");
        }
    }
}
"#);
        assert_eq!(hits.len(), 1, "{hits:?}");
    }

    /// #1057: a storage re-read in an `if let` condition counts as a re-read.
    #[test]
    fn re_read_in_if_condition_counts() {
        let hits = run(r#"
use soroban_sdk::{contract, contractimpl, symbol_short, vec, Address, Env};

#[contract]
pub struct C;

#[contractimpl]
impl C {
    pub fn settle(env: Env, to: Address, amount: i128) {
        env.storage().persistent().set(&to, &amount);
        if let Some(v) = env.storage().persistent().get::<Address, i128>(&to) {
            env.invoke_contract::<()>(&to, &symbol_short!("cb"), vec![&env, v.into()]);
        }
    }
}
"#);
        assert!(hits.is_empty(), "{hits:?}");
    }
}
