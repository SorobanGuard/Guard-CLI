//! Reentrancy-risk: `invoke_contract` after a storage write without a re-read.

use crate::util::{contractimpl_functions_excluding_test, receiver_chain_contains_storage};
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{ExprMethodCall, File};

const CHECK_NAME: &str = "reentrancy-risk";

/// Flags `#[contractimpl]` methods that call `invoke_contract` or
/// `invoke_contract_check` after a storage write (`set`, `remove`, `append`)
/// without reading state again first.
pub struct ReentrancyRiskCheck;

impl Check for ReentrancyRiskCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions_excluding_test(file) {
            let fn_name = method.sig.ident.to_string();
            let mut v = ReentrancyVisitor::default();
            v.visit_block(&method.block);
            if let Some(line) = v.invoke_after_write_line {
                out.push(Finding {
                    check_name: CHECK_NAME.to_string(),
                    severity: Severity::High,
                    file_path: String::new(),
                    line,
                    function_name: fn_name.clone(),
                    description: format!(
                        "Method `{fn_name}` calls `invoke_contract` after a storage write. \
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
                         *after* the `invoke_contract` call (checks-effects-interactions \
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
    if !matches!(name.as_str(), "get" | "get_unchecked" | "has") {
        return false;
    }
    receiver_chain_contains_storage(&m.receiver)
}

fn is_invoke_contract(m: &ExprMethodCall) -> bool {
    matches!(
        m.method.to_string().as_str(),
        "invoke_contract" | "invoke_contract_check"
    )
}

#[derive(Default)]
struct ReentrancyVisitor {
    wrote: bool,
    re_read_after_write: bool,
    invoke_after_write_line: Option<usize>,
}

impl<'ast> Visit<'ast> for ReentrancyVisitor {
    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        if is_storage_write(i) {
            self.wrote = true;
            self.re_read_after_write = false;
        } else if self.wrote && is_storage_read(i) {
            self.re_read_after_write = true;
        } else if self.wrote
            && !self.re_read_after_write
            && is_invoke_contract(i)
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
        // Snapshot state inherited from before the if expression.
        let wrote_before = self.wrote;
        let re_read_before = self.re_read_after_write;

        // Evaluate the `then` branch in isolation.
        let mut then_visitor = ReentrancyVisitor {
            wrote: wrote_before,
            re_read_after_write: re_read_before,
            invoke_after_write_line: self.invoke_after_write_line,
        };
        then_visitor.visit_block(&expr_if.then_branch);

        // Evaluate the `else` branch (if present) in isolation, starting from
        // the *same* pre-if state, not the then-branch's exit state.
        let mut else_visitor = ReentrancyVisitor {
            wrote: wrote_before,
            re_read_after_write: re_read_before,
            invoke_after_write_line: self.invoke_after_write_line,
        };
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
}
