//! Missing `env.require_auth()` before storage writes in `#[contractimpl]` methods.

use crate::util::{
    address_param_names, contractimpl_functions_excluding_test, env_param_name,
    is_storage_mutation_call, receiver_is_auth_gate, type_is_address,
};
use crate::{Check, Finding, Severity};
use std::collections::HashSet;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Block, Expr, ExprMethodCall, File, Pat, Stmt};

const CHECK_NAME: &str = "missing-require-auth";

/// Flags `#[contractimpl]` methods that write via `env.storage()` without calling
/// `<env_param>.require_auth()` where `<env_param>` is the actual name of the `Env` parameter.
pub struct MissingRequireAuthCheck;

impl Check for MissingRequireAuthCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions_excluding_test(file) {
            let env_param = env_param_name(&method.sig);
            let address_params = address_param_names(&method.sig);
            let mut scan = FuncBodyScan::new(env_param.as_deref(), address_params);
            let state = scan.scan_block(&method.block, AuthState::default());
            if !state.storage_write || state.env_require_auth || state.auth_helper_called {
                continue;
            }
            let line = first_storage_write_line(&method.block)
                .unwrap_or_else(|| method.sig.ident.span().start().line);
            let fn_name = method.sig.ident.to_string();
            let env_name = env_param.as_deref().unwrap_or("env");
            out.push(Finding {
                check_name: CHECK_NAME.to_string(),
                severity: Severity::High,
                file_path: String::new(),
                line,
                function_name: fn_name.clone(),
                description: format!(
                    "Method `{fn_name}` writes to `{env_name}.storage()` but does not call \
                     `{env_name}.require_auth()`. Callers may mutate contract state without proving \
                     they are authorized."
                ),
                rule_url: Some(
                    "https://github.com/SorobanGuard/Guard-CLI/blob/main/docs/checks.md#missing-require-auth-high"
                        .to_string(),
                ),
                suggestion: Some(format!(
                    "Add `{env_name}.require_auth();` as the first statement in the function body."
                )),
            });
        }
        out
    }
}

fn is_env_require_auth(
    m: &ExprMethodCall,
    env_name: &str,
    address_names: &[String],
    address_locals: &HashSet<String>,
) -> bool {
    if m.method != "require_auth" && m.method != "require_auth_for_args" {
        return false;
    }
    receiver_is_auth_gate(&m.receiver, env_name, address_names, address_locals)
}

fn is_auth_helper_method_call(
    m: &ExprMethodCall,
    env_name: &str,
    address_names: &[String],
    address_locals: &HashSet<String>,
) -> bool {
    let name = m.method.to_string();
    // Require an exact helper name (not merely a name fragment) so methods like
    // `check_authorization_table()` are not mistaken for an auth call.
    name == "assert_auth"
        || name == "check_auth"
        || (name.starts_with("require_auth")
            && !is_env_require_auth(m, env_name, address_names, address_locals)
            && !matches!(&*m.receiver, Expr::Path(_)))
}

/// Name bound by a `let` pattern whose (possibly annotated) type is `Address`.
fn address_local_binding(pat: &Pat) -> Option<String> {
    match pat {
        Pat::Type(pt) => {
            if type_is_address(&pt.ty) {
                address_local_binding(&pt.pat)
            } else {
                None
            }
        }
        Pat::Ident(pi) => Some(pi.ident.to_string()),
        _ => None,
    }
}

/// Per-path state used to decide whether an auth call *dominates* a write.
#[derive(Clone, Default)]
struct AuthState {
    storage_write: bool,
    env_require_auth: bool,
    auth_helper_called: bool,
    address_locals: HashSet<String>,
}

impl AuthState {
    /// Merge the exit states of mutually exclusive branches. Auth must hold on
    /// every path to count; a write on any path still counts.
    fn merge_branches(branches: Vec<AuthState>) -> AuthState {
        let mut storage_write = false;
        let mut env_require_auth = !branches.is_empty();
        let mut auth_helper_called = !branches.is_empty();
        let mut address_locals = HashSet::new();
        for branch in branches {
            storage_write |= branch.storage_write;
            env_require_auth &= branch.env_require_auth;
            auth_helper_called &= branch.auth_helper_called;
            address_locals.extend(branch.address_locals);
        }
        AuthState {
            storage_write,
            env_require_auth,
            auth_helper_called,
            address_locals,
        }
    }
}

struct FuncBodyScan {
    env_name: String,
    address_names: Vec<String>,
}

impl FuncBodyScan {
    fn new(env_name: Option<&str>, address_names: Vec<String>) -> Self {
        Self {
            env_name: env_name.unwrap_or("env").to_string(),
            address_names,
        }
    }

    fn is_auth_call(&self, m: &ExprMethodCall, locals: &HashSet<String>) -> bool {
        is_env_require_auth(m, &self.env_name, &self.address_names, locals)
            || is_auth_helper_method_call(m, &self.env_name, &self.address_names, locals)
    }

    fn scan_block(&mut self, block: &Block, mut state: AuthState) -> AuthState {
        for stmt in &block.stmts {
            self.scan_stmt(stmt, &mut state);
        }
        state
    }

    fn scan_stmt(&mut self, stmt: &Stmt, state: &mut AuthState) {
        match stmt {
            Stmt::Local(local) => {
                if let (Some(name), Some(init)) =
                    (address_local_binding(&local.pat), &local.init)
                {
                    state.address_locals.insert(name);
                    let mut isolated = AuthState {
                        address_locals: state.address_locals.clone(),
                        ..AuthState::default()
                    };
                    self.scan_expr(&init.expr, &mut isolated);
                    state.storage_write |= isolated.storage_write;
                }
            }
            Stmt::Expr(expr, _) => self.scan_expr(expr, state),
            _ => {
                // Items/macros cannot dominate a later write in a way this
                // check can prove; conservatively ignore them.
            }
        }
    }

    fn scan_expr(&mut self, expr: &Expr, state: &mut AuthState) {
        match expr {
            Expr::MethodCall(m) => {
                // Receiver and arguments are evaluated before the call.
                self.scan_expr(&m.receiver, state);
                for arg in &m.args {
                    self.scan_expr(arg, state);
                }
                if is_storage_mutation_call(m) {
                    state.storage_write = true;
                }
                if is_env_require_auth(m, &self.env_name, &self.address_names, &state.address_locals) {
                    state.env_require_auth = true;
                }
                if is_auth_helper_method_call(m, &self.env_name, &self.address_names, &state.address_locals) {
                    state.auth_helper_called = true;
                }
            }
            Expr::If(expr_if) => {
                // The condition always executes, so auth there is unconditional.
                self.scan_expr(&expr_if.cond, state);
                let mut then_state = state.clone();
                then_state = self.scan_block(&expr_if.then_branch, then_state);

                let mut branches = vec![then_state];
                if let Some((_, else_expr)) = &expr_if.else_branch {
                    let mut else_state = state.clone();
                    self.scan_expr(else_expr, &mut else_state);
                    branches.push(else_state);
                } else {
                    // No else arm: the "do nothing" path has no auth.
                    branches.push(state.clone());
                }
                *state = AuthState::merge_branches(branches);
            }
            Expr::Match(expr_match) => {
                self.scan_expr(&expr_match.expr, state);
                let mut branches = Vec::new();
                for arm in &expr_match.arms {
                    let mut arm_state = state.clone();
                    if let Some((_, guard)) = &arm.guard {
                        self.scan_expr(guard, &mut arm_state);
                    }
                    self.scan_expr(&arm.body, &mut arm_state);
                    branches.push(arm_state);
                }
                if branches.is_empty() {
                    branches.push(state.clone());
                }
                *state = AuthState::merge_branches(branches);
            }
            Expr::Loop(_) | Expr::While(_) | Expr::ForLoop(_) => {
                // A loop can execute zero times, so auth inside it never
                // dominates later writes. Collect writes conservatively.
                let mut body_state = state.clone();
                let mut collector = visitor::StorageOnly { storage_write: false };
                visit::visit_expr(&mut collector, expr);
                body_state.storage_write |= collector.storage_write;
                state.storage_write |= body_state.storage_write;
            }
            Expr::Closure(_) => {
                // Closures may never be called: their auth cannot gate writes.
                let mut collector = visitor::StorageOnly { storage_write: false };
                visit::visit_expr(&mut collector, expr);
                state.storage_write |= collector.storage_write;
            }
            Expr::Block(block) => {
                let inner = self.scan_block(&block.block, state.clone());
                state.storage_write |= inner.storage_write;
                state.env_require_auth |= inner.env_require_auth;
                state.auth_helper_called |= inner.auth_helper_called;
                state.address_locals = inner.address_locals;
            }
            Expr::Paren(p) => self.scan_expr(&p.expr, state),
            Expr::Group(g) => self.scan_expr(&g.expr, state),
            Expr::Reference(r) => self.scan_expr(&r.expr, state),
            Expr::Assign(a) => {
                self.scan_expr(&a.left, state);
                self.scan_expr(&a.right, state);
            }
            Expr::Call(c) => {
                self.scan_expr(&c.func, state);
                for arg in &c.args {
                    self.scan_expr(arg, state);
                }
            }
            Expr::Let(l) => self.scan_expr(&l.expr, state),
            Expr::Return(r) => {
                if let Some(e) = &r.expr {
                    self.scan_expr(e, state);
                }
            }
            _ => {
                // Unknown expression kinds are traversed for storage writes
                // only; auth found there is not treated as dominating.
                let mut collector = visitor::StorageOnly { storage_write: false };
                visit::visit_expr(&mut collector, expr);
                state.storage_write |= collector.storage_write;
            }
        }
    }
}

mod visitor {
    use super::*;
    use syn::visit::Visit;

    pub(super) struct StorageOnly {
        pub(super) storage_write: bool,
    }

    impl<'ast> Visit<'ast> for StorageOnly {
        fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
            if is_storage_mutation_call(i) {
                self.storage_write = true;
            }
            visit::visit_expr_method_call(self, i);
        }
    }
}

struct FirstStorageWrite {
    line: Option<usize>,
}

impl<'ast> Visit<'ast> for FirstStorageWrite {
    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        if self.line.is_none() && is_storage_mutation_call(i) {
            self.line = Some(i.span().start().line);
        }
        visit::visit_expr_method_call(self, i);
    }
}

fn first_storage_write_line(block: &Block) -> Option<usize> {
    let mut v = FirstStorageWrite { line: None };
    v.visit_block(block);
    v.line
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Check;
    use syn::parse_file;

    fn run_on_src(src: &str) -> Result<Vec<Finding>, syn::Error> {
        let file = parse_file(src)?;
        Ok(MissingRequireAuthCheck.run(&file, src))
    }

    #[test]
    fn flags_persistent_set_without_env_require_auth() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Env, Symbol};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn set_balance(env: Env, amount: i128) {
        env.storage().persistent().set(&Symbol::new(&env, "bal"), &amount);
    }
}
"#,
        )?;
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].function_name, "set_balance");
        assert_eq!(hits[0].severity, Severity::High);
        assert_eq!(hits[0].check_name, CHECK_NAME);
        Ok(())
    }

    #[test]
    fn passes_when_env_require_auth_present() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Address, Env, Symbol};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn set_balance(env: Env, user: Address, amount: i128) {
        env.require_auth();
        env.storage().persistent().set(&Symbol::new(&env, "bal"), &amount);
    }
}
"#,
        )?;
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn passes_when_only_address_require_auth() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Address, Env, Symbol};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn set_balance(env: Env, user: Address, amount: i128) {
        user.require_auth();
        env.storage().persistent().set(&Symbol::new(&env, "bal"), &amount);
    }
}
"#,
        )?;
        assert!(
            hits.is_empty(),
            "`user.require_auth()` should satisfy the check when user is an Address"
        );
        Ok(())
    }

    #[test]
    fn passes_when_from_address_require_auth() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Address, Env, Symbol};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn set_balance(env: Env, user: Address, amount: i128) {
        let from: Address = user;
        from.require_auth();
        env.storage().persistent().set(&Symbol::new(&env, "bal"), &amount);
    }
}
"#,
        )?;
        assert!(hits.is_empty());
        Ok(())
    }

    // ── Issue #1049: branch-sensitive auth dominance ────────────────────────

    #[test]
    fn conditional_auth_does_not_gate_a_later_write() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Address, Env, Symbol};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn withdraw(env: Env, to: Address, amount: i128) {
        if amount > 100 {
            to.require_auth();
        }
        env.storage().persistent().set(&Symbol::new(&env, "bal"), &0);
    }
}
"#,
        )?;
        assert_eq!(hits.len(), 1, "auth in one if arm must not gate the write");
        Ok(())
    }

    #[test]
    fn auth_in_both_if_arms_gates_a_later_write() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Address, Env, Symbol};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn withdraw(env: Env, to: Address, amount: i128) {
        if amount > 100 {
            to.require_auth();
        } else {
            to.require_auth();
        }
        env.storage().persistent().set(&Symbol::new(&env, "bal"), &0);
    }
}
"#,
        )?;
        assert!(hits.is_empty(), "auth on every path must gate the write");
        Ok(())
    }

    #[test]
    fn auth_in_one_match_arm_does_not_gate_a_later_write() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Address, Env, Symbol};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn withdraw(env: Env, to: Address, kind: u32) {
        match kind {
            1 => to.require_auth(),
            _ => (),
        }
        env.storage().persistent().set(&Symbol::new(&env, "bal"), &0);
    }
}
"#,
        )?;
        assert_eq!(hits.len(), 1);
        Ok(())
    }

    #[test]
    fn auth_inside_a_loop_does_not_gate_a_later_write() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Address, Env, Symbol};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn withdraw(env: Env, to: Address, count: u32) {
        for _ in 0..count {
            to.require_auth();
        }
        env.storage().persistent().set(&Symbol::new(&env, "bal"), &0);
    }
}
"#,
        )?;
        assert_eq!(hits.len(), 1);
        Ok(())
    }

    #[test]
    fn auth_inside_a_closure_does_not_gate_a_later_write() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Address, Env, Symbol};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn withdraw(env: Env, to: Address) {
        let check = || to.require_auth();
        env.storage().persistent().set(&Symbol::new(&env, "bal"), &0);
    }
}
"#,
        )?;
        assert_eq!(hits.len(), 1);
        Ok(())
    }
}
