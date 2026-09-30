//! Flags `initialize`/`init`/`setup` functions in `#[contractimpl]` that do not guard
//! against being called more than once.

use crate::util::{contractimpl_functions_excluding_test, receiver_chain_contains_storage};
use crate::{Check, Finding, Severity};
use syn::visit::{self, Visit};
use syn::{ExprMethodCall, File};

const CHECK_NAME: &str = "re-initialization-risk";

pub struct ReInitializationRiskCheck;

impl Check for ReInitializationRiskCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions_excluding_test(file) {
            let fn_name = method.sig.ident.to_string();
            if !is_init_fn(&fn_name) {
                continue;
            }
            let mut scan = BodyScan::default();
            scan.visit_block(&method.block);
            if !scan.has_storage_write || scan.has_guard {
                continue;
            }
            out.push(Finding {
                check_name: CHECK_NAME.to_string(),
                severity: Severity::High,
                file_path: String::new(),
                line: method.sig.ident.span().start().line,
                function_name: fn_name.clone(),
                description: format!(
                    "Function `{fn_name}` writes to storage but does not guard against \
                     re-initialization. An attacker can call it again to overwrite the owner \
                     or reset critical contract state."
                ),
                rule_url: Some(
                    "https://github.com/SorobanGuard/Guard-CLI/blob/main/docs/checks.md#re-initialization-risk-high"
                        .to_string(),
                ),
                suggestion: Some(
                    "Check `env.storage().*.has(&key)` and panic or return if already initialized, \
                     e.g. `require!(!env.storage().instance().has(&key), \"already initialized\");`."
                        .to_string(),
                ),
            });
        }
        out
    }
}

fn is_init_fn(name: &str) -> bool {
    name == "init"
        || name == "initialize"
        || name == "setup"
        || name == "constructor"
        || name.starts_with("init_")
        || name.starts_with("initialize_")
        || name.starts_with("setup_")
}

#[derive(Default)]
struct BodyScan {
    has_storage_write: bool,
    has_guard: bool,
}

impl<'ast> Visit<'ast> for BodyScan {
    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        let method = i.method.to_string();
        if method == "set" && receiver_chain_contains_storage(&i.receiver) {
            self.has_storage_write = true;
        }
        // A bare `.has()`/`.is_some()`/`.is_none()` call is no longer treated as a guard
        // here: it only counts when it actually gates an early return/panic, which
        // `visit_expr_if` below verifies.
        visit::visit_expr_method_call(self, i);
    }

    fn visit_expr_if(&mut self, i: &'ast syn::ExprIf) {
        if is_storage_guard_check(&i.cond) && block_diverges(&i.then_branch) {
            self.has_guard = true;
        }
        visit::visit_expr_if(self, i);
    }

    fn visit_macro(&mut self, i: &'ast syn::Macro) {
        let name = i
            .path
            .segments
            .last()
            .map(|s| s.ident.to_string())
            .unwrap_or_default();
        if name == "require" {
            // `require!(<cond>, ...)` only counts as a re-init guard when `<cond>` itself
            // is a storage presence check, e.g. `require!(!env.storage().instance().has(&k), ..)`.
            // A `require!` validating unrelated input (e.g. `require!(fee >= 0, ..)`) must not
            // count, since it never gates the storage write.
            if let Ok(cond) = i.parse_body_with(syn::Expr::parse_without_eager_brace) {
                if is_storage_guard_check(&cond) {
                    self.has_guard = true;
                }
            }
        }
        // A bare `panic!(..)` is only a guard when it is the divergent branch of an
        // `if` whose condition is itself a storage guard check (handled in `visit_expr_if`).
        visit::visit_macro(self, i);
    }
}

/// Does `expr` check the presence/absence of a value read from storage (e.g.
/// `env.storage().instance().has(&key)`, or its negation)? This is what makes an `if`
/// condition or a `require!` argument an actual re-initialization guard, rather than an
/// unrelated boolean check that merely happens to sit near the write.
fn is_storage_guard_check(expr: &syn::Expr) -> bool {
    match expr {
        syn::Expr::MethodCall(mc) => {
            matches!(
                mc.method.to_string().as_str(),
                "has" | "is_some" | "is_none"
            ) && receiver_chain_contains_storage(&mc.receiver)
        }
        syn::Expr::Unary(u) if matches!(u.op, syn::UnOp::Not(_)) => is_storage_guard_check(&u.expr),
        syn::Expr::Paren(p) => is_storage_guard_check(&p.expr),
        syn::Expr::Binary(b) => is_storage_guard_check(&b.left) || is_storage_guard_check(&b.right),
        _ => false,
    }
}

/// Does this block contain a statement that would stop execution before falling through
/// to the rest of the function (a `return`, or a `panic!`/`require!` invocation)? Used to
/// confirm an `if` guarded by a storage check actually prevents the write from executing,
/// rather than just performing the check and continuing.
fn block_diverges(block: &syn::Block) -> bool {
    block.stmts.iter().any(stmt_diverges)
}

fn stmt_diverges(stmt: &syn::Stmt) -> bool {
    match stmt {
        syn::Stmt::Expr(syn::Expr::Return(_), _) => true,
        syn::Stmt::Expr(syn::Expr::Macro(m), _) => macro_name_diverges(&m.mac),
        syn::Stmt::Macro(m) => macro_name_diverges(&m.mac),
        _ => false,
    }
}

fn macro_name_diverges(mac: &syn::Macro) -> bool {
    mac.path
        .segments
        .last()
        .is_some_and(|s| matches!(s.ident.to_string().as_str(), "panic" | "require"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Check;
    use syn::parse_file;

    fn run(src: &str) -> Vec<Finding> {
        let file = parse_file(src).expect("parse");
        ReInitializationRiskCheck.run(&file, src)
    }

    #[test]
    fn flags_init_with_unrelated_is_some_and_unconditional_write() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env, Address};
pub struct C;
#[contractimpl]
impl C {
    pub fn initialize(env: Env, admin: Address, referrer: Option<Address>) {
        if referrer.is_some() {
            // unrelated referral logic
        }
        env.storage().instance().set(&0, &admin);
    }
}
"#);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].check_name, CHECK_NAME);
    }

    #[test]
    fn passes_when_storage_has_guard_gates_write() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env, Address};
pub struct C;
#[contractimpl]
impl C {
    pub fn initialize(env: Env, admin: Address) {
        if env.storage().instance().has(&0) {
            panic!("already initialized");
        }
        env.storage().instance().set(&0, &admin);
    }
}
"#);
        assert!(hits.is_empty());
    }

    #[test]
    fn flags_init_when_has_result_is_ignored_not_gating_write() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env, Address};
pub struct C;
#[contractimpl]
impl C {
    pub fn init(env: Env, admin: Address) {
        let _present = env.storage().instance().has(&0);
        env.storage().instance().set(&0, &admin);
    }
}
"#);
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn flags_init_when_require_only_validates_unrelated_input() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env, Address};
pub struct C;
#[contractimpl]
impl C {
    pub fn initialize(env: Env, admin: Address, fee: i128) {
        require!(fee >= 0, "bad fee");
        env.storage().instance().set(&0, &admin);
    }
}
"#);
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn passes_when_require_guard_checks_storage_presence() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env, Address};
pub struct C;
#[contractimpl]
impl C {
    pub fn initialize(env: Env, admin: Address) {
        require!(!env.storage().instance().has(&0), "already initialized");
        env.storage().instance().set(&0, &admin);
    }
}
"#);
        assert!(hits.is_empty());
    }

    #[test]
    fn flags_init_without_any_guard() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env, Address};
pub struct C;
#[contractimpl]
impl C {
    pub fn initialize(env: Env, admin: Address) {
        env.storage().instance().set(&0, &admin);
    }
}
"#);
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn ignores_deinit() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env, Address};
pub struct C;
#[contractimpl]
impl C {
    pub fn deinit(env: Env, admin: Address) {
        env.storage().instance().set(&0, &admin);
    }
}
"#);
        assert!(hits.is_empty());
    }

    #[test]
    fn ignores_commit_setup() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env, Address};
pub struct C;
#[contractimpl]
impl C {
    pub fn commit_setup(env: Env, admin: Address) {
        env.storage().instance().set(&0, &admin);
    }
}
"#);
        assert!(hits.is_empty());
    }

    #[test]
    fn flags_init_still() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env, Address};
pub struct C;
#[contractimpl]
impl C {
    pub fn init(env: Env, admin: Address) {
        env.storage().instance().set(&0, &admin);
    }
}
"#);
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn flags_initialize_still() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env, Address};
pub struct C;
#[contractimpl]
impl C {
    pub fn initialize(env: Env, admin: Address) {
        env.storage().instance().set(&0, &admin);
    }
}
"#);
        assert_eq!(hits.len(), 1);
    }
}
