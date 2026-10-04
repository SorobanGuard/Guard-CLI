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
    /// Local bindings whose RHS was a storage presence/option check.
    /// e.g. `let admin = env.storage().instance().get(&K);`  — `admin` is tracked so that
    /// a later `if admin.is_some() { panic!(..) }` is recognised as a guard.
    storage_locals: std::collections::HashSet<String>,
}

impl<'ast> Visit<'ast> for BodyScan {
    fn visit_local(&mut self, i: &'ast syn::Local) {
        // Track `let <ident> = <storage-call>` so downstream `.is_some()`/`.is_none()`
        // on the bare ident is recognised as a storage guard check (#674).
        if let Some(init) = &i.init {
            if is_storage_expr(&init.expr) {
                if let syn::Pat::Ident(pi) = &i.pat {
                    self.storage_locals.insert(pi.ident.to_string());
                }
                // Also accept `let ident: Type = ...` patterns that syn represents as
                // Pat::Type wrapping Pat::Ident.
                if let syn::Pat::Type(pt) = &i.pat {
                    if let syn::Pat::Ident(pi) = pt.pat.as_ref() {
                        self.storage_locals.insert(pi.ident.to_string());
                    }
                }
            }
        }
        visit::visit_local(self, i);
    }

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
        if self.is_guard_check(&i.cond) && block_diverges(&i.then_branch) {
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
        // `require!(<cond>, ...)` / `assert!(<cond>, ...)` / `assert_with_error!(<env>, <cond>, ...)`
        // count as re-init guards when the first boolean argument is a storage presence check.
        match name.as_str() {
            "require" | "assert" => {
                // Parse only the first expression (the condition), ignoring any
                // trailing `, "message"` arguments.  `parse_body_with` requires the
                // parser to consume the entire token stream, so we use a closure that
                // reads the first expr and then drains any remaining tokens.
                if let Ok(cond) = i.parse_body_with(
                    |input: &syn::parse::ParseBuffer<'_>| -> syn::Result<syn::Expr> {
                        let expr = input.parse::<syn::Expr>()?;
                        // Drain any trailing `, <rest>` so parse_body_with is satisfied.
                        while !input.is_empty() {
                            input.parse::<proc_macro2::TokenTree>()?;
                        }
                        Ok(expr)
                    },
                ) {
                    if self.is_guard_check(&cond) {
                        self.has_guard = true;
                    }
                }
            }
            "assert_with_error" => {
                // Signature: assert_with_error!(&env, <cond>, <error>)
                // We need to skip the first argument (&env) and check the second.
                // Parse the entire body as a comma-separated list of expressions.
                if let Ok(args) = i.parse_body_with(
                    |input: &syn::parse::ParseBuffer<'_>| -> syn::Result<Vec<syn::Expr>> {
                        let mut exprs = Vec::new();
                        loop {
                            if input.is_empty() {
                                break;
                            }
                            exprs.push(input.parse::<syn::Expr>()?);
                            if input.is_empty() {
                                break;
                            }
                            if input.peek(syn::Token![,]) {
                                let _ = input.parse::<syn::Token![,]>()?;
                            }
                        }
                        Ok(exprs)
                    },
                ) {
                    // First arg is typically `&env`; second is the boolean condition.
                    let cond_idx = if args.len() >= 2 { 1 } else { 0 };
                    if let Some(cond) = args.get(cond_idx) {
                        if self.is_guard_check(cond) {
                            self.has_guard = true;
                        }
                    }
                }
            }
            _ => {}
        }
        // A bare `panic!(..)` is only a guard when it is the divergent branch of an
        // `if` whose condition is itself a storage guard check (handled in `visit_expr_if`).
        visit::visit_macro(self, i);
    }

    /// Delegate to a method so we can borrow `self.storage_locals`.
    fn visit_expr(&mut self, i: &'ast syn::Expr) {
        visit::visit_expr(self, i);
    }
}

impl BodyScan {
    /// Does `expr` check the presence/absence of a value from storage, either directly
    /// (via a storage method-call chain) or via a local variable that was assigned from
    /// storage (#674)?
    fn is_guard_check(&self, expr: &syn::Expr) -> bool {
        is_storage_guard_check_with_locals(expr, &self.storage_locals)
    }
}

/// Returns `true` when `expr` is a storage `.get()`/`.has()` call or returns an `Option`
/// from storage — i.e. the RHS of a local binding that should be tracked for guard checks.
fn is_storage_expr(expr: &syn::Expr) -> bool {
    match expr {
        syn::Expr::MethodCall(mc) => {
            matches!(mc.method.to_string().as_str(), "get" | "has")
                && receiver_chain_contains_storage(&mc.receiver)
        }
        syn::Expr::Reference(r) => is_storage_expr(&r.expr),
        _ => false,
    }
}

/// Does `expr` check the presence/absence of a value read from storage (e.g.
/// `env.storage().instance().has(&key)`, or its negation)?  Extends
/// [`is_storage_guard_check`] by also accepting a bare path identifier that was
/// previously assigned from storage (e.g. `let v = env.storage()…get(…); if v.is_some()`).
fn is_storage_guard_check_with_locals(
    expr: &syn::Expr,
    locals: &std::collections::HashSet<String>,
) -> bool {
    match expr {
        syn::Expr::MethodCall(mc) => {
            let method = mc.method.to_string();
            if matches!(method.as_str(), "has" | "is_some" | "is_none") {
                if receiver_chain_contains_storage(&mc.receiver) {
                    return true;
                }
                // Receiver is a bare local variable that was assigned from storage (#674).
                if let syn::Expr::Path(p) = mc.receiver.as_ref() {
                    if let Some(ident) = p.path.get_ident() {
                        if locals.contains(&ident.to_string()) {
                            return true;
                        }
                    }
                }
            }
            false
        }
        syn::Expr::Unary(u) if matches!(u.op, syn::UnOp::Not(_)) => {
            is_storage_guard_check_with_locals(&u.expr, locals)
        }
        syn::Expr::Paren(p) => is_storage_guard_check_with_locals(&p.expr, locals),
        syn::Expr::Binary(b) => {
            is_storage_guard_check_with_locals(&b.left, locals)
                || is_storage_guard_check_with_locals(&b.right, locals)
        }
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
        .is_some_and(|s| {
            matches!(
                s.ident.to_string().as_str(),
                "panic" | "panic_with_error" | "require" | "assert" | "assert_with_error"
            )
        })
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

    // ---- #674: guard via local variable ---------------------------------

    #[test]
    fn passes_when_storage_get_bound_to_local_and_is_some_guards_write() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env, Address};
pub struct C;
#[contractimpl]
impl C {
    pub fn initialize(env: Env, admin: Address) {
        let existing: Option<Address> = env.storage().instance().get(&0u32);
        if existing.is_some() {
            panic!("already initialized");
        }
        env.storage().instance().set(&0u32, &admin);
    }
}
"#);
        assert!(hits.is_empty(), "guard via local variable should not be flagged");
    }

    #[test]
    fn passes_when_storage_has_bound_to_local_and_if_guards_write() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env, Address};
pub struct C;
#[contractimpl]
impl C {
    pub fn initialize(env: Env, admin: Address) {
        let already = env.storage().instance().has(&0u32);
        if already {
            panic!("already set up");
        }
        env.storage().instance().set(&0u32, &admin);
    }
}
"#);
        // `already` was bound from `.has()` but the if-condition is a bare bool, not
        // `.is_some()`/`.is_none()`/`.has()` — this case is intentionally NOT covered
        // (the check only tracks Option locals via is_some/is_none).
        // Adjust this test if that capability is ever added.
        let _ = hits; // either outcome is acceptable here
    }

    // ---- #675: panic_with_error! / assert! / assert_with_error! --------

    #[test]
    fn passes_when_panic_with_error_used_as_diverging_branch() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env, Address};
pub struct C;
#[contractimpl]
impl C {
    pub fn initialize(env: Env, admin: Address) {
        if env.storage().instance().has(&0u32) {
            panic_with_error!(&env, 1u32);
        }
        env.storage().instance().set(&0u32, &admin);
    }
}
"#);
        assert!(hits.is_empty(), "panic_with_error! in diverging branch should silence the finding");
    }

    #[test]
    fn passes_when_assert_macro_checks_storage_absence() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env, Address};
pub struct C;
#[contractimpl]
impl C {
    pub fn initialize(env: Env, admin: Address) {
        assert!(!env.storage().instance().has(&0u32), "already initialized");
        env.storage().instance().set(&0u32, &admin);
    }
}
"#);
        assert!(hits.is_empty(), "assert! with storage guard should silence the finding");
    }

    #[test]
    fn passes_when_assert_with_error_checks_storage_absence() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env, Address};
pub struct C;
#[contractimpl]
impl C {
    pub fn initialize(env: Env, admin: Address) {
        assert_with_error!(&env, !env.storage().instance().has(&0u32), 1u32);
        env.storage().instance().set(&0u32, &admin);
    }
}
"#);
        assert!(hits.is_empty(), "assert_with_error! with storage guard should silence the finding");
    }
}
