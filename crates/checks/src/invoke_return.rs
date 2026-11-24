//! Flags fallible cross-contract calls whose result is silently discarded.
//!
//! `env.invoke_contract(..)` / `invoke_contract_check(..)` return `T` and trap the whole
//! transaction if the callee fails, so there is no failure to ignore and discarding a
//! (often unit) return value is fine. The calls that *can* fail silently are the fallible
//! ones, which return a `Result` the caller must inspect:
//!
//! - `env.try_invoke_contract(..)`;
//! - `try_*` methods on a contract client — an expression or `let` binding built with
//!   `<X>Client::new(..)` (`token::Client`, `TokenClient`, a generated `FooClient`),
//!   e.g. `client.try_transfer(..)`.
//!
//! A result is discarded when the call is a bare statement, bound to `_` / `_name`, or bound
//! to a name that is never read.

use crate::util::contractimpl_functions_excluding_test;
use crate::{Check, Finding, Severity};
use std::collections::HashSet;
use syn::visit::{self, Visit};
use syn::{Block, Expr, ExprMethodCall, File, Ident, Pat, Stmt};

const CHECK_NAME: &str = "unchecked-invoke-return";

pub struct UncheckedInvokeReturnCheck;

impl Check for UncheckedInvokeReturnCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions_excluding_test(file) {
            let fn_name = method.sig.ident.to_string();
            let mut scan = InvokeReturnScan {
                fn_name,
                findings: Vec::new(),
                client_bindings: HashSet::new(),
            };
            scan.visit_block(&method.block);
            out.extend(scan.findings);
        }
        out
    }
}

struct InvokeReturnScan {
    fn_name: String,
    findings: Vec<Finding>,
    /// Local bindings holding a contract client (`let c = token::Client::new(..)`).
    client_bindings: HashSet<String>,
}

impl InvokeReturnScan {
    fn push_finding(&mut self, m: &ExprMethodCall) {
        self.findings.push(Finding {
            check_name: CHECK_NAME.to_string(),
            severity: Severity::Medium,
            file_path: String::new(),
            line: m.method.span().start().line,
            function_name: self.fn_name.clone(),
            description: format!(
                "Result of the fallible call `{}` in `{}` is discarded. Unlike \
                 `invoke_contract`, which traps the transaction when the callee fails, \
                 `{}` returns the failure as a `Result`, so ignoring it lets the \
                 function carry on as if the call had succeeded.",
                m.method, self.fn_name, m.method
            ),
            rule_url: Some(
                "https://github.com/SorobanGuard/Guard-CLI/blob/main/docs/checks.md#unchecked-invoke-return-medium"
                    .to_string(),
            ),
            suggestion: Some(
                "Match on the `Result` (or call `.unwrap()` / `?`) and handle the error case, \
                 or use the non-`try_` variant if a failure should abort the transaction."
                    .to_string(),
            ),
        });
    }
}

impl<'ast> Visit<'ast> for InvokeReturnScan {
    fn visit_block(&mut self, block: &'ast Block) {
        for (i, stmt) in block.stmts.iter().enumerate() {
            match stmt {
                // Bare expression statement (semicolon present): `env.try_invoke_contract(...);`
                Stmt::Expr(Expr::MethodCall(m), Some(_)) => {
                    if self.is_fallible_call(m) {
                        self.push_finding(m);
                    }
                }
                // Local variable binding: `let _ = env.try_invoke_contract(...);`
                Stmt::Local(local) => {
                    if let Some(init) = &local.init {
                        self.track_client_binding(&local.pat, &init.expr);
                        if let Some(m) = self.extract_fallible_call(&init.expr) {
                            let pat = match &local.pat {
                                Pat::Type(pt) => &*pt.pat,
                                other => other,
                            };
                            let is_discarded = match pat {
                                Pat::Wild(_) => true,
                                Pat::Ident(pi) => {
                                    let name = pi.ident.to_string();
                                    name.starts_with('_')
                                        || !is_ident_used_in_stmts(&pi.ident, &block.stmts[i + 1..])
                                }
                                _ => false,
                            };
                            if is_discarded {
                                self.push_finding(m);
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        visit::visit_block(self, block);
    }
}

/// `X::new(..)` where `X` ends with `Client` (looking through `&` and parens).
fn is_client_ctor(expr: &Expr) -> bool {
    match expr {
        Expr::Reference(r) => is_client_ctor(&r.expr),
        Expr::Paren(p) => is_client_ctor(&p.expr),
        Expr::Call(call) => {
            let Expr::Path(p) = &*call.func else {
                return false;
            };
            let segs = &p.path.segments;
            let n = segs.len();
            n >= 2
                && segs[n - 1].ident == "new"
                && segs[n - 2].ident.to_string().ends_with("Client")
        }
        _ => false,
    }
}

impl InvokeReturnScan {
    fn track_client_binding(&mut self, pat: &Pat, init: &Expr) {
        let pat = match pat {
            Pat::Type(pt) => &*pt.pat,
            other => other,
        };
        if let Pat::Ident(pi) = pat {
            let name = pi.ident.to_string();
            if is_client_ctor(init) {
                self.client_bindings.insert(name);
            } else {
                self.client_bindings.remove(&name);
            }
        }
    }

    fn is_client_expr(&self, expr: &Expr) -> bool {
        match expr {
            Expr::Path(p) => p
                .path
                .get_ident()
                .is_some_and(|i| self.client_bindings.contains(&i.to_string())),
            Expr::Reference(r) => self.is_client_expr(&r.expr),
            Expr::Paren(p) => self.is_client_expr(&p.expr),
            other => is_client_ctor(other),
        }
    }

    /// `try_invoke_contract(..)`, or a `try_*` method on a contract client.
    fn is_fallible_call(&self, m: &ExprMethodCall) -> bool {
        m.method == "try_invoke_contract"
            || (m.method.to_string().starts_with("try_") && self.is_client_expr(&m.receiver))
    }

    /// The fallible call whose `Result` *is* `expr` (looking through parens). A call
    /// further down a method chain (`client.try_transfer(..).is_ok()`,
    /// `.unwrap()`) has its result inspected, so it is not returned.
    fn extract_fallible_call<'e>(&self, expr: &'e Expr) -> Option<&'e ExprMethodCall> {
        match expr {
            Expr::MethodCall(m) if self.is_fallible_call(m) => Some(m),
            Expr::Paren(p) => self.extract_fallible_call(&p.expr),
            // `?` propagates the call's error to the caller — the opposite of ignoring it.
            _ => None,
        }
    }
}

struct IdentUsageVisitor<'a> {
    target: &'a Ident,
    used: bool,
}

impl<'ast, 'a> Visit<'ast> for IdentUsageVisitor<'a> {
    /// Only count actual *reads* (identifier appearing in expression position).
    /// Overriding `visit_expr_path` instead of `visit_ident` avoids counting
    /// `Pat::Ident` nodes (variable declarations / shadowing `let` bindings) as
    /// uses of the identifier.
    fn visit_expr_path(&mut self, expr: &'ast syn::ExprPath) {
        if expr.path.is_ident(self.target) {
            self.used = true;
        }
        visit::visit_expr_path(self, expr);
    }

    fn visit_macro(&mut self, m: &'ast syn::Macro) {
        fn check_tokens(tokens: proc_macro2::TokenStream, target: &str) -> bool {
            for tt in tokens {
                match tt {
                    proc_macro2::TokenTree::Ident(id) => {
                        if id == target {
                            return true;
                        }
                    }
                    proc_macro2::TokenTree::Group(g) => {
                        if check_tokens(g.stream(), target) {
                            return true;
                        }
                    }
                    _ => {}
                }
            }
            false
        }
        if check_tokens(m.tokens.clone(), &self.target.to_string()) {
            self.used = true;
        }
        visit::visit_macro(self, m);
    }
}

/// Returns `true` if `ident` is *read* (used in expression position) in `stmts`.
///
/// Stops scanning as soon as a shadowing `let <ident> = …` is encountered —
/// any subsequent use of the same name refers to the new binding, not the
/// original `invoke_contract` result.
fn is_ident_used_in_stmts(ident: &Ident, stmts: &[Stmt]) -> bool {
    for stmt in stmts {
        // Check for a shadowing re-declaration *before* visiting the statement
        // for reads.  A `let res = …` pattern rebinds `res`, so uses of `res`
        // after this point belong to the new binding.
        if let Stmt::Local(local) = stmt {
            let pat = match &local.pat {
                Pat::Type(pt) => &*pt.pat,
                other => other,
            };
            if let Pat::Ident(pi) = pat {
                if pi.ident == *ident {
                    // This statement re-declares the name.  The RHS initialiser
                    // of the shadowing let (if any) is still part of the *old*
                    // scope — check it for reads before stopping.
                    if let Some(init) = &local.init {
                        let mut visitor = IdentUsageVisitor {
                            target: ident,
                            used: false,
                        };
                        visitor.visit_expr(&init.expr);
                        if visitor.used {
                            return true;
                        }
                    }
                    // The name is now shadowed; don't look further.
                    return false;
                }
            }
        }

        let mut visitor = IdentUsageVisitor {
            target: ident,
            used: false,
        };
        visitor.visit_stmt(stmt);
        if visitor.used {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Check;
    use syn::parse_file;

    fn run(src: &str) -> Vec<Finding> {
        let file = parse_file(src).expect("parse");
        UncheckedInvokeReturnCheck.run(&file, src)
    }

    #[test]
    fn flags_bare_invoke_contract() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env, Symbol, Address};
pub struct C;
#[contractimpl]
impl C {
    pub fn f(env: Env, callee: Address) {
        env.try_invoke_contract::<(), soroban_sdk::Error>(&callee, &Symbol::short("do"), ());
    }
}
"#);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Medium);
    }

    #[test]
    fn flags_let_underscore_invoke_contract() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env, Symbol, Address};
pub struct C;
#[contractimpl]
impl C {
    pub fn f(env: Env, callee: Address) {
        let _ = env.try_invoke_contract::<(), soroban_sdk::Error>(&callee, &Symbol::short("do"), ());
    }
}
"#);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Medium);
    }

    #[test]
    fn flags_let_unused_binding() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env, Symbol, Address};
pub struct C;
#[contractimpl]
impl C {
    pub fn f(env: Env, callee: Address) {
        let _result = env.try_invoke_contract::<(), soroban_sdk::Error>(&callee, &Symbol::short("do"), ());
    }
}
"#);
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn flags_unreferenced_binding() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env, Symbol, Address};
pub struct C;
#[contractimpl]
impl C {
    pub fn f(env: Env, callee: Address) {
        let res = env.try_invoke_contract::<i128, soroban_sdk::Error>(&callee, &Symbol::short("do"), ());
    }
}
"#);
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn passes_when_binding_is_used() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env, Symbol, Address};
pub struct C;
#[contractimpl]
impl C {
    pub fn f(env: Env, callee: Address) -> i128 {
        let res = env.try_invoke_contract::<i128, soroban_sdk::Error>(&callee, &Symbol::short("do"), ());
        res.unwrap().unwrap() + 1
    }
}
"#);
        assert!(hits.is_empty());
    }

    #[test]
    fn passes_when_binding_is_checked_in_assert() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env, Symbol, Address};
pub struct C;
#[contractimpl]
impl C {
    pub fn f(env: Env, callee: Address) {
        let res = env.try_invoke_contract::<i128, soroban_sdk::Error>(&callee, &Symbol::short("do"), ());
        assert!(res.is_ok());
    }
}
"#);
        assert!(hits.is_empty());
    }

    #[test]
    fn passes_when_invoke_result_propagated_with_try_operator() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env, Symbol, Address};
pub struct C;
#[contractimpl]
impl C {
    pub fn f(env: Env, callee: Address) -> Result<(), soroban_sdk::Error> {
        let _ = env.try_invoke_contract::<(), soroban_sdk::Error>(&callee, &Symbol::short("do"), ())?;
        Ok(())
    }
}
"#);
        assert!(hits.is_empty());
    }

    #[test]
    fn flags_let_underscore_with_type_invoke_contract() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env, Symbol, Address};
pub struct C;
#[contractimpl]
impl C {
    pub fn f(env: Env, callee: Address) {
        let _: Result<_, _> = env.try_invoke_contract::<(), soroban_sdk::Error>(&callee, &Symbol::short("do"), ());
    }
}
"#);
        assert_eq!(hits.len(), 1);
    }

    /// Regression test for issue #694: a shadowing `let res = 5;` must NOT count
    /// as a "use" of the original invoke_contract result.  The original return value
    /// was never actually read — the binding was immediately shadowed — so the check
    /// must still produce a finding.
    #[test]
    fn flags_invoke_result_shadowed_without_use() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env, Symbol, Address};
pub struct C;
#[contractimpl]
impl C {
    pub fn f(env: Env, callee: Address) {
        let res = env.try_invoke_contract::<i128, soroban_sdk::Error>(&callee, &Symbol::short("do"), ());
        let res = 5i128;   // shadows without reading the invoke result
        let _ = res;
    }
}
"#);
        assert_eq!(hits.len(), 1, "shadowing let should not count as a use; got: {hits:#?}");
    }

    /// Shadowing where the RHS of the shadowing let *reads* the original binding
    /// — that IS a genuine use and must suppress the finding.
    #[test]
    fn passes_when_shadowing_rhs_reads_original_binding() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env, Symbol, Address};
pub struct C;
#[contractimpl]
impl C {
    pub fn f(env: Env, callee: Address) -> i128 {
        let res = env.try_invoke_contract::<i128, soroban_sdk::Error>(&callee, &Symbol::short("do"), ());
        let res = res.unwrap().unwrap() + 1;  // RHS reads original `res` before shadowing
        res
    }
}
"#);
        assert!(hits.is_empty(), "RHS of shadowing let reads original binding — should pass; got: {hits:#?}");
    }

    /// #1059: `invoke_contract` traps on failure, so there is nothing to ignore.
    #[test]
    fn passes_discarded_plain_invoke_contract() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env, Symbol, Address};
pub struct C;
#[contractimpl]
impl C {
    pub fn f(env: Env, callee: Address) {
        env.invoke_contract::<()>(&callee, &Symbol::short("do"), ());
        let _ = env.invoke_contract_check::<()>(&callee, &Symbol::short("do"), ());
    }
}
"#);
        assert!(hits.is_empty(), "{hits:#?}");
    }

    /// #1059: a client's `try_*` method returns a `Result` that can be dropped.
    #[test]
    fn flags_discarded_client_try_method() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, token, Env, Address};
pub struct C;
#[contractimpl]
impl C {
    pub fn pay(env: Env, tok: Address, to: Address, amount: i128) {
        let client = token::Client::new(&env, &tok);
        client.try_transfer(&env.current_contract_address(), &to, &amount);
        let _ = token::TokenClient::new(&env, &tok).try_burn(&to, &amount);
    }
}
"#);
        assert_eq!(hits.len(), 2, "{hits:#?}");
        assert!(hits[0].description.contains("try_transfer"));
        assert!(!hits[0].description.contains("silently ignored"));
    }

    /// #1059: inspecting the `Result`, or non-client `try_*` methods, is fine.
    #[test]
    fn passes_checked_try_calls_and_non_client_try_methods() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, token, Env, Address};
pub struct C;
#[contractimpl]
impl C {
    pub fn pay(env: Env, tok: Address, to: Address, amount: i128) -> bool {
        let client = token::Client::new(&env, &tok);
        if client.try_transfer(&env.current_contract_address(), &to, &amount).is_err() {
            return false;
        }
        let ok = client.try_burn(&to, &amount).is_ok();
        let n: u32 = 5u64.try_into().unwrap();
        let _ = n;
        ok
    }
}
"#);
        assert!(hits.is_empty(), "{hits:#?}");
    }
}
