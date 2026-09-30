//! Flags `env.invoke_contract(…)` / `env.invoke_contract_check(…)` calls whose return value is silently discarded.

use crate::util::contractimpl_functions_excluding_test;
use crate::{Check, Finding, Severity};
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
                "Return value of `{}` in `{}` is discarded. \
                 A failure in the callee will be silently ignored, potentially \
                 leaving the contract in an inconsistent state.",
                m.method, self.fn_name
            ),
            rule_url: Some(
                "https://github.com/SorobanGuard/Guard-CLI/blob/main/docs/checks.md#unchecked-invoke-return-medium"
                    .to_string(),
            ),
            suggestion: Some(
                "Bind the return value and handle or assert it."
                    .to_string(),
            ),
        });
    }
}

impl<'ast> Visit<'ast> for InvokeReturnScan {
    fn visit_block(&mut self, block: &'ast Block) {
        for (i, stmt) in block.stmts.iter().enumerate() {
            match stmt {
                // Bare expression statement (semicolon present): `env.invoke_contract(...);`
                Stmt::Expr(Expr::MethodCall(m), Some(_)) => {
                    if is_invoke_contract(m) {
                        self.push_finding(m);
                    }
                }
                // Local variable binding: `let _ = env.invoke_contract(...);`
                Stmt::Local(local) => {
                    if let Some(init) = &local.init {
                        if let Some(m) = extract_invoke_contract(&init.expr) {
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

fn is_invoke_contract(m: &ExprMethodCall) -> bool {
    m.method == "invoke_contract" || m.method == "invoke_contract_check"
}

fn extract_invoke_contract(expr: &Expr) -> Option<&ExprMethodCall> {
    match expr {
        Expr::MethodCall(m) => {
            if is_invoke_contract(m) {
                Some(m)
            } else {
                extract_invoke_contract(&m.receiver)
            }
        }
        Expr::Paren(p) => extract_invoke_contract(&p.expr),
        // A `?` on the invoke call already propagates a callee failure to the
        // caller — it is the opposite of silently ignoring it. Any discarded
        // binding here (e.g. `let _ = env.invoke_contract(...)?;`) only throws
        // away the `Ok` payload, which this check does not flag.
        Expr::Try(_) => None,
        _ => None,
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
        env.invoke_contract::<()>(&callee, &Symbol::short("do"), ());
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
        let _ = env.invoke_contract::<()>(&callee, &Symbol::short("do"), ());
    }
}
"#);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Medium);
    }

    #[test]
    fn flags_let_underscore_invoke_contract_check() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env, Symbol, Address};
pub struct C;
#[contractimpl]
impl C {
    pub fn f(env: Env, callee: Address) {
        let _ = env.invoke_contract_check::<()>(&callee, &Symbol::short("do"), ());
    }
}
"#);
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn flags_let_unused_binding() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env, Symbol, Address};
pub struct C;
#[contractimpl]
impl C {
    pub fn f(env: Env, callee: Address) {
        let _result = env.invoke_contract::<()>(&callee, &Symbol::short("do"), ());
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
        let res = env.invoke_contract::<i128>(&callee, &Symbol::short("do"), ());
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
        let res: i128 = env.invoke_contract(&callee, &Symbol::short("do"), ());
        res + 1
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
        let res: i128 = env.invoke_contract(&callee, &Symbol::short("do"), ());
        assert!(res > 0);
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
        let _ = env.invoke_contract::<()>(&callee, &Symbol::short("do"), ())?;
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
        let _: () = env.invoke_contract::<()>(&callee, &Symbol::short("do"), ());
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
        let res: i128 = env.invoke_contract(&callee, &Symbol::short("do"), ());
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
        let res: i128 = env.invoke_contract(&callee, &Symbol::short("do"), ());
        let res = res + 1;  // RHS reads original `res` before shadowing
        res
    }
}
"#);
        assert!(hits.is_empty(), "RHS of shadowing let reads original binding — should pass; got: {hits:#?}");
    }
}
