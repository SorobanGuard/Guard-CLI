//! Detect cross-contract return values used directly in storage writes without validation.
//!
//! Pattern: `invoke_contract(…)` result stored in a binding that is then passed to
//! `env.storage().*.set(…, &binding)` without any intervening `if`, `match`, or
//! `unwrap_or*` / `ok_or*` / `checked_*` call.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use std::collections::HashSet;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, File, Pat, Stmt};

const CHECK_NAME: &str = "unsafe-cross-contract-input";

pub struct UnsafeCrossContractInputCheck;

impl Check for UnsafeCrossContractInputCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            let mut v = XcInputVisitor {
                fn_name,
                xc_bindings: HashSet::new(),
                out: &mut out,
            };
            // Walk statements in order so binding collection precedes usage checks.
            for stmt in &method.block.stmts {
                v.visit_stmt(stmt);
            }
        }
        out
    }
}

/// Returns `true` if this method call is (or transitively wraps) `invoke_contract`.
fn is_invoke_contract(e: &Expr) -> bool {
    match e {
        Expr::MethodCall(m) => {
            if m.method == "invoke_contract" {
                return true;
            }
            is_invoke_contract(&m.receiver)
        }
        Expr::Call(c) => {
            // env.invoke_contract(…) expressed as a plain function call — unlikely but safe to check
            if let Expr::Path(p) = &*c.func {
                if p.path.segments.iter().any(|s| s.ident == "invoke_contract") {
                    return true;
                }
            }
            false
        }
        _ => false,
    }
}

fn receiver_chain_contains_storage(expr: &Expr) -> bool {
    match expr {
        Expr::MethodCall(m) => {
            if m.method == "storage" {
                return true;
            }
            receiver_chain_contains_storage(&m.receiver)
        }
        _ => false,
    }
}

fn is_storage_set(m: &ExprMethodCall) -> bool {
    m.method == "set" && receiver_chain_contains_storage(&m.receiver)
}

struct XcInputVisitor<'a> {
    fn_name: String,
    /// Local binding names that hold an `invoke_contract` return value.
    xc_bindings: HashSet<String>,
    out: &'a mut Vec<Finding>,
}

impl<'ast> Visit<'ast> for XcInputVisitor<'ast> {
    fn visit_stmt(&mut self, stmt: &'ast Stmt) {
        // Collect `let <ident> = …invoke_contract(…)` bindings.
        if let Stmt::Local(local) = stmt {
            if let Some(init) = &local.init {
                if is_invoke_contract(&init.expr) {
                    if let Pat::Ident(pi) = &local.pat {
                        self.xc_bindings.insert(pi.ident.to_string());
                    }
                }
            }
        }
        visit::visit_stmt(self, stmt);
    }

    fn visit_expr_method_call(&mut self, m: &'ast ExprMethodCall) {
        if is_storage_set(m) {
            // Check if any argument is (or references) an xc binding.
            for arg in &m.args {
                if let Some(name) = ref_ident(arg) {
                    if self.xc_bindings.contains(&name) {
                        self.out.push(Finding {
                            check_name: CHECK_NAME.to_string(),
                            severity: Severity::High,
                            file_path: String::new(),
                            line: m.span().start().line,
                            function_name: self.fn_name.clone(),
                            description: format!(
                                "`{}` stores the return value of `invoke_contract` directly \
                                 into contract storage without validation. Validate or sanitize \
                                 cross-contract return values before persisting them.",
                                self.fn_name
                            ),
                            rule_url: Some(
                                "https://github.com/SorobanGuard/Guard-CLI/blob/main/docs/checks.md#unsafe-cross-contract-input-high"
                                    .to_string(),
                            ),
                        });
                    }
                }
            }
        }
        visit::visit_expr_method_call(self, m);
    }
}

/// Extract the identifier name from a reference expression `&binding` or plain `binding`.
fn ref_ident(e: &Expr) -> Option<String> {
    match e {
        Expr::Reference(r) => ref_ident(&r.expr),
        Expr::Path(p) => p.path.get_ident().map(|i| i.to_string()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Check;
    use syn::parse_file;

    fn run(src: &str) -> Vec<Finding> {
        let file = parse_file(src).expect("parse");
        UnsafeCrossContractInputCheck.run(&file, src)
    }

    #[test]
    fn flags_invoke_contract_direct_to_storage() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env, Address, Symbol};
pub struct C;
#[contractimpl]
impl C {
    pub fn relay(env: Env, callee: Address) {
        let result = env.invoke_contract::<i128>(&callee, &Symbol::short("get"), ());
        env.storage().persistent().set(&Symbol::short("k"), &result);
    }
}
"#);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::High);
        assert_eq!(hits[0].check_name, CHECK_NAME);
    }

    #[test]
    fn passes_when_result_validated_before_storage() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env, Address, Symbol};
pub struct C;
#[contractimpl]
impl C {
    pub fn relay(env: Env, callee: Address) {
        let result: i128 = env.invoke_contract(&callee, &Symbol::short("get"), ());
        let safe = if result > 0 { result } else { 0 };
        env.storage().persistent().set(&Symbol::short("k"), &safe);
    }
}
"#);
        // `safe` is not an xc_binding; no finding expected
        assert!(hits.is_empty());
    }

    #[test]
    fn ignores_non_xc_storage_write() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env, Symbol};
pub struct C;
#[contractimpl]
impl C {
    pub fn store(env: Env, val: i128) {
        env.storage().persistent().set(&Symbol::short("k"), &val);
    }
}
"#);
        assert!(hits.is_empty());
    }
}
