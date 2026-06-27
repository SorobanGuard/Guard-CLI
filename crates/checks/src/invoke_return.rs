//! Flags `env.invoke_contract(…)` calls whose return value is silently discarded.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, File, Stmt};

const CHECK_NAME: &str = "unchecked-invoke-return";

pub struct UncheckedInvokeReturnCheck;

impl Check for UncheckedInvokeReturnCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
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

impl<'ast> Visit<'ast> for InvokeReturnScan {
    fn visit_stmt(&mut self, stmt: &'ast Stmt) {
        // Only flag when invoke_contract is a bare expression statement (semicolon present),
        // meaning the return value is discarded.
        if let Stmt::Expr(Expr::MethodCall(m), Some(_)) = stmt {
            if is_invoke_contract(m) {
                self.findings.push(Finding {
                    check_name: CHECK_NAME.to_string(),
                    severity: Severity::Medium,
                    file_path: String::new(),
                    line: m.method.span().start().line,
                    function_name: self.fn_name.clone(),
                    description: format!(
                        "Return value of `env.invoke_contract()` in `{}` is discarded. \
                         A failure in the callee will be silently ignored, potentially \
                         leaving the contract in an inconsistent state.",
                        self.fn_name
                    ),
                    rule_url: Some(
                        "https://github.com/SorobanGuard/Guard-CLI/blob/main/docs/checks.md#unchecked-invoke-return-medium"
                            .to_string(),
                    ),
                    suggestion: Some(
                        "Bind the return value: `let _result = env.invoke_contract(…);` \
                         and handle or assert it."
                            .to_string(),
                    ),
                });
            }
        }
        visit::visit_stmt(self, stmt);
    }
}

fn is_invoke_contract(m: &ExprMethodCall) -> bool {
    m.method == "invoke_contract"
}
