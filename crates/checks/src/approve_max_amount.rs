//! Token `approve` calls with a saturated (`MAX`) allowance amount.

use crate::util::contractimpl_functions_excluding_test;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, File};

const CHECK_NAME: &str = "approve-max-amount";

/// Flags `approve(from, spender, amount, expiration)` on a token client when `amount` is an
/// integer `MAX` constant such as `i128::MAX`. An unlimited allowance lets a compromised spender
/// drain the whole balance. `MAX - 1` and other expressions are not matched.
pub struct ApproveMaxAmountCheck;

impl Check for ApproveMaxAmountCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions_excluding_test(file) {
            let fn_name = method.sig.ident.to_string();
            let mut v = ApproveVisitor { hits: Vec::new() };
            v.visit_block(&method.block);

            for line in v.hits {
                out.push(Finding {
                    check_name: CHECK_NAME.to_string(),
                    severity: Severity::Medium,
                    file_path: String::new(),
                    line,
                    function_name: fn_name.clone(),
                    description: format!(
                        "Function `{fn_name}` approves a spender for an unlimited amount. A later \
                         compromise of the spender lets it move the entire balance."
                    ),
                    rule_url: Some(
                        "https://github.com/SorobanGuard/Guard-CLI/blob/main/docs/checks.md#approve-max-amount-medium"
                            .to_string(),
                    ),
                    suggestion: Some(
                        "Approve only the amount the spender needs, and give the allowance an expiration."
                            .to_string(),
                    ),
                });
            }
        }
        out
    }
}

/// True for a bare `MAX` path such as `i128::MAX`, `u64::MAX` or `core::i128::MAX`.
fn is_max_constant(expr: &Expr) -> bool {
    match expr {
        Expr::Path(p) => p
            .path
            .segments
            .last()
            .is_some_and(|s| s.ident == "MAX"),
        Expr::Paren(p) => is_max_constant(&p.expr),
        _ => false,
    }
}

struct ApproveVisitor {
    hits: Vec<usize>,
}

impl Visit<'_> for ApproveVisitor {
    fn visit_expr_method_call(&mut self, i: &ExprMethodCall) {
        // The token interface is `approve(from, spender, amount, expiration_ledger)`.
        if i.method == "approve" && i.args.len() == 4 {
            if let Some(amount) = i.args.iter().nth(2) {
                if is_max_constant(amount) {
                    self.hits.push(i.span().start().line);
                }
            }
        }
        visit::visit_expr_method_call(self, i);
    }
}
