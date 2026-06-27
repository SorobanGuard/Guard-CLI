//! Flags token `transfer`/`transfer_from` calls in `#[contractimpl]` methods that lack
//! a preceding `balance()` or `authorized()` check.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{ExprMethodCall, File};

const CHECK_NAME: &str = "missing-balance-check";

pub struct MissingBalanceCheck;

impl Check for MissingBalanceCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            let mut scan = BodyScan::default();
            scan.visit_block(&method.block);
            if scan.has_transfer && !scan.has_balance_check {
                let line = scan
                    .transfer_line
                    .unwrap_or_else(|| method.sig.ident.span().start().line);
                out.push(Finding {
                    check_name: CHECK_NAME.to_string(),
                    severity: Severity::High,
                    file_path: String::new(),
                    line,
                    function_name: fn_name.clone(),
                    description: format!(
                        "Function `{fn_name}` calls `transfer` or `transfer_from` without a \
                         preceding `balance()` or `authorized()` check. An invalid transfer may \
                         cause a runtime panic that disrupts multi-step atomic operations."
                    ),
                    rule_url: Some(
                        "https://github.com/SorobanGuard/Guard-CLI/blob/main/docs/checks.md#missing-balance-check-high"
                            .to_string(),
                    ),
                    suggestion: Some(
                        "Call `token_client.balance(&sender)` before transferring and verify \
                         the sender holds sufficient funds."
                            .to_string(),
                    ),
                });
            }
        }
        out
    }
}

#[derive(Default)]
struct BodyScan {
    has_transfer: bool,
    has_balance_check: bool,
    transfer_line: Option<usize>,
}

impl<'ast> Visit<'ast> for BodyScan {
    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        let method = i.method.to_string();
        if matches!(method.as_str(), "transfer" | "transfer_from") {
            self.has_transfer = true;
            if self.transfer_line.is_none() {
                self.transfer_line = Some(i.method.span().start().line);
            }
        }
        if matches!(method.as_str(), "balance" | "authorized") {
            self.has_balance_check = true;
        }
        visit::visit_expr_method_call(self, i);
    }
}
