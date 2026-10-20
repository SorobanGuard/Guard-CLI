//! `extend_ttl` calls with a literal zero threshold or extend-to value.

use crate::util::contractimpl_functions_excluding_test;
use crate::{Check, Finding, Severity};
use quote::ToTokens;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, File, Lit};

const CHECK_NAME: &str = "extend-ttl-no-op";

/// Flags `extend_ttl` calls whose threshold or extend-to argument is the literal `0`. Such a call
/// never extends anything, yet it satisfies `missing-ttl-extension`, which only checks that the
/// call exists. Non-literal arguments are not flagged.
pub struct ExtendTtlNoOpCheck;

impl Check for ExtendTtlNoOpCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions_excluding_test(file) {
            let fn_name = method.sig.ident.to_string();
            let mut v = TtlZeroVisitor { hits: Vec::new() };
            v.visit_block(&method.block);

            for line in v.hits {
                out.push(Finding {
                    check_name: CHECK_NAME.to_string(),
                    severity: Severity::Low,
                    file_path: String::new(),
                    line,
                    function_name: fn_name.clone(),
                    description: format!(
                        "Function `{fn_name}` calls `extend_ttl` with a zero threshold or extend-to \
                         value. The call never extends the entry, so it still expires."
                    ),
                    rule_url: Some(
                        "https://github.com/SorobanGuard/Guard-CLI/blob/main/docs/checks.md#extend-ttl-no-op-low"
                            .to_string(),
                    ),
                    suggestion: Some(
                        "Pass a non-zero extend-to value, for example the TTL the entry needs to live for."
                            .to_string(),
                    ),
                });
            }
        }
        out
    }
}

/// True for an integer literal equal to zero, such as `0` or `0u32`.
fn is_zero_literal(expr: &Expr) -> bool {
    match expr {
        Expr::Lit(l) => match &l.lit {
            Lit::Int(n) => n.base10_parse::<u128>().is_ok_and(|v| v == 0),
            _ => false,
        },
        _ => false,
    }
}

struct TtlZeroVisitor {
    hits: Vec<usize>,
}

impl Visit<'_> for TtlZeroVisitor {
    fn visit_expr_method_call(&mut self, i: &ExprMethodCall) {
        if i.method == "extend_ttl" {
            let receiver = i.receiver.to_token_stream().to_string();
            // Keyed form: `extend_ttl(&key, threshold, extend_to)`.
            // Instance form: `instance().extend_ttl(threshold, extend_to)`.
            let pair = match i.args.len() {
                3 => Some((1, 2)),
                2 if receiver.contains("instance") => Some((0, 1)),
                _ => None,
            };
            if let Some((t, e)) = pair {
                if is_zero_literal(&i.args[t]) || is_zero_literal(&i.args[e]) {
                    self.hits.push(i.span().start().line);
                }
            }
        }
        visit::visit_expr_method_call(self, i);
    }
}
