//! Exact `==` / `!=` comparisons against ledger time or sequence.

use crate::util::contractimpl_functions_excluding_test;
use crate::{Check, Finding, Severity};
use quote::ToTokens;
use std::collections::HashSet;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{BinOp, Expr, ExprBinary, File, Local, Pat};

const CHECK_NAME: &str = "timestamp-equality-comparison";

/// Flags `==` and `!=` where one side is `env.ledger().timestamp()` or `.sequence()`, or a
/// local bound directly from one of them. Ledger time and sequence advance in jumps, so an
/// exact match is rarely true. Ordering comparisons (`>=`, `<`) are the safe alternative.
pub struct TimestampEqualityCheck;

impl Check for TimestampEqualityCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions_excluding_test(file) {
            let fn_name = method.sig.ident.to_string();
            let mut v = TimeVisitor {
                ledger_locals: HashSet::new(),
                hits: Vec::new(),
            };
            v.visit_block(&method.block);

            for line in v.hits {
                out.push(Finding {
                    check_name: CHECK_NAME.to_string(),
                    severity: Severity::Medium,
                    file_path: String::new(),
                    line,
                    function_name: fn_name.clone(),
                    description: format!(
                        "Function `{fn_name}` compares ledger time or sequence with `==` or `!=`. \
                         Ledger time and sequence advance in jumps, so the branch may never run, or \
                         may run one ledger early or late."
                    ),
                    rule_url: Some(
                        "https://github.com/SorobanGuard/Guard-CLI/blob/main/docs/checks.md#timestamp-equality-comparison-medium"
                            .to_string(),
                    ),
                    suggestion: Some(
                        "Use an ordering comparison such as `>=` or `<` against the deadline.".to_string(),
                    ),
                });
            }
        }
        out
    }
}

/// True when the expression reads ledger time or sequence.
fn reads_ledger_clock(expr: &Expr) -> bool {
    let text = expr.to_token_stream().to_string();
    text.contains("ledger") && (text.contains("timestamp") || text.contains("sequence"))
}

struct TimeVisitor {
    /// Locals bound directly from ledger time or sequence.
    ledger_locals: HashSet<String>,
    hits: Vec<usize>,
}

impl TimeVisitor {
    fn is_clock_operand(&self, expr: &Expr) -> bool {
        if reads_ledger_clock(expr) {
            return true;
        }
        match expr {
            Expr::Path(p) if p.path.segments.len() == 1 => {
                self.ledger_locals.contains(&p.path.segments[0].ident.to_string())
            }
            Expr::Paren(p) => self.is_clock_operand(&p.expr),
            _ => false,
        }
    }
}

impl Visit<'_> for TimeVisitor {
    fn visit_local(&mut self, local: &Local) {
        if let (Pat::Ident(pat), Some(init)) = (&local.pat, &local.init) {
            if reads_ledger_clock(&init.expr) {
                self.ledger_locals.insert(pat.ident.to_string());
            }
        }
        visit::visit_local(self, local);
    }

    fn visit_expr_binary(&mut self, i: &ExprBinary) {
        if matches!(i.op, BinOp::Eq(_) | BinOp::Ne(_))
            && (self.is_clock_operand(&i.left) || self.is_clock_operand(&i.right))
        {
            self.hits.push(i.span().start().line);
        }
        visit::visit_expr_binary(self, i);
    }
}
