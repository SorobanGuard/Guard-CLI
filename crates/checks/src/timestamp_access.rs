//! Ledger time compared with a caller-supplied value, which authorises nothing.

use crate::util::{contractimpl_functions_excluding_test, env_param_name};
use crate::{Check, Finding, Severity};
use proc_macro2::{TokenStream, TokenTree};
use quote::ToTokens;
use std::collections::HashSet;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{BinOp, Expr, ExprBinary, File, FnArg, Pat};

const CHECK_NAME: &str = "timestamp-access-control";

/// Flags an ordering or equality comparison between `env.ledger().timestamp()` (or sequence) and
/// a value taken from a public function parameter. When the caller supplies the deadline, the
/// caller also chooses the time window, so the check gates nothing. Comparisons against values
/// read from storage or constants are not flagged.
pub struct TimestampAccessControlCheck;

impl Check for TimestampAccessControlCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions_excluding_test(file) {
            let fn_name = method.sig.ident.to_string();
            let env_name = env_param_name(&method.sig);
            let params: HashSet<String> = method
                .sig
                .inputs
                .iter()
                .filter_map(|arg| match arg {
                    FnArg::Typed(t) => match &*t.pat {
                        Pat::Ident(p) => Some(p.ident.to_string()),
                        _ => None,
                    },
                    FnArg::Receiver(_) => None,
                })
                .filter(|name| Some(name) != env_name.as_ref())
                .collect();

            let mut v = ClockVisitor {
                params: &params,
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
                        "Function `{fn_name}` compares ledger time with a caller-supplied value. \
                         The caller picks the time window, so the time check authorises nothing."
                    ),
                    rule_url: Some(
                        "https://github.com/SorobanGuard/Guard-CLI/blob/main/docs/checks.md#timestamp-access-control-medium"
                            .to_string(),
                    ),
                    suggestion: Some(
                        "Store the deadline in contract state when the will or lock is created, and compare against that."
                            .to_string(),
                    ),
                });
            }
        }
        out
    }
}

fn is_comparison(op: &BinOp) -> bool {
    matches!(
        op,
        BinOp::Lt(_) | BinOp::Le(_) | BinOp::Gt(_) | BinOp::Ge(_) | BinOp::Eq(_) | BinOp::Ne(_)
    )
}

/// Identifiers and literal-free text of an expression, including inside groups.
fn idents_of(ts: TokenStream, out: &mut HashSet<String>) {
    for tt in ts {
        match tt {
            TokenTree::Ident(i) => {
                out.insert(i.to_string());
            }
            TokenTree::Group(g) => idents_of(g.stream(), out),
            _ => {}
        }
    }
}

fn reads_ledger_clock(expr: &Expr) -> bool {
    let text = expr.to_token_stream().to_string();
    text.contains("ledger") && (text.contains("timestamp") || text.contains("sequence"))
}

struct ClockVisitor<'a> {
    params: &'a HashSet<String>,
    hits: Vec<usize>,
}

impl Visit<'_> for ClockVisitor<'_> {
    fn visit_expr_binary(&mut self, i: &ExprBinary) {
        if is_comparison(&i.op) {
            let (clock, other) = if reads_ledger_clock(&i.left) {
                (true, &i.right)
            } else if reads_ledger_clock(&i.right) {
                (true, &i.left)
            } else {
                (false, &i.left)
            };
            if clock {
                let text = other.to_token_stream().to_string();
                let mut idents = HashSet::new();
                idents_of(other.to_token_stream(), &mut idents);
                let from_param = idents.iter().any(|name| self.params.contains(name));
                // A value read from storage is trusted state, not caller input.
                if from_param && !text.contains("storage") {
                    self.hits.push(i.span().start().line);
                }
            }
        }
        visit::visit_expr_binary(self, i);
    }
}
