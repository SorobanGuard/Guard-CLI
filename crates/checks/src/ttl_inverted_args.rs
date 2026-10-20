//! `extend_ttl` calls whose threshold is greater than the extend-to value.

use crate::util::contractimpl_functions_excluding_test;
use crate::{Check, Finding, Severity};
use quote::ToTokens;
use std::collections::HashMap;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, File, Item, Lit};

const CHECK_NAME: &str = "ttl-threshold-greater-than-extend-to";

/// Flags `extend_ttl` calls where the threshold is greater than the extend-to value, so the
/// call can only extend when the entry is already past the point it would be extended to.
/// This usually means the two arguments were swapped. Only integer literals and file-level
/// `const` integers are compared.
pub struct TtlInvertedArgsCheck;

impl Check for TtlInvertedArgsCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let consts = int_consts(file);
        let mut out = Vec::new();
        for method in contractimpl_functions_excluding_test(file) {
            let fn_name = method.sig.ident.to_string();
            let mut v = TtlVisitor {
                consts: &consts,
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
                        "Function `{fn_name}` calls `extend_ttl` with a threshold greater than the \
                         extend-to value. The call can never usefully extend the entry, which \
                         usually means the arguments are swapped."
                    ),
                    rule_url: Some(
                        "https://github.com/SorobanGuard/Guard-CLI/blob/main/docs/checks.md#ttl-threshold-greater-than-extend-to-medium"
                            .to_string(),
                    ),
                    suggestion: Some(
                        "Pass the threshold first and the extend-to value second, with threshold <= extend-to."
                            .to_string(),
                    ),
                });
            }
        }
        out
    }
}

/// File-level `const NAME: <int type> = <integer literal>;` items.
fn int_consts(file: &File) -> HashMap<String, u128> {
    let mut map = HashMap::new();
    for item in &file.items {
        if let Item::Const(c) = item {
            if let Expr::Lit(l) = &*c.expr {
                if let Lit::Int(n) = &l.lit {
                    if let Ok(value) = n.base10_parse::<u128>() {
                        map.insert(c.ident.to_string(), value);
                    }
                }
            }
        }
    }
    map
}

struct TtlVisitor<'a> {
    consts: &'a HashMap<String, u128>,
    hits: Vec<usize>,
}

impl TtlVisitor<'_> {
    fn int_value(&self, expr: &Expr) -> Option<u128> {
        match expr {
            Expr::Lit(l) => match &l.lit {
                Lit::Int(n) => n.base10_parse::<u128>().ok(),
                _ => None,
            },
            Expr::Path(p) if p.path.segments.len() == 1 => {
                self.consts.get(&p.path.segments[0].ident.to_string()).copied()
            }
            _ => None,
        }
    }
}

impl Visit<'_> for TtlVisitor<'_> {
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
                let threshold = self.int_value(&i.args[t]);
                let extend_to = self.int_value(&i.args[e]);
                if let (Some(threshold), Some(extend_to)) = (threshold, extend_to) {
                    if threshold > extend_to {
                        self.hits.push(i.span().start().line);
                    }
                }
            }
        }
        visit::visit_expr_method_call(self, i);
    }
}
