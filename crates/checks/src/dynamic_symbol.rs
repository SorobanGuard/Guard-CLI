//! `Symbol::new` built from a caller-supplied function parameter.

use crate::util::contractimpl_functions_excluding_test;
use crate::{Check, Finding, Severity};
use proc_macro2::{TokenStream, TokenTree};
use quote::ToTokens;
use std::collections::HashSet;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprCall, File, Pat};

const CHECK_NAME: &str = "dynamic-symbol-from-input";

/// Flags `Symbol::new(&env, <expr>)` when `<expr>` uses a parameter of the public function.
/// `Symbol::new` traps on over-long or invalid input, and a caller-chosen symbol selects which
/// storage key or event topic is touched. Literal and `const` symbols are not flagged.
pub struct DynamicSymbolFromInputCheck;

impl Check for DynamicSymbolFromInputCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions_excluding_test(file) {
            let fn_name = method.sig.ident.to_string();
            let params: HashSet<String> = method
                .sig
                .inputs
                .iter()
                .filter_map(|arg| match arg {
                    syn::FnArg::Typed(t) => match &*t.pat {
                        Pat::Ident(p) => Some(p.ident.to_string()),
                        _ => None,
                    },
                    syn::FnArg::Receiver(_) => None,
                })
                .collect();

            let mut v = SymbolVisitor {
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
                        "Function `{fn_name}` builds a `Symbol` from a caller-supplied parameter. \
                         Over-long or invalid input traps, and the caller chooses which storage \
                         key or event topic is used."
                    ),
                    rule_url: Some(
                        "https://github.com/SorobanGuard/Guard-CLI/blob/main/docs/checks.md#dynamic-symbol-from-input-medium"
                            .to_string(),
                    ),
                    suggestion: Some(
                        "Use a `symbol_short!` literal or a `const` symbol, or map the caller's value to one of a fixed set."
                            .to_string(),
                    ),
                });
            }
        }
        out
    }
}

/// Every identifier that appears in a token stream, including inside groups.
fn collect_idents(ts: TokenStream, out: &mut HashSet<String>) {
    for tt in ts {
        match tt {
            TokenTree::Ident(i) => {
                out.insert(i.to_string());
            }
            TokenTree::Group(g) => collect_idents(g.stream(), out),
            _ => {}
        }
    }
}

struct SymbolVisitor<'a> {
    params: &'a HashSet<String>,
    hits: Vec<usize>,
}

impl Visit<'_> for SymbolVisitor<'_> {
    fn visit_expr_call(&mut self, i: &ExprCall) {
        let is_symbol_new = match &*i.func {
            Expr::Path(p) => {
                let segs: Vec<String> = p.path.segments.iter().map(|s| s.ident.to_string()).collect();
                segs.len() >= 2 && segs[segs.len() - 2] == "Symbol" && segs[segs.len() - 1] == "new"
            }
            _ => false,
        };
        // `Symbol::new(&env, text)` takes the text second.
        if is_symbol_new {
            if let Some(text) = i.args.iter().nth(1) {
                let mut idents = HashSet::new();
                collect_idents(text.to_token_stream(), &mut idents);
                if idents.iter().any(|name| self.params.contains(name)) {
                    self.hits.push(i.span().start().line);
                }
            }
        }
        visit::visit_expr_call(self, i);
    }
}
