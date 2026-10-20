//! The same storage key used under more than one storage tier across a contract.

use crate::util::contractimpl_functions_excluding_test;
use crate::{Check, Finding, Severity};
use quote::ToTokens;
use std::collections::BTreeMap;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, File};

const CHECK_NAME: &str = "storage-durability-mismatch";

/// Flags a storage key that is accessed under more than one tier (`temporary()`,
/// `persistent()` or `instance()`) across a contract's functions. Each tier is an
/// independent keyspace, so the same key in two tiers holds two unrelated entries.
/// Only literal and `const`-style keys are compared, to avoid noise from locals.
pub struct StorageDurabilityMismatchCheck;

impl Check for StorageDurabilityMismatchCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        // key -> every (tier, line, function) that touches it.
        let mut uses: BTreeMap<String, Vec<(&'static str, usize, String)>> = BTreeMap::new();
        for method in contractimpl_functions_excluding_test(file) {
            let fn_name = method.sig.ident.to_string();
            let mut v = KeyVisitor { uses: Vec::new() };
            v.visit_block(&method.block);
            for (key, tier, line) in v.uses {
                uses.entry(key).or_default().push((tier, line, fn_name.clone()));
            }
        }

        let mut out = Vec::new();
        for (key, entries) in uses {
            let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
            for (tier, _, _) in &entries {
                *counts.entry(tier).or_default() += 1;
            }
            if counts.len() < 2 {
                continue;
            }
            // Report the accesses under every tier except the most used one.
            let common = counts
                .iter()
                .max_by_key(|(_, n)| **n)
                .map(|(tier, _)| *tier)
                .unwrap_or_default();
            for (tier, line, fn_name) in entries {
                if tier == common {
                    continue;
                }
                out.push(Finding {
                    check_name: CHECK_NAME.to_string(),
                    severity: Severity::Medium,
                    file_path: String::new(),
                    line,
                    function_name: fn_name.clone(),
                    description: format!(
                        "Function `{fn_name}` uses storage key `{key}` in the `{tier}` tier, but \
                         the same key is used in another tier. Each tier is a separate entry, so \
                         reads can return stale or missing data when the temporary entry expires."
                    ),
                    rule_url: Some(
                        "https://github.com/SorobanGuard/Guard-CLI/blob/main/docs/checks.md#storage-durability-mismatch-medium"
                            .to_string(),
                    ),
                    suggestion: Some(
                        "Use one storage tier for each key, or give the two uses distinct keys."
                            .to_string(),
                    ),
                });
            }
        }
        out
    }
}

/// Collects `(key, tier, line)` for storage `get`/`set`/`has`/`remove` calls whose key is a
/// literal or a `const`-style path.
struct KeyVisitor {
    uses: Vec<(String, &'static str, usize)>,
}

impl Visit<'_> for KeyVisitor {
    fn visit_expr_method_call(&mut self, i: &ExprMethodCall) {
        if matches!(i.method.to_string().as_str(), "get" | "set" | "has" | "remove") {
            let receiver = i.receiver.to_token_stream().to_string();
            if receiver.contains("storage") {
                if let (Some(tier), Some(key)) = (tier_of(&receiver), i.args.first().and_then(const_key)) {
                    self.uses.push((key, tier, i.span().start().line));
                }
            }
        }
        visit::visit_expr_method_call(self, i);
    }
}

fn tier_of(receiver: &str) -> Option<&'static str> {
    ["temporary", "persistent", "instance"]
        .into_iter()
        .find(|tier| receiver.contains(tier))
}

/// A key is comparable only when it is a string/integer literal or an uppercase path
/// (a `const`), so local variables are not compared.
fn const_key(expr: &Expr) -> Option<String> {
    let inner = match expr {
        Expr::Reference(r) => &*r.expr,
        other => other,
    };
    match inner {
        Expr::Path(p) if p.path.segments.len() == 1 => {
            let ident = p.path.segments[0].ident.to_string();
            ident.starts_with(|c: char| c.is_ascii_uppercase()).then_some(ident)
        }
        Expr::Lit(l) => Some(l.lit.to_token_stream().to_string()),
        _ => None,
    }
}
