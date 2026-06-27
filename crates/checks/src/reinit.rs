//! Flags `initialize`/`init`/`setup` functions in `#[contractimpl]` that do not guard
//! against being called more than once.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, File};

const CHECK_NAME: &str = "re-initialization-risk";

pub struct ReInitializationRiskCheck;

impl Check for ReInitializationRiskCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            if !is_init_fn(&fn_name) {
                continue;
            }
            let mut scan = BodyScan::default();
            scan.visit_block(&method.block);
            if !scan.has_storage_write || scan.has_guard {
                continue;
            }
            out.push(Finding {
                check_name: CHECK_NAME.to_string(),
                severity: Severity::High,
                file_path: String::new(),
                line: method.sig.ident.span().start().line,
                function_name: fn_name.clone(),
                description: format!(
                    "Function `{fn_name}` writes to storage but does not guard against \
                     re-initialization. An attacker can call it again to overwrite the owner \
                     or reset critical contract state."
                ),
                rule_url: Some(
                    "https://github.com/SorobanGuard/Guard-CLI/blob/main/docs/checks.md#re-initialization-risk-high"
                        .to_string(),
                ),
                suggestion: Some(
                    "Check `env.storage().*.has(&key)` and panic or return if already initialized, \
                     e.g. `require!(!env.storage().instance().has(&key), \"already initialized\");`."
                        .to_string(),
                ),
            });
        }
        out
    }
}

fn is_init_fn(name: &str) -> bool {
    name.contains("init") || name.contains("setup")
}

fn receiver_chain_contains_storage(expr: &Expr) -> bool {
    match expr {
        Expr::MethodCall(m) => {
            if m.method == "storage" {
                return true;
            }
            receiver_chain_contains_storage(&m.receiver)
        }
        Expr::Field(f) => receiver_chain_contains_storage(&f.base),
        _ => false,
    }
}

#[derive(Default)]
struct BodyScan {
    has_storage_write: bool,
    has_guard: bool,
}

impl<'ast> Visit<'ast> for BodyScan {
    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        let method = i.method.to_string();
        if method == "set" && receiver_chain_contains_storage(&i.receiver) {
            self.has_storage_write = true;
        }
        if matches!(method.as_str(), "has" | "is_some" | "is_none") {
            self.has_guard = true;
        }
        visit::visit_expr_method_call(self, i);
    }

    fn visit_macro(&mut self, i: &'ast syn::Macro) {
        let name = i
            .path
            .segments
            .last()
            .map(|s| s.ident.to_string())
            .unwrap_or_default();
        if matches!(name.as_str(), "require" | "panic") {
            self.has_guard = true;
        }
        visit::visit_macro(self, i);
    }
}
