//! Panic-in-contract: `panic!`, `unwrap()`, `expect(…)`, `unreachable!()` in contract methods.

use crate::util::{contractimpl_functions_excluding_test, receiver_chain_contains_storage};
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, File};

/// Returns true when `expr` is **exactly** `.get(…)`/`.get_unchecked(…)` chained directly onto a
/// `.storage()` receiver chain — the same pattern that
/// `uninitialized_storage_read::UninitializedStorageReadCheck` reports under its own, more
/// specific, `uninitialized-storage-read` finding. Only that single-hop pattern is suppressed
/// here so that `.unwrap()`/`.expect()` further downstream (e.g. on the result of
/// `.checked_mul(…)` that was itself computed from a storage read) are still reported.
///
/// In other words: `storage.get(&k).unwrap()` → suppressed (owned by `uninitialized-storage-read`)
///                 `storage.get(&k).unwrap_or(0).checked_mul(x).unwrap()` → NOT suppressed here
fn is_storage_get(expr: &Expr) -> bool {
    match expr {
        Expr::MethodCall(m) => {
            (m.method == "get" || m.method == "get_unchecked")
                && receiver_chain_contains_storage(&m.receiver)
        }
        _ => false,
    }
}

const CHECK_NAME: &str = "panic-in-contract";

/// Flags `panic!`, `unreachable!`, `.unwrap()`, and `.expect(…)` inside
/// `#[contractimpl]` methods. These abort the transaction with an unhelpful error.
pub struct PanicInContractCheck;

impl Check for PanicInContractCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions_excluding_test(file) {
            let fn_name = method.sig.ident.to_string();
            let mut v = PanicVisitor {
                fn_name: fn_name.clone(),
                out: &mut out,
            };
            v.visit_block(&method.block);
        }
        out
    }
}

fn macro_name(mac: &syn::Macro) -> String {
    mac.path
        .segments
        .last()
        .map(|s| s.ident.to_string())
        .unwrap_or_default()
}

struct PanicVisitor<'a> {
    fn_name: String,
    out: &'a mut Vec<Finding>,
}

impl PanicVisitor<'_> {
    fn push(&mut self, line: usize, pattern: &str) {
        self.out.push(Finding {
            check_name: CHECK_NAME.to_string(),
            severity: Severity::Medium,
            file_path: String::new(),
            line,
            function_name: self.fn_name.clone(),
            description: format!(
                "`{pattern}` in `{}` will abort the transaction with an unhelpful error. \
                 Use `env.panic_with_error` or return a `Result` with a typed error instead.",
                self.fn_name
            ),
            rule_url: Some(
                "https://github.com/SorobanGuard/Guard-CLI/blob/main/docs/checks.md#panic-in-contract-medium"
                    .to_string(),
            ),
            suggestion: Some(
                "Replace with `env.panic_with_error(&MyError::Variant)` or change the \
                 return type to `Result<T, MyError>` and return `Err(…)` instead."
                    .to_string(),
            ),
        });
    }
}

impl<'ast> Visit<'ast> for PanicVisitor<'_> {
    fn visit_macro(&mut self, i: &'ast syn::Macro) {
        let name = macro_name(i);
        if matches!(name.as_str(), "panic" | "unreachable") {
            self.push(i.span().start().line, &format!("{name}!"));
        }
        visit::visit_macro(self, i);
    }

    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        let name = i.method.to_string();
        if matches!(name.as_str(), "unwrap" | "expect") && !is_storage_get(&i.receiver) {
            self.push(i.span().start().line, &format!(".{name}()"));
        }
        visit::visit_expr_method_call(self, i);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Check;
    use syn::parse_file;

    fn run(src: &str) -> Vec<Finding> {
        let file = parse_file(src).expect("parse");
        PanicInContractCheck.run(&file, src)
    }

    #[test]
    fn flags_unwrap() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn f(_env: Env) -> u32 {
        Some(1u32).unwrap()
    }
}
"#);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Medium);
    }

    #[test]
    fn flags_expect() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn f(_env: Env) -> u32 {
        Some(1u32).expect("missing")
    }
}
"#);
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn flags_panic_macro() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn f(_env: Env) { panic!("oh no"); }
}
"#);
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn flags_unreachable_macro() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn f(_env: Env) { unreachable!(); }
}
"#);
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn ignores_non_contractimpl() {
        let hits = run(r#"
pub struct C;
impl C {
    pub fn f() { panic!("nope"); }
}
"#);
        assert!(hits.is_empty());
    }
}
