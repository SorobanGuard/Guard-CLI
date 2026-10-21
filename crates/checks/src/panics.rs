//! Panic-in-contract: `panic!`, `unwrap()`, `expect(…)`, `unreachable!()` in contract methods.
//!
//! Also hosts `public-fn-without-return-type-errors`: a `#[contractimpl]` public method that
//! can `panic` but does not return `Result<_, E>` where `E` is a `#[contracterror]` type.

use crate::util::{contractimpl_functions_excluding_test, receiver_chain_contains_storage};
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, File, Item, ReturnType, Type};

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
        if matches!(name.as_str(), "panic" | "unreachable" | "todo" | "unimplemented") {
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

const RETURN_TYPE_CHECK_NAME: &str = "public-fn-without-return-type-errors";

/// Flags `#[contractimpl]` public methods that can `panic` (`panic!`/`unwrap`/`expect`) but do
/// not return `Result<_, E>` where `E` is a `#[contracterror]` type. Suppressed entirely when the
/// crate defines no `#[contracterror]` type (opt-in by convention).
pub struct PublicFnWithoutReturnTypeErrorsCheck;

impl Check for PublicFnWithoutReturnTypeErrorsCheck {
    fn name(&self) -> &str {
        RETURN_TYPE_CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        if !crate_defines_contracterror(file) {
            return Vec::new();
        }
        let mut out = Vec::new();
        for method in contractimpl_functions_excluding_test(file) {
            if !matches!(method.vis, syn::Visibility::Public(_)) {
                continue;
            }
            if returns_typed_result(&method.sig.output) {
                continue;
            }
            let mut probe = PanicProbe { found: false };
            probe.visit_block(&method.block);
            if !probe.found {
                continue;
            }
            let fn_name = method.sig.ident.to_string();
            out.push(Finding {
                check_name: RETURN_TYPE_CHECK_NAME.to_string(),
                severity: Severity::Low,
                file_path: String::new(),
                line: method.sig.span().start().line,
                function_name: fn_name.clone(),
                description: format!(
                    "`{fn_name}` can `panic` but does not return `Result<_, E>` with a \
                     `#[contracterror]` type. Panics surface as opaque traps; typed errors give \
                     clients a stable, matchable failure code."
                ),
                rule_url: Some(
                    "https://github.com/SorobanGuard/Guard-CLI/blob/main/docs/checks.md#public-fn-without-return-type-errors-low"
                        .to_string(),
                ),
                suggestion: Some(
                    "Change the return type to `Result<T, MyError>` and return `Err(MyError::Variant)` \
                     instead of panicking."
                        .to_string(),
                ),
            });
        }
        out
    }
}

/// Returns true when the file declares at least one `#[contracterror]` type.
fn crate_defines_contracterror(file: &File) -> bool {
    file.items.iter().any(|item| match item {
        Item::Struct(s) => has_contracterror_attr(&s.attrs),
        Item::Enum(e) => has_contracterror_attr(&e.attrs),
        _ => false,
    })
}

fn has_contracterror_attr(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|a| {
        a.path
            .segments
            .last()
            .map(|s| s.ident == "contracterror")
            .unwrap_or(false)
    })
}

/// Returns true when the signature's return type is `Result<_, _>`.
fn returns_typed_result(output: &ReturnType) -> bool {
    let ty = match output {
        ReturnType::Type(_, ty) => ty,
        ReturnType::Default => return false,
    };
    let path = match ty.as_ref() {
        Type::Path(p) => &p.path,
        _ => return false,
    };
    path.segments
        .last()
        .map(|s| s.ident == "Result")
        .unwrap_or(false)
}

struct PanicProbe {
    found: bool,
}

impl<'ast> Visit<'ast> for PanicProbe {
    fn visit_macro(&mut self, i: &'ast syn::Macro) {
        let name = macro_name(i);
        if matches!(name.as_str(), "panic" | "unreachable" | "todo" | "unimplemented") {
            self.found = true;
        }
        visit::visit_macro(self, i);
    }

    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        let name = i.method.to_string();
        if matches!(name.as_str(), "unwrap" | "expect") && !is_storage_get(&i.receiver) {
            self.found = true;
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

    fn run_return_type(src: &str) -> Vec<Finding> {
        let file = parse_file(src).expect("parse");
        PublicFnWithoutReturnTypeErrorsCheck.run(&file, src)
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
    fn flags_todo_macro() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn f(_env: Env) { todo!("not implemented yet"); }
}
"#);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].check_name, "panic-in-contract");
    }

    #[test]
    fn flags_unimplemented_macro() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn f(_env: Env) { unimplemented!(); }
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

    #[test]
    fn return_type_flags_panicking_bare_fn() {
        let hits = run_return_type(r#"
use soroban_sdk::{contracterror, contractimpl, Env};
#[contracterror]
#[derive(Copy, Clone)]
#[repr(u32)]
pub enum MyError { Bad = 1 }
pub struct C;
#[contractimpl]
impl C {
    pub fn f(_env: Env) -> u32 {
        Some(1u32).unwrap()
    }
}
"#);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Low);
        assert_eq!(hits[0].check_name, "public-fn-without-return-type-errors");
    }

    #[test]
    fn return_type_ignores_result_fn() {
        let hits = run_return_type(r#"
use soroban_sdk::{contracterror, contractimpl, Env};
#[contracterror]
#[derive(Copy, Clone)]
#[repr(u32)]
pub enum MyError { Bad = 1 }
pub struct C;
#[contractimpl]
impl C {
    pub fn f(_env: Env) -> Result<u32, MyError> {
        Some(1u32).ok_or(MyError::Bad)
    }
}
"#);
        assert!(hits.is_empty());
    }

    #[test]
    fn return_type_suppressed_without_contracterror() {
        let hits = run_return_type(r#"
use soroban_sdk::{contractimpl, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn f(_env: Env) -> u32 {
        Some(1u32).unwrap()
    }
}
"#);
        assert!(hits.is_empty());
    }

    #[test]
    fn return_type_ignores_non_panicking_fn() {
        let hits = run_return_type(r#"
use soroban_sdk::{contracterror, contractimpl, Env};
#[contracterror]
#[derive(Copy, Clone)]
#[repr(u32)]
pub enum MyError { Bad = 1 }
pub struct C;
#[contractimpl]
impl C {
    pub fn f(_env: Env) -> u32 { 1u32 }
}
"#);
        assert!(hits.is_empty());
    }
}
