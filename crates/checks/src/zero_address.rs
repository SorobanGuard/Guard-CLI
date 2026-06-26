//! Missing zero-address check: `Address` parameters with no zero/default assertion.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::visit::{self, Visit};
use syn::{File, FnArg, Pat, PatType, Type, TypePath};

const CHECK_NAME: &str = "missing-zero-address-check";

/// Flags public `#[contractimpl]` methods whose name suggests admin/ownership
/// semantics, that accept an `Address` parameter, and whose body never asserts
/// the address is non-default (no call to `require_auth`, `assert!`, or a helper
/// containing "zero", "default", or "check_address").
pub struct MissingZeroAddressCheck;

const SENSITIVE_NAMES: &[&str] = &[
    "set_owner",
    "set_admin",
    "initialize",
    "init",
    "transfer_ownership",
    "update_admin",
    "set_manager",
    "set_operator",
];

fn is_address_type(ty: &Type) -> bool {
    if let Type::Path(TypePath { path, .. }) = ty {
        path.segments.last().is_some_and(|s| s.ident == "Address")
    } else {
        false
    }
}

fn has_address_param(method: &syn::ImplItemFn) -> bool {
    method.sig.inputs.iter().any(|arg| {
        if let FnArg::Typed(PatType { ty, .. }) = arg {
            is_address_type(ty)
        } else {
            false
        }
    })
}

fn address_param_names(method: &syn::ImplItemFn) -> Vec<String> {
    method
        .sig
        .inputs
        .iter()
        .filter_map(|arg| {
            if let FnArg::Typed(PatType { pat, ty, .. }) = arg {
                if is_address_type(ty) {
                    if let Pat::Ident(p) = pat.as_ref() {
                        return Some(p.ident.to_string());
                    }
                }
            }
            None
        })
        .collect()
}

#[derive(Default)]
struct BodyScan {
    has_guard: bool,
}

impl<'ast> Visit<'ast> for BodyScan {
    fn visit_expr_method_call(&mut self, i: &'ast syn::ExprMethodCall) {
        let name = i.method.to_string();
        if name.contains("require_auth")
            || name.contains("zero")
            || name.contains("default")
            || name.contains("check_address")
            || name.contains("assert")
            || name.contains("validate")
        {
            self.has_guard = true;
        }
        visit::visit_expr_method_call(self, i);
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        let name = mac
            .path
            .segments
            .last()
            .map(|s| s.ident.to_string())
            .unwrap_or_default();
        if matches!(name.as_str(), "assert" | "require") {
            self.has_guard = true;
        }
        visit::visit_macro(self, mac);
    }
}

impl Check for MissingZeroAddressCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            let is_sensitive = SENSITIVE_NAMES.contains(&fn_name.as_str());
            if !is_sensitive {
                continue;
            }
            if !has_address_param(method) {
                continue;
            }
            let mut scan = BodyScan::default();
            scan.visit_block(&method.block);
            if scan.has_guard {
                continue;
            }
            let addr_params = address_param_names(method);
            out.push(Finding {
                check_name: CHECK_NAME.to_string(),
                severity: Severity::Medium,
                file_path: String::new(),
                line: method.sig.ident.span().start().line,
                function_name: fn_name.clone(),
                description: format!(
                    "Method `{fn_name}` accepts `Address` parameter(s) ({}) but does not \
                     assert they are non-default. Passing a zero/default address to an admin \
                     function can lock the contract permanently.",
                    addr_params.join(", ")
                ),
                rule_url: Some(
                    "https://github.com/SorobanGuard/Guard-CLI/blob/main/docs/checks.md#missing-zero-address-check-medium"
                        .to_string(),
                ),
                suggestion: None,
            });
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Check;
    use syn::parse_file;

    fn run(src: &str) -> Vec<Finding> {
        let file = parse_file(src).expect("parse");
        MissingZeroAddressCheck.run(&file, src)
    }

    #[test]
    fn flags_set_owner_without_guard() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env, Address};
pub struct C;
#[contractimpl]
impl C {
    pub fn set_owner(env: Env, new_owner: Address) {
        env.storage().instance().set(&"owner", &new_owner);
    }
}
"#);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Medium);
    }

    #[test]
    fn passes_when_require_auth_present() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env, Address};
pub struct C;
#[contractimpl]
impl C {
    pub fn set_owner(env: Env, new_owner: Address) {
        env.require_auth();
        env.storage().instance().set(&"owner", &new_owner);
    }
}
"#);
        assert!(hits.is_empty());
    }

    #[test]
    fn passes_when_assert_macro_present() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env, Address};
pub struct C;
#[contractimpl]
impl C {
    pub fn initialize(env: Env, admin: Address) {
        assert!(admin != Address::default());
        env.storage().instance().set(&"admin", &admin);
    }
}
"#);
        assert!(hits.is_empty());
    }

    #[test]
    fn ignores_non_sensitive_name() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env, Address};
pub struct C;
#[contractimpl]
impl C {
    pub fn deposit(env: Env, from: Address) {
        let _ = from;
    }
}
"#);
        assert!(hits.is_empty());
    }

    #[test]
    fn ignores_non_contractimpl() {
        let hits = run(r#"
use soroban_sdk::{Env, Address};
pub struct C;
impl C {
    pub fn set_owner(_env: Env, _new_owner: Address) {}
}
"#);
        assert!(hits.is_empty());
    }
}
