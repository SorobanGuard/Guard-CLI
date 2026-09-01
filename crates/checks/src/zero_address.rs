//! Missing zero-address check: `Address` parameters with no zero/default assertion.

use crate::util::contractimpl_functions_excluding_test;
use crate::{Check, Finding, Severity};
use syn::punctuated::Punctuated;
use syn::visit::{self, Visit};
use syn::{
    BinOp, Expr, ExprBinary, ExprMethodCall, File, FnArg, Pat, PatType, Token, Type, TypePath,
};

const CHECK_NAME: &str = "missing-zero-address-check";

/// Flags public `#[contractimpl]` methods whose name suggests admin/ownership
/// semantics, that accept an `Address` parameter, and whose body never actually
/// compares that parameter against a zero/default `Address` (e.g.
/// `assert!(admin != Address::default())` or `admin.is_zero()`).
///
/// An authorization check such as `require_auth()` proves the *caller* is
/// authorised; it says nothing about the *value* of the address argument being
/// passed in, so it is not treated as a guard on its own.
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

/// Method names that, called directly on the address parameter, are themselves a
/// zero/default check (e.g. `admin.is_zero()`). Matched exactly — never by
/// substring — so unrelated calls such as `.unwrap_or_default()` can never match.
const ADDRESS_PREDICATE_METHODS: &[&str] = &["is_zero", "is_default"];

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

/// Strips `&`, `(...)`, and `.clone()` wrappers to see if `e` refers to one of
/// `addr_params`.
fn is_addr_param_ref(e: &Expr, addr_params: &[String]) -> bool {
    match e {
        Expr::Path(p) => p
            .path
            .get_ident()
            .is_some_and(|i| addr_params.iter().any(|a| a == &i.to_string())),
        Expr::Reference(r) => is_addr_param_ref(&r.expr, addr_params),
        Expr::Paren(p) => is_addr_param_ref(&p.expr, addr_params),
        Expr::MethodCall(m) if m.method == "clone" => is_addr_param_ref(&m.receiver, addr_params),
        _ => false,
    }
}

/// True for an expression that produces the default/zero value being compared
/// against, e.g. `Address::default()` or `Default::default()`.
fn is_default_producing(e: &Expr) -> bool {
    match e {
        Expr::Call(c) => {
            if let Expr::Path(p) = &*c.func {
                p.path.segments.last().is_some_and(|s| s.ident == "default")
            } else {
                false
            }
        }
        Expr::Reference(r) => is_default_producing(&r.expr),
        Expr::Paren(p) => is_default_producing(&p.expr),
        _ => false,
    }
}

/// True if `bin` is an `==`/`!=` comparison between one of `addr_params` and a
/// default/zero-producing expression, in either operand order.
fn is_zero_address_comparison(bin: &ExprBinary, addr_params: &[String]) -> bool {
    if !matches!(bin.op, BinOp::Eq(_) | BinOp::Ne(_)) {
        return false;
    }
    (is_addr_param_ref(&bin.left, addr_params) && is_default_producing(&bin.right))
        || (is_addr_param_ref(&bin.right, addr_params) && is_default_producing(&bin.left))
}

/// Manual recursive walk (not `syn::visit::Visit`) used to inspect macro bodies,
/// which are re-parsed as standalone `Expr` trees outside the source file's AST
/// lifetime.
fn expr_contains_zero_check(expr: &Expr, addr_params: &[String]) -> bool {
    match expr {
        Expr::Binary(bin) => {
            is_zero_address_comparison(bin, addr_params)
                || expr_contains_zero_check(&bin.left, addr_params)
                || expr_contains_zero_check(&bin.right, addr_params)
        }
        Expr::Unary(u) => expr_contains_zero_check(&u.expr, addr_params),
        Expr::Paren(p) => expr_contains_zero_check(&p.expr, addr_params),
        Expr::MethodCall(m) => {
            (ADDRESS_PREDICATE_METHODS.contains(&m.method.to_string().as_str())
                && is_addr_param_ref(&m.receiver, addr_params))
                || expr_contains_zero_check(&m.receiver, addr_params)
        }
        _ => false,
    }
}

/// True if any comma-separated expression in `assert!(...)`/`require!(...)`'s
/// argument list is (or contains) a real zero-address comparison.
fn macro_contains_zero_check(mac: &syn::Macro, addr_params: &[String]) -> bool {
    mac.parse_body_with(Punctuated::<Expr, Token![,]>::parse_terminated)
        .map(|exprs| {
            exprs
                .iter()
                .any(|e| expr_contains_zero_check(e, addr_params))
        })
        .unwrap_or(false)
}

struct BodyScan<'a> {
    addr_params: &'a [String],
    has_guard: bool,
}

impl<'ast, 'a> Visit<'ast> for BodyScan<'a> {
    fn visit_expr_binary(&mut self, i: &'ast ExprBinary) {
        if is_zero_address_comparison(i, self.addr_params) {
            self.has_guard = true;
        }
        visit::visit_expr_binary(self, i);
    }

    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        let name = i.method.to_string();
        if ADDRESS_PREDICATE_METHODS.contains(&name.as_str())
            && is_addr_param_ref(&i.receiver, self.addr_params)
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
        if matches!(name.as_str(), "assert" | "require")
            && macro_contains_zero_check(mac, self.addr_params)
        {
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
        for method in contractimpl_functions_excluding_test(file) {
            let fn_name = method.sig.ident.to_string();
            let is_sensitive = SENSITIVE_NAMES.contains(&fn_name.as_str());
            if !is_sensitive {
                continue;
            }
            if !has_address_param(method) {
                continue;
            }
            let addr_params = address_param_names(method);
            let mut scan = BodyScan {
                addr_params: &addr_params,
                has_guard: false,
            };
            scan.visit_block(&method.block);
            if scan.has_guard {
                continue;
            }
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
                suggestion: Some(format!(
                    "Add `assert!({} != Address::default(), \"zero address\");` at the top \
                     of `{fn_name}` to reject the default/zero address.",
                    addr_params.first().map(String::as_str).unwrap_or("addr")
                )),
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
    fn flags_when_only_unwrap_or_default_present() {
        // Regression test for #464: `.unwrap_or_default()` anywhere in the body
        // must not be mistaken for a zero-address guard on `admin`.
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env, Address};
pub struct C;
#[contractimpl]
impl C {
    pub fn set_admin(env: Env, admin: Address) {
        let prev: Address = env.storage().instance().get(&"admin").unwrap_or_default();
        let _ = prev;
        env.storage().instance().set(&"admin", &admin);
    }
}
"#);
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn flags_when_only_require_auth_present() {
        // Regression test for #465: `require_auth()` proves the caller is
        // authorised, not that `new_owner` isn't the zero address.
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
        assert_eq!(hits.len(), 1);
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
    fn passes_when_require_auth_and_real_comparison_present() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env, Address};
pub struct C;
#[contractimpl]
impl C {
    pub fn set_owner(env: Env, new_owner: Address) {
        env.require_auth();
        assert!(new_owner != Address::default(), "zero address");
        env.storage().instance().set(&"owner", &new_owner);
    }
}
"#);
        assert!(hits.is_empty());
    }

    #[test]
    fn passes_when_is_zero_predicate_present() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env, Address};
pub struct C;
#[contractimpl]
impl C {
    pub fn set_admin(env: Env, admin: Address) {
        self.validate_fee_config();
        assert!(!admin.is_zero());
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
