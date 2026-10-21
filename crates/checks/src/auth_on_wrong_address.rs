//! `auth-on-wrong-address` check.
//!
//! Flags transfer-like functions where `require_auth()` is invoked only on the
//! credit-side (recipient) address while the debit-side (owner) address is
//! never authorised. This is a common copy/paste bug that lets anyone move
//! another user's funds by naming themselves as the recipient.

use crate::check::{Check, CheckContext, Finding, Severity};
use crate::registry::Rule;
use syn::{
    visit::Visit, Expr, ExprCall, ExprMethodCall, FnArg, ImplItem, ImplItemFn, Item, Pat, Type,
};

/// Debit-side parameter names (the party whose funds are moved).
const DEBIT_NAMES: &[&str] = &["from", "owner", "sender", "payer", "spender"];

/// Credit-side parameter names (the party receiving funds).
const CREDIT_NAMES: &[&str] = &["to", "recipient", "dest"];

/// Names of methods that perform a transfer or balance debit.
const TRANSFER_METHODS: &[&str] = &[
    "transfer",
    "transfer_from",
    "move",
    "debit",
    "withdraw",
    "spend",
    "burn",
];

/// The `auth-on-wrong-address` check.
pub struct AuthOnWrongAddressCheck;

impl Check for AuthOnWrongAddressCheck {
    fn name(&self) -> &'static str {
        "auth-on-wrong-address"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn rule(&self) -> Rule {
        Rule::AuthOnWrongAddress
    }

    fn check(&self, ctx: &CheckContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        for item in &ctx.ast.items {
            let Item::Impl(item_impl) = item else {
                continue;
            };

            if !is_contract_impl(item_impl) {
                continue;
            }

            for impl_item in &item_impl.items {
                let ImplItem::Fn(method) = impl_item else {
                    continue;
                };

                if let Some(finding) = check_method(method) {
                    findings.push(finding);
                }
            }
        }

        findings
    }
}

/// Returns `true` if the impl block is annotated with `#[contractimpl]`.
fn is_contract_impl(item_impl: &syn::ItemImpl) -> bool {
    item_impl.attrs.iter().any(|attr| {
        attr.path()
            .segments
            .last()
            .map(|seg| seg.ident == "contractimpl")
            .unwrap_or(false)
    })
}

/// Classifies a parameter name into debit-side or credit-side.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Side {
    Debit,
    Credit,
}

/// Extracts the identifier of a simple `name: Type` parameter.
fn param_ident(arg: &FnArg) -> Option<String> {
    let FnArg::Typed(pat_type) = arg else {
        return None;
    };
    let Pat::Ident(pat_ident) = &*pat_type.pat else {
        return None;
    };
    Some(pat_ident.ident.to_string())
}

/// Classifies a parameter name, supporting common aliases.
fn classify(name: &str) -> Option<Side> {
    let lower = name.to_ascii_lowercase();

    // Direct matches.
    if DEBIT_NAMES.contains(&lower.as_str()) {
        return Some(Side::Debit);
    }
    if CREDIT_NAMES.contains(&lower.as_str()) {
        return Some(Side::Credit);
    }

    // Alias support: names like `from_addr`, `owner_address`, `to_account`,
    // `recipient_addr`, `sender_id`, etc.
    for base in DEBIT_NAMES {
        if lower.starts_with(base) || lower.ends_with(base) {
            return Some(Side::Debit);
        }
    }
    for base in CREDIT_NAMES {
        if lower.starts_with(base) || lower.ends_with(base) {
            return Some(Side::Credit);
        }
    }

    None
}

/// Checks a single contract method.
fn check_method(method: &ImplItemFn) -> Option<Finding> {
    // Collect debit-side and credit-side parameter identifiers.
    let mut debit_params: Vec<String> = Vec::new();
    let mut credit_params: Vec<String> = Vec::new();

    for arg in &method.sig.inputs {
        let Some(name) = param_ident(arg) else {
            continue;
        };
        match classify(&name) {
            Some(Side::Debit) => debit_params.push(name),
            Some(Side::Credit) => credit_params.push(name),
            None => {}
        }
    }

    // The check only applies to functions that have both sides.
    if debit_params.is_empty() || credit_params.is_empty() {
        return None;
    }

    // Detect whether the body performs a transfer/debit operation.
    let mut transfer_visitor = TransferVisitor::default();
    transfer_visitor.visit_block(&method.block);
    if !transfer_visitor.found {
        return None;
    }

    // Collect which addresses have `require_auth` / `require_auth_for_args`
    // invoked on them.
    let mut auth_visitor = AuthVisitor::default();
    auth_visitor.visit_block(&method.block);

    let debit_authed = debit_params.iter().any(|p| auth_visitor.authed.contains(p));
    let credit_authed = credit_params.iter().any(|p| auth_visitor.authed.contains(p));

    // Flag only when auth is present on credit-side but not on debit-side.
    if credit_authed && !debit_authed {
        let method_name = method.sig.ident.to_string();
        let credit_list = credit_params.join(", ");
        let debit_list = debit_params.join(", ");
        return Some(Finding {
            check: "auth-on-wrong-address",
            severity: Severity::High,
            description: format!(
                "`{method_name}` calls `require_auth` only on the recipient (`{credit_list}`) \
                 but never on the debited party (`{debit_list}`); anyone can move another \
                 user's funds by naming themselves as the recipient."
            ),
            rule_url: "docs/checks.md#auth-on-wrong-address-high",
            suggestion: format!(
                "Call `require_auth()` (or `require_auth_for_args`) on the debited party \
                 (`{debit_list}`) instead of, or in addition to, the recipient."
            ),
        });
    }

    None
}

/// Visitor that detects transfer/debit operations in a method body.
#[derive(Default)]
struct TransferVisitor {
    found: bool,
}

impl<'ast> Visit<'ast> for TransferVisitor {
    fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
        let name = node.method.to_string();
        if TRANSFER_METHODS.contains(&name.as_str()) {
            self.found = true;
        }
        syn::visit::visit_expr_method_call(self, node);
    }

    fn visit_expr_call(&mut self, node: &'ast ExprCall) {
        if let Expr::Path(path) = &*node.func {
            if let Some(seg) = path.path.segments.last() {
                let name = seg.ident.to_string();
                if TRANSFER_METHODS.contains(&name.as_str()) {
                    self.found = true;
                }
            }
        }
        syn::visit::visit_expr_call(self, node);
    }
}

/// Visitor that records which identifiers have `require_auth` invoked on them.
#[derive(Default)]
struct AuthVisitor {
    authed: Vec<String>,
}

impl<'ast> Visit<'ast> for AuthVisitor {
    fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
        let name = node.method.to_string();
        if name == "require_auth" || name == "require_auth_for_args" {
            if let Expr::Path(path) = &*node.receiver {
                if let Some(ident) = path.path.get_ident() {
                    self.authed.push(ident.to_string());
                }
            }
        }
        syn::visit::visit_expr_method_call(self, node);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::check::CheckContext;
    use syn::parse_quote;

    fn run(src: syn::File) -> Vec<Finding> {
        let ctx = CheckContext { ast: src };
        AuthOnWrongAddressCheck.check(&ctx)
    }

    #[test]
    fn flags_auth_on_to_only() {
        let src: syn::File = parse_quote! {
            #[contractimpl]
            impl Token {
                pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
                    to.require_auth();
                    Self::do_transfer(&env, &from, &to, amount);
                }
            }
        };
        let findings = run(src);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn clean_when_auth_on_from() {
        let src: syn::File = parse_quote! {
            #[contractimpl]
            impl Token {
                pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
                    from.require_auth();
                    Self::do_transfer(&env, &from, &to, amount);
                }
            }
        };
        let findings = run(src);
        assert!(findings.is_empty());
    }

    #[test]
    fn clean_when_auth_on_both() {
        let src: syn::File = parse_quote! {
            #[contractimpl]
            impl Token {
                pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
                    from.require_auth();
                    to.require_auth();
                    Self::do_transfer(&env, &from, &to, amount);
                }
            }
        };
        let findings = run(src);
        assert!(findings.is_empty());
    }

    #[test]
    fn flags_with_renamed_params_via_alias() {
        let src: syn::File = parse_quote! {
            #[contractimpl]
            impl Token {
                pub fn transfer(env: Env, owner_address: Address, recipient_addr: Address, amount: i128) {
                    recipient_addr.require_auth();
                    Self::do_transfer(&env, &owner_address, &recipient_addr, amount);
                }
            }
        };
        let findings = run(src);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn clean_with_renamed_params_auth_on_owner() {
        let src: syn::File = parse_quote! {
            #[contractimpl]
            impl Token {
                pub fn transfer(env: Env, sender_id: Address, dest_account: Address, amount: i128) {
                    sender_id.require_auth();
                    Self::do_transfer(&env, &sender_id, &dest_account, amount);
                }
            }
        };
        let findings = run(src);
        assert!(findings.is_empty());
    }

    #[test]
    fn ignores_non_transfer_functions() {
        let src: syn::File = parse_quote! {
            #[contractimpl]
            impl Token {
                pub fn balance(env: Env, owner: Address, to: Address) -> i128 {
                    to.require_auth();
                    0
                }
            }
        };
        let findings = run(src);
        assert!(findings.is_empty());
    }
}