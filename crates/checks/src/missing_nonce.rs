//! `missing-nonce`: replay-sensitive code that never reads or checks a nonce.
//!
//! Soroban's host already provides replay protection for `Address::require_auth()`:
//! every `SorobanAuthorizationEntry` carries a nonce and an expiration ledger that the host
//! verifies and consumes, so a contract normally does not manage its own nonces. This check
//! therefore only reports the cases where replay protection really is the contract's job:
//!
//! 1. a function that verifies a signature itself (`ed25519_verify`, `secp256k1_recover`,
//!    `secp256r1_verify`) and writes storage, because the host never sees that signature
//!    and cannot stop it being replayed; and
//! 2. a public function that acts on behalf of an `Address` parameter (it writes storage)
//!    without any `require_auth` / `require_auth_for_args` call or auth helper, so nothing
//!    ties the call to that address's host-managed nonce.

use crate::util::{
    contractimpl_functions_excluding_test, is_storage_mutation_call,
    receiver_chain_contains_storage,
};
use crate::{Check, Finding, Severity};
use syn::visit::{self, Visit};
use syn::FnArg;

const CHECK_NAME: &str = "missing-nonce";
const NONCE_KEYWORDS: &[&str] = &["nonce", "sequence", "seq_num", "replay"];

/// Host crypto functions whose result a contract uses to authenticate a caller itself.
const SIGNATURE_VERIFY_METHODS: &[&str] =
    &["ed25519_verify", "secp256k1_recover", "secp256r1_verify"];

const RULE_URL: &str =
    "https://github.com/SorobanGuard/Guard-CLI/blob/main/docs/checks.md#missing-nonce-medium";

pub struct MissingNonceCheck;

impl Check for MissingNonceCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &syn::File, _source: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        for method in contractimpl_functions_excluding_test(file) {
            let mut scan = BodyScan::default();
            scan.visit_block(&method.block);
            if !scan.storage_write || contains_nonce_reference(&method.block) {
                continue;
            }

            let name = method.sig.ident.to_string();
            let is_public = matches!(method.vis, syn::Visibility::Public(_));
            let (description, suggestion) = if scan.verifies_signature {
                (
                    format!(
                        "`{name}` verifies a signature itself and writes storage, but never \
                         checks a nonce. The host's replay protection only covers \
                         `require_auth`, so the same signed payload can be submitted again."
                    ),
                    "Include a per-signer nonce (or a deadline plus a used-payload record) in the \
                     signed message, check it, and store the consumed value before acting."
                        .to_string(),
                )
            } else if is_public && contains_address_param(&method.sig.inputs) && !scan.has_auth {
                (
                    format!(
                        "`{name}` takes an `Address` and writes storage without `require_auth`, \
                         so nothing binds the call to that address's host-managed nonce."
                    ),
                    "Call `address.require_auth()` (the host then provides replay protection), or \
                     check and consume an explicit nonce if the call is authorized another way."
                        .to_string(),
                )
            } else {
                continue;
            };

            findings.push(Finding {
                check_name: CHECK_NAME.to_string(),
                severity: Severity::Medium,
                file_path: String::new(),
                line: method.sig.ident.span().start().line,
                function_name: name,
                description,
                rule_url: Some(RULE_URL.to_string()),
                suggestion: Some(suggestion),
            });
        }
        findings
    }
}

#[derive(Default)]
struct BodyScan {
    storage_write: bool,
    verifies_signature: bool,
    has_auth: bool,
}

/// `require_auth`, `require_auth_for_args`, and the common helper spellings
/// (`require_auth_*`, `assert_auth`, `check_auth`).
fn is_auth_call_name(name: &str) -> bool {
    name.starts_with("require_auth") || name == "assert_auth" || name == "check_auth"
}

impl<'ast> Visit<'ast> for BodyScan {
    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        let method = node.method.to_string();
        if is_storage_mutation_call(node) {
            self.storage_write = true;
        }
        if SIGNATURE_VERIFY_METHODS.contains(&method.as_str()) {
            self.verifies_signature = true;
        }
        if is_auth_call_name(&method) {
            self.has_auth = true;
        }
        visit::visit_expr_method_call(self, node);
    }

    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if let syn::Expr::Path(p) = &*node.func {
            if p.path
                .segments
                .last()
                .is_some_and(|s| is_auth_call_name(&s.ident.to_string()))
            {
                self.has_auth = true;
            }
        }
        visit::visit_expr_call(self, node);
    }
}

fn contains_address_param(inputs: &syn::punctuated::Punctuated<FnArg, syn::token::Comma>) -> bool {
    inputs.iter().any(|arg| {
        if let FnArg::Typed(pat_type) = arg {
            matches!(
                &*pat_type.ty,
                syn::Type::Path(type_path) if type_path.path.segments.last().is_some_and(|s| s.ident == "Address")
            )
        } else {
            false
        }
    })
}

/// Requires the nonce keyword to be an actual value reference (a variable/const read, e.g.
/// a storage key or an argument passed into a comparison or call) rather than any identifier
/// occurring anywhere in the body — a `let` binding name or an unrelated method name (like
/// `.sequence()`) no longer counts, since neither reads a nonce value.
fn contains_nonce_reference(block: &syn::Block) -> bool {
    let mut visitor = NonceKeywordVisitor::default();
    visit::visit_block(&mut visitor, block);
    visitor.found
}

fn str_contains_nonce_keyword(s: &str) -> bool {
    let lower = s.to_lowercase();
    NONCE_KEYWORDS.iter().any(|keyword| lower.contains(keyword))
}

#[derive(Default)]
struct NonceKeywordVisitor {
    found: bool,
}

impl<'ast> Visit<'ast> for NonceKeywordVisitor {
    fn visit_expr_path(&mut self, node: &'ast syn::ExprPath) {
        if let Some(ident) = node.path.get_ident() {
            // Use the same case-insensitive substring match as the macro and
            // string-literal paths so idiomatic names like `tx_nonce`,
            // `user_nonce`, or `nonce_value` are recognised (issue #666).
            if str_contains_nonce_keyword(&ident.to_string()) {
                self.found = true;
            }
        }
        visit::visit_expr_path(self, node);
    }

    fn visit_macro(&mut self, m: &'ast syn::Macro) {
        if m.path
            .segments
            .last()
            .is_some_and(|s| s.ident == "symbol_short")
        {
            if let Ok(syn::Lit::Str(s)) = syn::parse2::<syn::Lit>(m.tokens.clone()) {
                if str_contains_nonce_keyword(&s.value()) {
                    self.found = true;
                }
            }
        }
        visit::visit_macro(self, m);
    }

    // A bare string literal (a log tag, an event topic, an unused `let`) does
    // not read a nonce. Only count literals used to build a key: arguments to
    // `Symbol::new(..)` or to a storage call (`.get(&"nonce")`, `.set(..)`).
    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if let syn::Expr::Path(p) = &*node.func {
            let mut segs = p.path.segments.iter().rev();
            let is_symbol_new = segs.next().is_some_and(|s| s.ident == "new")
                && segs.next().is_some_and(|s| s.ident == "Symbol");
            if is_symbol_new && node.args.iter().any(is_nonce_str_lit) {
                self.found = true;
            }
        }
        visit::visit_expr_call(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        if receiver_chain_contains_storage(&node.receiver)
            && node.args.iter().any(is_nonce_str_lit)
        {
            self.found = true;
        }
        visit::visit_expr_method_call(self, node);
    }
}

fn is_nonce_str_lit(expr: &syn::Expr) -> bool {
    match expr {
        syn::Expr::Lit(syn::ExprLit {
            lit: syn::Lit::Str(s),
            ..
        }) => str_contains_nonce_keyword(&s.value()),
        syn::Expr::Reference(r) => is_nonce_str_lit(&r.expr),
        syn::Expr::Paren(p) => is_nonce_str_lit(&p.expr),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_file;

    #[test]
    fn flags_missing_nonce() -> Result<(), syn::Error> {
        let src = r#"
#[contractimpl]
impl C {
    pub fn update(env: Env, user: Address, new_val: u32) {
        env.storage().instance().set(&symbol_short!("val"), &new_val);
    }
}
        "#;
        let file = parse_file(src)?;
        let check = MissingNonceCheck;
        let findings = check.run(&file, src);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].check_name, "missing-nonce");
        assert_eq!(findings[0].function_name, "update");
        assert_eq!(findings[0].line, 4);
        Ok(())
    }

    #[test]
    fn ignores_local_vec_push() -> Result<(), syn::Error> {
        let src = r#"
#[contractimpl]
impl C {
    pub fn update(env: Env, user: Address, new_val: u32) {
        let mut log: Vec<u32> = Vec::new(&env);
        log.push_back(new_val);
    }
}
        "#;
        let file = parse_file(src)?;
        let check = MissingNonceCheck;
        let findings = check.run(&file, src);
        assert!(findings.is_empty());
        Ok(())
    }

    #[test]
    fn ignores_with_nonce() -> Result<(), syn::Error> {
        let src = r#"
#[contractimpl]
impl C {
    pub fn update(env: Env, user: Address, nonce: u64) {
        env.storage().instance().set(&symbol_short!("nonce"), &nonce);
    }
}
        "#;
        let file = parse_file(src)?;
        let check = MissingNonceCheck;
        let findings = check.run(&file, src);
        assert_eq!(findings.len(), 0);
        Ok(())
    }

    #[test]
    fn ignores_local_collection_write_not_storage() -> Result<(), syn::Error> {
        let src = r#"
#[contractimpl]
impl C {
    pub fn set_operator(env: Env, op: Address) {
        let mut log: Vec<Address> = Vec::new(&env);
        log.push_back(op.clone());
    }
}
        "#;
        let file = parse_file(src)?;
        let check = MissingNonceCheck;
        let findings = check.run(&file, src);
        assert_eq!(findings.len(), 0);
        Ok(())
    }

    #[test]
    fn flags_unrelated_sequence_local_with_unprotected_write() -> Result<(), syn::Error> {
        let src = r#"
#[contractimpl]
impl C {
    pub fn update(env: Env, user: Address, v: u32) {
        let sequence = env.ledger().sequence();
        env.storage().instance().set(&V, &v);
    }
}
        "#;
        let file = parse_file(src)?;
        let check = MissingNonceCheck;
        let findings = check.run(&file, src);
        assert_eq!(findings.len(), 1);
        Ok(())
    }

    #[test]
    fn flags_unrelated_nonce_string_literals() -> Result<(), syn::Error> {
        let src = r#"
#[contractimpl]
impl C {
    pub fn update(env: Env, user: Address, new_val: u32) {
        let tag = "sequence";
        env.events().publish(("replay",), new_val);
        log!(&env, "sequence");
        env.storage().instance().set(&user, &new_val);
    }
}
        "#;
        let file = parse_file(src)?;
        let findings = MissingNonceCheck.run(&file, src);
        assert_eq!(findings.len(), 1);
        Ok(())
    }

    #[test]
    fn ignores_nonce_string_used_as_storage_key() -> Result<(), syn::Error> {
        let src = r#"
#[contractimpl]
impl C {
    pub fn update(env: Env, user: Address, new_val: u32) {
        let n: u64 = env.storage().instance().get(&"nonce").unwrap_or(0);
        env.storage().instance().set(&Symbol::new(&env, "nonce"), &(n + 1));
        env.storage().instance().set(&user, &new_val);
    }
}
        "#;
        let file = parse_file(src)?;
        let findings = MissingNonceCheck.run(&file, src);
        assert_eq!(findings.len(), 0);
        Ok(())
    }

    #[test]
    fn flags_fully_qualified_address_param() -> Result<(), syn::Error> {
        let src = r#"
#[contractimpl]
impl C {
    pub fn update(env: Env, user: soroban_sdk::Address, new_val: u32) {
        env.storage().instance().set(&symbol_short!("val"), &new_val);
    }
}
        "#;
        let file = parse_file(src)?;
        let check = MissingNonceCheck;
        let findings = check.run(&file, src);
        assert_eq!(findings.len(), 1);
        Ok(())
    }

    /// Regression test for #666: compound names that contain a nonce keyword
    /// (tx_nonce, user_nonce, nonce_value) must be recognised as nonce protection.
    #[test]
    fn recognises_compound_nonce_identifier_names() -> Result<(), syn::Error> {
        let src = r#"
#[contractimpl]
impl C {
    pub fn update(env: Env, user: Address, tx_nonce: u64) {
        env.storage().instance().set(&symbol_short!("val"), &tx_nonce);
    }
}
        "#;
        let file = parse_file(src)?;
        let check = MissingNonceCheck;
        let findings = check.run(&file, src);
        assert!(
            findings.is_empty(),
            "tx_nonce should be recognised as nonce protection, got: {:?}", findings
        );
        Ok(())
    }

    #[test]
    fn ignores_missing_nonce_inside_cfg_test() -> Result<(), syn::Error> {
        let src = r#"
#[contractimpl]
impl C {
    pub fn update(env: Env, user: Address, new_val: u32) {
        env.storage().instance().set(&symbol_short!("val"), &new_val);
    }
}

#[cfg(test)]
mod tests {
    use soroban_sdk::{contractimpl, Env, Address};

    #[contractimpl]
    impl C {
        pub fn update(env: Env, user: Address, new_val: u32) {
            env.storage().instance().set(&symbol_short!("val"), &new_val);
        }
    }
}
        "#;
        let file = parse_file(src)?;
        let check = MissingNonceCheck;
        let findings = check.run(&file, src);
        assert_eq!(findings.len(), 1);
        Ok(())
    }

    /// #1052: `require_auth` gets replay protection from the host's per-address nonce.
    #[test]
    fn ignores_require_auth_protected_transfer() -> Result<(), syn::Error> {
        let src = r#"
#[contractimpl]
impl C {
    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        from.require_auth();
        env.storage().persistent().set(&from, &amount);
        env.storage().persistent().set(&to, &amount);
    }
}
        "#;
        let file = parse_file(src)?;
        assert!(MissingNonceCheck.run(&file, src).is_empty());
        Ok(())
    }

    #[test]
    fn ignores_require_auth_for_args_and_auth_helpers() -> Result<(), syn::Error> {
        let src = r#"
#[contractimpl]
impl C {
    pub fn a(env: Env, user: Address, v: u32) {
        user.require_auth_for_args((v,).into_val(&env));
        env.storage().instance().set(&user, &v);
    }
    pub fn b(env: Env, user: Address, v: u32) {
        require_auth_admin(&env);
        env.storage().instance().set(&user, &v);
    }
}
        "#;
        let file = parse_file(src)?;
        assert!(MissingNonceCheck.run(&file, src).is_empty());
        Ok(())
    }

    /// The host cannot protect a signature the contract checks itself, so this is flagged
    /// even though the function also calls `require_auth`.
    #[test]
    fn flags_self_verified_signature_without_nonce() -> Result<(), syn::Error> {
        let src = r#"
#[contractimpl]
impl C {
    pub fn claim(env: Env, relayer: Address, pk: BytesN<32>, msg: Bytes, sig: BytesN<64>) {
        relayer.require_auth();
        env.crypto().ed25519_verify(&pk, &msg, &sig);
        env.storage().persistent().set(&pk, &true);
    }
}
        "#;
        let file = parse_file(src)?;
        let findings = MissingNonceCheck.run(&file, src);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].description.contains("verifies a signature"));
        Ok(())
    }

    #[test]
    fn ignores_self_verified_signature_with_nonce() -> Result<(), syn::Error> {
        let src = r#"
#[contractimpl]
impl C {
    pub fn claim(env: Env, pk: BytesN<32>, msg: Bytes, sig: BytesN<64>, nonce: u64) {
        env.crypto().ed25519_verify(&pk, &msg, &sig);
        env.storage().persistent().set(&pk, &nonce);
    }
}
        "#;
        let file = parse_file(src)?;
        assert!(MissingNonceCheck.run(&file, src).is_empty());
        Ok(())
    }

    /// #1051: `update` is a storage write.
    #[test]
    fn flags_update_only_mutation_without_auth() -> Result<(), syn::Error> {
        let src = r#"
#[contractimpl]
impl C {
    pub fn credit(env: Env, user: Address, amount: i128) {
        env.storage().persistent().update(&user, |old: Option<i128>| old.unwrap_or(0) + amount);
    }
}
        "#;
        let file = parse_file(src)?;
        assert_eq!(MissingNonceCheck.run(&file, src).len(), 1);
        Ok(())
    }

    /// #1051 / #510: a `Vec` push on a value loaded from storage is not itself a write.
    #[test]
    fn ignores_vec_push_on_storage_chain() -> Result<(), syn::Error> {
        let src = r#"
#[contractimpl]
impl C {
    pub fn log(env: Env, user: Address) {
        env.storage().instance().get::<_, Vec<Address>>(&0).unwrap().push_back(user);
    }
}
        "#;
        let file = parse_file(src)?;
        assert!(MissingNonceCheck.run(&file, src).is_empty());
        Ok(())
    }
}
