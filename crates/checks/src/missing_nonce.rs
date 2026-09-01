use crate::util::{contractimpl_functions_excluding_test, receiver_chain_contains_storage};
use crate::{Check, Finding, Severity};
use syn::visit::{self, Visit};
use syn::FnArg;

const CHECK_NAME: &str = "missing-nonce";
const NONCE_KEYWORDS: &[&str] = &["nonce", "sequence", "seq_num", "replay"];

pub struct MissingNonceCheck;

impl Check for MissingNonceCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &syn::File, _source: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        for method in contractimpl_functions_excluding_test(file) {
            if matches!(method.vis, syn::Visibility::Public(_)) {
                let has_storage_write = contains_storage_write(&method.block);
                let has_address_param = contains_address_param(&method.sig.inputs);
                let has_nonce = contains_nonce_reference(&method.block);

                if has_storage_write && has_address_param && !has_nonce {
                    let name = method.sig.ident.to_string();
                    findings.push(Finding {
                        check_name: CHECK_NAME.to_string(),
                        severity: Severity::Medium,
                        file_path: String::new(),
                        line: method.sig.ident.span().start().line,
                        function_name: name.clone(),
                        description:
                            "State-mutating method with Address parameter lacks nonce/replay protection"
                                .to_string(),
                        rule_url: Some(
                            "https://github.com/SorobanGuard/Guard-CLI/blob/main/docs/checks.md#missing-nonce-medium"
                                .to_string(),
                        ),
                        suggestion: Some(
                            "Add nonce or sequence number validation to prevent replay attacks"
                                .to_string(),
                        ),
                    });
                }
            }
        }
        findings
    }
}

fn contains_storage_write(block: &syn::Block) -> bool {
    let mut visitor = StorageWriteVisitor::default();
    visit::visit_block(&mut visitor, block);
    visitor.found_write
}

#[derive(Default)]
struct StorageWriteVisitor {
    found_write: bool,
}

impl<'ast> Visit<'ast> for StorageWriteVisitor {
    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        if matches!(
            node.method.to_string().as_str(),
            "set" | "remove" | "append" | "push" | "push_back"
        ) && receiver_chain_contains_storage(&node.receiver)
        {
            self.found_write = true;
        }
        visit::visit_expr_method_call(self, node);
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
            if NONCE_KEYWORDS.iter().any(|keyword| ident == keyword) {
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

    fn visit_expr_lit(&mut self, node: &'ast syn::ExprLit) {
        if let syn::Lit::Str(s) = &node.lit {
            if str_contains_nonce_keyword(&s.value()) {
                self.found = true;
            }
        }
        visit::visit_expr_lit(self, node);
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
}
