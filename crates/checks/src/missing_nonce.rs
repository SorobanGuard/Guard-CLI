use crate::{Check, Finding, Severity};
use syn::visit::{self, Visit};
use syn::{ImplItem, ItemImpl, FnArg, Pat};

const CHECK_NAME: &str = "missing-nonce";
const NONCE_KEYWORDS: &[&str] = &["nonce", "sequence", "seq_num", "replay"];

pub struct MissingNonceCheck;

impl Check for MissingNonceCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &syn::File, _source: &str) -> Vec<Finding> {
        let mut visitor = NonceVisitor::default();
        visit::visit_file(&mut visitor, file);
        visitor.findings
    }
}

#[derive(Default)]
struct NonceVisitor {
    findings: Vec<Finding>,
}

impl<'ast> Visit<'ast> for NonceVisitor {
    fn visit_item_impl(&mut self, node: &'ast ItemImpl) {
        if has_contractimpl_attr(&node.attrs) {
            for item in &node.items {
                if let ImplItem::Fn(method) = item {
                    if method.sig.vis.is_pub() {
                        let has_storage_write = contains_storage_write(&method.block);
                        let has_address_param = contains_address_param(&method.sig.inputs);
                        let has_nonce = contains_nonce_reference(&method.block);

                        if has_storage_write && has_address_param && !has_nonce {
                            let name = method.sig.ident.to_string();
                            self.findings.push(Finding {
                                check_name: CHECK_NAME.to_string(),
                                severity: Severity::Medium,
                                file_path: String::new(),
                                line: method.span().start().line,
                                function_name: name.clone(),
                                description:
                                    "State-mutating method with Address parameter lacks nonce/replay protection"
                                        .to_string(),
                                rule_url: None,
                                suggestion: Some(
                                    "Add nonce or sequence number validation to prevent replay attacks"
                                        .to_string(),
                                ),
                            });
                        }
                    }
                }
            }
        }
        visit::visit_item_impl(self, node);
    }
}

fn has_contractimpl_attr(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        if let syn::Meta::Path(path) = &attr.meta {
            path.segments
                .last()
                .map(|seg| seg.ident == "contractimpl")
                .unwrap_or(false)
        } else {
            false
        }
    })
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
        ) {
            self.found_write = true;
        }
        visit::visit_expr_method_call(self, node);
    }
}

fn contains_address_param(inputs: &syn::punctuated::Punctuated<FnArg, syn::token::Comma>) -> bool {
    inputs.iter().any(|arg| {
        if let FnArg::Typed(pat_type) = arg {
            let ty_str = format!("{:?}", pat_type.ty);
            ty_str.contains("Address")
        } else {
            false
        }
    })
}

fn contains_nonce_reference(block: &syn::Block) -> bool {
    let block_text = format!("{:?}", block);
    NONCE_KEYWORDS
        .iter()
        .any(|&keyword| block_text.to_lowercase().contains(keyword))
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
}
