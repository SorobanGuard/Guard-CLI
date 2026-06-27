use crate::{Check, Finding, Severity};
use syn::visit::{self, Visit};
use syn::{ImplItem, ItemImpl};

const CHECK_NAME: &str = "unprotected-token-mint";
const MINT_NAMES: &[&str] = &["mint", "burn", "issue", "redeem", "create_tokens"];

pub struct UnprotectedTokenMintCheck;

impl Check for UnprotectedTokenMintCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &syn::File, _source: &str) -> Vec<Finding> {
        let mut visitor = MintVisitor::default();
        visit::visit_file(&mut visitor, file);
        visitor.findings
    }
}

#[derive(Default)]
struct MintVisitor {
    findings: Vec<Finding>,
}

impl<'ast> Visit<'ast> for MintVisitor {
    fn visit_item_impl(&mut self, node: &'ast ItemImpl) {
        if has_contractimpl_attr(&node.attrs) {
            for item in &node.items {
                if let ImplItem::Fn(method) = item {
                    let name = method.sig.ident.to_string();
                    if is_mint_name(&name) && method.sig.vis.is_pub() {
                        let has_auth = contains_auth_call(&method.block);
                        if !has_auth {
                            self.findings.push(Finding {
                                check_name: CHECK_NAME.to_string(),
                                severity: Severity::High,
                                file_path: String::new(),
                                line: method.span().start().line,
                                function_name: name.clone(),
                                description: format!(
                                    "Mint/burn method `{}` lacks require_auth call",
                                    name
                                ),
                                rule_url: None,
                                suggestion: Some(
                                    "Add env.require_auth() to restrict minting to authorized callers"
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

fn is_mint_name(name: &str) -> bool {
    MINT_NAMES.iter().any(|&m| name.contains(m))
}

fn contains_auth_call(block: &syn::Block) -> bool {
    let mut visitor = AuthCallVisitor::default();
    visit::visit_block(&mut visitor, block);
    visitor.found_auth
}

#[derive(Default)]
struct AuthCallVisitor {
    found_auth: bool,
}

impl<'ast> Visit<'ast> for AuthCallVisitor {
    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        if matches!(node.method.to_string().as_str(), "require_auth" | "require_auth_for_args") {
            self.found_auth = true;
        }
        visit::visit_expr_method_call(self, node);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_file;

    #[test]
    fn flags_unprotected_mint() -> Result<(), syn::Error> {
        let src = r#"
#[contractimpl]
impl C {
    pub fn mint(env: Env, to: Address, amount: u128) {
        env.storage().instance().set(&symbol_short!("supply"), &amount);
    }
}
        "#;
        let file = parse_file(src)?;
        let check = UnprotectedTokenMintCheck;
        let findings = check.run(&file, src);
        assert_eq!(findings.len(), 1);
        Ok(())
    }
}
