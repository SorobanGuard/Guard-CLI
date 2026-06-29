use crate::{Check, Finding, Severity};
use syn::visit::{self, Visit};
use syn::{ImplItem, ItemImpl};

const CHECK_NAME: &str = "unprotected-contract-deployment";

pub struct UnprotectedContractDeploymentCheck;

impl Check for UnprotectedContractDeploymentCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &syn::File, _source: &str) -> Vec<Finding> {
        let mut visitor = DeploymentVisitor::default();
        visit::visit_file(&mut visitor, file);
        visitor.findings
    }
}

#[derive(Default)]
struct DeploymentVisitor {
    findings: Vec<Finding>,
}

impl<'ast> Visit<'ast> for DeploymentVisitor {
    fn visit_item_impl(&mut self, node: &'ast ItemImpl) {
        if has_contractimpl_attr(&node.attrs) {
            for item in &node.items {
                if let ImplItem::Fn(method) = item {
                    if method.sig.vis.is_pub() {
                        let (has_deployer, line) = has_deployer_call(&method.block);
                        let has_auth = contains_auth_call(&method.block);

                        if has_deployer && !has_auth {
                            self.findings.push(Finding {
                                check_name: CHECK_NAME.to_string(),
                                severity: Severity::High,
                                file_path: String::new(),
                                line,
                                function_name: method.sig.ident.to_string(),
                                description:
                                    "Contract deployment call lacks require_auth protection"
                                        .to_string(),
                                rule_url: None,
                                suggestion: Some(
                                    "Add env.require_auth() before deployment operations"
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

fn has_deployer_call(block: &syn::Block) -> (bool, usize) {
    let mut visitor = DeployerVisitor::default();
    visit::visit_block(&mut visitor, block);
    (visitor.found_deployer, visitor.line)
}

#[derive(Default)]
struct DeployerVisitor {
    found_deployer: bool,
    line: usize,
}

impl<'ast> Visit<'ast> for DeployerVisitor {
    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        if node.method == "deployer" {
            self.found_deployer = true;
            self.line = node.span().start().line;
        }
        visit::visit_expr_method_call(self, node);
    }
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
    fn flags_unprotected_deployer() -> Result<(), syn::Error> {
        let src = r#"
#[contractimpl]
impl C {
    pub fn upload(env: Env, wasm: Bytes) {
        env.deployer().upload_contract_wasm(&wasm);
    }
}
        "#;
        let file = parse_file(src)?;
        let check = UnprotectedContractDeploymentCheck;
        let findings = check.run(&file, src);
        assert_eq!(findings.len(), 1);
        Ok(())
    }
}
