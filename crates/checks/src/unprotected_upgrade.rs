use crate::{Check, Finding, Severity};
use syn::visit::{self, Visit};
use syn::{ImplItem, ItemImpl};

const CHECK_NAME: &str = "unprotected-upgrade";
const SENSITIVE_NAMES: &[&str] = &["upgrade", "migrate", "set_wasm", "replace_wasm"];

pub struct UnprotectedUpgradeCheck;

impl Check for UnprotectedUpgradeCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &syn::File, _source: &str) -> Vec<Finding> {
        let mut visitor = UpgradeVisitor::default();
        visit::visit_file(&mut visitor, file);
        visitor.findings
    }
}

#[derive(Default)]
struct UpgradeVisitor {
    findings: Vec<Finding>,
}

impl<'ast> Visit<'ast> for UpgradeVisitor {
    fn visit_item_impl(&mut self, node: &'ast ItemImpl) {
        if has_contractimpl_attr(&node.attrs) {
            for item in &node.items {
                if let ImplItem::Fn(method) = item {
                    let name = method.sig.ident.to_string();
                    if is_sensitive_name(&name) && method.sig.vis.is_pub() {
                        let has_auth = contains_auth_call(&method.block);
                        if !has_auth {
                            self.findings.push(Finding {
                                check_name: CHECK_NAME.to_string(),
                                severity: Severity::High,
                                file_path: String::new(),
                                line: method.span().start().line,
                                function_name: name.clone(),
                                description: format!(
                                    "Upgrade/migrate method `{}` lacks require_auth call",
                                    name
                                ),
                                rule_url: None,
                                suggestion: Some("Add env.require_auth() at the start".to_string()),
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

fn is_sensitive_name(name: &str) -> bool {
    SENSITIVE_NAMES.iter().any(|&s| name.contains(s))
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
    fn flags_unprotected_upgrade() -> Result<(), syn::Error> {
        let src = r#"
#[contractimpl]
impl C {
    pub fn upgrade(env: Env, new_code: Bytes) {
        env.invoke_wasm(&new_code);
    }
}
        "#;
        let file = parse_file(src)?;
        let check = UnprotectedUpgradeCheck;
        let findings = check.run(&file, src);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].check_name, "unprotected-upgrade");
        Ok(())
    }

    #[test]
    fn ignores_protected_migrate() -> Result<(), syn::Error> {
        let src = r#"
#[contractimpl]
impl C {
    pub fn migrate(env: Env, new_code: Bytes) {
        env.require_auth();
        env.invoke_wasm(&new_code);
    }
}
        "#;
        let file = parse_file(src)?;
        let check = UnprotectedUpgradeCheck;
        let findings = check.run(&file, src);
        assert_eq!(findings.len(), 0);
        Ok(())
    }
}
