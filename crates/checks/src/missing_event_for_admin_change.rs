use crate::{Check, Finding, Severity};
use syn::visit::{self, Visit};
use syn::{ImplItem, ItemImpl};

const CHECK_NAME: &str = "missing-event-for-admin-change";
const ADMIN_NAMES: &[&str] = &["set_owner", "set_admin", "transfer_ownership", "set_operator"];

pub struct MissingEventForAdminChangeCheck;

impl Check for MissingEventForAdminChangeCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &syn::File, _source: &str) -> Vec<Finding> {
        let mut visitor = AdminEventVisitor::default();
        visit::visit_file(&mut visitor, file);
        visitor.findings
    }
}

#[derive(Default)]
struct AdminEventVisitor {
    findings: Vec<Finding>,
}

impl<'ast> Visit<'ast> for AdminEventVisitor {
    fn visit_item_impl(&mut self, node: &'ast ItemImpl) {
        if has_contractimpl_attr(&node.attrs) {
            for item in &node.items {
                if let ImplItem::Fn(method) = item {
                    let name = method.sig.ident.to_string();
                    if is_admin_name(&name) && method.sig.vis.is_pub() {
                        let has_storage_write = has_storage_write(&method.block);
                        let has_event = has_event_emit(&method.block);

                        if has_storage_write && !has_event {
                            self.findings.push(Finding {
                                check_name: CHECK_NAME.to_string(),
                                severity: Severity::Medium,
                                file_path: String::new(),
                                line: method.span().start().line,
                                function_name: name.clone(),
                                description: format!(
                                    "Admin change function `{}` lacks event emission",
                                    name
                                ),
                                rule_url: None,
                                suggestion: Some(
                                    "Emit an event with env.events().publish() to track admin changes"
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

fn is_admin_name(name: &str) -> bool {
    ADMIN_NAMES.iter().any(|&a| name.contains(a))
}

fn has_storage_write(block: &syn::Block) -> bool {
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
        if matches!(node.method.to_string().as_str(), "set" | "remove" | "append") {
            self.found_write = true;
        }
        visit::visit_expr_method_call(self, node);
    }
}

fn has_event_emit(block: &syn::Block) -> bool {
    let mut visitor = EventVisitor::default();
    visit::visit_block(&mut visitor, block);
    visitor.found_event
}

#[derive(Default)]
struct EventVisitor {
    found_event: bool,
}

impl<'ast> Visit<'ast> for EventVisitor {
    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        if node.method == "publish" {
            self.found_event = true;
        }
        visit::visit_expr_method_call(self, node);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_file;

    #[test]
    fn flags_missing_event() -> Result<(), syn::Error> {
        let src = r#"
#[contractimpl]
impl C {
    pub fn set_owner(env: Env, new_owner: Address) {
        env.storage().instance().set(&symbol_short!("owner"), &new_owner);
    }
}
        "#;
        let file = parse_file(src)?;
        let check = MissingEventForAdminChangeCheck;
        let findings = check.run(&file, src);
        assert_eq!(findings.len(), 1);
        Ok(())
    }
}
