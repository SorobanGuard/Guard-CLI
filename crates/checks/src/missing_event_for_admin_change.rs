use crate::util::contractimpl_functions_excluding_test;
use crate::util::receiver_chain_contains_events;
use crate::util::receiver_chain_contains_storage;
use crate::{Check, Finding, Severity};
use syn::visit::{self, Visit};
use syn::spanned::Spanned;


const CHECK_NAME: &str = "missing-event-for-admin-change";
const ADMIN_NAMES: &[&str] = &["set_owner", "set_admin", "transfer_ownership", "set_operator"];

pub struct MissingEventForAdminChangeCheck;

impl Check for MissingEventForAdminChangeCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &syn::File, _source: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        for method in contractimpl_functions_excluding_test(file) {
            let name = method.sig.ident.to_string();
            if is_admin_name(&name) && matches!(method.vis, syn::Visibility::Public(_)) {
                let has_storage_write = has_storage_write(&method.block);
                let has_event = has_event_emit(&method.block);

                if has_storage_write && !has_event {
                    findings.push(Finding {
                        check_name: CHECK_NAME.to_string(),
                        severity: Severity::Medium,
                        file_path: String::new(),
                        line: method.sig.fn_token.span().start().line,
                        function_name: name.clone(),
                        description: format!("Admin change function `{}` lacks event emission", name),
                        rule_url: Some(
                            "https://github.com/SorobanGuard/Guard-CLI/blob/main/docs/checks.md#missing-event-for-admin-change-medium"
                                .to_string(),
                        ),
                        suggestion: Some(
                            "Emit an event with env.events().publish() to track admin changes"
                                .to_string(),
                        ),
                    });
                }
            }
        }
        findings
    }
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
        if matches!(
            node.method.to_string().as_str(),
            "set" | "remove" | "append"
        ) && receiver_chain_contains_storage(&node.receiver)
        {
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
        if node.method == "publish" && receiver_chain_contains_events(&node.receiver) {
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

    #[test]
    fn ignores_local_collection_write_not_storage() -> Result<(), syn::Error> {
        let src = r#"
#[contractimpl]
impl C {
    pub fn set_operator(env: Env, op: Address) {
        let mut log: Map<Address, u32> = Map::new(&env);
        log.set(op.clone(), 1);
    }
}
        "#;
        let file = parse_file(src)?;
        let check = MissingEventForAdminChangeCheck;
        let findings = check.run(&file, src);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].line, 6);
        assert_eq!(findings.len(), 0);
        Ok(())
    }

    #[test]
    fn ignores_missing_event_inside_cfg_test() -> Result<(), syn::Error> {
        let src = r#"
#[contractimpl]
impl C {
    pub fn set_owner(env: Env, new_owner: Address) {
        env.events().publish((symbol_short!("owner"),), new_owner);
    }
}

#[cfg(test)]
mod tests {
    use soroban_sdk::{contractimpl, Env, Address};

    #[contractimpl]
    impl C {
        pub fn set_owner(env: Env, new_owner: Address) {
            env.storage().instance().set(&symbol_short!("owner"), &new_owner);
        }
    }
}
        "#;
        let file = parse_file(src)?;
        let check = MissingEventForAdminChangeCheck;
        let findings = check.run(&file, src);
        assert_eq!(findings.len(), 0);
        Ok(())
    }
}
