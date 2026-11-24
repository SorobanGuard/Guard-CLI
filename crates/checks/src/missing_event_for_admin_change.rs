use crate::util::{
    contractimpl_functions_excluding_test, env_param_name, is_event_publish_call,
    is_storage_mutation_call,
};
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
                let env_name = env_param_name(&method.sig).unwrap_or_else(|| "env".to_string());
                let has_event = has_event_emit(&method.block, &env_name);

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
        if is_storage_mutation_call(node) {
            self.found_write = true;
        }
        visit::visit_expr_method_call(self, node);
    }
}

fn has_event_emit(block: &syn::Block, env_name: &str) -> bool {
    let mut visitor = EventVisitor {
        env_name,
        found_event: false,
    };
    visit::visit_block(&mut visitor, block);
    visitor.found_event
}

struct EventVisitor<'a> {
    env_name: &'a str,
    found_event: bool,
}

impl<'ast> Visit<'ast> for EventVisitor<'_> {
    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        if is_event_publish_call(node, self.env_name) {
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
        assert_eq!(findings[0].function_name, "set_owner");
        assert_eq!(findings[0].line, 4);
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

    /// #1060: a `#[contractevent]` `.publish(&env)` counts as the admin-change event.
    #[test]
    fn ignores_admin_change_with_contractevent_publish() -> Result<(), syn::Error> {
        let src = r#"
#[contractimpl]
impl C {
    pub fn set_owner(env: Env, new_owner: Address) {
        env.storage().instance().set(&symbol_short!("owner"), &new_owner);
        OwnerChanged { new_owner }.publish(&env);
    }
}
        "#;
        let file = parse_file(src)?;
        assert!(MissingEventForAdminChangeCheck.run(&file, src).is_empty());
        Ok(())
    }
}
