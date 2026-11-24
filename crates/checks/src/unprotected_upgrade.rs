//! Unprotected-upgrade: an exported method replaces the contract's WASM
//! (`env.deployer().update_current_contract_wasm(..)`) without authorization first.
//!
//! Every public `#[contractimpl]` method is checked, whatever its name: the upgrade can sit
//! in `upgrade`, `set_code`, `admin_action` or anything else.

use crate::util::{
    is_admin_var_name,
    self, contractimpl_functions_excluding_test, env_param_name, pat_ident_name,
    receiver_chain_contains, receiver_chain_contains_storage,
};
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Block, Expr, ExprMethodCall};

const CHECK_NAME: &str = "unprotected-upgrade";

pub struct UnprotectedUpgradeCheck;

impl Check for UnprotectedUpgradeCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &syn::File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions_excluding_test(file) {
            let name = method.sig.ident.to_string();
            if matches!(method.vis, syn::Visibility::Public(_)) {
                let env_name = env_param_name(&method.sig).unwrap_or_else(|| "env".to_string());
                let address_names = util::address_param_names(&method.sig);
                let sensitive_line = first_wasm_update_line(&method.block);
                let auth_line = first_valid_auth_line(method, &env_name, &address_names);

                let unprotected = match (sensitive_line, auth_line) {
                    (Some(sensitive), Some(auth)) => auth >= sensitive,
                    (Some(_), None) => true,
                    (None, _) => false,
                };

                if unprotected {
                    out.push(Finding {
                        check_name: CHECK_NAME.to_string(),
                        severity: Severity::High,
                        file_path: String::new(),
                        line: sensitive_line.unwrap_or_else(|| method.sig.fn_token.span().start().line),
                        function_name: name.clone(),
                        description: format!(
                            "Method `{}` replaces the contract WASM with \
                             `deployer().update_current_contract_wasm(..)` without a valid \
                             `require_auth` before it, so anyone can swap the contract's code",
                            name
                        ),
                        rule_url: Some(
                            "https://github.com/SorobanGuard/Guard-CLI/blob/main/docs/checks.md#unprotected-upgrade-high"
                                .to_string(),
                        ),
                        suggestion: Some(
                            "Load the admin from storage and call `admin.require_auth()` before \
                             `update_current_contract_wasm`."
                                .to_string(),
                        ),
                    });
                }
            }
        }
        out
    }
}

/// `….deployer().update_current_contract_wasm(..)` — the soroban-sdk upgrade API.
fn is_wasm_update_call(node: &ExprMethodCall) -> bool {
    node.method == "update_current_contract_wasm"
        && receiver_chain_contains(&node.receiver, "deployer")
}

fn first_wasm_update_line(block: &Block) -> Option<usize> {
    let mut v = WasmUpdateVisitor::default();
    visit::visit_block(&mut v, block);
    v.line
}

#[derive(Default)]
struct WasmUpdateVisitor {
    line: Option<usize>,
}

impl<'ast> Visit<'ast> for WasmUpdateVisitor {
    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        if self.line.is_none() && is_wasm_update_call(node) {
            self.line = Some(node.span().start().line);
        }
        visit::visit_expr_method_call(self, node);
    }
}

fn first_valid_auth_line(
    method: &syn::ImplItemFn,
    env_name: &str,
    _address_names: &[String],
) -> Option<usize> {
    let mut scanner = AuthScanner::new(env_name.to_string(), _address_names.to_vec());
    scanner.visit_block(&method.block);
    scanner.first_valid_auth_line
}

struct AuthScanner {
    env_name: String,
    address_names: Vec<String>,
    admin_vars: std::collections::HashSet<String>,
    first_valid_auth_line: Option<usize>,
}

impl AuthScanner {
    fn new(env_name: String, address_names: Vec<String>) -> Self {
        Self {
            env_name,
            address_names,
            admin_vars: std::collections::HashSet::new(),
            first_valid_auth_line: None,
        }
    }
}

impl<'ast> Visit<'ast> for AuthScanner {
    fn visit_stmt(&mut self, node: &'ast syn::Stmt) {
        if let syn::Stmt::Local(local) = node {
            if let Some(init) = &local.init {
                if receiver_chain_contains_storage(&init.expr)
                    && receiver_chain_contains(&init.expr, "get")
                {
                    if let Some(var_name) = pat_ident_name(&local.pat) {
                        if is_admin_var_name(&var_name) {
                            self.admin_vars.insert(var_name);
                        }
                    }
                }
            }
        }
        visit::visit_stmt(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        if self.first_valid_auth_line.is_none()
            && is_valid_auth_call(node, &self.env_name, &self.address_names, &self.admin_vars)
        {
            self.first_valid_auth_line = Some(node.span().start().line);
        }
        visit::visit_expr_method_call(self, node);
    }
}

fn is_valid_auth_call(
    method_call: &ExprMethodCall,
    env_name: &str,
    _address_names: &[String],
    admin_vars: &std::collections::HashSet<String>,
) -> bool {
    if method_call.method != "require_auth" && method_call.method != "require_auth_for_args" {
        return false;
    }
    match &*method_call.receiver {
        Expr::Path(p) => {
            if p.path.is_ident(env_name) {
                return true;
            }
            if let Some(ident) = p.path.get_ident() {
                let name = ident.to_string();
                if admin_vars.contains(&name) {
                    return true;
                }
            }
            false
        }
        _ => false,
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
    pub fn upgrade(env: Env, new_code: BytesN<32>) {
        env.deployer().update_current_contract_wasm(new_code);
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
    pub fn migrate(env: Env, new_code: BytesN<32>) {
        env.require_auth();
        env.deployer().update_current_contract_wasm(new_code);
    }
}
        "#;
        let file = parse_file(src)?;
        let check = UnprotectedUpgradeCheck;
        let findings = check.run(&file, src);
        assert_eq!(findings.len(), 0);
        Ok(())
    }

    #[test]
    fn ignores_unrelated_require_auth_on_address() -> Result<(), syn::Error> {
        let src = r#"
#[contractimpl]
impl C {
    pub fn upgrade(env: Env, to: Address, new_code: BytesN<32>) {
        to.require_auth();
        env.deployer().update_current_contract_wasm(new_code);
    }
}
        "#;
        let file = parse_file(src)?;
        let check = UnprotectedUpgradeCheck;
        let findings = check.run(&file, src);
        assert_eq!(findings.len(), 1);
        Ok(())
    }

    #[test]
    fn flags_auth_after_wasm_update() -> Result<(), syn::Error> {
        let src = r#"
#[contractimpl]
impl C {
    pub fn upgrade(env: Env, new_code: BytesN<32>) {
        env.deployer().update_current_contract_wasm(new_code);
        env.require_auth();
    }
}
        "#;
        let file = parse_file(src)?;
        let check = UnprotectedUpgradeCheck;
        let findings = check.run(&file, src);
        assert_eq!(findings.len(), 1);
        Ok(())
    }

    #[test]
    fn passes_for_read_only_getter_upgrade_pending() -> Result<(), syn::Error> {
        let src = r#"
#[contractimpl]
impl C {
    pub fn upgrade_pending(env: Env) -> bool {
        env.storage().instance().get(&symbol_short!("upgraded")).unwrap_or(false)
    }
}
        "#;
        let file = parse_file(src)?;
        let check = UnprotectedUpgradeCheck;
        let findings = check.run(&file, src);
        assert!(findings.is_empty());
        Ok(())
    }

    #[test]
    fn passes_when_stored_admin_require_auth_precedes_upgrade() -> Result<(), syn::Error> {
        let src = r#"
#[contractimpl]
impl C {
    pub fn upgrade(env: Env, new_code: BytesN<32>) {
        let admin: Address = env.storage().instance().get(&0).unwrap();
        admin.require_auth();
        env.deployer().update_current_contract_wasm(new_code);
    }
}
        "#;
        let file = parse_file(src)?;
        let check = UnprotectedUpgradeCheck;
        let findings = check.run(&file, src);
        assert!(findings.is_empty());
        Ok(())
    }

    #[test]
    fn passes_when_stored_owner_require_auth_precedes_upgrade() -> Result<(), syn::Error> {
        let src = r#"
#[contractimpl]
impl C {
    pub fn upgrade(env: Env, new_wasm: BytesN<32>) {
        let owner: Address = env.storage().instance().get(&OWNER_KEY).unwrap();
        owner.require_auth();
        env.deployer().update_current_contract_wasm(new_wasm);
    }
}
        "#;
        let file = parse_file(src)?;
        let findings = UnprotectedUpgradeCheck.run(&file, src);
        assert_eq!(findings.len(), 0);
        Ok(())
    }

    #[test]
    fn ignores_methods_inside_cfg_test() -> Result<(), syn::Error> {
        let src = r#"
#[contractimpl]
impl C {
    pub fn upgrade(env: Env, new_code: BytesN<32>) {
        env.deployer().update_current_contract_wasm(new_code);
    }
}

#[cfg(test)]
mod tests {
    use soroban_sdk::{contractimpl, Env, Bytes};

    #[contractimpl]
    impl C {
        pub fn upgrade(env: Env, new_code: BytesN<32>) {
            env.deployer().update_current_contract_wasm(new_code);
        }
    }
}
        "#;
        let file = parse_file(src)?;
        let check = UnprotectedUpgradeCheck;
        let findings = check.run(&file, src);
        assert_eq!(findings.len(), 1);
        Ok(())
    }

    /// #1061: the upgrade is found in any exported method, whatever its name.
    #[test]
    fn flags_wasm_update_in_any_exported_method() -> Result<(), syn::Error> {
        let src = r#"
#[contractimpl]
impl C {
    pub fn set_code(env: Env, hash: BytesN<32>) {
        env.deployer().update_current_contract_wasm(hash);
    }

    pub fn admin_action(e: Env, hash: BytesN<32>) {
        let d = e.deployer();
        e.deployer().update_current_contract_wasm(hash.clone());
        let _ = d;
    }
}
        "#;
        let file = parse_file(src)?;
        let findings = UnprotectedUpgradeCheck.run(&file, src);
        let names: Vec<_> = findings.iter().map(|f| f.function_name.as_str()).collect();
        assert_eq!(names, ["set_code", "admin_action"]);
        Ok(())
    }

    /// #1061: a method that never replaces the WASM is not reported, and an unrelated
    /// `update_current_contract_wasm` method (not on a deployer) is ignored.
    #[test]
    fn ignores_methods_without_deployer_wasm_update() -> Result<(), syn::Error> {
        let src = r#"
#[contractimpl]
impl C {
    pub fn upgrade(env: Env, hash: BytesN<32>) {
        env.storage().instance().set(&KEY, &hash);
    }

    pub fn other(env: Env, registry: Registry, hash: BytesN<32>) {
        registry.update_current_contract_wasm(hash);
    }
}
        "#;
        let file = parse_file(src)?;
        assert!(UnprotectedUpgradeCheck.run(&file, src).is_empty());
        Ok(())
    }
}
