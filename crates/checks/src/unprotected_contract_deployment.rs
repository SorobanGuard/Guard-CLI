use crate::util::{
    is_admin_var_name,
    self, contractimpl_functions_excluding_test, env_param_name, pat_ident_name,
    receiver_chain_contains, receiver_chain_contains_storage,
};
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall};

const CHECK_NAME: &str = "unprotected-contract-deployment";

pub struct UnprotectedContractDeploymentCheck;

impl Check for UnprotectedContractDeploymentCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &syn::File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions_excluding_test(file) {
            if matches!(method.vis, syn::Visibility::Public(_)) {
                let (has_deployer, line) = has_deployer_call(&method.block);
                if has_deployer {
                    let env_name =
                        env_param_name(&method.sig).unwrap_or_else(|| "env".to_string());
                    let address_names = util::address_param_names(&method.sig);
                    let auth_line = first_valid_auth_line(method, &env_name, &address_names);

                    let unprotected = match auth_line {
                        Some(auth) => auth >= line,
                        None => true,
                    };

                    if unprotected {
                        out.push(Finding {
                            check_name: CHECK_NAME.to_string(),
                            severity: Severity::High,
                            file_path: String::new(),
                            line,
                            function_name: method.sig.ident.to_string(),
                            description:
                                "Contract deployment call lacks valid require_auth protection"
                                    .to_string(),
                            rule_url: Some(
                                "https://github.com/SorobanGuard/Guard-CLI/blob/main/docs/checks.md#unprotected-contract-deployment-high"
                                    .to_string(),
                            ),
                            suggestion: Some(
                                "Add env.require_auth() before deployment operations"
                                    .to_string(),
                            ),
                        });
                    }
                }
            }
        }
        out
    }
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
        if is_deployment_call(node) {
            self.found_deployer = true;
            self.line = node.span().start().line;
        }
        visit::visit_expr_method_call(self, node);
    }
}

/// Returns true when `node` is a real contract-creation call, i.e. the
/// outermost method is `deploy` / `deploy_v2` and its receiver chain goes
/// through `with_current_contract(..)` or `with_address(..)`.
///
/// Read-only helpers (`deployed_address`), wasm uploads
/// (`upload_contract_wasm`) and upgrades (`update_current_contract_wasm`)
/// are intentionally not matched here.
fn is_deployment_call(node: &ExprMethodCall) -> bool {
    if node.method != "deploy" && node.method != "deploy_v2" {
        return false;
    }
    receiver_chain_contains(&node.receiver, "with_current_contract")
        || receiver_chain_contains(&node.receiver, "with_address")
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
    fn does_not_flag_upload_contract_wasm() -> Result<(), syn::Error> {
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
        assert!(findings.is_empty());
        Ok(())
    }

    #[test]
    fn does_not_flag_deployed_address() -> Result<(), syn::Error> {
        let src = r#"
#[contractimpl]
impl C {
    pub fn address(env: Env, salt: BytesN<32>) -> Address {
        env.deployer().with_current_contract(salt).deployed_address()
    }
}
        "#;
        let file = parse_file(src)?;
        let check = UnprotectedContractDeploymentCheck;
        let findings = check.run(&file, src);
        assert!(findings.is_empty());
        Ok(())
    }

    #[test]
    fn does_not_flag_update_current_contract_wasm() -> Result<(), syn::Error> {
        let src = r#"
#[contractimpl]
impl C {
    pub fn upgrade(env: Env, hash: BytesN<32>) {
        env.deployer().update_current_contract_wasm(hash);
    }
}
        "#;
        let file = parse_file(src)?;
        let check = UnprotectedContractDeploymentCheck;
        let findings = check.run(&file, src);
        assert!(findings.is_empty());
        Ok(())
    }

    #[test]
    fn flags_unprotected_deploy_v2() -> Result<(), syn::Error> {
        let src = r#"
#[contractimpl]
impl C {
    pub fn deploy(env: Env, salt: BytesN<32>, wasm: Bytes, init: Val) {
        env.deployer().with_current_contract(salt).deploy_v2(wasm, init);
    }
}
        "#;
        let file = parse_file(src)?;
        let check = UnprotectedContractDeploymentCheck;
        let findings = check.run(&file, src);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].function_name, "deploy");
        assert_eq!(findings[0].line, 5);
        Ok(())
    }

    #[test]
    fn passes_when_env_require_auth_precedes_deploy_v2() -> Result<(), syn::Error> {
        let src = r#"
#[contractimpl]
impl C {
    pub fn deploy(env: Env, salt: BytesN<32>, wasm: Bytes, init: Val) {
        env.require_auth();
        env.deployer().with_current_contract(salt).deploy_v2(wasm, init);
    }
}
        "#;
        let file = parse_file(src)?;
        let check = UnprotectedContractDeploymentCheck;
        let findings = check.run(&file, src);
        assert!(findings.is_empty());
        Ok(())
    }

    #[test]
    fn flags_auth_after_deploy() -> Result<(), syn::Error> {
        let src = r#"
#[contractimpl]
impl C {
    pub fn deploy(env: Env, salt: BytesN<32>, wasm: Bytes, init: Val) {
        env.deployer().with_current_contract(salt).deploy_v2(wasm, init);
        env.require_auth();
    }
}
        "#;
        let file = parse_file(src)?;
        let check = UnprotectedContractDeploymentCheck;
        let findings = check.run(&file, src);
        assert_eq!(findings.len(), 1);
        Ok(())
    }

    #[test]
    fn passes_when_stored_admin_require_auth_precedes_deploy() -> Result<(), syn::Error> {
        let src = r#"
#[contractimpl]
impl C {
    pub fn deploy(env: Env, salt: BytesN<32>, wasm: Bytes, init: Val) {
        let admin: Address = env.storage().instance().get(&0).unwrap();
        admin.require_auth();
        env.deployer().with_current_contract(salt).deploy_v2(wasm, init);
    }
}
        "#;
        let file = parse_file(src)?;
        let check = UnprotectedContractDeploymentCheck;
        let findings = check.run(&file, src);
        assert!(findings.is_empty());
        Ok(())
    }

    #[test]
    fn ignores_methods_inside_cfg_test() -> Result<(), syn::Error> {
        let src = r#"
#[contractimpl]
impl C {
    pub fn deploy(env: Env, salt: BytesN<32>, wasm: Bytes, init: Val) {
        env.deployer().with_current_contract(salt).deploy_v2(wasm, init);
    }
}

#[cfg(test)]
mod tests {
    use soroban_sdk::{contractimpl, Env, Bytes, BytesN, Val};

    #[contractimpl]
    impl C {
        pub fn deploy(env: Env, salt: BytesN<32>, wasm: Bytes, init: Val) {
            env.deployer().with_current_contract(salt).deploy_v2(wasm, init);
        }
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
