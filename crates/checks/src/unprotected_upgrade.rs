use crate::util::{
    contractimpl_functions_excluding_test,
    env_param_name,
    pat_ident_name,
    receiver_chain_contains,
    receiver_chain_contains_storage,
};
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::{Block, Expr, ExprMethodCall};

const CHECK_NAME: &str = "unprotected-upgrade";
const SENSITIVE_NAMES: &[&str] = &[
    "upgrade",
    "migrate",
    "set_wasm",
    "replace_wasm",
];

pub struct UnprotectedUpgradeCheck;

impl Check for UnprotectedUpgradeCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &syn::File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions_excluding_test(file) {
            let name = method.sig.ident.to_string();
            if is_sensitive_name(&name) && matches!(method.vis, syn::Visibility::Public(_)) {
                let env_name = env_param_name(&method.sig).unwrap_or_else(|| "env".to_string());
                let address_names = util::address_param_names(&method.sig);
                let sensitive_line = first_invoke_wasm_line(&method.block);
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
                            "Upgrade/migrate method `{}` lacks valid require_auth protection before the sensitive operation",
                            name
                        ),
                        rule_url: Some(
                            "https://github.com/SorobanGuard/Guard-CLI/blob/main/docs/checks.md#unprotected-upgrade-high"
                                .to_string(),
                        ),
                        suggestion: Some("Add env.require_auth() at the start".to_string()),
                    });
                }
            }
        }
        out
    }
}

fn is_sensitive_name(name: &str) -> bool {
    SENSITIVE_NAMES.contains(name)
}

fn first_invoke_wasm_line(block: &Block) -> Option<usize> {
    let mut v = InvokeWasmVisitor::default();
    visit::visit_block(&mut v, block);
    v.line
}

#[derive(Default)]
struct InvokeWasmVisitor {
    line: Option<usize>,
}

impl<'ast> Visit<'ast> for InvokeWasmVisitor {
    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        if self.line.is_none() && node.method == "invoke_wasm" {
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
            if let syn::Local(local) = local {
                if local.pat.is_ident() {
                    let ident = local.pat.as_ident().unwrap();
                    if ident == self.env_name {
                        return;
                    }
                    if self.address_names.iter().any(|&name| name == ident.to_string()) {
                        return;
                    }
                    if let Some(name) = ident.to_string().strip_prefix("admin_") {
                        self.admin_vars.insert(name.to_string());
                    }
                }
            }
        }
        if let syn::Stmt::Expr(expr) = node {
            if let Expr::MethodCall(m, _, _) = expr.as_ref() {
                if m.method == "require_auth" || m.method == "require_auth_for_args" {
                    self.first_valid_auth_line = Some(m.span().start().line);
                    return;
                }
            }
        }
        visit::visit_stmt(self, node);
    }
}