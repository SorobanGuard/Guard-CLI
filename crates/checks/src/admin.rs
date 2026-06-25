//! Privileged-style entrypoints without any `require_auth` / `require_auth_for_args` call.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Block, Expr, ExprIf, ExprMethodCall, File, Visibility};

const CHECK_NAME: &str = "unprotected-admin";

/// Known high-risk entrypoint names (exact match, snake_case).
const SENSITIVE_NAMES: &[&str] = &[
    "set_owner",
    "set_admin",
    "transfer_ownership",
    "pause",
    "unpause",
    "migrate",
    "upgrade",
    "emergency_pause",
    "emergency_stop",
    "grant_role",
    "revoke_role",
    "withdraw_fees",
    "set_fee",
    "set_fees",
    "renounce_ownership",
    "destroy",
    "kill",
];

/// `pub` methods whose name matches a sensitive admin pattern and whose body never calls
/// `require_auth` or `require_auth_for_args` (any receiver).
pub struct UnprotectedAdminCheck;

impl Check for UnprotectedAdminCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            if !matches!(method.vis, Visibility::Public(_)) {
                continue;
            }
            let name = method.sig.ident.to_string();
            if !SENSITIVE_NAMES.contains(&name.as_str()) {
                continue;
            }
            if body_has_auth_gate(&method.block) {
                continue;
            }
            let line = method.sig.fn_token.span().start().line;
            out.push(Finding {
                check_name: CHECK_NAME.to_string(),
                severity: Severity::High,
                file_path: String::new(),
                line,
                function_name: name.clone(),
                description: format!(
                    "Public method `{name}` matches a privileged admin pattern but has no \
                     `require_auth()` or `require_auth_for_args()` call in its body. \
                     Anyone may invoke this entrypoint."
                ),
            });
        }
        out
    }
}

fn receiver_chain_contains_storage(expr: &Expr) -> bool {
    match expr {
        Expr::MethodCall(m) => {
            if m.method == "storage" {
                return true;
            }
            receiver_chain_contains_storage(&m.receiver)
        }
        Expr::Field(f) => receiver_chain_contains_storage(&f.base),
        _ => false,
    }
}

fn is_storage_read_call(m: &ExprMethodCall) -> bool {
    m.method == "get" && receiver_chain_contains_storage(&m.receiver)
}

fn body_has_auth_gate(block: &Block) -> bool {
    let mut v = AuthGateScan::default();
    v.visit_block(block);
    v.found || v.storage_read_and_conditional
}

#[derive(Default)]
struct AuthGateScan {
    found: bool,
    storage_read: bool,
    storage_read_and_conditional: bool,
}

impl<'ast> Visit<'ast> for AuthGateScan {
    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        let m = i.method.to_string();
        if matches!(m.as_str(), "require_auth" | "require_auth_for_args") {
            self.found = true;
        }
        if is_storage_read_call(i) {
            self.storage_read = true;
        }
        visit::visit_expr_method_call(self, i);
    }

    fn visit_expr_if(&mut self, i: &'ast ExprIf) {
        let had_storage_read_before = self.storage_read;
        visit::visit_expr_if(self, i);
        if had_storage_read_before {
            self.storage_read_and_conditional = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Check;
    use syn::parse_file;

    #[test]
    fn flags_set_owner_without_auth() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Address, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn set_owner(env: Env, owner: Address) {
        let _ = (env, owner);
    }
}
"#,
        )?;
        let hits = UnprotectedAdminCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::High);
        assert_eq!(hits[0].function_name, "set_owner");
        Ok(())
    }

    #[test]
    fn passes_when_require_auth_present() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Address, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn set_owner(env: Env, owner: Address) {
        env.require_auth();
        let _ = owner;
    }
}
"#,
        )?;
        let hits = UnprotectedAdminCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn passes_when_require_auth_for_args_present() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Address, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn set_owner(env: Env, owner: Address) {
        env.require_auth_for_args((owner,));
    }
}
"#,
        )?;
        let hits = UnprotectedAdminCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn ignores_private_set_owner() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Address, Env};

pub struct C;

#[contractimpl]
impl C {
    fn set_owner(env: Env, owner: Address) {
        let _ = (env, owner);
    }
}
"#,
        )?;
        let hits = UnprotectedAdminCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn ignores_unrelated_public_fn() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn hello(env: Env) {
        let _ = env;
    }
}
"#,
        )?;
        let hits = UnprotectedAdminCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }
}
