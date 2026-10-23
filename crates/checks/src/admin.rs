//! Privileged-style entrypoints without any `require_auth` / `require_auth_for_args` call.

use crate::util::{
    contractimpl_functions_excluding_test, is_admin_var_name, pat_ident_name,
    receiver_chain_contains, receiver_chain_contains_storage,
};
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

/// Prefixes that mark a function as sensitive (e.g., `set_admin_fee`, `pause_withdrawals`,
/// `emergency_shutdown`).
const SENSITIVE_PREFIXES: &[&str] = &["set_admin", "pause_", "emergency_"];

/// `pub` methods whose name matches a sensitive admin pattern and whose body never calls
/// `require_auth` or `require_auth_for_args` (any receiver).
pub struct UnprotectedAdminCheck {
    extra_names: Vec<String>,
}

impl UnprotectedAdminCheck {
    pub fn new() -> Self {
        Self {
            extra_names: Vec::new(),
        }
    }

    /// Extend the built-in `SENSITIVE_NAMES` list with project-specific names.
    pub fn with_extra_names(extra: Vec<String>) -> Self {
        Self { extra_names: extra }
    }
}

impl Default for UnprotectedAdminCheck {
    fn default() -> Self {
        Self::new()
    }
}

impl Check for UnprotectedAdminCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions_excluding_test(file) {
            if !matches!(method.vis, Visibility::Public(_)) {
                continue;
            }
            let name = method.sig.ident.to_string();
            if !is_sensitive_name(&name, &self.extra_names) {
                continue;
            }
            let addr_names = crate::util::address_param_names(&method.sig);
            let env_name = crate::util::env_param_name(&method.sig);
            if body_has_auth_gate(&method.block, env_name.as_deref(), &addr_names) {
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
                rule_url: Some(
                    "https://github.com/SorobanGuard/Guard-CLI/blob/main/docs/checks.md#unprotected-admin-high"
                        .to_string(),
                ),
                suggestion: Some(
                    "Add `env.require_auth();` or verify the caller against a stored admin address."
                        .to_string(),
                ),
            });
        }
        out
    }
}

fn is_sensitive_name(name: &str, extra: &[String]) -> bool {
    SENSITIVE_NAMES.contains(&name)
        || SENSITIVE_PREFIXES
            .iter()
            .any(|prefix| name.starts_with(prefix))
        || extra.iter().any(|e| e == name)
}

fn body_has_auth_gate(block: &Block, env_name: Option<&str>, address_names: &[String]) -> bool {
    let mut v = AuthGateScan::new(env_name.map(str::to_string), address_names.to_vec());
    v.visit_block(block);
    v.found || v.storage_read_and_conditional
}

fn block_diverges(block: &Block) -> bool {
    block.stmts.iter().any(|stmt| match stmt {
        syn::Stmt::Expr(expr, _) => expr_diverges(expr),
        syn::Stmt::Macro(stmt) => stmt.mac.path.is_ident("panic"),
        _ => false,
    })
}

fn expr_diverges(expr: &Expr) -> bool {
    match expr {
        Expr::Return(_) => true,
        Expr::Macro(expr) => expr.mac.path.is_ident("panic"),
        Expr::MethodCall(expr) => {
            matches!(
                expr.method.to_string().as_str(),
                "require_auth" | "require_auth_for_args"
            )
        }
        Expr::Block(expr) => block_diverges(&expr.block),
        Expr::If(expr) => {
            block_diverges(&expr.then_branch)
                && expr
                    .else_branch
                    .as_ref()
                    .is_some_and(|(_, branch)| expr_diverges(branch))
        }
        _ => false,
    }
}

#[derive(Default)]
struct AuthGateScan {
    found: bool,
    storage_read_vars: std::collections::HashSet<String>,
    storage_read_and_conditional: bool,
    address_names: Vec<String>,
    env_name: Option<String>,
}

impl AuthGateScan {
    fn new(env_name: Option<String>, address_names: Vec<String>) -> Self {
        Self {
            found: false,
            env_name,
            storage_read_vars: std::collections::HashSet::new(),
            storage_read_and_conditional: false,
            address_names,
        }
    }
}

impl AuthGateScan {
    /// Only a `require_auth` on the admin/caller actually gates the privileged action:
    /// the `Env` parameter, a binding read from storage under an admin-like name, an
    /// admin-like `Address` parameter/local, or a storage read chain used directly.
    /// An auth call on an unrelated address (e.g. a target user) does not count.
    fn receiver_is_privileged(&self, receiver: &syn::Expr) -> bool {
        match receiver {
            syn::Expr::Path(p) => {
                let Some(ident) = p.path.get_ident().map(|i| i.to_string()) else {
                    return false;
                };
                self.env_name.as_deref() == Some(ident.as_str())
                    || self.storage_read_vars.contains(&ident)
                    || is_privileged_name(&ident)
            }
            syn::Expr::MethodCall(mc) => {
                (receiver_chain_contains_storage(receiver)
                    && receiver_chain_contains(receiver, "get"))
                    || self.receiver_is_privileged(&mc.receiver)
            }
            syn::Expr::Reference(r) => self.receiver_is_privileged(&r.expr),
            syn::Expr::Paren(p) => self.receiver_is_privileged(&p.expr),
            syn::Expr::Field(f) => match &f.member {
                syn::Member::Named(n) => is_privileged_name(&n.to_string()),
                syn::Member::Unnamed(_) => false,
            },
            _ => false,
        }
    }
}

fn is_privileged_name(name: &str) -> bool {
    let lower = name.to_lowercase();
    [
        "admin",
        "authority",
        "owner",
        "caller",
        "invoker",
        "operator",
        "governance",
    ]
    .iter()
    .any(|k| lower.contains(k))
}

impl<'ast> Visit<'ast> for AuthGateScan {
    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        let m = i.method.to_string();
        if matches!(m.as_str(), "require_auth" | "require_auth_for_args")
            && self.receiver_is_privileged(&i.receiver)
        {
            self.found = true;
        }
        visit::visit_expr_method_call(self, i);
    }

    fn visit_stmt(&mut self, node: &'ast syn::Stmt) {
        if let syn::Stmt::Local(local) = node {
            if let Some(init) = &local.init {
                if receiver_chain_contains_storage(&init.expr)
                    && receiver_chain_contains(&init.expr, "get")
                {
                    if let Some(var_name) = pat_ident_name(&local.pat) {
                        if is_admin_var_name(&var_name) {
                            self.storage_read_vars.insert(var_name);
                        }
                    }
                }
            }
        }
        visit::visit_stmt(self, node);
    }

    fn visit_expr_if(&mut self, i: &'ast ExprIf) {
        let had_tracked_var = !self.storage_read_vars.is_empty();
        visit::visit_expr_if(self, i);
        let branch_diverges = block_diverges(&i.then_branch)
            || i
                .else_branch
                .as_ref()
                .is_some_and(|(_, branch)| expr_diverges(branch));
        if had_tracked_var && branch_diverges && !self.storage_read_and_conditional {
            let all_names: Vec<String> = self
                .storage_read_vars
                .iter()
                .cloned()
                .chain(self.address_names.clone())
                .collect();
            let name_set: std::collections::HashSet<String> = all_names.iter().cloned().collect();
            if expr_references_any(&i.cond, &name_set) {
                self.storage_read_and_conditional = true;
            }
        }
    }
}

fn expr_references_any(expr: &syn::Expr, names: &std::collections::HashSet<String>) -> bool {
    struct RefVisitor<'a> {
        names: &'a std::collections::HashSet<String>,
        found: bool,
    }
    impl<'a, 'ast> Visit<'ast> for RefVisitor<'a> {
        fn visit_expr_path(&mut self, node: &'ast syn::ExprPath) {
            if node
                .path
                .segments
                .last()
                .is_some_and(|s| self.names.contains(&s.ident.to_string()))
            {
                self.found = true;
            }
            visit::visit_expr_path(self, node);
        }
    }
    let mut v = RefVisitor {
        names,
        found: false,
    };
    visit::visit_expr(&mut v, expr);
    v.found
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
        let hits = UnprotectedAdminCheck::new().run(&file, "");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::High);
        assert_eq!(hits[0].function_name, "set_owner");
        Ok(())
    }

    #[test]
    fn flags_require_auth_on_unrelated_address() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Address, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn pause(env: Env, user: Address) {
        user.require_auth();
        let _ = env;
    }
}
"#,
        )?;
        let hits = UnprotectedAdminCheck::new().run(&file, "");
        assert_eq!(hits.len(), 1);
        Ok(())
    }

    #[test]
    fn passes_when_stored_admin_require_auth() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Address, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn pause(env: Env) {
        let admin: Address = env.storage().instance().get(&KEY).unwrap();
        admin.require_auth();
    }
}
"#,
        )?;
        let hits = UnprotectedAdminCheck::new().run(&file, "");
        assert!(hits.is_empty());
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
        let hits = UnprotectedAdminCheck::new().run(&file, "");
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
        let hits = UnprotectedAdminCheck::new().run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn flags_storage_admin_write_after_noop_if() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Address, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn set_admin(env: Env, new_admin: Address) {
        let admin: Address = env.storage().instance().get(&ADMIN_KEY).unwrap();
        if admin != new_admin { /* no-op */ }
        env.storage().instance().set(&ADMIN_KEY, &new_admin);
    }
}
"#,
        )?;
        let hits = UnprotectedAdminCheck::new().run(&file, "");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].function_name, "set_admin");
        Ok(())
    }

    #[test]
    fn passes_when_storage_admin_if_branch_diverges() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Address, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn set_admin(env: Env, admin: Address, caller: Address) {
        let stored: Address = env.storage().instance().get(&ADMIN_KEY).unwrap();
        if caller != stored {
            return;
            let _ = admin;
        }
    }

    pub fn set_owner(env: Env, owner: Address, caller: Address) {
        let stored: Address = env.storage().instance().get(&OWNER_KEY).unwrap();
        if caller == stored {
            let _ = owner;
        } else {
            panic!("unauthorized");
        }
    }
}
"#,
        )?;
        let hits = UnprotectedAdminCheck::new().run(&file, "");
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
        let hits = UnprotectedAdminCheck::new().run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn flags_prefix_match_set_admin_fee() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn set_admin_fee(env: Env, fee: i128) {
        let _ = (env, fee);
    }
}
"#,
        )?;
        let hits = UnprotectedAdminCheck::new().run(&file, "");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].function_name, "set_admin_fee");
        Ok(())
    }

    #[test]
    fn flags_prefix_match_pause_withdrawals() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn pause_withdrawals(env: Env) {
        let _ = env;
    }
}
"#,
        )?;
        let hits = UnprotectedAdminCheck::new().run(&file, "");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].function_name, "pause_withdrawals");
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
        let hits = UnprotectedAdminCheck::new().run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn unrelated_if_after_storage_read_does_not_suppress() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Address, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn set_admin(env: Env, new_admin: Address) {
        let x = env.storage().instance().get(&1).unwrap();
        if x > 0 { let _ = env; }
        env.storage().instance().set(&2, &new_admin);
    }
}
"#,
        )?;
        let hits = UnprotectedAdminCheck::new().run(&file, "");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].function_name, "set_admin");
        Ok(())
    }

    #[test]
    fn storage_read_compare_in_if_is_recognized_as_gate() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Address, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn set_admin(env: Env, new_admin: Address) {
        let stored_admin: Address = env.storage().instance().get(&1).unwrap();
        if stored_admin == new_admin { panic!(); }
        env.storage().instance().set(&2, &new_admin);
    }
}
"#,
        )?;
        let hits = UnprotectedAdminCheck::new().run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }
}
