//! Missing `env.require_auth()` before storage writes in `#[contractimpl]` methods.

use crate::util::{
    address_param_names, contractimpl_functions_excluding_test, env_param_name,
    is_storage_mutation_call, receiver_is_auth_gate, type_is_address,
};
use crate::{Check, Finding, Severity};
use std::collections::HashSet;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Block, Expr, ExprMethodCall, File, Pat, Stmt};

const CHECK_NAME: &str = "missing-require-auth";

/// Flags `#[contractimpl]` methods that write via `env.storage()` without calling
/// `<env_param>.require_auth()` where `<env_param>` is the actual name of the `Env` parameter.
pub struct MissingRequireAuthCheck;

impl Check for MissingRequireAuthCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions_excluding_test(file) {
            let env_param = env_param_name(&method.sig);
            let address_params = address_param_names(&method.sig);
            let mut scan = FuncBodyScan::new(env_param.as_deref(), address_params);
            scan.visit_block(&method.block);
            if !scan.storage_write || scan.env_require_auth || scan.auth_helper_called {
                continue;
            }
            let line = first_storage_write_line(&method.block)
                .unwrap_or_else(|| method.sig.ident.span().start().line);
            let fn_name = method.sig.ident.to_string();
            let env_name = env_param.as_deref().unwrap_or("env");
            out.push(Finding {
                check_name: CHECK_NAME.to_string(),
                severity: Severity::High,
                file_path: String::new(),
                line,
                function_name: fn_name.clone(),
                description: format!(
                    "Method `{fn_name}` writes to `{env_name}.storage()` but does not call \
                     `{env_name}.require_auth()`. Callers may mutate contract state without proving \
                     they are authorized."
                ),
                rule_url: Some(
                    "https://github.com/SorobanGuard/Guard-CLI/blob/main/docs/checks.md#missing-require-auth-high"
                        .to_string(),
                ),
                suggestion: Some(format!(
                    "Add `{env_name}.require_auth();` as the first statement in the function body."
                )),
            column: None,
            end_line: None,
            end_column: None,
            });
        }
        out
    }
}

fn is_env_require_auth(
    m: &ExprMethodCall,
    env_name: &str,
    address_names: &[String],
    address_locals: &HashSet<String>,
) -> bool {
    if m.method != "require_auth" && m.method != "require_auth_for_args" {
        return false;
    }
    receiver_is_auth_gate(&m.receiver, env_name, address_names, address_locals)
}

fn is_auth_helper_method_call(
    m: &ExprMethodCall,
    env_name: &str,
    address_names: &[String],
    address_locals: &HashSet<String>,
) -> bool {
    let name = m.method.to_string();
    // Require an exact helper name (not merely a name fragment) so methods like
    // `check_authorization_table()` are not mistaken for an auth call.
    name == "assert_auth"
        || name == "check_auth"
        || (name.starts_with("require_auth")
            && !is_env_require_auth(m, env_name, address_names, address_locals)
            && !matches!(&*m.receiver, Expr::Path(_)))
}

/// Name bound by a `let` pattern whose (possibly annotated) type is `Address`.
fn address_local_binding(pat: &Pat) -> Option<String> {
    match pat {
        Pat::Type(pt) => {
            if type_is_address(&pt.ty) {
                address_local_binding(&pt.pat)
            } else {
                None
            }
        }
        Pat::Ident(pi) => Some(pi.ident.to_string()),
        _ => None,
    }
}

struct FuncBodyScan {
    env_name: String,
    address_names: Vec<String>,
    address_locals: HashSet<String>,
    storage_write: bool,
    env_require_auth: bool,
    auth_helper_called: bool,
}

impl FuncBodyScan {
    fn new(env_name: Option<&str>, address_names: Vec<String>) -> Self {
        Self {
            env_name: env_name.unwrap_or("env").to_string(),
            address_names,
            address_locals: HashSet::new(),
            storage_write: false,
            env_require_auth: false,
            auth_helper_called: false,
        }
    }
}

impl<'ast> Visit<'ast> for FuncBodyScan {
    fn visit_stmt(&mut self, stmt: &'ast Stmt) {
        if let Stmt::Local(local) = stmt {
            if let (Some(name), Some(_init)) = (address_local_binding(&local.pat), &local.init) {
                self.address_locals.insert(name);
            }
        }
        visit::visit_stmt(self, stmt);
    }

    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        if is_storage_mutation_call(i) {
            self.storage_write = true;
        }
        if is_env_require_auth(i, &self.env_name, &self.address_names, &self.address_locals) {
            self.env_require_auth = true;
        }
        if is_auth_helper_method_call(i, &self.env_name, &self.address_names, &self.address_locals)
        {
            self.auth_helper_called = true;
        }
        visit::visit_expr_method_call(self, i);
    }
}

struct FirstStorageWrite {
    line: Option<usize>,
}

impl<'ast> Visit<'ast> for FirstStorageWrite {
    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        if self.line.is_none() && is_storage_mutation_call(i) {
            self.line = Some(i.span().start().line);
        }
        visit::visit_expr_method_call(self, i);
    }
}

fn first_storage_write_line(block: &Block) -> Option<usize> {
    let mut v = FirstStorageWrite { line: None };
    v.visit_block(block);
    v.line
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Check;
    use syn::parse_file;

    fn run_on_src(src: &str) -> Result<Vec<Finding>, syn::Error> {
        let file = parse_file(src)?;
        Ok(MissingRequireAuthCheck.run(&file, src))
    }

    #[test]
    fn flags_persistent_set_without_env_require_auth() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Env, Symbol};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn set_balance(env: Env, amount: i128) {
        env.storage().persistent().set(&Symbol::new(&env, "bal"), &amount);
    }
}
"#,
        )?;
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].function_name, "set_balance");
        assert_eq!(hits[0].severity, Severity::High);
        assert_eq!(hits[0].check_name, CHECK_NAME);
        Ok(())
    }

    #[test]
    fn passes_when_env_require_auth_present() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Address, Env, Symbol};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn set_balance(env: Env, user: Address, amount: i128) {
        env.require_auth();
        env.storage().persistent().set(&Symbol::new(&env, "bal"), &amount);
    }
}
"#,
        )?;
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn passes_when_only_address_require_auth() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Address, Env, Symbol};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn set_balance(env: Env, user: Address, amount: i128) {
        user.require_auth();
        env.storage().persistent().set(&Symbol::new(&env, "bal"), &amount);
    }
}
"#,
        )?;
        assert!(
            hits.is_empty(),
            "`user.require_auth()` should satisfy the check when user is an Address"
        );
        Ok(())
    }

    #[test]
    fn passes_when_from_address_require_auth() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Address, Env, Symbol};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn set_balance(env: Env, user: Address, amount: i128) {
        let from: Address = user;
        from.require_auth();
        env.storage().persistent().set(&Symbol::new(&env, "bal"), &amount);
    }
}
"#,
        )?;
        assert!(hits.is_empty());
        Ok(())
    }
}
