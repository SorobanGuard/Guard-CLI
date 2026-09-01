//! Missing `env.require_auth()` before storage writes in `#[contractimpl]` methods.

use crate::util::{
    contractimpl_functions_excluding_test, is_storage_mutation_call, receiver_is_auth_gate,
};
use crate::{Check, Finding, Severity};
use std::collections::HashSet;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Block, Expr, ExprMethodCall, File, FnArg, Pat, Stmt, Type};

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
            });
        }
        out
    }
}

/// Returns the name of the first parameter whose type is `Env` (or `soroban_sdk::Env`).
fn env_param_name(sig: &syn::Signature) -> Option<String> {
    for arg in &sig.inputs {
        let FnArg::Typed(pat_type) = arg else {
            continue;
        };
        if !type_is_env(&pat_type.ty) {
            continue;
        }
        if let Pat::Ident(ident) = &*pat_type.pat {
            return Some(ident.ident.to_string());
        }
    }
    None
}

fn type_is_env(ty: &Type) -> bool {
    let Type::Path(tp) = ty else {
        return false;
    };
    tp.path.segments.last().is_some_and(|s| s.ident == "Env")
}

fn type_is_address(ty: &Type) -> bool {
    let Type::Path(tp) = ty else {
        return false;
    };
    tp.path.segments.last().is_some_and(|s| s.ident == "Address")
}

fn address_param_names(sig: &syn::Signature) -> Vec<String> {
    let mut names = Vec::new();
    for arg in &sig.inputs {
        let FnArg::Typed(pat_type) = arg else {
            continue;
        };
        if type_is_address(&pat_type.ty) {
            if let Pat::Ident(ident) = &*pat_type.pat {
                names.push(ident.ident.to_string());
            }
        }
    }
    names
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
    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        from.require_auth();
        env.storage().persistent().set(&Symbol::new(&env, "bal"), &amount);
    }
}
"#,
        )?;
        assert!(
            hits.is_empty(),
            "`from.require_auth()` should satisfy the check when from is an Address"
        );
        Ok(())
    }

    #[test]
    fn passes_when_env_require_auth_for_args_only() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Address, Env, Symbol};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn set_balance(env: Env, user: Address, amount: i128) {
        env.require_auth_for_args((user, amount));
        env.storage().persistent().set(&Symbol::new(&env, "bal"), &amount);
    }
}
"#,
        )?;
        assert!(
            hits.is_empty(),
            "require_auth_for_args should be a valid auth gate"
        );
        Ok(())
    }

    #[test]
    fn recognizes_soroban_sdk_contractimpl_path() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Env, Symbol};

pub struct Contract;

#[soroban_sdk::contractimpl]
impl Contract {
    pub fn bad(env: Env) {
        env.storage().instance().set(&Symbol::new(&env, "k"), &0u32);
    }
}
"#,
        )?;
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].function_name, "bad");
        Ok(())
    }

    #[test]
    fn ignores_non_contractimpl_impl() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{Env, Symbol};

pub struct Contract;

impl Contract {
    pub fn helper(env: Env) {
        env.storage().persistent().set(&Symbol::new(&env, "k"), &0u32);
    }
}
"#,
        )?;
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn flags_when_env_param_renamed_and_no_auth() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Env, Symbol};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn set_balance(e: Env, amount: i128) {
        e.storage().persistent().set(&Symbol::new(&e, "bal"), &amount);
    }
}
"#,
        )?;
        assert_eq!(hits.len(), 1, "renamed param `e` should still be flagged");
        Ok(())
    }

    #[test]
    fn passes_when_renamed_env_param_has_require_auth() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Env, Symbol};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn set_balance(e: Env, amount: i128) {
        e.require_auth();
        e.storage().persistent().set(&Symbol::new(&e, "bal"), &amount);
    }
}
"#,
        )?;
        assert!(hits.is_empty(), "e.require_auth() should satisfy the check");
        Ok(())
    }

    #[test]
    fn helper_name_fragment_does_not_suppress_finding() -> Result<(), syn::Error> {
        // #512: `self.check_authorization_table()` merely starts with `check_auth`
        // but is not an auth call, so the missing-require-auth finding must still fire.
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Env, Symbol};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn set_config(env: Env, v: u32) {
        self.check_authorization_table();
        env.storage().instance().set(&Symbol::new(&env, "cfg"), &v);
    }
}
"#,
        )?;
        assert_eq!(
            hits.len(),
            1,
            "`self.check_authorization_table()` must not suppress the finding"
        );
        Ok(())
    }

    #[test]
    fn passes_when_self_field_require_auth() -> Result<(), syn::Error> {
        // #514: `self.admin.require_auth()` has an `Expr::Field` receiver.
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Env, Symbol};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn set_config(env: Env, v: u32) {
        self.admin.require_auth();
        env.storage().instance().set(&Symbol::new(&env, "cfg"), &v);
    }
}
"#,
        )?;
        assert!(
            hits.is_empty(),
            "`self.admin.require_auth()` should satisfy the check"
        );
        Ok(())
    }

    #[test]
    fn passes_when_cloned_address_require_auth() -> Result<(), syn::Error> {
        // #514: `admin.clone().require_auth()` has an `Expr::MethodCall` receiver.
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Address, Env, Symbol};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn set_config(env: Env, admin: Address, v: u32) {
        admin.clone().require_auth();
        env.storage().instance().set(&Symbol::new(&env, "cfg"), &v);
    }
}
"#,
        )?;
        assert!(
            hits.is_empty(),
            "`admin.clone().require_auth()` should satisfy the check"
        );
        Ok(())
    }

    #[test]
    fn passes_when_local_address_require_auth() -> Result<(), syn::Error> {
        // #514: a function-local binding of type `Address` is a valid auth gate.
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Address, Env, Symbol};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn set_config(env: Env, v: u32) {
        let admin: Address = env.storage().instance().get(&Symbol::new(&env, "admin")).unwrap();
        admin.require_auth();
        env.storage().instance().set(&Symbol::new(&env, "cfg"), &v);
    }
}
"#,
        )?;
        assert!(
            hits.is_empty(),
            "`let admin: Address = ...; admin.require_auth()` should satisfy the check"
        );
        Ok(())
    }

    #[test]
    fn passes_when_only_storage_call_is_extend_ttl() -> Result<(), syn::Error> {
        // #401: extending a ledger entry's TTL is not a state mutation and must not be
        // flagged as requiring prior authorization.
        let hits = run_on_src(
            r#"
use soroban_sdk::Env;

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn bump_balance(env: Env, key: u32) {
        env.storage().persistent().extend_ttl(&key, 100, 1000);
    }
}
"#,
        )?;
        assert!(
            hits.is_empty(),
            "`extend_ttl` alone must not be treated as a storage mutation requiring auth"
        );
        Ok(())
    }
}
