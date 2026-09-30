//! Cross-contract calls where the callee address originates from storage (delegate-call risk).
//!
//! If an attacker can corrupt contract storage (e.g., via a malicious upgrade or temporary
//! storage), `env.invoke_contract` with a storage-derived address could be redirected to a
//! contract the attacker controls.
//!
//! Detection: within a single `#[contractimpl]` method, if a storage read expression
//! (containing `.storage()`) exists alongside an `env.invoke_contract` / `env.try_call`,
//! the method is flagged. This catches both inlined and variable-mediated patterns.

use crate::util::{contractimpl_functions_excluding_test, receiver_chain_contains_storage};
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, File, FnArg, Pat, Signature, Type};

const CHECK_NAME: &str = "delegate-call-risk";

/// Flags `#[contractimpl]` methods that contain both a storage read (`.storage()`) and a
/// cross-contract call (`env.invoke_contract` / `env.try_call`).
pub struct DelegateCallRiskCheck;

impl Check for DelegateCallRiskCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions_excluding_test(file) {
            let fn_name = method.sig.ident.to_string();
            let mut v = DelegateVisitor {
                has_storage_read: false,
                last_invoke_contract_line: None,
                env_ident: env_param_name(&method.sig).unwrap_or_else(|| "env".to_string()),
            };
            v.visit_block(&method.block);
            if v.has_storage_read {
                if let Some(line) = v.last_invoke_contract_line {
                    out.push(Finding {
                        check_name: CHECK_NAME.to_string(),
                        severity: Severity::High,
                        file_path: String::new(),
                        line,
                        function_name: fn_name.to_string(),
                        description: format!(
                            "Method `{fn_name}` reads from storage and calls \
                             `env.invoke_contract`/`env.try_call`. If storage can be \
                             poisoned (e.g., via upgrade or temp-storage race), the call \
                             can be redirected to an attacker-controlled contract.",
                        ),
                        rule_url: Some(
                            "https://github.com/SorobanGuard/Guard-CLI/blob/main/docs/checks.md#delegate-call-risk-high"
                                .to_string(),
                        ),
                        suggestion: Some(
                            "Pass the callee address as a verified parameter or store it under \
                             an admin-controlled key; call `caller.require_auth()` before using \
                             any storage-derived address in `env.invoke_contract`."
                                .to_string(),
                        ),
                    });
                }
            }
        }
        out
    }
}

struct DelegateVisitor {
    has_storage_read: bool,
    last_invoke_contract_line: Option<usize>,
    env_ident: String,
}

impl<'ast> Visit<'ast> for DelegateVisitor {
    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        if receiver_chain_contains_storage(&i.receiver) && i.method == "get" {
            self.has_storage_read = true;
        }
        if is_invoke_or_try_call(i) && is_env_receiver(&i.receiver, &self.env_ident) {
            self.last_invoke_contract_line = Some(i.span().start().line);
        }
        visit::visit_expr_method_call(self, i);
    }

    fn visit_expr(&mut self, i: &'ast Expr) {
        if self.has_storage_read && self.last_invoke_contract_line.is_some() {
            return;
        }
        visit::visit_expr(self, i);
    }
}

fn is_invoke_or_try_call(i: &ExprMethodCall) -> bool {
    matches!(
        i.method.to_string().as_str(),
        "invoke_contract" | "try_call"
    )
}

fn is_env_receiver(expr: &Expr, env_ident: &str) -> bool {
    matches!(expr, Expr::Path(p) if p.path.is_ident(env_ident))
}

/// Finds the name bound to the `Env`-typed parameter in a method signature (e.g. `env`
/// in `fn f(env: Env, ..)` or `e` in `fn f(e: Env, ..)`), so the check follows whatever
/// the contract actually calls its `Env` parameter instead of assuming it's named `env`.
fn env_param_name(sig: &Signature) -> Option<String> {
    sig.inputs.iter().find_map(|arg| {
        let FnArg::Typed(pat_type) = arg else {
            return None;
        };
        let ty = match pat_type.ty.as_ref() {
            Type::Reference(r) => r.elem.as_ref(),
            other => other,
        };
        let Type::Path(type_path) = ty else {
            return None;
        };
        if type_path.path.segments.last()?.ident != "Env" {
            return None;
        }
        let Pat::Ident(pat_ident) = pat_type.pat.as_ref() else {
            return None;
        };
        Some(pat_ident.ident.to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Check;
    use syn::parse_file;

    #[test]
    fn flags_invoke_with_storage_address() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Address, Env, Symbol};

pub struct C;

#[contractimpl]
impl C {
    pub fn call_external(env: Env) {
        let addr: Address = env.storage().instance().get(&0).unwrap();
        env.invoke_contract(&addr, &Symbol::new(&env, "do_thing"), ());
    }
}
"#,
        )?;
        let hits = DelegateCallRiskCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::High);
        Ok(())
    }

    #[test]
    fn passes_with_hardcoded_address() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Address, Env, Symbol};

pub struct C;

#[contractimpl]
impl C {
    pub fn call_external(env: Env, to: Address) {
        env.invoke_contract(&to, &Symbol::new(&env, "do_thing"), ());
    }
}
"#,
        )?;
        let hits = DelegateCallRiskCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn passes_no_invoke_call() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn just_storage(env: Env) {
        let _ = env.storage().instance().get::<i32>(&0);
    }
}
"#,
        )?;
        let hits = DelegateCallRiskCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn flags_try_call_with_storage_address() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Address, Env, Symbol};

pub struct C;

#[contractimpl]
impl C {
    pub fn call_external(env: Env) {
        let addr: Address = env.storage().instance().get(&0).unwrap();
        let _ = env.try_call(&addr, &Symbol::new(&env, "do_thing"), ());
    }
}
"#,
        )?;
        let hits = DelegateCallRiskCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        Ok(())
    }

    #[test]
    fn passes_storage_and_no_invoke() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn just_storage(env: Env) {
        let val = env.storage().instance().get::<i32>(&0);
        let _ = val;
    }
}
"#,
        )?;
        let hits = DelegateCallRiskCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn passes_invoke_and_no_storage() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Address, Env, Symbol};

pub struct C;

#[contractimpl]
impl C {
    pub fn call_external(env: Env, to: Address) {
        env.invoke_contract(&to, &Symbol::new(&env, "do_thing"), ());
    }
}
"#,
        )?;
        let hits = DelegateCallRiskCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }
}
