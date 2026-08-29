//! Flags `initialize`/`init`/`setup` functions in `#[contractimpl]` that do not guard
//! against being called more than once.

use crate::util::{contractimpl_functions_excluding_test, receiver_chain_contains_storage};
use crate::{Check, Finding, Severity};
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, File};

const CHECK_NAME: &str = "re-initialization-risk";

pub struct ReInitializationRiskCheck;

impl Check for ReInitializationRiskCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions_excluding_test(file) {
            let fn_name = method.sig.ident.to_string();
            if !is_init_fn(&fn_name) {
                continue;
            }
            let mut scan = BodyScan::default();
            scan.visit_block(&method.block);
            if !scan.has_storage_write || scan.has_guard {
                continue;
            }
            out.push(Finding {
                check_name: CHECK_NAME.to_string(),
                severity: Severity::High,
                file_path: String::new(),
                line: method.sig.ident.span().start().line,
                function_name: fn_name.clone(),
                description: format!(
                    "Function `{fn_name}` writes to storage but does not guard against \
                     re-initialization. An attacker can call it again to overwrite the owner \
                     or reset critical contract state."
                ),
                rule_url: Some(
                    "https://github.com/SorobanGuard/Guard-CLI/blob/main/docs/checks.md#re-initialization-risk-high"
                        .to_string(),
                ),
                suggestion: Some(
                    "Check `env.storage().*.has(&key)` and panic or return if already initialized, \
                     e.g. `require!(!env.storage().instance().has(&key), \"already initialized\");`."
                        .to_string(),
                ),
            });
        }
        out
    }
}

fn is_init_fn(name: &str) -> bool {
    name.contains("init") || name.contains("setup")
}

#[derive(Default)]
struct BodyScan {
    has_storage_write: bool,
    has_guard: bool,
}

impl<'ast> Visit<'ast> for BodyScan {
    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        let method = i.method.to_string();
        if matches!(method.as_str(), "set" | "remove" | "append" | "update")
            && receiver_chain_contains_storage(&i.receiver)
        {
            self.has_storage_write = true;
        }
        if matches!(method.as_str(), "has" | "is_some" | "is_none")
            && receiver_chain_contains_storage(&i.receiver)
        {
            // Only counts as a re-init guard when the check is performed against storage
            // (e.g. `env.storage().instance().has(&key)`), not an unrelated Option/collection.
            self.has_guard = true;
        }
        visit::visit_expr_method_call(self, i);
    }

    fn visit_macro(&mut self, i: &'ast syn::Macro) {
        let name = i
            .path
            .segments
            .last()
            .map(|s| s.ident.to_string())
            .unwrap_or_default();
        if matches!(name.as_str(), "require" | "panic") {
            self.has_guard = true;
        }
        visit::visit_macro(self, i);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Check;
    use syn::parse_file;

    fn run(src: &str) -> Vec<Finding> {
        let file = parse_file(src).expect("parse");
        ReInitializationRiskCheck.run(&file, src)
    }

    #[test]
    fn flags_init_with_unrelated_is_some_and_unconditional_write() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env, Address};
pub struct C;
#[contractimpl]
impl C {
    pub fn initialize(env: Env, admin: Address, referrer: Option<Address>) {
        if referrer.is_some() {
            // unrelated referral logic
        }
        env.storage().instance().set(&0, &admin);
    }
}
"#);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].check_name, CHECK_NAME);
    }

    #[test]
    fn passes_when_storage_has_guard_gates_write() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env, Address};
pub struct C;
#[contractimpl]
impl C {
    pub fn initialize(env: Env, admin: Address) {
        if env.storage().instance().has(&0) {
            panic!("already initialized");
        }
        env.storage().instance().set(&0, &admin);
    }
}
"#);
        assert!(hits.is_empty());
    }

    #[test]
    fn flags_init_with_update_based_write() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env, Address, Vec};
pub struct C;
#[contractimpl]
impl C {
    pub fn setup(env: Env, admins: Vec<Address>) {
        env.storage().instance().update(&0, |_| admins);
    }
}
"#);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].check_name, CHECK_NAME);
    }

    #[test]
    fn flags_init_without_any_guard() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env, Address};
pub struct C;
#[contractimpl]
impl C {
    pub fn initialize(env: Env, admin: Address) {
        env.storage().instance().set(&0, &admin);
    }
}
"#);
        assert_eq!(hits.len(), 1);
    }
}
