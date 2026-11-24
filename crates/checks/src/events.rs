
//! Detection of state-changing functions (storage writes) without event emission.

use crate::util::{
    contractimpl_functions_excluding_test, env_param_name, is_event_publish_call,
    is_storage_mutation_call,
};
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Block, ExprMethodCall, File};

const CHECK_NAME: &str = "missing-event-emission";

/// Flags functions that write to storage but don't emit any events.
pub struct MissingEventEmissionCheck;

impl Check for MissingEventEmissionCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions_excluding_test(file) {
            let mut scan = FuncBodyScan {
                env_name: env_param_name(&method.sig).unwrap_or_else(|| "env".to_string()),
                ..FuncBodyScan::default()
            };
            scan.visit_block(&method.block);
            if !scan.storage_write || scan.event_emitted {
                continue;
            }
            let line = first_storage_write_line(&method.block)
                .unwrap_or_else(|| method.sig.ident.span().start().line);
            let fn_name = method.sig.ident.to_string();
            out.push(Finding {
                check_name: CHECK_NAME.to_string(),
                severity: Severity::Medium,
                file_path: String::new(),
                line,
                function_name: fn_name.clone(),
                description: format!(
                    "Method `{fn_name}` writes to storage but does not emit an event. Consider using \
                     `env.events().publish(…)` to allow off-chain indexers to track contract activity."
                ),
                rule_url: Some(
                    "https://github.com/SorobanGuard/Guard-CLI/blob/main/docs/checks.md#missing-event-emission-medium"
                        .to_string(),
                ),
                suggestion: Some(format!(
                    "Add `env.events().publish((symbol_short!(\"{fn_name}\"), …), &payload)` \
                     after the storage write so off-chain indexers can track this state change."
                )),
            });
        }
        out
    }
}

#[derive(Default)]
struct FuncBodyScan {
    /// Name of the method's `Env` parameter, for `MyEvent { .. }.publish(&env)`.
    env_name: String,
    storage_write: bool,
    event_emitted: bool,
}

impl<'ast> Visit<'ast> for FuncBodyScan {
    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        if is_storage_mutation_call(i) {
            self.storage_write = true;
        }
        if is_event_publish_call(i, &self.env_name) {
            self.event_emitted = true;
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

    #[test]
    fn flags_storage_write_without_event() {
        let src = r#"
use soroban_sdk::{contractimpl, Symbol, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn set_balance(env: Env, amount: i128) {
        env.storage().instance().set(&Symbol::new(&env, "bal"), &amount);
    }
}
"#;
        let file = parse_file(src).unwrap();
        let findings = MissingEventEmissionCheck.run(&file, src);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn passes_with_event() {
        let src = r#"
use soroban_sdk::{contractimpl, Symbol, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn set_balance(env: Env, amount: i128) {
        env.storage().instance().set(&Symbol::new(&env, "bal"), &amount);
        env.events().publish((Symbol::new(&env, "update_balance"), amount));
    }
}
"#;
        let file = parse_file(src).unwrap();
        let findings = MissingEventEmissionCheck.run(&file, src);
        assert!(findings.is_empty());
    }

    /// #1060 / #603: `#[contractevent]` structs emit with `.publish(&env)`.
    #[test]
    fn passes_with_contractevent_publish() {
        let src = r#"
use soroban_sdk::{contract, contractevent, contractimpl, symbol_short, Address, Env};

#[contractevent]
pub struct Deposited {
    #[topic]
    pub from: Address,
    pub amount: i128,
}

#[contract]
pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn deposit(env: Env, from: Address, amount: i128) {
        env.storage().persistent().set(&from, &amount);
        Deposited { from, amount }.publish(&env);
    }

    pub fn deposit_renamed_env(e: Env, from: Address, amount: i128) {
        e.storage().persistent().set(&from, &amount);
        let event = Deposited { from, amount };
        event.publish(&e);
    }
}
"#;
        let file = parse_file(src).unwrap();
        let findings = MissingEventEmissionCheck.run(&file, src);
        assert!(findings.is_empty(), "{findings:#?}");
    }

    /// A `publish` that does not take the method's `Env` is not an event emission.
    #[test]
    fn flags_unrelated_publish_method() {
        let src = r#"
use soroban_sdk::{contractimpl, symbol_short, Env};
pub struct Contract;
#[contractimpl]
impl Contract {
    pub fn set(env: Env, feed: Feed, v: i128) {
        env.storage().instance().set(&symbol_short!("v"), &v);
        feed.publish(v);
    }
}
"#;
        let file = parse_file(src).unwrap();
        assert_eq!(MissingEventEmissionCheck.run(&file, src).len(), 1);
    }

    /// #1060 / #731: extending a TTL changes no state, so no event is needed.
    #[test]
    fn passes_extend_ttl_only_function() {
        let src = r#"
use soroban_sdk::{contractimpl, symbol_short, Env};
pub struct Contract;
#[contractimpl]
impl Contract {
    pub fn keep_alive(env: Env) {
        env.storage().instance().extend_ttl(100, 1000);
        env.storage().persistent().extend_ttl(&symbol_short!("bal"), 100, 1000);
        env.storage().persistent().bump(&symbol_short!("bal"), 100, 1000);
    }
}
"#;
        let file = parse_file(src).unwrap();
        let findings = MissingEventEmissionCheck.run(&file, src);
        assert!(findings.is_empty(), "{findings:#?}");
    }
}
