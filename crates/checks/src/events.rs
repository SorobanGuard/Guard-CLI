
//! Detection of state-changing functions (storage writes) without event emission.

use crate::util::{
    contractimpl_functions_excluding_test, is_storage_mutation_call, receiver_chain_contains_events,
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
            let mut scan = FuncBodyScan::default();
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

// Storage writes use the shared `util::is_storage_mutation_call` (issue #731), which
// counts `set`/`remove`/`append` only: extending a TTL doesn't change any stored value,
// so it isn't a state change an indexer needs an event for (same reasoning as #401).

fn is_event_publish_call(m: &ExprMethodCall) -> bool {
    m.method == "publish" && receiver_chain_contains_events(&m.receiver)
}

#[derive(Default)]
struct FuncBodyScan {
    storage_write: bool,
    event_emitted: bool,
}

impl<'ast> Visit<'ast> for FuncBodyScan {
    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        if is_storage_mutation_call(i) {
            self.storage_write = true;
        }
        if is_event_publish_call(i) {
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

    /// Issue #731: a TTL-only function changes no stored value and must not be
    /// reported, matching util::is_storage_mutation_call (#401).
    #[test]
    fn ttl_only_function_is_not_flagged() {
        let src = r#"
use soroban_sdk::{contractimpl, Symbol, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn keep_alive(env: Env) {
        let key = Symbol::new(&env, "bal");
        env.storage().persistent().extend_ttl(&key, 100, 1000);
        env.storage().instance().bump(100, 1000);
    }
}
"#;
        let file = parse_file(src).unwrap();
        assert!(MissingEventEmissionCheck.run(&file, src).is_empty());
    }

    /// The finding for a function that extends a TTL *and* writes points at the
    /// write, not the TTL call that comes first.
    #[test]
    fn ttl_before_write_reports_the_write_line() {
        let src = r#"
use soroban_sdk::{contractimpl, Symbol, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn update(env: Env, amount: i128) {
        let key = Symbol::new(&env, "bal");
        env.storage().persistent().extend_ttl(&key, 100, 1000);
        env.storage().persistent().set(&key, &amount);
    }
}
"#;
        let file = parse_file(src).unwrap();
        let findings = MissingEventEmissionCheck.run(&file, src);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].line, 11);
    }

    #[test]
    fn remove_and_append_still_count_as_writes() {
        for call in ["remove(&key)", "append(&key)"] {
            let src = format!(
                r#"
use soroban_sdk::{{contractimpl, Symbol, Env}};

pub struct Contract;

#[contractimpl]
impl Contract {{
    pub fn change(env: Env) {{
        let key = Symbol::new(&env, "bal");
        env.storage().persistent().{call};
    }}
}}
"#
            );
            let file = parse_file(&src).unwrap();
            assert_eq!(MissingEventEmissionCheck.run(&file, &src).len(), 1, "{call}");
        }
    }
}
