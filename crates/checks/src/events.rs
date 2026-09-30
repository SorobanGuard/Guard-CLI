
//! Detection of state-changing functions (storage writes) without event emission.

use crate::util::{
    contractimpl_functions_excluding_test, receiver_chain_contains_events,
    receiver_chain_contains_storage,
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

// Issue #698 — planned fix: this private copy diverges from the canonical
// `crate::util::is_storage_mutation_call` (util.rs), which deliberately excludes
// `extend_ttl` / `bump`. A TTL bump doesn't change stored data, can't move funds and
// is intentionally permissionless in Soroban. Because this copy includes them, a
// function that only bumps TTL is falsely reported as "writes to storage but does not
// emit an event".
//
// Change: delete this function and add `is_storage_mutation_call` to the existing
// `use crate::util::{...}` import at the top of the file. Both call sites
// (`FuncBodyScan::visit_expr_method_call` and `FirstStorageWrite`) then use the shared
// definition unchanged. `receiver_chain_contains_storage` stays imported only if
// something else still uses it, otherwise it is dropped to keep clippy clean.
//
// Regression tests to add in `mod tests` below:
//   - `passes_when_function_only_extends_ttl`: a `#[contractimpl]` method whose body
//     is only `env.storage().instance().extend_ttl(100, 200);` -> no findings.
//   - `passes_when_function_only_bumps`: same with `env.storage().persistent().bump(&key, 100);`
//     -> no findings.
//   - `flags_set_even_when_ttl_is_also_extended`: `set(..)` + `extend_ttl(..)` with no
//     event -> one finding whose `line` points at the `set`, not at `extend_ttl`
//     (checks `first_storage_write_line` uses the shared predicate too).
// The existing `flags_storage_write_without_event` and `passes_with_event` must keep
// passing unchanged.
fn is_storage_mutation_call(m: &ExprMethodCall) -> bool {
    let name = m.method.to_string();
    if !matches!(
        name.as_str(),
        "set" | "remove" | "extend_ttl" | "bump" | "append"
    ) {
        return false;
    }
    receiver_chain_contains_storage(&m.receiver)
}

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
}
