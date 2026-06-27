
//! Detection of state-changing functions (storage writes) without event emission.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Block, Expr, ExprMethodCall, File};

const CHECK_NAME: &str = "missing-event-emission";

/// Flags functions that write to storage but don't emit any events.
pub struct MissingEventEmissionCheck;

impl Check for MissingEventEmissionCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
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
                rule_url: None,
                suggestion: None,
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

fn receiver_chain_contains_events(expr: &Expr) -> bool {
    match expr {
        Expr::MethodCall(m) => {
            if m.method == "events" {
                return true;
            }
            receiver_chain_contains_events(&m.receiver)
        }
        Expr::Field(f) => receiver_chain_contains_events(&f.base),
        _ => false,
    }
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
