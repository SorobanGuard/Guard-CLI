//! Persistent storage writes that never extend the entry's TTL in the same function.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, File};

const CHECK_NAME: &str = "missing-ttl-extension";

/// Detects writes to **persistent** storage (`env.storage().persistent()`) in a function that
/// never calls `extend_ttl` on a persistent entry in that same function. Persistent ledger
/// entries expire on their own TTL; without an `extend_ttl` call the data can be archived away.
pub struct MissingTtlExtensionCheck;

impl Check for MissingTtlExtensionCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            let mut v = TtlVisitor {
                mutations: Vec::new(),
                has_extend: false,
            };
            v.visit_block(&method.block);
            if v.has_extend {
                continue;
            }
            for line in v.mutations {
                out.push(Finding {
                    check_name: CHECK_NAME.to_string(),
                    severity: Severity::Low,
                    file_path: String::new(),
                    line,
                    function_name: fn_name.clone(),
                    description: format!(
                        "Method `{fn_name}` writes to **persistent** storage but never calls \
                         `extend_ttl` on it in the same function. Without a TTL extension the \
                         entry can expire and be archived off the ledger."
                    ),
                });
            }
        }
        out
    }
}

fn receiver_chain_contains_storage(expr: &Expr) -> bool {
    match expr {
        Expr::MethodCall(m) => m.method == "storage" || receiver_chain_contains_storage(&m.receiver),
        Expr::Field(f) => receiver_chain_contains_storage(&f.base),
        _ => false,
    }
}

fn receiver_chain_contains_persistent(expr: &Expr) -> bool {
    match expr {
        Expr::MethodCall(m) => {
            m.method == "persistent" || receiver_chain_contains_persistent(&m.receiver)
        }
        Expr::Field(f) => receiver_chain_contains_persistent(&f.base),
        _ => false,
    }
}

fn is_persistent_chain(m: &ExprMethodCall) -> bool {
    receiver_chain_contains_storage(&m.receiver) && receiver_chain_contains_persistent(&m.receiver)
}

fn is_persistent_mutation(m: &ExprMethodCall) -> bool {
    matches!(m.method.to_string().as_str(), "set" | "remove" | "append") && is_persistent_chain(m)
}

fn is_persistent_extend_ttl(m: &ExprMethodCall) -> bool {
    m.method == "extend_ttl" && is_persistent_chain(m)
}

struct TtlVisitor {
    mutations: Vec<usize>,
    has_extend: bool,
}

impl Visit<'_> for TtlVisitor {
    fn visit_expr_method_call(&mut self, i: &ExprMethodCall) {
        if is_persistent_mutation(i) {
            self.mutations.push(i.span().start().line);
        } else if is_persistent_extend_ttl(i) {
            self.has_extend = true;
        }
        visit::visit_expr_method_call(self, i);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Check;
    use syn::parse_file;

    #[test]
    fn flags_persistent_set_without_extend_ttl() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, symbol_short, Env};

pub struct C;

const K: soroban_sdk::Symbol = symbol_short!("k");

#[contractimpl]
impl C {
    pub fn put(env: Env, v: u32) {
        env.require_auth();
        env.storage().persistent().set(&K, &v);
    }
}
"#,
        )?;
        let hits = MissingTtlExtensionCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Low);
        Ok(())
    }

    #[test]
    fn passes_when_extend_ttl_present() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, symbol_short, Env};

pub struct C;

const K: soroban_sdk::Symbol = symbol_short!("k");

#[contractimpl]
impl C {
    pub fn put(env: Env, v: u32) {
        env.require_auth();
        env.storage().persistent().set(&K, &v);
        env.storage().persistent().extend_ttl(&K, 100, 1000);
    }
}
"#,
        )?;
        let hits = MissingTtlExtensionCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn ignores_temporary_storage() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, symbol_short, Env};

pub struct C;

const K: soroban_sdk::Symbol = symbol_short!("k");

#[contractimpl]
impl C {
    pub fn put(env: Env, v: u32) {
        env.require_auth();
        env.storage().temporary().set(&K, &v);
    }
}
"#,
        )?;
        let hits = MissingTtlExtensionCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }
}
