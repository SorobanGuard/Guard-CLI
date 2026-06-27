//! Detects reads from persistent/instance storage where the return value is
//! unwrapped with `unwrap()` or `expect()` without a prior `has()` guard.
//!
//! Reading uninitialized storage in Soroban returns `None`; calling `.unwrap()`
//! on it panics and aborts the contract invocation, which can brick a contract
//! or be exploited by an attacker who triggers the panic intentionally.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, File};

const CHECK_NAME: &str = "uninitialized-storage-read";

pub struct UninitializedStorageReadCheck;

impl Check for UninitializedStorageReadCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            let mut v = StorageReadVisitor { fn_name, out: &mut out };
            v.visit_block(&method.block);
        }
        out
    }
}

/// Returns true when the receiver chain contains `.storage()` followed by a
/// `.get(…)` call — i.e. this is a raw storage read that returns `Option<T>`.
fn is_storage_get(expr: &Expr) -> bool {
    match expr {
        Expr::MethodCall(m) => {
            if m.method == "get" || m.method == "get_unchecked" {
                return receiver_chain_contains_storage(&m.receiver);
            }
            is_storage_get(&m.receiver)
        }
        _ => false,
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

struct StorageReadVisitor<'a> {
    fn_name: String,
    out: &'a mut Vec<Finding>,
}

impl Visit<'_> for StorageReadVisitor<'_> {
    fn visit_expr_method_call(&mut self, i: &ExprMethodCall) {
        let method = i.method.to_string();
        // Flag `.unwrap()` or `.expect(…)` chained directly onto a storage `.get(…)` call.
        if (method == "unwrap" || method == "expect") && is_storage_get(&i.receiver) {
            self.out.push(Finding {
                check_name: CHECK_NAME.to_string(),
                severity: Severity::High,
                file_path: String::new(),
                line: i.span().start().line,
                function_name: self.fn_name.clone(),
                description: format!(
                    "`{}` reads from storage with `.{}()` and immediately calls `.{method}()`. \
                     If the key has never been written the contract will panic on uninitialized storage.",
                    self.fn_name,
                    if method == "unwrap" { "get" } else { "get" },
                    method = method,
                ),
                rule_url: Some(
                    "https://github.com/SorobanGuard/Guard-CLI/blob/main/docs/checks.md#uninitialized-storage-read-high"
                        .to_string(),
                ),
                suggestion: Some(
                    "Use `.unwrap_or_default()`, `.unwrap_or(fallback)`, or guard with \
                     `env.storage().<tier>().has(&key)` before reading."
                        .to_string(),
                ),
            });
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
    fn flags_storage_get_unwrap() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, symbol_short, Env};
pub struct C;
const K: soroban_sdk::Symbol = symbol_short!("k");
#[contractimpl]
impl C {
    pub fn get_val(env: Env) -> u32 {
        env.storage().persistent().get(&K).unwrap()
    }
}
"#,
        )?;
        let hits = UninitializedStorageReadCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::High);
        assert_eq!(hits[0].check_name, CHECK_NAME);
        Ok(())
    }

    #[test]
    fn flags_storage_get_expect() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, symbol_short, Env};
pub struct C;
const K: soroban_sdk::Symbol = symbol_short!("k");
#[contractimpl]
impl C {
    pub fn get_val(env: Env) -> u32 {
        env.storage().instance().get(&K).expect("must exist")
    }
}
"#,
        )?;
        let hits = UninitializedStorageReadCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::High);
        Ok(())
    }

    #[test]
    fn ignores_unwrap_or_default() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, symbol_short, Env};
pub struct C;
const K: soroban_sdk::Symbol = symbol_short!("k");
#[contractimpl]
impl C {
    pub fn get_val(env: Env) -> u32 {
        env.storage().persistent().get(&K).unwrap_or_default()
    }
}
"#,
        )?;
        let hits = UninitializedStorageReadCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn ignores_unwrap_or() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, symbol_short, Env};
pub struct C;
const K: soroban_sdk::Symbol = symbol_short!("k");
#[contractimpl]
impl C {
    pub fn get_val(env: Env) -> u32 {
        env.storage().temporary().get(&K).unwrap_or(0)
    }
}
"#,
        )?;
        let hits = UninitializedStorageReadCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }
}
