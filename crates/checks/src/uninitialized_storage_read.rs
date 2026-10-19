//! Detects reads from persistent/instance storage where the return value is
//! unwrapped with `unwrap()` or `expect()` without a prior `has()` guard.
//!
//! Reading uninitialized storage in Soroban returns `None`; calling `.unwrap()`
//! on it panics and aborts the contract invocation, which can brick a contract
//! or be exploited by an attacker who triggers the panic intentionally.

use crate::util::{contractimpl_functions_excluding_test, receiver_chain_contains_storage};
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
        for method in contractimpl_functions_excluding_test(file) {
            let fn_name = method.sig.ident.to_string();
            let mut v = StorageReadVisitor {
                fn_name,
                block: &method.block,
                out: &mut out,
            };
            v.visit_block(&method.block);
        }
        out
    }
}

/// Returns `true` when the block contains a `.has(&key)` call on a storage
/// receiver where the key argument token-text matches `read_key_text` AND
/// the `.has()` call appears **before** the line of the unsafe read
/// (`read_line`).
fn block_has_storage_has_guard(block: &syn::Block, read_key_text: &str, read_line: usize) -> bool {
    let mut v = StorageHasGuardVisitor {
        read_key_text,
        read_line,
        found: false,
    };
    v.visit_block(block);
    v.found
}

struct StorageHasGuardVisitor<'a> {
    read_key_text: &'a str,
    read_line: usize,
    found: bool,
}

impl<'ast> Visit<'ast> for StorageHasGuardVisitor<'ast> {
    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        if self.found {
            return;
        }
        if i.method == "has" && receiver_chain_contains_storage(&i.receiver) {
            // The .has() call must appear before the unwrap site.
            let has_line = i.method.span().start().line;
            if has_line < self.read_line {
                // And the key argument must match the read key.
                if let Some(arg) = i.args.first() {
                    use quote::ToTokens;
                    let arg_text = arg.to_token_stream().to_string();
                    // Compare stripping whitespace for robustness (&KEY vs & KEY).
                    if arg_text.replace(' ', "") == self.read_key_text.replace(' ', "") {
                        self.found = true;
                        return;
                    }
                }
            }
        }
        visit::visit_expr_method_call(self, i);
    }
}

/// Returns true when the receiver chain contains `.storage()` followed by a
/// `.get(…)` call — i.e. this is a raw storage read that returns `Option<T>`.
/// Also returns the first argument (the key) as a token string when found.
fn is_storage_get(expr: &Expr) -> Option<String> {
    match expr {
        Expr::MethodCall(m) => {
            if (m.method == "get" || m.method == "get_unchecked")
                && receiver_chain_contains_storage(&m.receiver)
            {
                use quote::ToTokens;
                let key_text = m
                    .args
                    .first()
                    .map(|a| a.to_token_stream().to_string())
                    .unwrap_or_default();
                return Some(key_text);
            }
            is_storage_get(&m.receiver)
        }
        _ => None,
    }
}

struct StorageReadVisitor<'a> {
    fn_name: String,
    block: &'a syn::Block,
    out: &'a mut Vec<Finding>,
}

impl Visit<'_> for StorageReadVisitor<'_> {
    fn visit_expr_method_call(&mut self, i: &ExprMethodCall) {
        let method = i.method.to_string();
        // Flag `.unwrap()` or `.expect(…)` chained directly onto a storage `.get(…)` call.
        if method == "unwrap" || method == "expect" {
            if let Some(key_text) = is_storage_get(&i.receiver) {
                let read_line = i.span().start().line;
                if !block_has_storage_has_guard(self.block, &key_text, read_line) {
                    self.out.push(Finding {
                        check_name: CHECK_NAME.to_string(),
                        severity: Severity::High,
                        file_path: String::new(),
                        line: read_line,
                        function_name: self.fn_name.clone(),
                        description: format!(
                            "`{}` reads from storage with `.get()` and immediately calls `.{method}()`. \
                             If the key has never been written the contract will panic on uninitialized storage.",
                            self.fn_name,
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
            }
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

    /// A `.has(&K)` guard for the same key before the read should suppress.
    #[test]
    fn ignores_correct_has_guard_before_read() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, symbol_short, Env};
pub struct C;
const K: soroban_sdk::Symbol = symbol_short!("k");
#[contractimpl]
impl C {
    pub fn get_val(env: Env) -> u32 {
        if env.storage().persistent().has(&K) {
            env.storage().persistent().get(&K).unwrap()
        } else {
            0
        }
    }
}
"#,
        )?;
        let hits = UninitializedStorageReadCheck.run(&file, "");
        assert!(hits.is_empty(), "matching has() guard should suppress finding");
        Ok(())
    }

    /// A `.has(&OTHER_KEY)` guard for a *different* key must NOT suppress the finding.
    #[test]
    fn flags_has_guard_for_wrong_key() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, symbol_short, Env};
pub struct C;
const ADMIN_KEY: soroban_sdk::Symbol = symbol_short!("admin");
const OTHER_KEY: soroban_sdk::Symbol = symbol_short!("other");
#[contractimpl]
impl C {
    pub fn get_admin(env: Env) -> u32 {
        if env.storage().instance().has(&OTHER_KEY) {
            // guard is for OTHER_KEY, not ADMIN_KEY — should still flag
        }
        env.storage().persistent().get(&ADMIN_KEY).unwrap()
    }
}
"#,
        )?;
        let hits = UninitializedStorageReadCheck.run(&file, "");
        assert_eq!(hits.len(), 1, "wrong-key has() guard must not suppress the finding");
        Ok(())
    }

    /// A `.has(&K)` guard that appears *after* the read must NOT suppress the finding.
    #[test]
    fn flags_has_guard_after_read() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, symbol_short, Env};
pub struct C;
const K: soroban_sdk::Symbol = symbol_short!("k");
#[contractimpl]
impl C {
    pub fn get_val(env: Env) -> u32 {
        let v = env.storage().persistent().get(&K).unwrap();
        // guard comes too late
        let _ = env.storage().persistent().has(&K);
        v
    }
}
"#,
        )?;
        let hits = UninitializedStorageReadCheck.run(&file, "");
        assert_eq!(hits.len(), 1, "has() guard after the read must not suppress the finding");
        Ok(())
    }
}
