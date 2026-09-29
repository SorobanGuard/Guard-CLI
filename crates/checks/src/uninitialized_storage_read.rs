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

/// Returns true when `expr` is a `.has(&key)` call on a storage receiver chain.
fn is_storage_has(expr: &Expr) -> bool {
    match expr {
        Expr::MethodCall(m) => {
            m.method == "has" && receiver_chain_contains_storage(&m.receiver)
        }
        _ => false,
    }
}

/// Returns true when `expr` is a `.get(…)`/`.get_unchecked(…)` call on a
/// storage receiver chain — i.e. a raw storage read that returns `Option<T>`.
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

/// Returns the argument expression passed to a `.has(…)` call, if any.
fn has_key_arg(expr: &Expr) -> Option<&Expr> {
    match expr {
        Expr::MethodCall(m) if m.method == "has" => m.args.first(),
        _ => None,
    }
}

/// Returns the argument expression passed to a `.get(…)`/`.get_unchecked(…)`
/// call, if any.
fn get_key_arg(expr: &Expr) -> Option<&Expr> {
    match expr {
        Expr::MethodCall(m) if m.method == "get" || m.method == "get_unchecked" => {
            m.args.first()
        }
        _ => None,
    }
}

/// Returns true when the two key expressions refer to the same storage key.
///
/// This is a conservative syntactic comparison: identical token streams (e.g.
/// the same `&K` constant or the same `&key` identifier) are treated as the
/// same key. Anything else is treated as a different key so that a guard on an
/// unrelated key does not suppress the finding.
fn same_key(a: &Expr, b: &Expr) -> bool {
    let a = quote::quote!(#a).to_string();
    let b = quote::quote!(#b).to_string();
    a == b
}

/// Returns true when `block` contains a `.has(&key)` guard that dominates the
/// flagged read of `key` — i.e. a guard in a divergent (early-return) branch
/// that gates the read, rather than any `.has()` call anywhere in the function.
fn block_has_gating_has_guard(block: &syn::Block, key: &Expr) -> bool {
    let mut v = GatingHasGuardVisitor { key, found: false };
    v.visit_block(block);
    v.found
}

struct GatingHasGuardVisitor<'a> {
    key: &'a Expr,
    found: bool,
}

impl<'ast> Visit<'ast> for GatingHasGuardVisitor<'_> {
    fn visit_expr_if(&mut self, i: &'ast syn::ExprIf) {
        // A guard gates the read when the `if` condition is a `.has(&key)`
        // check on the same key and the branch diverges (returns/panics),
        // so control only reaches the read when the key is present.
        if let Expr::MethodCall(m) = &*i.cond {
            if is_storage_has(&i.cond) {
                if let Some(arg) = has_key_arg(&i.cond) {
                    if same_key(arg, self.key) && block_diverges(&i.then_branch) {
                        self.found = true;
                        return;
                    }
                }
            }
            // Also handle the negated form `if !has(&key) { return …; }`.
            if m.method == "has" {
                if let Some(arg) = has_key_arg(&i.cond) {
                    if same_key(arg, self.key) && block_diverges(&i.then_branch) {
                        self.found = true;
                        return;
                    }
                }
            }
        }
        if let Expr::Unary(u) = &*i.cond {
            if matches!(u.op, syn::UnOp::Not(_)) && is_storage_has(&u.expr) {
                if let Some(arg) = has_key_arg(&u.expr) {
                    if same_key(arg, self.key) && block_diverges(&i.then_branch) {
                        self.found = true;
                        return;
                    }
                }
            }
        }
        visit::visit_expr_if(self, i);
    }
}

/// Returns true when `block` always diverges (returns, panics, etc.) so that
/// reaching the end of the `if` branch is impossible.
fn block_diverges(block: &syn::Block) -> bool {
    let mut v = DivergesVisitor { found: false };
    v.visit_block(block);
    v.found
}

#[derive(Default)]
struct DivergesVisitor {
    found: bool,
}

impl<'ast> Visit<'ast> for DivergesVisitor {
    fn visit_expr_return(&mut self, _i: &'ast syn::ExprReturn) {
        self.found = true;
    }

    fn visit_macro(&mut self, i: &'ast syn::Macro) {
        if i.path.is_ident("panic")
            || i.path.is_ident("unreachable")
            || i.path.is_ident("todo")
            || i.path.is_ident("unimplemented")
        {
            self.found = true;
        }
        visit::visit_macro(self, i);
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
        if (method == "unwrap" || method == "expect") && is_storage_get(&i.receiver) {
            if let Some(key) = get_key_arg(&i.receiver) {
                if block_has_gating_has_guard(self.block, key) {
                    visit::visit_expr_method_call(self, i);
                    return;
                }
            }
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
                    "get",
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

    #[test]
    fn ignores_gated_read_with_early_return() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, symbol_short, Env};
pub struct C;
const K: soroban_sdk::Symbol = symbol_short!("k");
#[contractimpl]
impl C {
    pub fn get_val(env: Env) -> u32 {
        if !env.storage().persistent().has(&K) {
            return 0;
        }
        env.storage().persistent().get(&K).unwrap()
    }
}
"#,
        )?;
        let hits = UninitializedStorageReadCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn flags_read_guarded_by_unrelated_key() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, symbol_short, Env, Symbol};
pub struct C;
const K: soroban_sdk::Symbol = symbol_short!("k");
#[contractimpl]
impl C {
    pub fn get_val(env: Env, other_key: Symbol) -> u32 {
        if env.storage().instance().has(&other_key) {
            do_something();
        }
        env.storage().persistent().get(&K).unwrap()
    }
}
"#,
        )?;
        let hits = UninitializedStorageReadCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        Ok(())
    }
}
