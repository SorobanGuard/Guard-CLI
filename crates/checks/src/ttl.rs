//! Persistent storage writes that never extend the entry's TTL in the same function.

use crate::util::{
    contractimpl_functions_excluding_test, receiver_chain_contains_persistent,
    receiver_chain_contains_storage,
};
use crate::{Check, Finding, Severity};
use std::collections::HashSet;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, File};

const CHECK_NAME: &str = "missing-ttl-extension";

/// Detects writes to **persistent** storage (`env.storage().persistent()`) in a function that
/// never calls `extend_ttl` on the **same key** in that same function.
///
/// Previously this check used a single function-wide `has_extend` flag, which caused it to
/// silently drop all findings in any function that called `extend_ttl` on *any* key — even if
/// other persistent keys written in the same function had no TTL extension at all (issue #362).
///
/// The fix: we correlate each persistent mutation with the textual representation of its key
/// argument, and only suppress a mutation when `extend_ttl` is called with a key expression
/// that has the same text.
pub struct MissingTtlExtensionCheck;

impl Check for MissingTtlExtensionCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions_excluding_test(file) {
            let fn_name = method.sig.ident.to_string();
            let mut v = TtlVisitor {
                mutations: Vec::new(),
                extended_keys: HashSet::new(),
            };
            v.visit_block(&method.block);

            for (key_repr, line) in v.mutations {
                // Only suppress this mutation if we saw extend_ttl called with the same key.
                if v.extended_keys.contains(&key_repr) {
                    continue;
                }
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
                    rule_url: Some(
                        "https://github.com/SorobanGuard/Guard-CLI/blob/main/docs/checks.md#missing-ttl-extension-low"
                            .to_string(),
                    ),
                    suggestion: Some(
                        "Call `env.storage().persistent().extend_ttl(&key, threshold, extend_to)` after the write."
                            .to_string(),
                    ),
                });
            }
        }
        out
    }
}

fn is_persistent_chain(m: &ExprMethodCall) -> bool {
    receiver_chain_contains_storage(&m.receiver) && receiver_chain_contains_persistent(&m.receiver)
}

fn is_persistent_mutation(m: &ExprMethodCall) -> bool {
    matches!(m.method.to_string().as_str(), "set" | "remove" | "append") && is_persistent_chain(m)
}

fn is_persistent_extend_ttl(m: &ExprMethodCall) -> bool {
    // `bump` is the legacy (pre-`extend_ttl`) spelling of the same TTL operation; older or
    // unmigrated Soroban code still uses it, so accept both.
    matches!(m.method.to_string().as_str(), "extend_ttl" | "bump") && is_persistent_chain(m)
}

/// Return a stable textual representation of a key expression, used to correlate mutations
/// with `extend_ttl` calls that target the same storage key.
///
/// We normalise the syntax tree back to tokens via `quote::ToTokens` so that `&K` and `&K`
/// compare equal regardless of whitespace. A leading `&` reference is stripped first because
/// both `.set(&K, &v)` and `.extend_ttl(&K, t, e)` pass the key by reference — stripping
/// ensures both calls produce the same repr.
///
/// Returns `None` for expressions that produce an empty token stream (extremely rare).
/// In that case we do *not* suppress the finding (conservative: report rather than hide).
fn key_repr(expr: &Expr) -> Option<String> {
    use proc_macro2::TokenStream;
    use quote::ToTokens;

    // Strip a leading & so `&K` and `K` are treated as the same key.
    let inner = match expr {
        Expr::Reference(r) => &*r.expr,
        other => other,
    };

    let mut ts = TokenStream::new();
    inner.to_tokens(&mut ts);
    let s = ts.to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

struct TtlVisitor {
    /// Each element is `(key_repr, source_line)` for a persistent `.set`/`.remove`/`.append`.
    mutations: Vec<(String, usize)>,
    /// Textual key representations seen in `extend_ttl` calls within this function.
    extended_keys: HashSet<String>,
}

impl Visit<'_> for TtlVisitor {
    fn visit_expr_method_call(&mut self, i: &ExprMethodCall) {
        if is_persistent_mutation(i) {
            // First argument to `.set(&key, &value)` / `.remove(&key)` / `.append(&key, &value)`
            // is the storage key.
            if let Some(first_arg) = i.args.first() {
                if let Some(repr) = key_repr(first_arg) {
                    self.mutations.push((repr, i.span().start().line));
                } else {
                    // Unknown key shape — record with an empty sentinel so it is never
                    // suppressed (conservative: always report).
                    self.mutations
                        .push((format!("__unknown_{}", i.span().start().line), i.span().start().line));
                }
            }
        } else if is_persistent_extend_ttl(i) {
            // First argument to `.extend_ttl(&key, threshold, extend_to)` is the storage key.
            if let Some(first_arg) = i.args.first() {
                if let Some(repr) = key_repr(first_arg) {
                    self.extended_keys.insert(repr);
                }
                // If the key is unrepresentable we cannot suppress anything — conservative.
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
    fn passes_when_legacy_bump_present() -> Result<(), syn::Error> {
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
        env.storage().persistent().bump(&K, 1000);
    }
}
"#,
        )?;
        let hits = MissingTtlExtensionCheck.run(&file, "");
        assert!(hits.is_empty(), "{hits:?}");
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

    /// Regression test for issue #362.
    ///
    /// A function that writes two distinct persistent keys (K1 and K2) but only calls
    /// `extend_ttl` for K2 must produce exactly one finding — for K1.  The old
    /// function-scoped `has_extend` flag caused zero findings to be emitted.
    #[test]
    fn mixed_keys_only_extended_key_is_suppressed() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, symbol_short, Env};

pub struct C;

const K1: soroban_sdk::Symbol = symbol_short!("k1");
const K2: soroban_sdk::Symbol = symbol_short!("k2");

#[contractimpl]
impl C {
    /// Writes K1 and K2 but only extends TTL for K2.
    /// K1's missing extension must be reported.
    pub fn update(env: Env, a: u32, b: u32) {
        env.require_auth();
        env.storage().persistent().set(&K1, &a);
        env.storage().persistent().set(&K2, &b);
        env.storage().persistent().extend_ttl(&K2, 100, 1000);
    }
}
"#,
        )?;
        let hits = MissingTtlExtensionCheck.run(&file, "");
        assert_eq!(
            hits.len(),
            1,
            "expected exactly one finding (for K1), got: {hits:#?}"
        );
        assert_eq!(hits[0].function_name, "update");
        Ok(())
    }

    /// Both keys have corresponding extend_ttl calls — no findings expected.
    #[test]
    fn both_keys_extended_no_findings() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, symbol_short, Env};

pub struct C;

const K1: soroban_sdk::Symbol = symbol_short!("k1");
const K2: soroban_sdk::Symbol = symbol_short!("k2");

#[contractimpl]
impl C {
    pub fn update(env: Env, a: u32, b: u32) {
        env.require_auth();
        env.storage().persistent().set(&K1, &a);
        env.storage().persistent().set(&K2, &b);
        env.storage().persistent().extend_ttl(&K1, 100, 1000);
        env.storage().persistent().extend_ttl(&K2, 100, 1000);
    }
}
"#,
        )?;
        let hits = MissingTtlExtensionCheck.run(&file, "");
        assert!(
            hits.is_empty(),
            "expected no findings when all keys are extended, got: {hits:#?}"
        );
        Ok(())
    }

    /// Neither key has an extend_ttl call — two findings expected.
    #[test]
    fn no_keys_extended_two_findings() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, symbol_short, Env};

pub struct C;

const K1: soroban_sdk::Symbol = symbol_short!("k1");
const K2: soroban_sdk::Symbol = symbol_short!("k2");

#[contractimpl]
impl C {
    pub fn update(env: Env, a: u32, b: u32) {
        env.require_auth();
        env.storage().persistent().set(&K1, &a);
        env.storage().persistent().set(&K2, &b);
    }
}
"#,
        )?;
        let hits = MissingTtlExtensionCheck.run(&file, "");
        assert_eq!(
            hits.len(),
            2,
            "expected two findings (one per unextended key), got: {hits:#?}"
        );
        Ok(())
    }
}
