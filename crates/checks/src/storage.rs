//! Risky Soroban storage usage: temporary persistence and caller-derived `Symbol` keys.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprCall, ExprMethodCall, File};

const CHECK_NAME: &str = "unsafe-storage-patterns";

/// Detects (1) writes to **temporary** storage (TTL-bound; easy to misuse for “real” state) and
/// (2) `Symbol::new` keys built from non-literal strings (enumerable / collision-prone keys).
pub struct UnsafeStoragePatternsCheck;

impl Check for UnsafeStoragePatternsCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            let mut v = StorageVisitor {
                fn_name: fn_name.clone(),
                out: &mut out,
            };
            v.visit_block(&method.block);
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

fn receiver_chain_contains_temporary(expr: &Expr) -> bool {
    match expr {
        Expr::MethodCall(m) => {
            if m.method == "temporary" {
                return true;
            }
            receiver_chain_contains_temporary(&m.receiver)
        }
        Expr::Field(f) => receiver_chain_contains_temporary(&f.base),
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

fn is_temporary_storage_mutation(m: &ExprMethodCall) -> bool {
    is_storage_mutation_call(m) && receiver_chain_contains_temporary(&m.receiver)
}

fn is_temporary_get_unchecked(m: &ExprMethodCall) -> bool {
    m.method == "get_unchecked"
        && receiver_chain_contains_storage(&m.receiver)
        && receiver_chain_contains_temporary(&m.receiver)
}

fn is_symbol_new_path(expr: &Expr) -> bool {
    let Expr::Path(p) = expr else {
        return false;
    };
    let segs = &p.path.segments;
    segs.len() == 2 && segs[0].ident == "Symbol" && segs[1].ident == "new"
}

/// Second argument to `Symbol::new` is a string literal or a named constant path → stable key, no finding.
fn symbol_new_second_arg_is_string_lit(call: &ExprCall) -> bool {
    let Some(arg1) = call.args.iter().nth(1) else {
        return false;
    };
    match arg1 {
        Expr::Lit(syn::ExprLit {
            lit: syn::Lit::Str(_),
            ..
        }) => true,
        // Conventionally uppercase paths are named constants and therefore stable.
        Expr::Path(path) => path.path.segments.last().is_some_and(|segment| {
            segment
                .ident
                .to_string()
                .chars()
                .all(|c| !c.is_ascii_lowercase())
        }),
        _ => false,
    }
}

struct StorageVisitor<'a> {
    fn_name: String,
    out: &'a mut Vec<Finding>,
}

impl Visit<'_> for StorageVisitor<'_> {
    fn visit_expr_method_call(&mut self, i: &ExprMethodCall) {
        if is_temporary_get_unchecked(i) {
            self.out.push(Finding {
                check_name: CHECK_NAME.to_string(),
                severity: Severity::Medium,
                file_path: String::new(),
                line: i.span().start().line,
                function_name: self.fn_name.clone(),
                description: format!(
                    "Method `{}` calls `get_unchecked` on temporary storage. \
                     If the entry has expired the call will panic at runtime.",
                    self.fn_name
                ),
                rule_url: Some(
                    "https://github.com/SorobanGuard/Guard-CLI/blob/main/docs/checks.md#unsafe-storage-patterns-medium"
                        .to_string(),
                ),
                suggestion: Some(
                    "Use `env.storage().temporary().get(&key)` (returns `Option`) and handle the missing case."
                        .to_string(),
                ),
            });
        }
        if is_temporary_storage_mutation(i) {
            self.out.push(Finding {
                check_name: CHECK_NAME.to_string(),
                severity: Severity::Medium,
                file_path: String::new(),
                line: i.span().start().line,
                function_name: self.fn_name.clone(),
                description: format!(
                    "Method `{}` writes to **temporary** storage (`env.storage().temporary()`). \
                     Data expires with TTL—only use for scratch or contest-style flows, not \
                     long-lived balances or ownership.",
                    self.fn_name
                ),
                rule_url: Some(
                    "https://github.com/SorobanGuard/Guard-CLI/blob/main/docs/checks.md#unsafe-storage-patterns-medium"
                        .to_string(),
                ),
                suggestion: Some(
                    "Use `env.storage().persistent()` for long-lived state; reserve `temporary()` for scratch data only."
                        .to_string(),
                ),
            });
        }
        visit::visit_expr_method_call(self, i);
    }

    fn visit_expr_call(&mut self, i: &ExprCall) {
        if is_symbol_new_path(&i.func)
            && i.args.len() >= 2
            && !symbol_new_second_arg_is_string_lit(i)
        {
            self.out.push(Finding {
                check_name: CHECK_NAME.to_string(),
                severity: Severity::Medium,
                file_path: String::new(),
                line: i.span().start().line,
                function_name: self.fn_name.clone(),
                description: format!(
                    "`Symbol::new` in `{}` uses a non-literal key string. Keys derived from \
                     caller input are easier to guess or collide with; prefer `symbol_short!` / \
                     fixed literals or a namespaced encoding you control.",
                    self.fn_name
                ),
                rule_url: Some(
                    "https://github.com/SorobanGuard/Guard-CLI/blob/main/docs/checks.md#unsafe-storage-patterns-medium"
                        .to_string(),
                ),
                suggestion: Some(
                    "Use `symbol_short!(\"literal\")` or a named constant for storage keys."
                        .to_string(),
                ),
            });
        }
        visit::visit_expr_call(self, i);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Check;
    use syn::parse_file;

    #[test]
    fn flags_temporary_get_unchecked() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, symbol_short, Env};

pub struct C;

const K: soroban_sdk::Symbol = symbol_short!("k");

#[contractimpl]
impl C {
    pub fn load(env: Env) -> u32 {
        env.storage().temporary().get_unchecked(&K)
    }
}
"#,
        )?;
        let hits = UnsafeStoragePatternsCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        assert!(hits[0].description.contains("get_unchecked"));
        Ok(())
    }

    #[test]
    fn flags_temporary_set() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, symbol_short, Env};

pub struct C;

const K: soroban_sdk::Symbol = symbol_short!("k");

#[contractimpl]
impl C {
    pub fn stash(env: Env, v: u32) {
        env.require_auth();
        env.storage().temporary().set(&K, &v);
    }
}
"#,
        )?;
        let hits = UnsafeStoragePatternsCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Medium);
        assert!(hits[0].description.contains("temporary"));
        Ok(())
    }

    #[test]
    fn flags_dynamic_symbol_new() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env, Symbol};

pub struct C;

#[contractimpl]
impl C {
    pub fn put(env: Env, tag: soroban_sdk::String) {
        env.require_auth();
        let sym = Symbol::new(&env, tag);
        env.storage().persistent().set(&sym, &0u32);
    }
}
"#,
        )?;
        let hits = UnsafeStoragePatternsCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        assert!(hits[0].description.contains("Symbol::new"));
        Ok(())
    }

    #[test]
    fn ignores_symbol_new_with_literal() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env, Symbol};

pub struct C;

#[contractimpl]
impl C {
    pub fn put(env: Env) {
        env.require_auth();
        let sym = Symbol::new(&env, "fixed");
        env.storage().persistent().set(&sym, &0u32);
    }
}
"#,
        )?;
        let hits = UnsafeStoragePatternsCheck.run(&file, "");
        assert!(
            hits.iter().all(|h| !h.description.contains("Symbol::new")),
            "{hits:?}"
        );
        Ok(())
    }

    #[test]
    fn ignores_symbol_new_with_named_const() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env, Symbol};

pub struct C;

const KEY: &str = "balance";

#[contractimpl]
impl C {
    pub fn put(env: Env) {
        env.require_auth();
        let sym = Symbol::new(&env, KEY);
        env.storage().persistent().set(&sym, &0u32);
    }
}
"#,
        )?;
        let hits = UnsafeStoragePatternsCheck.run(&file, "");
        assert!(
            hits.iter().all(|h| !h.description.contains("Symbol::new")),
            "{hits:?}"
        );
        Ok(())
    }

    #[test]
    fn persistent_literal_key_no_storage_finding() -> Result<(), syn::Error> {
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
        let hits = UnsafeStoragePatternsCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }
}
