//! Risky Soroban storage usage: temporary persistence and caller-derived `Symbol` keys.

use crate::util::{
    contractimpl_functions_excluding_test, receiver_chain_contains_storage,
    receiver_chain_contains_temporary,
};
use crate::{Check, Finding, Severity};
use std::collections::HashSet;
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
        let known_consts = collect_const_and_static_names(file);
        let mut out = Vec::new();
        for method in contractimpl_functions_excluding_test(file) {
            let fn_name = method.sig.ident.to_string();
            let mut v = StorageVisitor {
                fn_name: fn_name.clone(),
                known_consts: &known_consts,
                out: &mut out,
            };
            v.visit_block(&method.block);
        }
        out
    }
}

fn is_storage_mutation_call(m: &ExprMethodCall) -> bool {
    let name = m.method.to_string();
    // `extend_ttl` / `bump` are TTL operations, not data writes: bumping the TTL of a
    // temporary entry is the correct thing to do, not a misuse worth flagging.
    if !matches!(name.as_str(), "set" | "remove" | "append") {
        return false;
    }
    receiver_chain_contains_storage(&m.receiver)
}

fn is_temporary_storage_mutation(m: &ExprMethodCall) -> bool {
    is_storage_mutation_call(m) && receiver_chain_contains_temporary(&m.receiver)
}

fn is_temporary_chain(expr: &Expr) -> bool {
    receiver_chain_contains_storage(expr) && receiver_chain_contains_temporary(expr)
}

/// `env.storage().temporary().get(&k).unwrap()` / `.expect(..)`: temporary entries are
/// deleted when their TTL lapses, so this panics after expiry (#1055).
fn is_temporary_get_unwrap(m: &ExprMethodCall) -> bool {
    if m.method != "unwrap" && m.method != "expect" {
        return false;
    }
    matches!(&*m.receiver, Expr::MethodCall(get) if get.method == "get" && is_temporary_chain(&get.receiver))
}

/// Lines of `old.unwrap()` / `old.expect(..)` inside the closure passed to
/// `env.storage().temporary().update(&k, |old| ..)` / `try_update(..)`, where `old` is the
/// closure's `Option<V>` parameter — `None` once the entry has expired.
fn temporary_update_closure_unwraps(m: &ExprMethodCall) -> Vec<usize> {
    if (m.method != "update" && m.method != "try_update") || !is_temporary_chain(&m.receiver) {
        return Vec::new();
    }
    struct UnwrapFinder<'a> {
        param: &'a str,
        lines: Vec<usize>,
    }
    impl Visit<'_> for UnwrapFinder<'_> {
        fn visit_expr_method_call(&mut self, i: &ExprMethodCall) {
            if (i.method == "unwrap" || i.method == "expect")
                && matches!(&*i.receiver, Expr::Path(p) if p.path.is_ident(self.param))
            {
                self.lines.push(i.span().start().line);
            }
            visit::visit_expr_method_call(self, i);
        }
    }
    let mut lines = Vec::new();
    for arg in &m.args {
        let Expr::Closure(closure) = arg else {
            continue;
        };
        let Some(param) = closure.inputs.first().and_then(crate::util::pat_ident_name) else {
            continue;
        };
        let mut finder = UnwrapFinder {
            param: &param,
            lines: Vec::new(),
        };
        finder.visit_expr(&closure.body);
        lines.extend(finder.lines);
    }
    lines
}

/// Matches a call whose *last two* path segments are `Symbol::new` — so both
/// the bare `Symbol::new` (imported) and fully-qualified `soroban_sdk::Symbol::new`
/// spellings are recognized, the same import style already supported for
/// `#[soroban_sdk::contractimpl]` (see `util::path_is_contractimpl`).
fn is_symbol_new_path(expr: &Expr) -> bool {
    let Expr::Path(p) = expr else {
        return false;
    };
    let mut rev = p.path.segments.iter().rev();
    let (Some(last), Some(second_last)) = (rev.next(), rev.next()) else {
        return false;
    };
    second_last.ident == "Symbol" && last.ident == "new"
}

/// Second argument to `Symbol::new` is a string literal, or a path that
/// resolves to a `const`/`static` item declared anywhere in the file →
/// stable key, no finding. `known_consts` holds the names of every such item
/// (see `collect_const_and_static_names`); resolving against it instead of
/// guessing from identifier casing means a lowercase-named const is
/// correctly treated as stable and an upper-cased *parameter* is not.
fn symbol_new_second_arg_is_string_lit(call: &ExprCall, known_consts: &HashSet<String>) -> bool {
    let Some(arg1) = call.args.iter().nth(1) else {
        return false;
    };
    match arg1 {
        Expr::Lit(syn::ExprLit {
            lit: syn::Lit::Str(_),
            ..
        }) => true,
        Expr::Path(path) => path
            .path
            .segments
            .last()
            .is_some_and(|segment| known_consts.contains(&segment.ident.to_string())),
        _ => false,
    }
}

/// Names of every `const`/`static` item declared anywhere in the file —
/// module level, inside an `impl`, or local to a function body. Walks the
/// whole tree via `syn::visit` so nesting depth doesn't matter.
fn collect_const_and_static_names(file: &File) -> HashSet<String> {
    struct ConstVisitor {
        names: HashSet<String>,
    }

    impl Visit<'_> for ConstVisitor {
        fn visit_item_const(&mut self, i: &syn::ItemConst) {
            self.names.insert(i.ident.to_string());
            visit::visit_item_const(self, i);
        }

        fn visit_item_static(&mut self, i: &syn::ItemStatic) {
            self.names.insert(i.ident.to_string());
            visit::visit_item_static(self, i);
        }
    }

    let mut visitor = ConstVisitor {
        names: HashSet::new(),
    };
    visitor.visit_file(file);
    visitor.names
}

struct StorageVisitor<'a> {
    fn_name: String,
    known_consts: &'a HashSet<String>,
    out: &'a mut Vec<Finding>,
}

impl Visit<'_> for StorageVisitor<'_> {
    fn visit_expr_method_call(&mut self, i: &ExprMethodCall) {
        let mut unwrap_lines = Vec::new();
        if is_temporary_get_unwrap(i) {
            unwrap_lines.push(i.method.span().start().line);
        }
        unwrap_lines.extend(temporary_update_closure_unwraps(i));
        for line in unwrap_lines {
            self.out.push(Finding {
                check_name: CHECK_NAME.to_string(),
                severity: Severity::Medium,
                file_path: String::new(),
                line,
                function_name: self.fn_name.clone(),
                description: format!(
                    "Method `{}` unwraps a value read from **temporary** storage. Temporary \
                     entries are deleted when their TTL lapses, so this panics once the entry \
                     has expired.",
                    self.fn_name
                ),
                rule_url: Some(
                    "https://github.com/SorobanGuard/Guard-CLI/blob/main/docs/checks.md#unsafe-storage-patterns-medium"
                        .to_string(),
                ),
                suggestion: Some(
                    "Handle the missing case: `match env.storage().temporary().get(&key) { Some(v) => .., None => .. }`, \
                     or `unwrap_or(default)`; in an `update`/`try_update` closure, match on the `Option` argument."
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
            && !symbol_new_second_arg_is_string_lit(i, self.known_consts)
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

    fn run_src(src: &str) -> Result<Vec<Finding>, syn::Error> {
        Ok(UnsafeStoragePatternsCheck.run(&parse_file(src)?, src))
    }

    /// #1055: `temporary().get(..).unwrap()` panics once the entry has expired.
    #[test]
    fn flags_temporary_get_unwrap_and_expect() -> Result<(), syn::Error> {
        let hits = run_src(
            r#"
use soroban_sdk::{contract, contractimpl, symbol_short, Env, Symbol};

#[contract]
pub struct C;

const K: Symbol = symbol_short!("k");

#[contractimpl]
impl C {
    pub fn load(env: Env) -> u32 {
        env.storage().temporary().get(&K).unwrap()
    }

    pub fn load_or_panic(env: Env) -> u32 {
        env.storage().temporary().get::<Symbol, u32>(&K).expect("expired")
    }
}
"#,
        )?;
        assert_eq!(hits.len(), 2, "{hits:?}");
        assert!(hits.iter().all(|h| h.description.contains("expired")));
        assert_eq!(hits[0].function_name, "load");
        assert_eq!(hits[1].function_name, "load_or_panic");
        Ok(())
    }

    /// #1055: unwrapping the `Option` handed to an `update` / `try_update` closure.
    #[test]
    fn flags_unwrap_in_temporary_update_closures() -> Result<(), syn::Error> {
        let hits = run_src(
            r#"
use soroban_sdk::{contract, contractimpl, symbol_short, Env, Symbol};

#[contract]
pub struct C;

const K: Symbol = symbol_short!("k");

#[contractimpl]
impl C {
    pub fn bump(env: Env) -> u32 {
        env.storage().temporary().update(&K, |old: Option<u32>| old.unwrap() + 1)
    }

    pub fn try_bump(env: Env) -> Result<u32, ()> {
        env.storage()
            .temporary()
            .try_update(&K, |old: Option<u32>| Ok(old.expect("expired") + 1))
    }
}
"#,
        )?;
        let unwraps: Vec<_> = hits
            .iter()
            .filter(|h| h.description.contains("unwraps"))
            .collect();
        assert_eq!(unwraps.len(), 2, "{hits:?}");
        Ok(())
    }

    /// #1055: handling the missing case, or persistent storage, is fine.
    #[test]
    fn ignores_handled_temporary_reads_and_persistent_unwrap() -> Result<(), syn::Error> {
        let hits = run_src(
            r#"
use soroban_sdk::{contract, contractimpl, symbol_short, Env, Symbol};

#[contract]
pub struct C;

const K: Symbol = symbol_short!("k");

#[contractimpl]
impl C {
    pub fn load(env: Env) -> u32 {
        env.storage().temporary().get(&K).unwrap_or(0)
    }

    pub fn load_match(env: Env) -> u32 {
        match env.storage().temporary().get::<Symbol, u32>(&K) {
            Some(v) => v,
            None => 0,
        }
    }

    pub fn load_persistent(env: Env) -> u32 {
        env.storage().persistent().get(&K).unwrap()
    }
}
"#,
        )?;
        assert!(hits.is_empty(), "{hits:?}");
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
    fn ignores_temporary_extend_ttl() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, symbol_short, Env};

pub struct C;

const K: soroban_sdk::Symbol = symbol_short!("k");

#[contractimpl]
impl C {
    pub fn keep(env: Env) {
        env.storage().temporary().extend_ttl(&K, 100, 1000);
    }
}
"#,
        )?;
        let hits = UnsafeStoragePatternsCheck.run(&file, "");
        assert!(hits.is_empty(), "{hits:?}");
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
    fn flags_fully_qualified_symbol_new_with_dynamic_key() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::Env;

pub struct C;

#[soroban_sdk::contractimpl]
impl C {
    pub fn put(env: Env, tag: soroban_sdk::String) {
        env.require_auth();
        let sym = soroban_sdk::Symbol::new(&env, tag);
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
    fn ignores_symbol_new_with_lowercase_named_const() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env, Symbol};

pub struct C;

const key: &str = "balance";

#[contractimpl]
impl C {
    pub fn put(env: Env) {
        env.require_auth();
        let sym = Symbol::new(&env, key);
        env.storage().persistent().set(&sym, &0u32);
    }
}
"#,
        )?;
        let hits = UnsafeStoragePatternsCheck.run(&file, "");
        assert!(
            hits.iter().all(|h| !h.description.contains("Symbol::new")),
            "a lowercase-named const is still a fixed literal, not a dynamic key: {hits:?}"
        );
        Ok(())
    }

    #[test]
    fn flags_symbol_new_with_uppercase_named_parameter() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env, Symbol};

pub struct C;

#[contractimpl]
impl C {
    pub fn put(env: Env, USER_SUPPLIED: soroban_sdk::String) {
        env.require_auth();
        let sym = Symbol::new(&env, USER_SUPPLIED);
        env.storage().persistent().set(&sym, &0u32);
    }
}
"#,
        )?;
        let hits = UnsafeStoragePatternsCheck.run(&file, "");
        assert_eq!(
            hits.iter().filter(|h| h.description.contains("Symbol::new")).count(),
            1,
            "an upper-cased parameter is still caller-controlled, not a stable const: {hits:?}"
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
