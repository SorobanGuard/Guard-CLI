//! Risky Soroban storage usage: temporary persistence and caller-derived `Symbol` keys.

use crate::util::is_temporary_storage_mutation_call;
use crate::util::{
    contractimpl_functions_excluding_test, receiver_chain_contains_storage,
    receiver_chain_contains_temporary,
};
use crate::{Check, Finding, Severity};
use std::collections::{HashMap, HashSet};
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
                dynamic_symbol_locals: HashMap::new(),
                reported_lines: HashSet::new(),
            };
            v.visit_block(&method.block);
        }
        out
    }
}

fn is_temporary_get_unchecked(m: &ExprMethodCall) -> bool {
    m.method == "get_unchecked"
        && receiver_chain_contains_storage(&m.receiver)
        && receiver_chain_contains_temporary(&m.receiver)
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
    /// Local bindings whose value was built from a dynamic `Symbol::new`, mapped to the
    /// line of that `Symbol::new` call (e.g. `let key = Symbol::new(&env, &name);`).
    dynamic_symbol_locals: HashMap<String, usize>,
    /// Lines already reported, so a key used by several storage calls is reported once.
    reported_lines: HashSet<usize>,
}

/// Storage methods whose first argument is a key.
const STORAGE_KEY_METHODS: &[&str] = &[
    "get",
    "get_unchecked",
    "has",
    "set",
    "remove",
    "update",
    "try_update",
    "extend_ttl",
    "bump",
    "append",
];

/// First line of a `Symbol::new(&env, <non-literal>)` call anywhere inside `expr`.
fn find_dynamic_symbol_new(expr: &Expr, known_consts: &HashSet<String>) -> Option<usize> {
    struct Finder<'a> {
        known_consts: &'a HashSet<String>,
        line: Option<usize>,
    }
    impl Visit<'_> for Finder<'_> {
        fn visit_expr_call(&mut self, i: &ExprCall) {
            if self.line.is_none()
                && is_symbol_new_path(&i.func)
                && i.args.len() >= 2
                && !symbol_new_second_arg_is_string_lit(i, self.known_consts)
            {
                self.line = Some(i.span().start().line);
            }
            visit::visit_expr_call(self, i);
        }
    }
    let mut finder = Finder {
        known_consts,
        line: None,
    };
    finder.visit_expr(expr);
    finder.line
}

/// Line of the dynamic `Symbol::new` behind the first tracked local referenced in `expr`.
fn find_dynamic_symbol_local(expr: &Expr, locals: &HashMap<String, usize>) -> Option<usize> {
    struct Finder<'a> {
        locals: &'a HashMap<String, usize>,
        line: Option<usize>,
    }
    impl Visit<'_> for Finder<'_> {
        fn visit_expr_path(&mut self, i: &syn::ExprPath) {
            if self.line.is_none() {
                if let Some(ident) = i.path.get_ident() {
                    self.line = self.locals.get(&ident.to_string()).copied();
                }
            }
            visit::visit_expr_path(self, i);
        }
    }
    let mut finder = Finder { locals, line: None };
    finder.visit_expr(expr);
    finder.line
}

impl StorageVisitor<'_> {
    /// Line of a dynamic `Symbol::new` that flows into `expr`, directly or through a local.
    fn dynamic_symbol_origin(&self, expr: &Expr) -> Option<usize> {
        find_dynamic_symbol_new(expr, self.known_consts)
            .or_else(|| find_dynamic_symbol_local(expr, &self.dynamic_symbol_locals))
    }

    fn report_dynamic_symbol_key(&mut self, line: usize) {
        if !self.reported_lines.insert(line) {
            return;
        }
        self.out.push(Finding {
            check_name: CHECK_NAME.to_string(),
            severity: Severity::Medium,
            file_path: String::new(),
            line,
            function_name: self.fn_name.clone(),
            description: format!(
                "`Symbol::new` in `{}` builds a storage key from a non-literal string. Keys \
                 derived from caller input are easier to guess or collide with; prefer \
                 `symbol_short!` / fixed literals or a namespaced encoding you control.",
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
}

impl Visit<'_> for StorageVisitor<'_> {
    fn visit_expr_method_call(&mut self, i: &ExprMethodCall) {
        // A dynamic `Symbol::new` only matters when it becomes a storage key; function
        // names for `invoke_contract` and event topics are not storage keys (#1054).
        if STORAGE_KEY_METHODS.contains(&i.method.to_string().as_str())
            && receiver_chain_contains_storage(&i.receiver)
        {
            if let Some(line) = i
                .args
                .first()
                .and_then(|key| self.dynamic_symbol_origin(key))
            {
                self.report_dynamic_symbol_key(line);
            }
        }
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
        if is_temporary_storage_mutation_call(i) {
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

    fn visit_local(&mut self, i: &syn::Local) {
        // Visit the initializer first so nested storage calls are checked, then record
        // whether this binding carries a dynamic symbol for later storage-key uses.
        visit::visit_local(self, i);
        if let (Some(init), Some(name)) = (&i.init, crate::util::pat_ident_name(&i.pat)) {
            match self.dynamic_symbol_origin(&init.expr) {
                Some(line) => {
                    self.dynamic_symbol_locals.insert(name, line);
                }
                None => {
                    // Shadowing with a clean value clears the taint.
                    self.dynamic_symbol_locals.remove(&name);
                }
            }
        }
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

    /// #1051: an `update` on temporary storage is a temporary-storage write.
    #[test]
    fn flags_temporary_update() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, symbol_short, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn bump_count(env: Env) {
        env.storage().temporary().update(&symbol_short!("n"), |old: Option<u32>| old.unwrap_or(0) + 1);
    }
}
"#,
        )?;
        let hits = UnsafeStoragePatternsCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        assert!(hits[0].description.contains("temporary"));
        Ok(())
    }

    /// #1054: a dynamic symbol used as an `invoke_contract` function name is not a key.
    #[test]
    fn ignores_dynamic_symbol_used_as_function_name() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Address, Env, String, Symbol, Val, Vec};
pub struct C;
#[contractimpl]
impl C {
    pub fn call(env: Env, id: Address, fn_name: String, args: Vec<Val>) {
        env.invoke_contract::<Val>(&id, &Symbol::new(&env, &fn_name), args);
        let name = Symbol::new(&env, &fn_name);
        env.invoke_contract::<Val>(&id, &name, Vec::new(&env));
    }
}
"#,
        )?;
        let hits = UnsafeStoragePatternsCheck.run(&file, "");
        assert!(hits.is_empty(), "{hits:?}");
        Ok(())
    }

    /// #1054: a dynamic symbol used as an event topic is not a key.
    #[test]
    fn ignores_dynamic_symbol_used_as_event_topic() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env, String, Symbol};
pub struct C;
#[contractimpl]
impl C {
    pub fn emit(env: Env, kind: String, data: u32) {
        env.events().publish((Symbol::new(&env, &kind),), data);
        let topic = Symbol::new(&env, &kind);
        env.events().publish((topic,), data);
    }
}
"#,
        )?;
        let hits = UnsafeStoragePatternsCheck.run(&file, "");
        assert!(hits.is_empty(), "{hits:?}");
        Ok(())
    }

    /// #1054: a dynamic symbol passed straight into a storage call is still a key.
    #[test]
    fn flags_inline_dynamic_symbol_storage_key() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env, String, Symbol};
pub struct C;
#[contractimpl]
impl C {
    pub fn put(env: Env, tag: String, v: u32) {
        env.require_auth();
        env.storage().persistent().set(&Symbol::new(&env, &tag), &v);
    }
}
"#,
        )?;
        let hits = UnsafeStoragePatternsCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].line, 8);
        Ok(())
    }

    /// #1054: taint follows a key built from the symbol and re-bound through locals, and a
    /// key used by several storage calls is reported once.
    #[test]
    fn flags_dynamic_symbol_through_locals_once() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Address, Env, String, Symbol};
pub struct C;
#[contractimpl]
impl C {
    pub fn put(env: Env, user: Address, tag: String, v: u32) {
        env.require_auth();
        let sym = Symbol::new(&env, &tag);
        let key = (sym, user);
        if !env.storage().persistent().has(&key) {
            env.storage().persistent().update(&key, |_old: Option<u32>| v);
        }
    }
}
"#,
        )?;
        let hits = UnsafeStoragePatternsCheck.run(&file, "");
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert_eq!(hits[0].line, 8);
        Ok(())
    }

    /// #1054: re-binding a name to a clean value clears it.
    #[test]
    fn ignores_shadowed_dynamic_symbol() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, symbol_short, Env, String, Symbol};
pub struct C;
#[contractimpl]
impl C {
    pub fn put(env: Env, tag: String, v: u32) {
        env.require_auth();
        let key = Symbol::new(&env, &tag);
        env.events().publish((key,), v);
        let key = symbol_short!("fixed");
        env.storage().persistent().set(&key, &v);
    }
}
"#,
        )?;
        let hits = UnsafeStoragePatternsCheck.run(&file, "");
        assert!(hits.is_empty(), "{hits:?}");
        Ok(())
    }
}
