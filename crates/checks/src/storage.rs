//! Risky Soroban storage usage: temporary persistence and caller-derived `Symbol` keys.

use crate::util::{
    contractimpl_functions_excluding_test, receiver_chain_contains_storage,
    receiver_chain_contains_temporary,
};
use crate::{Check, Finding, Severity};
use std::collections::{HashMap, HashSet};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprCall, ExprMethodCall, File, Pat, Stmt, Type};

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
            let collection_locals = collect_collection_locals(&method.block);
            let mut v = StorageVisitor {
                fn_name: fn_name.clone(),
                known_consts: &known_consts,
                collection_locals: &collection_locals,
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

/// True when the type path's last segment names a collection type we care
/// about (`Vec`, `Map`, `Bytes`).
fn type_is_collection(ty: &Type) -> bool {
    let Type::Path(tp) = ty else {
        return false;
    };
    tp.path
        .segments
        .last()
        .is_some_and(|s| matches!(s.ident.to_string().as_str(), "Vec" | "Map" | "Bytes"))
}

/// True when the expression is a collection constructor visible in the
/// function: `Vec::new`, `Map::new`, `Bytes::new`, or a `vec![]` macro.
fn expr_is_collection_ctor(expr: &Expr) -> bool {
    match expr {
        Expr::Call(call) => {
            let Expr::Path(p) = &*call.func else {
                return false;
            };
            let mut rev = p.path.segments.iter().rev();
            let (Some(last), Some(second_last)) = (rev.next(), rev.next()) else {
                return false;
            };
            last.ident == "new"
                && matches!(
                    second_last.ident.to_string().as_str(),
                    "Vec" | "Map" | "Bytes"
                )
        }
        Expr::Macro(m) => m
            .mac_path
            .segments
            .last()
            .is_some_and(|s| s.ident == "vec"),
        _ => false,
    }
}

/// Collects local bindings in the function body whose value is a collection,
/// limited to what is visible: `let v: Vec<_> = ...`, `let v = Vec::new()`,
/// `let v = Map::new()`, `let v = vec![]`.
fn collect_collection_locals(block: &syn::Block) -> HashMap<String, ()> {
    let mut names = HashMap::new();
    for stmt in &block.stmts {
        let Stmt::Local(local) = stmt else {
            continue;
        };
        let Pat::Ident(pat_ident) = &local.pat else {
            continue;
        };
        let name = pat_ident.ident.to_string();
        let typed = local
            .ty
            .as_ref()
            .is_some_and(|(_, ty)| type_is_collection(ty));
        let init_is_ctor = local
            .init
            .as_ref()
            .is_some_and(|init| expr_is_collection_ctor(&init.expr));
        if typed || init_is_ctor {
            names.insert(name, ());
        }
    }
    names
}

/// True when the value argument to `set` is a collection: a known local
/// collection binding, or an inline collection constructor.
fn value_is_collection(expr: &Expr, collection_locals: &HashMap<String, ()>) -> bool {
    match expr {
        Expr::Path(p) => p
            .path
            .segments
            .last()
            .is_some_and(|s| collection_locals.contains_key(&s.ident.to_string())),
        _ => expr_is_collection_ctor(expr),
    }
}

/// `env.storage().instance().set(&key, &value)` where `value` is a collection.
fn is_instance_storage_collection_set(
    m: &ExprMethodCall,
    collection_locals: &HashMap<String, ()>,
) -> bool {
    if m.method != "set" {
        return false;
    }
    if !receiver_chain_contains_storage(&m.receiver) {
        return false;
    }
    // Receiver must be the instance storage accessor, not temporary/persistent.
    let Expr::MethodCall(instance_call) = &*m.receiver else {
        return false;
    };
    if instance_call.method != "instance" {
        return false;
    }
    let Some(value_arg) = m.args.iter().nth(1) else {
        return false;
    };
    let value_expr = match value_arg {
        Expr::Reference(r) => &*r.expr,
        other => other,
    };
    value_is_collection(value_expr, collection_locals)
}

struct StorageVisitor<'a> {
    fn_name: String,
    known_consts: &'a HashSet<String>,
    collection_locals: &'a HashMap<String, ()>,
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
        if is_instance_storage_collection_set(i, self.collection_locals) {
            self.out.push(Finding {
                check_name: CHECK_NAME.to_string(),
                severity: Severity::Low,
                file_path: String::new(),
                line: i.span().start().line,
                function_name: self.fn_name.clone(),
                description: format!(
                    "Method `{}` stores a collection (`Vec`/`Map`/`Bytes`) in **instance** storage. \
                     Instance storage is loaded in full on every invocation and shares one TTL, so a \
                     growing collection increases the cost of every call, including unrelated ones.",
                    self.fn_name
                ),
                rule_url: Some(
                    "https://github.com/SorobanGuard/Guard-CLI/blob/main/docs/checks.md#instance-storage-collection-low"
                        .to_string(),
                ),
                suggestion: Some(
                    "Store collections in `env.storage().persistent()` (or split into per-key entries) so cost and TTL are scoped to the data actually used."
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
                    "Use `symbol_short!(\"KEY\")` or a `const` string literal for storage keys."
                        .to_string(),
                ),
            });
        }
        visit::visit_expr_call(self, i);
    }
}
