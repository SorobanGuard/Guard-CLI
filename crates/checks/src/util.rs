//! Shared helpers for walking `#[contractimpl]` impl blocks.

use std::collections::HashSet;
use syn::{Expr, FnArg, ImplItem, Item, ItemImpl, Pat, Signature, Type};

pub fn is_contractimpl(item_impl: &ItemImpl) -> bool {
    item_impl
        .attrs
        .iter()
        .any(|attr| path_is_contractimpl(attr.path()))
}

fn path_is_contractimpl(path: &syn::Path) -> bool {
    path.segments
        .last()
        .is_some_and(|s| s.ident == "contractimpl")
}

/// Does `attrs` contain a `#[cfg(...)]` predicate that gates its item to test
/// builds? Recognizes a bare `#[cfg(test)]` as well as `test` appearing
/// alongside other predicates inside `all(...)` / `any(...)`, e.g.
/// `#[cfg(all(test, not(target_arch = "wasm32")))]` or
/// `#[cfg(any(test, doctest))]` — both common ways Soroban crates gate
/// native-only test modules.
///
/// Deliberately does not look *inside* `not(...)`: `#[cfg(not(test))]` means
/// "only when NOT testing" (i.e. production code), and treating it as test
/// code would hide real code from every check that relies on this.
pub(crate) fn is_cfg_test(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        if !attr.path().is_ident("cfg") {
            return false;
        }
        attr.parse_args::<syn::Meta>()
            .map(|meta| meta_mentions_test(&meta))
            .unwrap_or(false)
    })
}

/// Does this `cfg` predicate mention the bare `test` identifier as one of
/// its own terms, recursing through nested `all(...)` / `any(...)`?
fn meta_mentions_test(meta: &syn::Meta) -> bool {
    match meta {
        syn::Meta::Path(path) => path.is_ident("test"),
        syn::Meta::List(list) if list.path.is_ident("all") || list.path.is_ident("any") => list
            .parse_args_with(syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated)
            .map(|metas| metas.iter().any(meta_mentions_test))
            .unwrap_or(false),
        _ => false,
    }
}

/// Every function item inside a `#[contractimpl]` impl that is **not** inside a
/// `#[cfg(test)]` module or a module named `tests`.
pub fn contractimpl_functions_excluding_test(file: &syn::File) -> Vec<&syn::ImplItemFn> {
    let mut out = Vec::new();
    collect_contractimpl_fns(&file.items, false, &mut out);
    out
}

/// The enclosing type's name for a `#[contractimpl]` block (e.g. `TokenContract` from
/// `impl TokenContract { ... }` or `impl Trait for TokenContract { ... }`). Empty string if
/// the self type isn't a simple path.
pub fn impl_type_name(item_impl: &ItemImpl) -> String {
    match &*item_impl.self_ty {
        syn::Type::Path(type_path) => type_path
            .path
            .segments
            .last()
            .map(|seg| seg.ident.to_string())
            .unwrap_or_default(),
        _ => String::new(),
    }
}

/// Like [`contractimpl_functions_excluding_test`] but paired with the name of the enclosing
/// type, so callers can disambiguate same-named methods on two different `#[contractimpl]`
/// types in the same file.
pub fn contractimpl_functions_with_type_excluding_test(
    file: &syn::File,
) -> Vec<(String, &syn::ImplItemFn)> {
    let mut out = Vec::new();
    collect_contractimpl_fns_with_type(&file.items, false, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse::Parser;
    use syn::parse_file;

    #[test]
    fn excludes_contractimpl_functions_inside_test_modules() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
#[contractimpl]
impl C {
    pub fn live(env: Env) {
        let _ = env;
    }
}

#[cfg(test)]
mod tests {
    use soroban_sdk::{contractimpl, Env};

    #[contractimpl]
    impl C {
        pub fn test_only(env: Env) {
            let _ = env;
        }
    }
}
"#,
        )?;

        let methods = contractimpl_functions_excluding_test(&file);
        assert_eq!(methods.len(), 1);
        assert_eq!(methods[0].sig.ident.to_string(), "live");
        Ok(())
    }

    #[test]
    fn excludes_contractimpl_functions_inside_cfg_all_test_not_wasm32_module() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
#[contractimpl]
impl C {
    pub fn live(env: Env) {
        let _ = env;
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod native {
    use soroban_sdk::{contractimpl, Env};

    #[contractimpl]
    impl C {
        pub fn test_only(env: Env) {
            let _ = env;
        }
    }
}
"#,
        )?;

        let methods = contractimpl_functions_excluding_test(&file);
        assert_eq!(methods.len(), 1);
        assert_eq!(methods[0].sig.ident.to_string(), "live");
        Ok(())
    }

    #[test]
    fn excludes_contractimpl_functions_inside_cfg_any_test_doctest_module() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
#[contractimpl]
impl C {
    pub fn live(env: Env) {
        let _ = env;
    }
}

#[cfg(any(test, doctest))]
mod integration {
    use soroban_sdk::{contractimpl, Env};

    #[contractimpl]
    impl C {
        pub fn test_only(env: Env) {
            let _ = env;
        }
    }
}
"#,
        )?;

        let methods = contractimpl_functions_excluding_test(&file);
        assert_eq!(methods.len(), 1);
        assert_eq!(methods[0].sig.ident.to_string(), "live");
        Ok(())
    }

    #[test]
    fn cfg_not_test_is_not_treated_as_test_code() {
        let attrs: Vec<syn::Attribute> = vec![syn::parse_quote!(#[cfg(not(test))])];
        assert!(
            !is_cfg_test(&attrs),
            "`#[cfg(not(test))]` gates production-only code, not test code"
        );
    }

    #[test]
    fn receiver_chain_contains_walks_a_nested_chain() -> Result<(), syn::Error> {
        // `env.storage().persistent().get(&key)` - the `get` call's receiver is
        // `env.storage().persistent()`, so the walk must pass through two method
        // calls and the `env` field/path to find each name.
        let expr: Expr = syn::parse_str("env.storage().persistent().get(&key)")?;
        let Expr::MethodCall(get_call) = &expr else {
            panic!("expected a method call");
        };

        assert!(receiver_chain_contains(&get_call.receiver, "storage"));
        assert!(receiver_chain_contains(&get_call.receiver, "persistent"));
        assert!(!receiver_chain_contains(&get_call.receiver, "temporary"));
        assert!(!receiver_chain_contains(&get_call.receiver, "events"));

        assert!(receiver_chain_contains_storage(&get_call.receiver));
        assert!(receiver_chain_contains_persistent(&get_call.receiver));
        Ok(())
    }

    #[test]
    fn pat_ident_name_reads_a_bare_binding() -> Result<(), syn::Error> {
        // `Pat` has no blanket `Parse` impl (it exposes explicit
        // `parse_single`/`parse_multi` associated functions instead), so it
        // must be parsed through the `Parser` trait rather than
        // `syn::parse_str::<Pat>`.
        let pat = Pat::parse_single.parse_str("admin")?;
        assert_eq!(pat_ident_name(&pat).as_deref(), Some("admin"));
        Ok(())
    }

    #[test]
    fn pat_ident_name_reads_a_type_ascribed_binding() -> Result<(), syn::Error> {
        // `Pat::parse_single` parses only the pattern grammar itself; the
        // `: Type` suffix that produces a `Pat::Type` is specific to where a
        // pattern is *used* (a `let` binding, here), not to `Pat` parsing in
        // general — so this needs a real `let` statement, matching how
        // `pat_ident_name` actually receives its input (`local.pat`).
        let syn::Stmt::Local(local) = syn::parse_str::<syn::Stmt>("let admin: Address = x;")? else {
            panic!("expected a let-binding statement");
        };
        assert_eq!(pat_ident_name(&local.pat).as_deref(), Some("admin"));
        Ok(())
    }

    #[test]
    fn pat_ident_name_is_none_for_a_non_ident_pattern() -> Result<(), syn::Error> {
        let pat = Pat::parse_single.parse_str("(a, b)")?;
        assert_eq!(pat_ident_name(&pat), None);
        Ok(())
    }
}

/// Does the receiver chain of `expr` contain a call to `.<method>()`? Walks back through
/// `Expr::MethodCall` receivers and `Expr::Field` bases. This is the single traversal the
/// `receiver_chain_contains_*` wrappers below share.
pub(crate) fn receiver_chain_contains(expr: &Expr, method: &str) -> bool {
    match expr {
        Expr::MethodCall(m) => m.method == method || receiver_chain_contains(&m.receiver, method),
        Expr::Field(f) => receiver_chain_contains(&f.base, method),
        _ => false,
    }
}

/// Does the receiver chain of `expr` contain a call to `.storage()`?
pub(crate) fn receiver_chain_contains_storage(expr: &Expr) -> bool {
    receiver_chain_contains(expr, "storage")
}

/// Does the receiver chain of `expr` contain a call to `.events()`?
pub(crate) fn receiver_chain_contains_events(expr: &Expr) -> bool {
    receiver_chain_contains(expr, "events")
}

/// Does this method call mutate persisted contract state in a way that requires prior
/// authorization?
///
/// Deliberately excludes `extend_ttl`/`bump`: extending a ledger entry's time-to-live does
/// not change the stored value, cannot move funds, and cannot escalate privilege — in Soroban
/// it is a deliberately permissionless operation (anyone paying the rent may keep an entry
/// alive). Only `set`, `remove`, and `append` actually change what is stored.
pub(crate) fn is_storage_mutation_call(m: &syn::ExprMethodCall) -> bool {
    let name = m.method.to_string();
    if !matches!(name.as_str(), "set" | "remove" | "append") {
        return false;
    }
    receiver_chain_contains_storage(&m.receiver)
}

/// Is `receiver` something `.require_auth()` / `.require_auth_for_args()` can be legally
/// called on? Recognizes the `Env` parameter, `Address` parameters, function-local bindings
/// of type `Address`, field accesses (`self.admin`, `self.owner`), and method-chain receivers
/// (`admin.clone()`, `get_admin(&env)`) — all of which yield an `Address`/auth-invoker in
/// practice. A bare path that is none of the above (a random local) is *not* treated as an
/// auth gate, so unrelated `.require_auth()` calls don't silence the check.
pub(crate) fn receiver_is_auth_gate(
    receiver: &Expr,
    env_name: &str,
    address_names: &[String],
    address_locals: &HashSet<String>,
) -> bool {
    match receiver {
        Expr::Path(p) => {
            p.path.is_ident(env_name)
                || address_names.iter().any(|a| p.path.is_ident(a))
                || p.path
                    .get_ident()
                    .map(|i| address_locals.contains(&i.to_string()))
                    .unwrap_or(false)
        }
        Expr::Field(_) | Expr::MethodCall(_) => true,
        _ => false,
    }
}

/// Does the receiver chain of `expr` contain a call to `.temporary()`?
pub(crate) fn receiver_chain_contains_temporary(expr: &Expr) -> bool {
    receiver_chain_contains(expr, "temporary")
}

/// Does the receiver chain of `expr` contain a call to `.persistent()`?
pub(crate) fn receiver_chain_contains_persistent(expr: &Expr) -> bool {
    receiver_chain_contains(expr, "persistent")
}

/// Is `name` one of the Soroban SDK cross-contract call entry points —
/// `invoke_contract`, `invoke_contract_check`, or the fallible `try_invoke_contract`?
/// Shared by the checks that need to recognise a cross-contract call regardless of
/// which entry point was used.
pub(crate) fn is_invoke_contract_method_name(name: &str) -> bool {
    matches!(
        name,
        "invoke_contract" | "invoke_contract_check" | "try_invoke_contract"
    )
}

/// Returns the name of the first parameter whose type is `Env` (or `soroban_sdk::Env`).
pub fn env_param_name(sig: &Signature) -> Option<String> {
    for arg in &sig.inputs {
        let FnArg::Typed(pat_type) = arg else {
            continue;
        };
        if !type_is_env(&pat_type.ty) {
            continue;
        }
        if let Pat::Ident(ident) = &*pat_type.pat {
            return Some(ident.ident.to_string());
        }
    }
    None
}

pub fn type_is_env(ty: &Type) -> bool {
    let Type::Path(tp) = ty else {
        return false;
    };
    tp.path.segments.last().is_some_and(|s| s.ident == "Env")
}

pub fn type_is_address(ty: &Type) -> bool {
    let Type::Path(tp) = ty else {
        return false;
    };
    tp.path.segments.last().is_some_and(|s| s.ident == "Address")
}

/// The bound name of a (possibly type-ascribed) pattern, e.g. `admin` from
/// both `admin` and `admin: Address`. `None` for anything else (a tuple,
/// wildcard, etc.) — those don't bind a single name a check could track.
///
/// Lives here once so every check that needs the name a `let` binds shares
/// it, rather than each keeping its own private copy.
pub(crate) fn pat_ident_name(pat: &Pat) -> Option<String> {
    match pat {
        Pat::Ident(ident) => Some(ident.ident.to_string()),
        Pat::Type(pat_type) => pat_ident_name(&pat_type.pat),
        _ => None,
    }
}

/// Name fragments that mark a `let` binding read from storage as the
/// privileged account (e.g. `admin`, `owner`). Shared so the admin, upgrade,
/// and deployment checks can't drift apart.
const ADMIN_VAR_KEYWORDS: &[&str] = &["admin", "authority", "owner", "caller"];

/// `true` if `name` looks like a binding holding the privileged account.
pub(crate) fn is_admin_var_name(name: &str) -> bool {
    let lower = name.to_lowercase();
    ADMIN_VAR_KEYWORDS.iter().any(|k| lower.contains(k))
}

/// Names of every `Address`-typed parameter.
pub fn address_param_names(sig: &Signature) -> Vec<String> {
    let mut names = Vec::new();
    for arg in &sig.inputs {
        let FnArg::Typed(pat_type) = arg else {
            continue;
        };
        if type_is_address(&pat_type.ty) {
            if let Pat::Ident(ident) = &*pat_type.pat {
                names.push(ident.ident.to_string());
            }
        }
    }
    names
}

fn collect_contractimpl_fns<'a>(
    items: &'a [Item],
    in_test_mod: bool,
    out: &mut Vec<&'a syn::ImplItemFn>,
) {
    for item in items {
        match item {
            Item::Mod(m) => {
                let is_test = in_test_mod
                    || is_cfg_test(&m.attrs)
                    || m.ident == "tests"
                    || m.ident == "test";
                if let Some((_, nested)) = &m.content {
                    collect_contractimpl_fns(nested, is_test, out);
                }
            }
            Item::Impl(item_impl) if !in_test_mod && is_contractimpl(item_impl) => {
                for impl_item in &item_impl.items {
                    if let ImplItem::Fn(m) = impl_item {
                        out.push(m);
                    }
                }
            }
            _ => {}
        }
    }
}

fn collect_contractimpl_fns_with_type<'a>(
    items: &'a [Item],
    in_test_mod: bool,
    out: &mut Vec<(String, &'a syn::ImplItemFn)>,
) {
    for item in items {
        match item {
            Item::Mod(m) => {
                let is_test = in_test_mod
                    || is_cfg_test(&m.attrs)
                    || m.ident == "tests"
                    || m.ident == "test";
                if let Some((_, nested)) = &m.content {
                    collect_contractimpl_fns_with_type(nested, is_test, out);
                }
            }
            Item::Impl(item_impl) if !in_test_mod && is_contractimpl(item_impl) => {
                let type_name = impl_type_name(item_impl);
                for impl_item in &item_impl.items {
                    if let ImplItem::Fn(m) = impl_item {
                        out.push((type_name.clone(), m));
                    }
                }
            }
            _ => {}
        }
    }
}

use std::collections::HashMap;

/// Centralised `use`-alias resolution for Soroban SDK imports (closes #981).
///
/// Builds a map from the *local* identifier (what appears in code) to the
/// *canonical* Soroban SDK item name, handling:
///
/// - `use soroban_sdk::Env` → `"Env" → "Env"`
/// - `use soroban_sdk::Env as E` → `"E" → "Env"`
/// - `use soroban_sdk::{Env, Address as Addr}` → both resolved
/// - `use soroban_sdk::*` → all known SDK items added under their canonical name
/// - Nested group trees
///
/// Unknown paths are not added, so a query that returns `None` means no alias
/// was found in this file.
pub struct ImportMap {
    /// local name → canonical SDK item name
    map: HashMap<String, String>,
}

impl ImportMap {
    const KNOWN_SDK_ITEMS: &'static [&'static str] = &[
        "Env", "Address", "Symbol", "Bytes", "BytesN", "String", "Map", "Vec",
        "TokenClient", "token",
    ];

    /// Build an `ImportMap` from a parsed file.
    pub fn from_file(file: &syn::File) -> Self {
        let mut map = HashMap::new();
        for item in &file.items {
            if let syn::Item::Use(u) = item {
                Self::collect_use_tree(&u.tree, &[], &mut map);
            }
        }
        ImportMap { map }
    }

    fn collect_use_tree(
        tree: &syn::UseTree,
        prefix: &[String],
        map: &mut HashMap<String, String>,
    ) {
        match tree {
            syn::UseTree::Path(p) => {
                let mut new_prefix = prefix.to_vec();
                new_prefix.push(p.ident.to_string());
                Self::collect_use_tree(&p.tree, &new_prefix, map);
            }
            syn::UseTree::Name(n) => {
                let local = n.ident.to_string();
                let canonical = Self::canonical_from_prefix_and_local(prefix, &local);
                if let Some(c) = canonical {
                    map.insert(local, c);
                }
            }
            syn::UseTree::Rename(r) => {
                let original = r.ident.to_string();
                let alias = r.rename.to_string();
                let canonical = Self::canonical_from_prefix_and_local(prefix, &original);
                if let Some(c) = canonical {
                    map.insert(alias, c);
                }
            }
            syn::UseTree::Glob(_) => {
                // `use soroban_sdk::*` — add all known items if path ends with soroban_sdk.
                if prefix.last().map(|s| s == "soroban_sdk").unwrap_or(false) {
                    for item in Self::KNOWN_SDK_ITEMS {
                        map.insert(item.to_string(), item.to_string());
                    }
                }
            }
            syn::UseTree::Group(g) => {
                for tree in &g.items {
                    Self::collect_use_tree(tree, prefix, map);
                }
            }
        }
    }

    fn canonical_from_prefix_and_local(prefix: &[String], local: &str) -> Option<String> {
        // Only resolve items from soroban_sdk.
        if prefix.iter().any(|p| p == "soroban_sdk") {
            if Self::KNOWN_SDK_ITEMS.contains(&local) {
                return Some(local.to_string());
            }
        }
        None
    }

    /// Return the canonical Soroban SDK name for a local identifier, if known.
    ///
    /// Returns `None` when the identifier wasn't imported from `soroban_sdk`.
    pub fn canonical_name<'a>(&'a self, local: &str) -> Option<&'a str> {
        self.map.get(local).map(String::as_str)
    }

    /// Returns `true` if `local` resolves to the given `canonical` SDK item.
    pub fn is_soroban_item(&self, local: &str, canonical: &str) -> bool {
        self.map.get(local).map(|c| c == canonical).unwrap_or(false)
    }
}

#[cfg(test)]
mod import_map_tests {
    use super::*;
    use syn::parse_file;

    fn map(src: &str) -> ImportMap {
        let file = parse_file(src).expect("parse");
        ImportMap::from_file(&file)
    }

    #[test]
    fn resolves_direct_import() {
        let m = map("use soroban_sdk::Env;");
        assert_eq!(m.canonical_name("Env"), Some("Env"));
        assert!(m.is_soroban_item("Env", "Env"));
    }

    #[test]
    fn resolves_rename() {
        let m = map("use soroban_sdk::Env as E;");
        assert_eq!(m.canonical_name("E"), Some("Env"));
        assert!(m.is_soroban_item("E", "Env"));
        assert_eq!(m.canonical_name("Env"), None, "original name not in scope");
    }

    #[test]
    fn resolves_group_import() {
        let m = map("use soroban_sdk::{Env, Address as Addr};");
        assert_eq!(m.canonical_name("Env"), Some("Env"));
        assert_eq!(m.canonical_name("Addr"), Some("Address"));
        assert_eq!(m.canonical_name("Address"), None, "Address aliased to Addr only");
    }

    #[test]
    fn resolves_glob_import() {
        let m = map("use soroban_sdk::*;");
        assert_eq!(m.canonical_name("Env"), Some("Env"));
        assert_eq!(m.canonical_name("Address"), Some("Address"));
    }

    #[test]
    fn non_soroban_import_not_resolved() {
        let m = map("use std::collections::HashMap;");
        assert_eq!(m.canonical_name("HashMap"), None);
    }

    #[test]
    fn unknown_identifier_returns_none() {
        let m = map("use soroban_sdk::Env;");
        assert_eq!(m.canonical_name("Token"), None);
    }
}
