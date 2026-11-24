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

    #[test]
    fn sensitive_names_matches_exact_names() {
        let m = SensitiveNames::with_defaults(&["set_admin"], &[]);
        assert!(m.matches("set_admin"));
        assert!(!m.matches("set_admin_and_owner"));
        assert!(!m.matches("update_admin"));
    }

    #[test]
    fn sensitive_names_matches_prefix_entries() {
        let m = SensitiveNames::with_defaults(&[], &["set_admin*".to_string()]);
        assert!(m.matches("set_admin"));
        assert!(m.matches("set_admin_and_owner"));
        assert!(!m.matches("update_admin"));
    }

    #[test]
    fn sensitive_names_matches_glob_entries() {
        let m = SensitiveNames::with_defaults(&[], &["*_admin".to_string()]);
        assert!(m.matches("set_admin"));
        assert!(m.matches("update_admin"));
        assert!(!m.matches("set_owner"));
    }

    #[test]
    fn sensitive_names_extra_widens_defaults() {
        let m = SensitiveNames::with_defaults(&["set_admin"], &["custom_priv".to_string()]);
        assert!(m.matches("set_admin"));
        assert!(m.matches("custom_priv"));
        assert!(!m.matches("other"));
    }

    #[test]
    fn sensitive_names_ignores_blank_entries() {
        let m = SensitiveNames::new(&["".to_string(), "  ".to_string()]);
        assert!(m.is_empty());
    }

    #[test]
    fn default_admin_names_include_reconciled_entries() {
        let m = SensitiveNames::with_defaults(DEFAULT_ADMIN_NAMES, &[]);
        for name in ["update_admin", "set_manager", "set_operator", "set_wasm", "replace_wasm", "mint", "burn", "issue", "redeem", "create_tokens"] {
            assert!(m.matches(name), "expected `{name}` to be a default admin name");
        }
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

/// Canonical default list of privileged/admin function names, shared by every
/// name-gated check so the per-check lists can't drift apart again.
///
/// This reconciles the previously separate `SENSITIVE_NAMES` / `MINT_NAMES`
/// constants: it is the union of the admin, zero-address, upgrade, token-mint
/// and admin-event lists (e.g. `update_admin` / `set_manager` used to exist
/// only in the zero-address list).
pub const DEFAULT_ADMIN_NAMES: &[&str] = &[
    // admin / ownership
    "set_admin",
    "update_admin",
    "change_admin",
    "transfer_admin",
    "set_owner",
    "update_owner",
    "change_owner",
    "transfer_owner",
    "set_manager",
    "update_manager",
    "set_operator",
    "update_operator",
    "set_authority",
    "update_authority",
    "set_governance",
    "update_governance",
    "set_governor",
    "update_governor",
    "set_controller",
    "update_controller",
    // upgrade / wasm
    "set_wasm",
    "update_wasm",
    "replace_wasm",
    "upgrade",
    "migrate",
    // token supply
    "mint",
    "burn",
    "issue",
    "redeem",
    "create_tokens",
    "clawback",
    "set_authorized",
    "set_authorized_amount",
    // pause / freeze
    "pause",
    "unpause",
    "freeze",
    "unfreeze",
    "set_paused",
    "set_frozen",
];

/// Default names for the token-mint check. A subset of [`DEFAULT_ADMIN_NAMES`]
/// covering the supply-changing entry points.
pub const DEFAULT_MINT_NAMES: &[&str] = &[
    "mint",
    "burn",
    "issue",
    "redeem",
    "create_tokens",
    "clawback",
];

/// Default names for the zero-address check: setters that take an `Address`
/// and must reject the zero address.
pub const DEFAULT_ZERO_ADDRESS_NAMES: &[&str] = &[
    "set_admin",
    "update_admin",
    "change_admin",
    "transfer_admin",
    "set_owner",
    "update_owner",
    "change_owner",
    "transfer_owner",
    "set_manager",
    "update_manager",
    "set_operator",
    "update_operator",
    "set_authority",
    "update_authority",
    "set_governance",
    "update_governance",
    "set_governor",
    "update_governor",
    "set_controller",
    "update_controller",
    "set_recipient",
    "update_recipient",
    "set_beneficiary",
    "update_beneficiary",
    "set_treasury",
    "update_treasury",
];

/// Default names for the upgrade check.
pub const DEFAULT_UPGRADE_NAMES: &[&str] = &["set_wasm", "update_wasm", "replace_wasm", "upgrade", "migrate"];

/// Default names for the admin-event check: privileged mutators that should
/// emit an event.
pub const DEFAULT_ADMIN_EVENT_NAMES: &[&str] = DEFAULT_ADMIN_NAMES;

/// Shared, configurable matcher for privileged function names.
///
/// Matching semantics (as documented in `docs/configuration.md`):
/// - an entry with no wildcard matches the function name **exactly**;
/// - an entry ending in `*` is a **prefix** match (`set_admin*` matches
///   `set_admin` and `set_admin_and_owner`);
/// - an entry containing `*` elsewhere is a **glob** match (`*_admin` matches
///   `set_admin` and `update_admin`).
///
/// `extra` entries are appended to the built-in defaults, so a config can only
/// widen the set of names a check treats as privileged, never narrow it.
#[derive(Debug, Clone, Default)]
pub struct SensitiveNames {
    exact: Vec<String>,
    prefixes: Vec<String>,
    globs: Vec<String>,
}

impl SensitiveNames {
    /// Build a matcher from `extra` entries only (no built-in defaults).
    pub fn new(extra: &[String]) -> Self {
        let mut matcher = Self::default();
        for entry in extra {
            matcher.push(entry);
        }
        matcher
    }

    /// Build a matcher from `defaults` plus the user-supplied `extra` entries.
    pub fn with_defaults(defaults: &[&str], extra: &[String]) -> Self {
        let mut matcher = Self::default();
        for entry in defaults {
            matcher.push(entry);
        }
        for entry in extra {
            matcher.push(entry);
        }
        matcher
    }

    fn push(&mut self, entry: &str) {
        let entry = entry.trim();
        if entry.is_empty() {
            return;
        }
        if let Some(prefix) = entry.strip_suffix('*') {
            if prefix.contains('*') {
                self.globs.push(entry.to_string());
            } else {
                self.prefixes.push(prefix.to_string());
            }
        } else if entry.contains('*') {
            self.globs.push(entry.to_string());
        } else {
            self.exact.push(entry.to_string());
        }
    }

    /// Does `name` match any exact entry, prefix, or glob in this matcher?
    pub fn matches(&self, name: &str) -> bool {
        self.exact.iter().any(|e| e == name)
            || self.prefixes.iter().any(|p| name.starts_with(p.as_str()))
            || self.globs.iter().any(|g| glob_matches(g, name))
    }

    /// `true` if this matcher has no entries at all.
    pub fn is_empty(&self) -> bool {
        self.exact.is_empty() && self.prefixes.is_empty() && self.globs.is_empty()
    }
}

/// Minimal `*`-wildcard glob matcher (no `?`, no character classes). Iterative
/// backtracking so it stays linear-ish in practice without recursion.
fn glob_matches(pattern: &str, name: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let name: Vec<char> = name.chars().collect();
    let (mut p, mut n) = (0usize, 0usize);
    let mut star: Option<usize> = None;
    let mut star_match = 0usize;
    while n < name.len() {
        if p < pattern.len() && pattern[p] == name[n] {
            p += 1;
            n += 1;
        } else if p < pattern.len() && pattern[p] == '*' {
            star = Some(p);
            star_match = n;
            p += 1;
        } else if let Some(star_pos) = star {
            p = star_pos + 1;
            star_match += 1;
            n = star_match;
        } else {
            return false;
        }
    }
    while p < pattern.len() && pattern[p] == '*' {
        p += 1;
    }
    p == pattern.len()
}

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
