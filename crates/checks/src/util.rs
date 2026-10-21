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
    fn getter_name_matches_default_patterns() {
        assert!(is_getter_name("get_balance", &[]));
        assert!(is_getter_name("is_frozen", &[]));
        assert!(is_getter_name("view_admin", &[]));
        assert!(is_getter_name("balance_of", &[]));
        assert!(is_getter_name("balance", &[]));
        assert!(is_getter_name("total_supply", &[]));
        assert!(!is_getter_name("transfer", &[]));
        assert!(!is_getter_name("set_admin", &[]));
    }

    #[test]
    fn getter_name_honours_custom_patterns() {
        assert!(is_getter_name("fetch_admin", &["fetch_"]));
        assert!(!is_getter_name("get_admin", &["fetch_"]));
    }

    #[test]
    fn transfer_params_are_classified_by_side() -> Result<(), syn::Error> {
        let sig: Signature = syn::parse_str(
            "fn transfer(env: Env, from: Address, to: Address, owner: Address, recipient: Address)",
        )?;
        let (debit, credit) = classify_transfer_params(&sig);
        assert_eq!(debit, vec!["from".to_string(), "owner".to_string()]);
        assert_eq!(credit, vec!["to".to_string(), "recipient".to_string()]);
        Ok(())
    }

    #[test]
    fn transfer_param_names_do_not_match_substrings() {
        assert!(is_debit_side_param_name("from_addr"));
        assert!(is_debit_side_param_name("token_owner"));
        assert!(!is_debit_side_param_name("platform"));
        assert!(is_credit_side_param_name("to"));
        assert!(!is_credit_side_param_name("token"));
    }

    #[test]
    fn receiver_refers_to_param_handles_clone_and_deref() -> Result<(), syn::Error> {
        let clone: Expr = syn::parse_str("from.clone()")?;
        assert!(receiver_refers_to_param(&clone, "from"));
        let deref: Expr = syn::parse_str("*from")?;
        assert!(receiver_refers_to_param(&deref, "from"));
        let other: Expr = syn::parse_str("to")?;
        assert!(!receiver_refers_to_param(&other, "from"));
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

/// Default name fragments that mark a `#[contractimpl]` method as a read-only getter.
/// Matched case-insensitively against the method name: a name starting with `get_`,
/// `is_`, or `view_`, ending with `_of`, or equal to `balance` / `total_supply`.
pub(crate) const DEFAULT_GETTER_PATTERNS: &[&str] = &[
    "get_",
    "is_",
    "view_",
    "_of",
    "balance",
    "total_supply",
];

/// Does `name` match one of the getter `patterns`? A pattern ending in `_` is a prefix
/// match, a pattern starting with `_` is a suffix match, and anything else is an exact
/// match. All comparisons are case-insensitive so `get_Balance` and `total_supply` both
/// match. Passing an empty `patterns` slice falls back to [`DEFAULT_GETTER_PATTERNS`].
pub(crate) fn is_getter_name(name: &str, patterns: &[&str]) -> bool {
    let lower = name.to_lowercase();
    let patterns = if patterns.is_empty() {
        DEFAULT_GETTER_PATTERNS
    } else {
        patterns
    };
    patterns.iter().any(|pattern| {
        let pattern = pattern.to_lowercase();
        if let Some(prefix) = pattern.strip_suffix('_') {
            lower.starts_with(prefix)
        } else if let Some(suffix) = pattern.strip_prefix('_') {
            lower.ends_with(suffix)
        } else {
            lower == pattern
        }
    })
}

/// Name fragments that mark a parameter as the *debited* side of a transfer — the party
/// whose funds move and who must therefore authorise the call.
const DEBIT_SIDE_KEYWORDS: &[&str] = &["from", "owner", "sender", "payer", "spender"];

/// Name fragments that mark a parameter as the *credited* side of a transfer — the
/// recipient, who must never be the only party authorising a debit.
const CREDIT_SIDE_KEYWORDS: &[&str] = &["to", "recipient", "dest"];

/// Is `name` a debit-side parameter name (`from`, `owner`, `sender`, `payer`, `spender`)?
/// Matches whole words within the identifier so `from_addr` and `token_owner` count while
/// `platform` does not.
pub(crate) fn is_debit_side_param_name(name: &str) -> bool {
    name_matches_keywords(name, DEBIT_SIDE_KEYWORDS)
}

/// Is `name` a credit-side parameter name (`to`, `recipient`, `dest`)?
pub(crate) fn is_credit_side_param_name(name: &str) -> bool {
    name_matches_keywords(name, CREDIT_SIDE_KEYWORDS)
}

/// Does `name` contain one of `keywords` as a whole word (split on `_` and camelCase
/// boundaries, case-insensitively)?
fn name_matches_keywords(name: &str, keywords: &[&str]) -> bool {
    let words = split_ident_words(name);
    keywords.iter().any(|k| words.iter().any(|w| w == k))
}

/// Split an identifier into lowercase words on `_` and camelCase boundaries:
/// `fromAddress` -> `["from", "address"]`, `token_owner` -> `["token", "owner"]`.
fn split_ident_words(name: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut prev_lower = false;
    for ch in name.chars() {
        if ch == '_' {
            if !current.is_empty() {
                words.push(std::mem::take(&mut current));
            }
            prev_lower = false;
            continue;
        }
        if ch.is_uppercase() && prev_lower && !current.is_empty() {
            words.push(std::mem::take(&mut current));
        }
        prev_lower = ch.is_lowercase() || ch.is_numeric();
        current.push(ch.to_ascii_lowercase());
    }
    if !current.is_empty() {
        words.push(current);
    }
    words
}

/// The `Address`-typed parameters of `sig` classified as debit-side vs credit-side, by
/// name. Returns `(debit_side, credit_side)`.
pub(crate) fn classify_transfer_params(sig: &Signature) -> (Vec<String>, Vec<String>) {
    let mut debit = Vec::new();
    let mut credit = Vec::new();
    for name in address_param_names(sig) {
        if is_debit_side_param_name(&name) {
            debit.push(name);
        } else if is_credit_side_param_name(&name) {
            credit.push(name);
        }
    }
    (debit, credit)
}

/// Does `receiver` refer to the parameter named `param`? Accepts the bare binding
/// (`from`), a clone (`from.clone()`), and a deref (`*from`), so aliases like
/// `let payer = from;` are covered by passing the alias name as `param`.
pub(crate) fn receiver_refers_to_param(receiver: &Expr, param: &str) -> bool {
    match receiver {
        Expr::Path(p) => p.path.is_ident(param),
        Expr::MethodCall(m) => {
            matches!(m.method.to_string().as_str(), "clone" | "to_address")
                && receiver_refers_to_param(&m.receiver, param)
        }
        Expr::Unary(u) if matches!(u.op, syn::UnOp::Deref(_)) => {
            receiver_refers_to_param(&u.expr, param)
        }
        Expr::Paren(p) => receiver_refers_to_param(&p.expr, param),
        _ => false,
    }
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
