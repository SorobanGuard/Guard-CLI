//! Shared helpers for walking `#[contractimpl]` impl blocks.

use std::collections::{HashMap, HashSet};
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

// ── Function summaries (issue #982) ─────────────────────────────────────────

/// A single-pass summary of what a non-`pub` (private) helper function does.
///
/// **Limitation**: resolution is same-file only.
#[derive(Debug, Clone, Default)]
pub struct FnSummary {
    /// The function calls `require_auth` or `require_auth_for_args` directly.
    pub requires_auth: bool,
    /// The function writes to any `env.storage()` bucket directly.
    pub writes_storage: bool,
    /// The function calls `env.events().publish` directly.
    pub publishes_event: bool,
    /// Idents of same-file functions that this function calls directly.
    pub calls: Vec<String>,
}

/// Build a `FnSummary` for every non-`pub` function in `file`.
///
/// Resolution depth is bounded at 3 to remain cycle-safe.
///
/// **Limitation**: same-file resolution only.
pub fn summarize(file: &syn::File) -> HashMap<String, FnSummary> {
    let mut direct: HashMap<String, FnSummary> = HashMap::new();
    collect_fn_summaries_direct(&file.items, &mut direct);

    let names: Vec<String> = direct.keys().cloned().collect();
    let mut resolved: HashMap<String, FnSummary> = direct.clone();

    for _ in 0..3 {
        let snapshot = resolved.clone();
        for name in &names {
            if let Some(summary) = resolved.get_mut(name) {
                for callee in &summary.calls.clone() {
                    if callee == name {
                        continue;
                    }
                    if let Some(callee_summary) = snapshot.get(callee) {
                        summary.requires_auth |= callee_summary.requires_auth;
                        summary.writes_storage |= callee_summary.writes_storage;
                        summary.publishes_event |= callee_summary.publishes_event;
                    }
                }
            }
        }
    }

    resolved
}

fn collect_fn_summaries_direct(items: &[Item], out: &mut HashMap<String, FnSummary>) {
    for item in items {
        match item {
            Item::Fn(f) => {
                if matches!(f.vis, syn::Visibility::Inherited) {
                    let summary = fn_summary_from_stmts(&f.block.stmts);
                    out.insert(f.sig.ident.to_string(), summary);
                }
            }
            Item::Impl(item_impl) => {
                for impl_item in &item_impl.items {
                    if let ImplItem::Fn(m) = impl_item {
                        if matches!(m.vis, syn::Visibility::Inherited) {
                            let summary = fn_summary_from_stmts(&m.block.stmts);
                            out.insert(m.sig.ident.to_string(), summary);
                        }
                    }
                }
            }
            Item::Mod(m) => {
                if let Some((_, nested)) = &m.content {
                    collect_fn_summaries_direct(nested, out);
                }
            }
            _ => {}
        }
    }
}

fn fn_summary_from_stmts(stmts: &[syn::Stmt]) -> FnSummary {
    use syn::visit::Visit;

    struct Visitor(FnSummary);

    impl Visit<'_> for Visitor {
        fn visit_expr_method_call(&mut self, node: &syn::ExprMethodCall) {
            let method = node.method.to_string();
            match method.as_str() {
                "require_auth" | "require_auth_for_args" => {
                    self.0.requires_auth = true;
                }
                "set" | "remove" => {
                    if is_storage_method_chain(&node.receiver) {
                        self.0.writes_storage = true;
                    }
                }
                "publish" => {
                    if is_events_chain(&node.receiver) {
                        self.0.publishes_event = true;
                    }
                }
                _ => {}
            }
            syn::visit::visit_expr_method_call(self, node);
        }
    }

    let mut v = Visitor(FnSummary::default());
    for stmt in stmts {
        v.visit_stmt(stmt);
    }
    v.0
}

fn is_storage_method_chain(expr: &Expr) -> bool {
    match expr {
        Expr::MethodCall(mc) => {
            let method = mc.method.to_string();
            matches!(
                method.as_str(),
                "persistent" | "instance" | "temporary" | "storage"
            ) || is_storage_method_chain(&mc.receiver)
        }
        _ => false,
    }
}

fn is_events_chain(expr: &Expr) -> bool {
    match expr {
        Expr::MethodCall(mc) => {
            let method = mc.method.to_string();
            method == "events" || is_events_chain(&mc.receiver)
        }
        _ => false,
    }
}

#[cfg(test)]
mod summarize_tests {
    use super::summarize;
    use syn::parse_file;

    #[test]
    fn private_fn_with_require_auth_is_detected() {
        let src = r#"
            fn check_caller(caller: soroban_sdk::Address) {
                caller.require_auth();
            }
        "#;
        let file = parse_file(src).unwrap();
        let summaries = summarize(&file);
        assert!(summaries["check_caller"].requires_auth);
    }

    #[test]
    fn private_fn_with_storage_write_is_detected() {
        let src = r#"
            fn write_val(env: Env) {
                env.storage().persistent().set(&"k", &1u32);
            }
        "#;
        let file = parse_file(src).unwrap();
        let summaries = summarize(&file);
        assert!(summaries["write_val"].writes_storage);
    }

    #[test]
    fn private_fn_with_event_publish_is_detected() {
        let src = r#"
            fn emit(env: Env) {
                env.events().publish(("ev",), 1u32);
            }
        "#;
        let file = parse_file(src).unwrap();
        let summaries = summarize(&file);
        assert!(summaries["emit"].publishes_event);
    }

    #[test]
    fn recursion_does_not_cause_infinite_loop() {
        let src = r#"
            fn recurse(n: u32) -> u32 {
                if n > 0 { recurse(n - 1) } else { 0 }
            }
        "#;
        let file = parse_file(src).unwrap();
        let _ = summarize(&file);
    }

    #[test]
    fn pub_fns_are_not_included_in_summaries() {
        let src = r#"
            pub fn public_fn() {}
        "#;
        let file = parse_file(src).unwrap();
        let summaries = summarize(&file);
        assert!(
            !summaries.contains_key("public_fn"),
            "public functions should not appear in fn summaries"
        );
    }
}
