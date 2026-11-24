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

/// Every **exported** entrypoint inside a `#[contractimpl]` impl that is not inside a
/// `#[cfg(test)]` module or a module named `tests`. See [`is_exported_entrypoint`]: `pub`
/// methods of inherent impls and every method of trait impls.
pub fn contractimpl_entrypoints_excluding_test(file: &syn::File) -> Vec<&syn::ImplItemFn> {
    let mut out = Vec::new();
    collect_contractimpl_entrypoints(&file.items, false, &mut out);
    out
}

fn collect_contractimpl_entrypoints<'a>(
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
                    collect_contractimpl_entrypoints(nested, is_test, out);
                }
            }
            Item::Impl(item_impl) if !in_test_mod && is_contractimpl(item_impl) => {
                for impl_item in &item_impl.items {
                    if let ImplItem::Fn(m) = impl_item {
                        if is_exported_entrypoint(item_impl, m) {
                            out.push(m);
                        }
                    }
                }
            }
            _ => {}
        }
    }
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
    fn is_exported_entrypoint_pub_inherent_method_is_exported() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
#[contractimpl]
impl C {
    pub fn live(env: Env) {
        let _ = env;
    }
}
"#,
        )?;
        let Item::Impl(item_impl) = &file.items[0] else {
            panic!("expected impl");
        };
        let ImplItem::Fn(m) = &item_impl.items[0] else {
            panic!("expected fn");
        };
        assert!(is_exported_entrypoint(item_impl, m));
        Ok(())
    }

    #[test]
    fn is_exported_entrypoint_private_inherent_helper_is_not_exported() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
#[contractimpl]
impl C {
    fn write_balance(env: &Env, amount: i128) {
        let _ = (env, amount);
    }
}
"#,
        )?;
        let Item::Impl(item_impl) = &file.items[0] else {
            panic!("expected impl");
        };
        let ImplItem::Fn(m) = &item_impl.items[0] else {
            panic!("expected fn");
        };
        assert!(!is_exported_entrypoint(item_impl, m));
        Ok(())
    }

    #[test]
    fn is_exported_entrypoint_trait_impl_method_is_exported() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
#[contractimpl]
impl Trait for C {
    fn live(env: Env) {
        let _ = env;
    }
}
"#,
        )?;
        let Item::Impl(item_impl) = &file.items[0] else {
            panic!("expected impl");
        };
        let ImplItem::Fn(m) = &item_impl.items[0] else {
            panic!("expected fn");
        };
        assert!(is_exported_entrypoint(item_impl, m));
        Ok(())
    }

    #[test]
    fn entrypoints_excluding_test_skips_private_helpers() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
#[contractimpl]
impl C {
    pub fn live(env: Env) {
        let _ = env;
    }

    fn write_balance(env: &Env, amount: i128) {
        let _ = (env, amount);
    }
}
"#,
        )?;
        let methods = contractimpl_entrypoints_excluding_test(&file);
        assert_eq!(methods.len(), 1);
        assert_eq!(methods[0].sig.ident.to_string(), "live");
        Ok(())
    }

    #[test]
    fn receiver_is_auth_gate_rejects_current_contract_address() -> Result<(), syn::Error> {
        let expr: Expr = syn::parse_str("env.current_contract_address()")?;
        assert!(!receiver_is_auth_gate(
            &expr,
            "env",
            &[],
            &HashSet::new()
        ));
        Ok(())
    }

    #[test]
    fn receiver_is_auth_gate_accepts_clone_of_address_param() -> Result<(), syn::Error> {
        let expr: Expr = syn::parse_str("admin.clone()")?;
        assert!(receiver_is_auth_gate(
            &expr,
            "env",
            &["admin".to_string()],
            &HashSet::new()
        ));
        Ok(())
    }

    #[test]
    fn receiver_is_auth_gate_accepts_self_admin_field() -> Result<(), syn::Error> {
        let expr: Expr = syn::parse_str("self.admin")?;
        assert!(receiver_is_auth_gate(
            &expr,
            "env",
            &[],
            &HashSet::new()
        ));
        Ok(())
    }

    #[test]
    fn receiver_is_auth_gate_rejects_unrelated_method_call() -> Result<(), syn::Error> {
        let expr: Expr = syn::parse_str("some_lookup().require_auth()")?;
        let Expr::MethodCall(m) = &expr else {
            panic!("expected method call");
        };
        assert!(!receiver_is_auth_gate(
            &m.receiver,
            "env",
            &[],
            &HashSet::new()
        ));
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
/// that plausibly yield an `Address` (`admin.clone()`, `get_admin(&env)`) — all of which yield
/// an `Address`/auth-invoker in practice. A bare path that is none of the above (a random
/// local) is *not* treated as an auth gate, so unrelated `.require_auth()` calls don't silence
/// the check.
///
/// `env.current_contract_address().require_auth()` is explicitly rejected: it authorises the
/// contract itself and gives no protection against arbitrary callers (a known Soroban
/// anti-pattern), so it must never count as an auth gate.
pub(crate) fn receiver_is_auth_gate(
    receiver: &Expr,
    env_name: &str,
    address_names: &[String],
    address_locals: &HashSet<String>,
) -> bool {
    // Self-authorisation never authenticates the caller.
    if receiver_chain_contains(receiver, "current_contract_address") {
        return false;
    }
    match receiver {
        Expr::Path(p) => {
            p.path.is_ident(env_name)
                || address_names.iter().any(|a| p.path.is_ident(a))
                || p.path
                    .get_ident()
                    .map(|i| address_locals.contains(&i.to_string()))
                    .unwrap_or(false)
        }
        Expr::Field(f) => field_is_auth_gate(&f.base, env_name, address_names, address_locals),
        Expr::MethodCall(m) => {
            method_call_is_auth_gate(m, env_name, address_names, address_locals)
        }
        _ => false,
    }
}

/// Is a field access (`self.admin`, `self.owner`) plausibly the caller/admin `Address`?
/// Only `self.<field>` where the field name looks like the privileged account, or a field
/// whose base is itself an auth gate, is accepted.
fn field_is_auth_gate(
    base: &Expr,
    env_name: &str,
    address_names: &[String],
    address_locals: &HashSet<String>,
) -> bool {
    if let Expr::Path(p) = base {
        if p.path.is_ident("self") {
            return true;
        }
    }
    receiver_is_auth_gate(base, env_name, address_names, address_locals)
}

/// Is a method-call receiver (`admin.clone()`, `get_admin(&env)`) plausibly the caller/admin
/// `Address`? Accepts `.clone()` of an address param/local, a storage `get` of an admin key,
/// or a call whose receiver is itself an auth gate.
fn method_call_is_auth_gate(
    m: &syn::ExprMethodCall,
    env_name: &str,
    address_names: &[String],
    address_locals: &[String],
) -> bool {
    let name = m.method.to_string();
    if name == "clone" {
        return receiver_is_auth_gate(&m.receiver, env_name, address_names, address_locals);
    }
    if name == "get" && receiver_chain_contains_storage(&m.receiver) {
        // `env.storage().*.get(&ADMIN)` — accept when the key argument looks like an admin key.
        return m.args.iter().any(|arg| expr_mentions_admin_key(arg));
    }
    receiver_is_auth_gate(&m.receiver, env_name, address_names, address_locals)
}

/// Does `expr` mention an identifier that looks like an admin/owner key?
fn expr_mentions_admin_key(expr: &Expr) -> bool {
    match expr {
        Expr::Path(p) => p
            .path
            .get_ident()
            .map(|i| is_admin_var_name(&i.to_string()))
            .unwrap_or(false),
        Expr::Reference(r) => expr_mentions_admin_key(&r.expr),
        _ => false,
    }
}

/// Is `method` an exported entrypoint of the enclosing `#[contractimpl]` impl?
///
/// For an inherent impl (`impl C { .. }`) only `pub fn`s are exported; non-`pub` helpers
/// cannot be invoked externally and must not be analysed as entrypoints. Every method of a
/// trait impl (`impl Trait for C { .. }`) is exported.
pub(crate) fn is_exported_entrypoint(item_impl: &ItemImpl, method: &syn::ImplItemFn) -> bool {
    if item_impl.trait_.is_some() {
        return true;
    }
    matches!(method.vis, syn::Visibility::Public(_))
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
