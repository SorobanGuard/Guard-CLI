//! Shared helpers for walking `#[contractimpl]` impl blocks.

use syn::{Expr, ImplItem, Item, ItemImpl};

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

/// Every function item inside a `#[contractimpl]` impl in the file.
fn is_cfg_test(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        if !attr.path().is_ident("cfg") {
            return false;
        }
        attr.parse_args::<syn::Ident>()
            .map(|id| id == "test")
            .unwrap_or(false)
    })
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
