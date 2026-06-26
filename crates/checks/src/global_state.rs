//! Detects `static mut` items in Soroban contracts (mutable global state).

use crate::{Check, Finding, Severity};
use syn::{File, Item, ItemStatic};
use syn::spanned::Spanned;

const CHECK_NAME: &str = "mutable-global-state";

pub struct MutableGlobalStateCheck;

impl Check for MutableGlobalStateCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        file.items
            .iter()
            .filter_map(|item| {
                if let Item::Static(ItemStatic { mutability, ident, .. }) = item {
                    if matches!(mutability, syn::StaticMutability::Mut(_)) {
                        return Some(Finding {
                            check_name: CHECK_NAME.to_string(),
                            severity: Severity::High,
                            file_path: String::new(),
                            line: ident.span().start().line,
                            function_name: String::new(),
                            description: format!(
                                "`static mut {ident}` introduces mutable global state. \
                                 In Soroban, contract instances are stateless between \
                                 invocations — `static mut` is unsafe and its value is \
                                 not persisted on-chain."
                            ),
                            rule_url: Some(
                                "https://github.com/SorobanGuard/Guard-CLI/blob/main/docs/checks.md#mutable-global-state-high"
                                    .to_string(),
                            ),
                            suggestion: Some(
                                "Replace `static mut` with `env.storage().persistent()` or `env.storage().instance()` for on-chain state."
                                    .to_string(),
                            ),
                        });
                    }
                }
                None
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_file;

    #[test]
    fn flags_static_mut() {
        let file = parse_file("static mut COUNT: u32 = 0;").unwrap();
        let hits = MutableGlobalStateCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::High);
        assert!(hits[0].description.contains("COUNT"));
    }

    #[test]
    fn ignores_immutable_static() {
        let file = parse_file("static COUNT: u32 = 0;").unwrap();
        let hits = MutableGlobalStateCheck.run(&file, "");
        assert!(hits.is_empty());
    }
}
