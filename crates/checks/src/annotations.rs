//! Detect `#[contractimpl]` blocks without a corresponding `#[contract]` struct in the same file.

use crate::{Check, Finding, Severity};
use syn::{Attribute, File, Item};

const CHECK_NAME: &str = "missing-contract-annotation";

pub struct MissingContractAnnotationCheck;

fn has_attr(attrs: &[Attribute], name: &str) -> bool {
    attrs.iter().any(|a| {
        let segs = &a.path().segments;
        // Matches `#[contract]` or `#[soroban_sdk::contract]`
        segs.last().map(|s| s.ident == name).unwrap_or(false)
    })
}

impl Check for MissingContractAnnotationCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let has_contract_struct = file.items.iter().any(|item| {
            if let Item::Struct(s) = item {
                has_attr(&s.attrs, "contract")
            } else {
                false
            }
        });

        if has_contract_struct {
            return vec![];
        }

        // Report every `#[contractimpl]` block that lacks a sibling `#[contract]` struct.
        file.items
            .iter()
            .filter_map(|item| {
                if let Item::Impl(imp) = item {
                    if has_attr(&imp.attrs, "contractimpl") {
                        let type_name = match &*imp.self_ty {
                            syn::Type::Path(tp) => tp
                                .path
                                .get_ident()
                                .map(|i| i.to_string())
                                .unwrap_or_else(|| "unknown".to_string()),
                            _ => "unknown".to_string(),
                        };
                        return Some(Finding {
                            check_name: CHECK_NAME.to_string(),
                            severity: Severity::Low,
                            file_path: String::new(),
                            line: 1,
                            function_name: type_name.clone(),
                            description: format!(
                                "`#[contractimpl]` found for `{type_name}` but no `#[contract]` \
                                 struct exists in this file. This is likely a copy-paste error; \
                                 add `#[contract]` to the struct definition."
                            ),
                            rule_url: Some(
                                "https://github.com/SorobanGuard/Guard-CLI/blob/main/docs/checks.md#missing-contract-annotation-low"
                                    .to_string(),
                            ),
                            suggestion: None,
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
    use crate::Check;
    use syn::parse_file;

    fn run(src: &str) -> Vec<Finding> {
        let file = parse_file(src).expect("parse");
        MissingContractAnnotationCheck.run(&file, src)
    }

    #[test]
    fn passes_when_contract_and_contractimpl_present() {
        let hits = run(r#"
use soroban_sdk::{contract, contractimpl, Env};
#[contract]
pub struct MyContract;
#[contractimpl]
impl MyContract {
    pub fn hello(_env: Env) {}
}
"#);
        assert!(hits.is_empty());
    }

    #[test]
    fn flags_contractimpl_without_contract_struct() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env};
pub struct MyContract;
#[contractimpl]
impl MyContract {
    pub fn hello(_env: Env) {}
}
"#);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Low);
        assert_eq!(hits[0].check_name, CHECK_NAME);
        assert_eq!(hits[0].function_name, "MyContract");
    }

    #[test]
    fn passes_when_no_contractimpl_at_all() {
        let hits = run(r#"
pub struct Foo;
impl Foo {
    pub fn bar() {}
}
"#);
        assert!(hits.is_empty());
    }

    #[test]
    fn flags_soroban_sdk_contractimpl_path() {
        let hits = run(r#"
pub struct MyContract;
#[soroban_sdk::contractimpl]
impl MyContract {
    pub fn go(_env: soroban_sdk::Env) {}
}
"#);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Low);
    }
}
