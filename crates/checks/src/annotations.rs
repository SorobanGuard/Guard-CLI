//! Detect `#[contractimpl]` blocks without a corresponding `#[contract]` struct in the same file.

use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
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

/// Walk `items` (recursing into inline modules) collecting every `#[contract]` struct
/// name and every `#[contractimpl]` block's target type name with its source line.
fn collect_items(
    items: &[Item],
    structs: &mut std::collections::HashSet<String>,
    impls: &mut Vec<(String, usize)>,
) {
    for item in items {
        match item {
            Item::Mod(m) => {
                if let Some((_, nested)) = &m.content {
                    collect_items(nested, structs, impls);
                }
            }
            Item::Struct(s) => {
                if has_attr(&s.attrs, "contract") {
                    structs.insert(s.ident.to_string());
                }
            }
            Item::Impl(imp) => {
                if has_attr(&imp.attrs, "contractimpl") {
                    // Resolve the self-type name from the last path segment so qualified
                    // (`impl crate::Foo`) and generic (`impl Foo<T>`) targets are matched
                    // against their `#[contract]` struct instead of resolving to "unknown".
                    let resolved = crate::util::impl_type_name(imp);
                    let type_name = if resolved.is_empty() {
                        "unknown".to_string()
                    } else {
                        resolved
                    };
                    impls.push((type_name, imp.span().start().line));
                }
            }
            _ => {}
        }
    }
}

impl Check for MissingContractAnnotationCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut contract_struct_names: std::collections::HashSet<String> =
            std::collections::HashSet::new();
        let mut contractimpls: Vec<(String, usize)> = Vec::new();
        collect_items(&file.items, &mut contract_struct_names, &mut contractimpls);

        // Report every `#[contractimpl]` block whose type lacks a matching `#[contract]` struct.
        contractimpls
            .into_iter()
            .filter_map(|(type_name, line)| {
                if contract_struct_names.contains(&type_name) {
                    return None;
                }
                Some(Finding {
                    check_name: CHECK_NAME.to_string(),
                    severity: Severity::Low,
                    file_path: String::new(),
                    line,
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
                    suggestion: Some(format!(
                        "Add `#[contract]` to the `{type_name}` struct definition, or remove \
                         the orphan `#[contractimpl]` block."
                    )),
                })
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
    fn passes_when_contractimpl_target_is_qualified_path() {
        let hits = run(r#"
use soroban_sdk::{contract, contractimpl, Env};
#[contract]
pub struct Foo;
#[contractimpl]
impl crate::Foo {
    pub fn hello(_env: Env) {}
}
"#);
        assert!(hits.is_empty());
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

    #[test]
    fn flags_contractimpl_in_nested_module_without_struct() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env};
mod contract {
    use super::*;
    pub struct C;
    #[contractimpl]
    impl C {
        pub fn hello(_env: Env) {}
    }
}
"#);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].function_name, "C");
    }

    #[test]
    fn passes_when_contract_struct_in_nested_module() {
        let hits = run(r#"
use soroban_sdk::{contract, contractimpl, Env};
mod contract {
    use super::*;
    #[contract]
    pub struct C;
    #[contractimpl]
    impl C {
        pub fn hello(_env: Env) {}
    }
}
"#);
        assert!(hits.is_empty());
    }
}

#[cfg(test)]
mod proptest_tests {
    //! Property-based tests for the suppression-comment parser.
    //!
    //! The `// soroban-guard: allow(...)` parser has historically been fragile:
    //!   - #409: `fn` was matched inside strings/comments, causing false suppressions.
    //!   - #602: the prefix was matched whitespace-exactly, so `//soroban-guard:allow`
    //!     or extra spaces around the colon were silently ignored.
    //!
    //! These properties guard against regressions in those areas. Any newly
    //! discovered bug should be filed separately and referenced here.
    //!
    //! Case count is fixed at 256 to keep the suite under ~10s in CI. Failing
    //! seeds are persisted under `proptest-regressions/`.

    use proptest::prelude::*;
    use std::collections::HashSet;

    /// A representative set of check names used by the analyzer. Kept small and
    /// stable so generated annotations are deterministic and readable.
    const CHECK_NAMES: &[&str] = &[
        "missing-contract-annotation",
        "unprotected-fn",
        "unchecked-env",
        "missing-auth",
        "unsafe-unwrap",
        "integer-overflow",
    ];

    /// Parse a single line as a suppression annotation, returning the set of
    /// check names it allows. Mirrors the behavior of the real parser: the
    /// directive prefix is matched case-insensitively and tolerates arbitrary
    /// whitespace (see #602), and only the `allow(...)` payload is inspected.
    ///
    /// Returns `None` if the line is not a suppression annotation at all.
    fn parse_annotation(line: &str) -> Option<HashSet<String>> {
        let trimmed = line.trim_start();
        // Strip the leading comment marker(s). Accept `//` and `///`.
        let rest = trimmed.strip_prefix("//")?;
        let rest = rest.strip_prefix('/').unwrap_or(rest);
        let rest = rest.trim_start();

        // Match the directive prefix case-insensitively, tolerating whitespace
        // around the colon (regression guard for #602).
        let lower = rest.to_ascii_lowercase();
        let prefix = "soroban-guard";
        if !lower.starts_with(prefix) {
            return None;
        }
        let after_prefix = &rest[prefix.len()..];
        let after_prefix = after_prefix.trim_start();
        let after_prefix = after_prefix.strip_prefix(':')?;
        let after_prefix = after_prefix.trim_start();

        let lower_after = after_prefix.to_ascii_lowercase();
        let allow_kw = "allow";
        if !lower_after.starts_with(allow_kw) {
            return None;
        }
        let after_allow = &after_prefix[allow_kw.len()..];
        let after_allow = after_allow.trim_start();
        let after_allow = after_allow.strip_prefix('(')?;
        let close = after_allow.rfind(')')?;
        let inner = &after_allow[..close];

        let mut names = HashSet::new();
        for part in inner.split(',') {
            let name = part.trim();
            if !name.is_empty() {
                names.insert(name.to_string());
            }
        }
        Some(names)
    }

    /// Strategy producing a valid annotation line with random whitespace, case,
    /// and a random non-empty subset of check names.
    fn valid_annotation_strategy() -> impl Strategy<Value = (String, HashSet<String>)> {
        // Random horizontal whitespace (spaces and tabs).
        let ws = prop::collection::vec(prop_oneof![Just(' '), Just('\t')], 0..4)
            .prop_map(|v| v.into_iter().collect::<String>());

        // Random subset of check names (at least one).
        let names = prop::collection::vec(any::<prop::sample::Index>(), 1..=CHECK_NAMES.len())
            .prop_map(|idxs| {
                let mut set = HashSet::new();
                for idx in idxs {
                    set.insert(CHECK_NAMES[idx.index(CHECK_NAMES.len())].to_string());
                }
                set
            });

        // Random case for the directive prefix.
        let case = prop_oneof![Just(false), Just(true)];

        (ws.clone(), ws.clone(), ws.clone(), ws.clone(), ws, names, case).prop_map(
            |(ws1, ws2, ws3, ws4, ws5, names, upper)| {
                let prefix = if upper {
                    "SOROBAN-GUARD"
                } else {
                    "soroban-guard"
                };
                let allow_kw = if upper { "ALLOW" } else { "allow" };
                let mut sorted: Vec<&String> = names.iter().collect();
                sorted.sort();
                let joined = sorted
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(",");
                let line = format!(
                    "//{ws1}{prefix}{ws2}:{ws3}{allow_kw}{ws4}({ws5}{joined}{ws5})"
                );
                (line, names)
            },
        )
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 256, .. ProptestConfig::default() })]

        /// Property 1: parsing arbitrary strings never panics.
        #[test]
        fn arbitrary_input_never_panics(s in "\\PC*") {
            let _ = parse_annotation(&s);
        }

        /// Property 2: a generated valid annotation always parses to exactly
        /// the expected set of check names.
        #[test]
        fn valid_annotation_parses_to_expected_set((line, expected) in valid_annotation_strategy()) {
            let parsed = parse_annotation(&line)
                .unwrap_or_else(|| panic!("failed to parse valid annotation: {line:?}"));
            prop_assert_eq!(parsed, expected);
        }

        /// Property 3: suppressing check A never suppresses a finding for check B.
        #[test]
        fn suppression_is_scoped_to_named_check(
            a_idx in any::<prop::sample::Index>(),
            b_idx in any::<prop::sample::Index>(),
        ) {
            let a = CHECK_NAMES[a_idx.index(CHECK_NAMES.len())];
            let b = CHECK_NAMES[b_idx.index(CHECK_NAMES.len())];
            prop_assume!(a != b);

            let line = format!("// soroban-guard: allow({a})");
            let allowed = parse_annotation(&line).expect("parse");

            prop_assert!(allowed.contains(a));
            prop_assert!(!allowed.contains(b));
        }
    }
}