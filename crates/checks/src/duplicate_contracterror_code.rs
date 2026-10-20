//! Duplicate `#[contracterror]` discriminant: two variants of the same enum share the same u32 code.

use crate::{Check, Finding, Severity};
use std::collections::HashMap;
use syn::spanned::Spanned;
use syn::{Attribute, Expr, File, Item, Lit};

const CHECK_NAME: &str = "duplicate-contracterror-code";

pub struct DuplicateContractErrorCodeCheck;

fn has_attr_named(attrs: &[Attribute], name: &str) -> bool {
    attrs.iter().any(|a| {
        a.path()
            .segments
            .last()
            .map(|s| s.ident == name)
            .unwrap_or(false)
    })
}

/// Compute duplicate discriminant findings for a single enum annotated with `#[contracterror]`.
fn check_enum(
    enum_name: &str,
    variants: &syn::punctuated::Punctuated<syn::Variant, syn::token::Comma>,
    findings: &mut Vec<Finding>,
) {
    // Map from discriminant value → (variant name, line) of first occurrence.
    let mut seen: HashMap<i64, (String, usize)> = HashMap::new();
    let mut next_discriminant: i64 = 0;

    for variant in variants {
        // Compute this variant's discriminant.
        let discriminant = if let Some((_, expr)) = &variant.discriminant {
            // Try to extract a literal integer.
            match expr {
                Expr::Lit(el) => match &el.lit {
                    Lit::Int(li) => li.base10_parse::<i64>().unwrap_or(next_discriminant),
                    _ => next_discriminant,
                },
                Expr::Unary(eu) => {
                    // Handle negation like `= -1`
                    if matches!(eu.op, syn::UnOp::Neg(_)) {
                        if let Expr::Lit(el) = eu.expr.as_ref() {
                            if let Lit::Int(li) = &el.lit {
                                li.base10_parse::<i64>()
                                    .map(|n| -n)
                                    .unwrap_or(next_discriminant)
                            } else {
                                next_discriminant
                            }
                        } else {
                            next_discriminant
                        }
                    } else {
                        next_discriminant
                    }
                }
                _ => next_discriminant,
            }
        } else {
            next_discriminant
        };

        let variant_name = variant.ident.to_string();
        let line = variant.ident.span().start().line;

        if let Some((first_variant, first_line)) = seen.get(&discriminant) {
            findings.push(Finding {
                check_name: CHECK_NAME.to_string(),
                severity: Severity::Medium,
                file_path: String::new(),
                line,
                function_name: enum_name.to_string(),
                description: format!(
                    "`#[contracterror]` enum `{enum_name}`: variant `{variant_name}` (line {line}) \
                     shares discriminant `{discriminant}` with `{first_variant}` (line {first_line}). \
                     Two error variants with the same code are indistinguishable to callers."
                ),
                rule_url: Some(
                    "https://github.com/SorobanGuard/Guard-CLI/blob/main/docs/checks.md\
                     #duplicate-contracterror-code-medium"
                        .to_string(),
                ),
                suggestion: Some(format!(
                    "Assign unique discriminants to all variants of `{enum_name}`."
                )),
            });
        } else {
            seen.insert(discriminant, (variant_name, line));
        }

        next_discriminant = discriminant + 1;
    }
}

/// Walk items recursively, skipping `#[cfg(test)]` modules.
fn walk_items(items: &[Item], findings: &mut Vec<Finding>) {
    for item in items {
        match item {
            Item::Mod(m) => {
                // Skip test modules.
                let is_test = m.attrs.iter().any(|a| {
                    if let Ok(syn::Meta::List(ml)) = a.parse_meta() {
                        let path = ml
                            .path
                            .segments
                            .iter()
                            .map(|s| s.ident.to_string())
                            .collect::<Vec<_>>()
                            .join("::");
                        if path == "cfg" {
                            return ml.tokens.to_string().contains("test");
                        }
                    }
                    false
                });
                if is_test {
                    continue;
                }
                if let Some((_, nested)) = &m.content {
                    walk_items(nested, findings);
                }
            }
            Item::Enum(e) => {
                // Only process enums annotated with `#[contracterror]` or
                // `#[soroban_sdk::contracterror]`.
                if has_attr_named(&e.attrs, "contracterror") {
                    check_enum(&e.ident.to_string(), &e.variants, findings);
                }
            }
            _ => {}
        }
    }
}

impl Check for DuplicateContractErrorCodeCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        walk_items(&file.items, &mut findings);
        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(src: &str) -> Vec<Finding> {
        let file = syn::parse_file(src).expect("fixture should parse");
        DuplicateContractErrorCodeCheck.run(&file, src)
    }

    #[test]
    fn explicit_duplicate_discriminant_reported() {
        let src = r#"
            #[contracterror]
            pub enum MyError {
                Foo = 1,
                Bar = 1,
            }
        "#;
        let findings = run(src);
        assert_eq!(findings.len(), 1, "expected one duplicate finding");
        assert!(findings[0].description.contains("Bar"));
        assert!(findings[0].description.contains("Foo"));
    }

    #[test]
    fn implicit_explicit_collision_reported() {
        // Foo=0 (implicit), Bar=0 (explicit collision)
        let src = r#"
            #[contracterror]
            pub enum MyError {
                Foo,
                Bar = 0,
            }
        "#;
        let findings = run(src);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].description.contains("Bar"));
    }

    #[test]
    fn unique_codes_not_reported() {
        let src = r#"
            #[contracterror]
            pub enum MyError {
                Foo = 1,
                Bar = 2,
                Baz = 3,
            }
        "#;
        assert!(run(src).is_empty());
    }

    #[test]
    fn non_contracterror_enum_ignored() {
        let src = r#"
            pub enum NotAnError {
                Foo = 1,
                Bar = 1,
            }
        "#;
        assert!(run(src).is_empty());
    }

    #[test]
    fn implicit_sequential_no_duplicate() {
        let src = r#"
            #[contracterror]
            pub enum MyError {
                A,
                B,
                C,
            }
        "#;
        assert!(run(src).is_empty());
    }
}
