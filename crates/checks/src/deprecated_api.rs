//! Detect usage of deprecated Soroban SDK APIs (Storage::bump, Symbol::short, etc.).

use crate::{Check, Finding, Severity};
use syn::File;

const CHECK_NAME: &str = "deprecated-soroban-api";

/// Table of deprecated Soroban SDK patterns and their modern replacements.
pub const DEPRECATED: &[(&str, &str)] = &[
    ("bump(", "extend_ttl(..)"),
    ("Symbol::short(", "symbol_short!(..) macro"),
    ("env.events().publish(", "#[contractevent] attribute macro"),
];

pub struct DeprecatedSorobanApiCheck;

impl Check for DeprecatedSorobanApiCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, _file: &File, source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        if !source.contains("#[contractimpl]") && !source.contains("#[contract]") {
            return out;
        }

        let mut in_block_comment = false;
        for (idx, line) in source.lines().enumerate() {
            let trimmed = line.trim_start();

            // Track block comment boundaries.
            if in_block_comment {
                if let Some(end) = trimmed.find("*/") {
                    in_block_comment = false;
                    let after = &trimmed[end + 2..];
                    check_line(&mut out, idx + 1, after);
                }
                continue;
            }

            if trimmed.starts_with("//") {
                continue;
            }

            if trimmed.contains("/*") {
                in_block_comment = true;
                let before = &trimmed[..trimmed.find("/*").unwrap()];
                check_line(&mut out, idx + 1, before);
                continue;
            }

            // Strip trailing line comment
            let code_part = if let Some(pos) = trimmed.find("//") {
                trimmed[..pos].trim_end()
            } else {
                trimmed
            };

            check_line(&mut out, idx + 1, code_part);
        }

        out
    }
}

fn check_line(out: &mut Vec<Finding>, line: usize, code: &str) {
    for &(pattern, replacement) in DEPRECATED {
        if code.contains(pattern) {
            out.push(Finding {
                check_name: CHECK_NAME.to_string(),
                severity: Severity::Low,
                file_path: String::new(),
                line,
                function_name: "contract".to_string(),
                description: format!(
                    "Deprecated Soroban SDK API `{pattern}` detected. Modern Soroban SDK contracts should use `{replacement}`."
                ),
                rule_url: Some(
                    "https://github.com/SorobanGuard/Guard-CLI/blob/main/docs/checks.md#deprecated-soroban-api-low"
                        .to_string(),
                ),
                suggestion: Some(format!("Replace `{pattern}` with `{replacement}`.")),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_file;

    fn run(src: &str) -> Vec<Finding> {
        let file = parse_file(src).expect("parse");
        DeprecatedSorobanApiCheck.run(&file, src)
    }

    #[test]
    fn catches_storage_bump() {
        let src = r#"
#[contract]
pub struct Contract;
#[contractimpl]
impl Contract {
    pub fn extend(e: Env) {
        e.storage().instance().bump(100, 1000);
    }
}
"#;
        let findings = run(src);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].description.contains("extend_ttl"));
    }

    #[test]
    fn catches_symbol_short() {
        let src = r#"
#[contract]
pub struct Contract;
#[contractimpl]
impl Contract {
    pub fn key(e: Env) {
        let s = Symbol::short("KEY");
    }
}
"#;
        let findings = run(src);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].description.contains("symbol_short"));
    }

    #[test]
    fn catches_events_publish() {
        let src = r#"
#[contract]
pub struct Contract;
#[contractimpl]
impl Contract {
    pub fn emit(e: Env) {
        e.events().publish((1,), 2);
    }
}
"#;
        let findings = run(src);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].description.contains("#[contractevent]"));
    }

    #[test]
    fn ignores_comments() {
        let src = r#"
#[contract]
pub struct Contract;
#[contractimpl]
impl Contract {
    pub fn safe(e: Env) {
        // e.storage().instance().bump(100, 1000);
    }
}
"#;
        let findings = run(src);
        assert_eq!(findings.len(), 0);
    }
}
