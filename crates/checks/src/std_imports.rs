//! `use std::` imports in files that also use `#[contractimpl]` — these break the `no_std` WASM build.

use crate::{Check, Finding, Severity};
use syn::File;

const CHECK_NAME: &str = "forbidden-std-imports";

/// Soroban contracts must compile to `no_std`; any `use std::...` import breaks the WASM build.
/// Works directly on the raw source text rather than the parsed AST.
pub struct ForbiddenStdImportsCheck;

impl Check for ForbiddenStdImportsCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, _file: &File, source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        if !source.contains("#[contractimpl]") {
            return out;
        }
        for (idx, line) in source.lines().enumerate() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("use std::") || trimmed.starts_with("use ::std::") {
                out.push(Finding {
                    check_name: CHECK_NAME.to_string(),
                    severity: Severity::High,
                    file_path: String::new(),
                    line: idx + 1,
                    function_name: "module".to_string(),
                    description: format!(
                        "`{}` imports from `std`. Soroban contracts compile to `no_std`; any \
                         `std::` import will break the WASM build.",
                        trimmed.trim_end_matches(';')
                    ),
                    rule_url: Some(
                        "https://github.com/SorobanGuard/Guard-CLI/blob/main/docs/checks.md#forbidden-std-imports-high"
                            .to_string(),
                    ),
                    suggestion: Some(
                        "Remove the `use std::` import or replace with a `no_std`-compatible alternative."
                            .to_string(),
                    ),
                });
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Check;
    use syn::parse_file;

    #[test]
    fn flags_std_import_with_contractimpl() -> Result<(), syn::Error> {
        let source = r#"
use std::collections::HashMap;
use soroban_sdk::{contractimpl, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn hello(env: Env) {
        let _ = env;
    }
}
"#;
        let file = parse_file(source)?;
        let hits = ForbiddenStdImportsCheck.run(&file, source);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::High);
        Ok(())
    }

    #[test]
    fn ignores_std_import_without_contractimpl() -> Result<(), syn::Error> {
        let source = r#"
use std::collections::HashMap;

pub struct C;
"#;
        let file = parse_file(source)?;
        let hits = ForbiddenStdImportsCheck.run(&file, source);
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn ignores_files_without_std() -> Result<(), syn::Error> {
        let source = r#"
use soroban_sdk::{contractimpl, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn hello(env: Env) {
        let _ = env;
    }
}
"#;
        let file = parse_file(source)?;
        let hits = ForbiddenStdImportsCheck.run(&file, source);
        assert!(hits.is_empty());
        Ok(())
    }
}
