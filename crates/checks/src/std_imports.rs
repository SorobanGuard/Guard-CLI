//! `use std::` imports in files that also use Soroban contract attributes — these break the `no_std` WASM build.

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

    fn run(&self, file: &File, source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        if !source.contains("#[contractimpl]") && !source.contains("#[contract]") {
            return out;
        }
        // `#[cfg(test)]` modules build for the host, where `std` is available,
        // so `extern crate std; use std::println;` inside them is fine (#1062).
        let test_ranges = crate::util::test_only_line_ranges(file);
        let mut in_block_comment = false;
        for (idx, line) in source.lines().enumerate() {
            let trimmed = line.trim_start();

            // Block-comment state is still tracked above for correctness, but a
            // line inside a test-only item is never reported.
            let in_test = crate::util::in_any_range(&test_ranges, idx + 1);

            // Track block comment boundaries.
            if in_block_comment {
                if let Some(end) = trimmed.find("*/") {
                    // Rest of the line after `*/` may contain real code.
                    in_block_comment = false;
                    // Continue processing the remainder below.
                    let after = &trimmed[end + 2..];
                    if !in_test && code_contains_std(after) {
                        push_finding(&mut out, idx, trimmed);
                    }
                }
                // Still inside a block comment — skip entirely.
                continue;
            }

            // Whole-line comments.
            if trimmed.starts_with("//") {
                continue;
            }

            // Check whether `/*` opens a block comment on this line.
            if trimmed.contains("/*") {
                in_block_comment = true;
                // Analyse only the portion before the `/*`.
                let before = &trimmed[..trimmed.find("/*").unwrap()];
                if !in_test && code_contains_std(before) {
                    push_finding(&mut out, idx, trimmed);
                }
                continue;
            }

            // Strip a trailing `//` line comment so patterns like
            //   `env.storage(); // TODO: replace with std::collections later`
            // are not flagged.
            let code_part = strip_line_comment(trimmed);

            // Strip string literal content so
            //   `let s = "uses std::mem-style layout";`
            // is not flagged.
            if !in_test && code_contains_std(code_part) {
                push_finding(&mut out, idx, trimmed);
            }
        }
        out
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Push a finding for a line that contains a real `std::` reference.
fn push_finding(out: &mut Vec<Finding>, idx: usize, trimmed: &str) {
    out.push(Finding {
        check_name: CHECK_NAME.to_string(),
        severity: Severity::High,
        file_path: String::new(),
        line: idx + 1,
        function_name: "module".to_string(),
        description: format!(
            "`{}` references `std`. Soroban contracts compile to `no_std`; any \
             `std::` import or path reference will break the WASM build.",
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

/// Return the slice of `line` before any trailing `//` comment, being careful
/// not to strip `//` that appears inside a string literal.
fn strip_line_comment(line: &str) -> &str {
    let mut in_str = false;
    let mut escape_next = false;
    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if escape_next {
            escape_next = false;
            i += 1;
            continue;
        }
        match bytes[i] {
            b'\\' if in_str => escape_next = true,
            b'"' => in_str = !in_str,
            b'/' if !in_str && i + 1 < bytes.len() && bytes[i + 1] == b'/' => {
                return &line[..i];
            }
            _ => {}
        }
        i += 1;
    }
    line
}

/// Returns `true` when the code fragment (already stripped of comments) contains
/// `std::` outside of string literals.
fn code_contains_std(code: &str) -> bool {
    let mut in_str = false;
    let mut escape_next = false;
    let bytes = code.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if escape_next {
            escape_next = false;
            i += 1;
            continue;
        }
        match bytes[i] {
            b'\\' if in_str => escape_next = true,
            b'"' => in_str = !in_str,
            _ if !in_str => {
                if bytes[i..].starts_with(b"std::") {
                    return true;
                }
            }
            _ => {}
        }
        i += 1;
    }
    false
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

    // ---- #676: std:: in comments or string literals must not be flagged ----

    #[test]
    fn ignores_std_in_trailing_line_comment() -> Result<(), syn::Error> {
        let source = r#"
#[contract]
pub struct C;
#[contractimpl]
impl C {
    pub fn foo() {
        let x = 1; // TODO: replace with std::collections later
    }
}
"#;
        let file = parse_file(source)?;
        let hits = ForbiddenStdImportsCheck.run(&file, source);
        assert!(hits.is_empty(), "std:: in a trailing comment should not be flagged");
        Ok(())
    }

    #[test]
    fn ignores_std_in_string_literal() -> Result<(), syn::Error> {
        let source = r#"
#[contract]
pub struct C;
#[contractimpl]
impl C {
    pub fn foo() {
        let s = "uses std::mem-style layout";
    }
}
"#;
        let file = parse_file(source)?;
        let hits = ForbiddenStdImportsCheck.run(&file, source);
        assert!(hits.is_empty(), "std:: inside a string literal should not be flagged");
        Ok(())
    }

    #[test]
    fn ignores_std_inside_block_comment() -> Result<(), syn::Error> {
        let source = r#"
#[contract]
pub struct C;
#[contractimpl]
impl C {
    /* use std::collections::HashMap; */
    pub fn foo() {}
}
"#;
        let file = parse_file(source)?;
        let hits = ForbiddenStdImportsCheck.run(&file, source);
        assert!(hits.is_empty(), "std:: inside a block comment should not be flagged");
        Ok(())
    }

    #[test]
    fn still_flags_real_std_import() -> Result<(), syn::Error> {
        let source = r#"
use std::collections::HashMap;
#[contract]
pub struct C;
#[contractimpl]
impl C {
    pub fn foo() {}
}
"#;
        let file = parse_file(source)?;
        let hits = ForbiddenStdImportsCheck.run(&file, source);
        assert_eq!(hits.len(), 1, "real std:: import must still be flagged");
        Ok(())
    }

    // ---- #1062: std:: inside test-only modules must not be flagged ----

    #[test]
    fn ignores_std_inside_cfg_test_module() -> Result<(), syn::Error> {
        let source = r#"
#![no_std]
use soroban_sdk::{contract, contractimpl, Env};

#[contract]
pub struct C;

#[contractimpl]
impl C {
    pub fn hello(env: Env) {
        let _ = env;
    }
}

#[cfg(test)]
mod test {
    extern crate std;
    use std::println;
    use std::vec::Vec;

    #[test]
    fn t() {
        let v: Vec<u32> = std::vec![1];
        println!("{:?}", v);
    }
}
"#;
        let file = parse_file(source)?;
        let hits = ForbiddenStdImportsCheck.run(&file, source);
        assert!(hits.is_empty(), "std:: inside #[cfg(test)] mod must not be flagged: {hits:?}");
        Ok(())
    }

    #[test]
    fn ignores_std_inside_cfg_all_test_module() -> Result<(), syn::Error> {
        let source = r#"
#[contract]
pub struct C;

#[cfg(all(test, feature = "testutils"))]
mod helpers {
    use std::string::String;
}
"#;
        let file = parse_file(source)?;
        let hits = ForbiddenStdImportsCheck.run(&file, source);
        assert!(hits.is_empty(), "std:: inside #[cfg(all(test, ..))] must not be flagged");
        Ok(())
    }

    #[test]
    fn still_flags_top_level_std_import_next_to_test_module() -> Result<(), syn::Error> {
        let source = r#"
use std::vec::Vec;

#[contract]
pub struct C;

#[cfg(test)]
mod test {
    extern crate std;
    use std::println;
}
"#;
        let file = parse_file(source)?;
        let hits = ForbiddenStdImportsCheck.run(&file, source);
        assert_eq!(hits.len(), 1, "only the top-level import should be flagged: {hits:?}");
        assert_eq!(hits[0].line, 2);
        Ok(())
    }

    #[test]
    fn still_flags_std_under_cfg_not_test() -> Result<(), syn::Error> {
        let source = r#"
#[contract]
pub struct C;

#[cfg(not(test))]
mod prod {
    use std::vec::Vec;
}
"#;
        let file = parse_file(source)?;
        let hits = ForbiddenStdImportsCheck.run(&file, source);
        assert_eq!(hits.len(), 1, "#[cfg(not(test))] is production code and must be flagged");
        Ok(())
    }
}
