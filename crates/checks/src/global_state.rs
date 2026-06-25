//! Detection of `static mut` declarations in Soroban contract source files.
//!
//! `static mut` variables are undefined behavior in a concurrent Soroban executor and
//! must never appear in contract code. Any mutation requires `unsafe` and is inherently
//! data-race prone in a multi-threaded host environment.

use crate::{Check, Finding, Severity};
use syn::{File, Item, StaticMutability};

const CHECK_NAME: &str = "mutable-global-state";

/// Flags any `static mut` declaration found in the source file.
pub struct MutableGlobalStateCheck;

impl Check for MutableGlobalStateCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for item in &file.items {
            if let Item::Static(s) = item {
                if matches!(s.mutability, StaticMutability::Mut(_)) {
                    out.push(finding_for(s));
                }
            }
        }
        out
    }
}

fn finding_for(s: &syn::ItemStatic) -> Finding {
    use syn::spanned::Spanned;
    let name = s.ident.to_string();
    Finding {
        check_name: CHECK_NAME.to_string(),
        severity: Severity::High,
        file_path: String::new(),
        line: s.span().start().line,
        function_name: "module".to_string(),
        description: format!(
            "`static mut {name}` is undefined behaviour in a concurrent Soroban executor. \
             Mutable statics require `unsafe` and are inherently data-race prone."
        ),
        rule_url: Some(
            "https://github.com/SorobanGuard/Guard-CLI/blob/main/docs/checks.md#mutable-global-state-high"
                .to_string(),
        ),
        suggestion: Some(
            "Remove the `mut` qualifier and use contract storage (`env.storage()`) for mutable state."
                .to_string(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Check;
    use syn::parse_file;

    #[test]
    fn flags_static_mut() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
static mut COUNTER: u32 = 0;

pub struct C;
"#,
        )?;
        let hits = MutableGlobalStateCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::High);
        assert_eq!(hits[0].check_name, CHECK_NAME);
        assert!(hits[0].description.contains("COUNTER"));
        Ok(())
    }

    #[test]
    fn ignores_immutable_static() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
static COUNTER: u32 = 0;

pub struct C;
"#,
        )?;
        let hits = MutableGlobalStateCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn flags_multiple_static_mut() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
static mut A: u32 = 0;
static mut B: u64 = 1;
static C: &str = "ok";
"#,
        )?;
        let hits = MutableGlobalStateCheck.run(&file, "");
        assert_eq!(hits.len(), 2);
        Ok(())
    }
}
