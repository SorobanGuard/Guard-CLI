//! `debug-output-in-contract` check.
use crate::util::contractimpl_functions_excluding_test;
use crate::{Check, Finding, Severity};
use quote::ToTokens;
use syn::{spanned::Spanned, File};

const CHECK_NAME: &str = "debug-output-in-contract";
const RULE_URL: &str = "https://github.com/SorobanGuard/Guard-CLI/blob/main/docs/checks.md#debug-output-in-contract-low";

pub struct DebugOutputInContract;

fn body_text(block: &syn::Block) -> String {
    let mut ts = proc_macro2::TokenStream::new();
    block.to_tokens(&mut ts);
    ts.to_string()
}

fn mk_finding(line: usize, fn_name: &str, description: &str, suggestion: &str) -> Finding {
    Finding {
        check_name: CHECK_NAME.to_string(),
        severity: Severity::Low,
        file_path: String::new(),
        line,
        function_name: fn_name.to_string(),
        description: description.to_string(),
        rule_url: Some(RULE_URL.to_string()),
        suggestion: Some(suggestion.to_string()),
    }
}

impl Check for DebugOutputInContract {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, source: &str) -> Vec<Finding> {
        let _ = source;

let mut out = Vec::new();
for method in contractimpl_functions_excluding_test(file) {
    let fn_name = method.sig.ident.to_string();
    let body = body_text(&method.block);
    for (pat, sev, desc, sug) in [
        ("println!", Severity::Medium, "std print macro in contract code", "Remove println! before deployment"),
        ("dbg!", Severity::Medium, "dbg! in contract code", "Remove dbg! before deployment"),
        ("eprintln!", Severity::Medium, "stderr print in contract code", "Remove eprint macros"),
        (".logs().add(", Severity::Low, "debug log via env.logs()", "Remove env.logs().add in production"),
    ] {
        if body.contains(pat) {
            out.push(Finding {
                check_name: CHECK_NAME.to_string(),
                severity: sev,
                file_path: String::new(),
                line: method.sig.ident.span().start().line,
                function_name: fn_name.clone(),
                description: desc.to_string(),
                rule_url: Some(RULE_URL.to_string()),
                suggestion: Some(sug.to_string()),
            });
        }
    }
}
out

    }

}


#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_file;
    fn run(src: &str) -> Vec<Finding> {
        DebugOutputInContract.run(&parse_file(src).unwrap(), src)
    }
    #[test]
    fn flags_println() {
        let src = "#[contractimpl]\nimpl C { pub fn f(_e: Env) { println!(\"x\"); } }";
        assert!(!run(src).is_empty());
    }
    #[test]
    fn clean() {
        let src = "#[contractimpl]\nimpl C { pub fn f(_e: Env) { let _ = 1; } }";
        assert!(run(src).is_empty());
    }
    #[test]
    fn non_contractimpl() {
        assert!(run("fn f(){println!(\"x\");}").is_empty());
    }
    #[test]
    fn cfg_test_excluded() {
        let src = "#[contractimpl] impl C { pub fn live() {} }\n#[cfg(test)] mod t { #[contractimpl] impl C { pub fn t() { println!(\"t\"); } } }";
        let file = parse_file(src).unwrap();
        let hits = DebugOutputInContract.run(&file, src);
        assert!(hits.is_empty());
    }
    #[test]
    fn allow_name_matches() {
        assert_eq!(CHECK_NAME, "debug-output-in-contract");
    }
}

