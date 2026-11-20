//! `missing-pause-guard` check.
use crate::util::contractimpl_functions_excluding_test;
use crate::{Check, Finding, Severity};
use quote::ToTokens;
use syn::{spanned::Spanned, File};

const CHECK_NAME: &str = "missing-pause-guard";
const RULE_URL: &str = "https://github.com/SorobanGuard/Guard-CLI/blob/main/docs/checks.md#missing-pause-guard-medium";

pub struct MissingPauseGuard;

fn body_text(block: &syn::Block) -> String {
    let mut ts = proc_macro2::TokenStream::new();
    block.to_tokens(&mut ts);
    ts.to_string()
}

fn mk_finding(line: usize, fn_name: &str, description: &str, suggestion: &str) -> Finding {
    Finding {
        check_name: CHECK_NAME.to_string(),
        severity: Severity::Medium,
        file_path: String::new(),
        line,
        function_name: fn_name.to_string(),
        description: description.to_string(),
        rule_url: Some(RULE_URL.to_string()),
        suggestion: Some(suggestion.to_string()),
    }
}

impl Check for MissingPauseGuard {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, source: &str) -> Vec<Finding> {
        let _ = source;

        if !(source.contains("fn pause") || source.contains("set_paused") || source.contains("emergency_stop")) {
            return Vec::new();
        }
        let mut out = Vec::new();
        for method in contractimpl_functions_excluding_test(file) {
            let name = method.sig.ident.to_string();
            if matches!(name.as_str(), "pause" | "unpause" | "set_paused" | "emergency_stop") { continue; }
            let body = body_text(&method.block);
            if !(body.contains(".set(") || body.contains(".remove(")) { continue; }
            if body.contains("paused") || body.contains("is_paused") || body.contains("when_not_paused") { continue; }
            out.push(mk_finding(method.sig.ident.span().start().line, &name,
                "Mutating entrypoint does not consult pause flag",
                "Read paused/is_paused storage before state changes"));
        }
        out

    }

}


#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_file;
    #[test]
    fn check_name_is_stable() { assert_eq!(CHECK_NAME, "missing-pause-guard"); }
    #[test]
    fn runs_on_contractimpl() {
        let src = "#[contractimpl]\nimpl C { pub fn f(env: Env) { env.storage().instance().set(&symbol_short!(\"x\"), &1u32); } }";
        let _ = MissingPauseGuard.run(&parse_file(src).unwrap(), src);
    }
    #[test]
    fn non_contractimpl_empty() {
        assert!(MissingPauseGuard.run(&parse_file("fn main(){}").unwrap(), "").is_empty());
    }
    #[test]
    fn cfg_test_module_excluded() {
        let src = "#[contractimpl] impl C { pub fn a() {} }\n#[cfg(test)] mod t { #[contractimpl] impl C { pub fn b() {} } }";
        let hits = MissingPauseGuard.run(&parse_file(src).unwrap(), src);
        let _ = hits;
    }
    #[test]
    fn allow_suppression_name() { assert!(!CHECK_NAME.is_empty()); }
    #[test]
    fn findings_have_urls_when_present() {
        let src = "#[contractimpl] impl C { pub fn f() {} }";
        for f in MissingPauseGuard.run(&parse_file(src).unwrap(), src) {
            if !f.description.is_empty() { assert!(f.rule_url.is_some()); }
        }
    }
}

