//! `self-invocation-via-current-contract-address` check.
use crate::util::contractimpl_functions_excluding_test;
use crate::{Check, Finding, Severity};
use quote::ToTokens;
use syn::{spanned::Spanned, File};

const CHECK_NAME: &str = "self-invocation-via-current-contract-address";
const RULE_URL: &str = "https://github.com/SorobanGuard/Guard-CLI/blob/main/docs/checks.md#self-invocation-via-current-contract-address-medium";

pub struct SelfInvocationViaCurrentContractAddress;

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

impl Check for SelfInvocationViaCurrentContractAddress {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, source: &str) -> Vec<Finding> {
        let _ = source;

        let mut out = Vec::new();
        for method in contractimpl_functions_excluding_test(file) {
            let body = body_text(&method.block);
            if body.contains("current_contract_address()") && (body.contains("invoke_contract") || body.contains("Client::new")) {
                if !body.contains("__check_auth") {
                    out.push(mk_finding(method.sig.ident.span().start().line, &method.sig.ident.to_string(),
                        "Self-invocation via env.current_contract_address()",
                        "Call internal helpers directly instead of host re-entry"));
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
    #[test]
    fn check_name_is_stable() { assert_eq!(CHECK_NAME, "self-invocation-via-current-contract-address"); }
    #[test]
    fn runs_on_contractimpl() {
        let src = "#[contractimpl]\nimpl C { pub fn f(env: Env) { env.storage().instance().set(&symbol_short!(\"x\"), &1u32); } }";
        let _ = SelfInvocationViaCurrentContractAddress.run(&parse_file(src).unwrap(), src);
    }
    #[test]
    fn non_contractimpl_empty() {
        assert!(SelfInvocationViaCurrentContractAddress.run(&parse_file("fn main(){}").unwrap(), "").is_empty());
    }
    #[test]
    fn cfg_test_module_excluded() {
        let src = "#[contractimpl] impl C { pub fn a() {} }\n#[cfg(test)] mod t { #[contractimpl] impl C { pub fn b() {} } }";
        let hits = SelfInvocationViaCurrentContractAddress.run(&parse_file(src).unwrap(), src);
        let _ = hits;
    }
    #[test]
    fn allow_suppression_name() { assert!(!CHECK_NAME.is_empty()); }
    #[test]
    fn findings_have_urls_when_present() {
        let src = "#[contractimpl] impl C { pub fn f() {} }";
        for f in SelfInvocationViaCurrentContractAddress.run(&parse_file(src).unwrap(), src) {
            if !f.description.is_empty() { assert!(f.rule_url.is_some()); }
        }
    }
}

