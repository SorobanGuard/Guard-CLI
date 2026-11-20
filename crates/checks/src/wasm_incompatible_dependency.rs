//! `wasm-incompatible-dependency` check.
use crate::util::contractimpl_functions_excluding_test;
use crate::{Check, Finding, Severity};
use quote::ToTokens;
use syn::{spanned::Spanned, File};

const CHECK_NAME: &str = "wasm-incompatible-dependency";
const RULE_URL: &str = "https://github.com/SorobanGuard/Guard-CLI/blob/main/docs/checks.md#wasm-incompatible-dependency-medium";

pub struct WasmIncompatibleDependency;

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

impl Check for WasmIncompatibleDependency {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, source: &str) -> Vec<Finding> {
        let _ = source;
        Vec::new()
    }

fn scans_manifest(&self) -> bool {
    true
}

fn run_on_manifest(
    &self,
    manifest_source: &str,
    _lib_file: Option<&File>,
    lib_source: Option<&str>,
) -> Vec<Finding> {
    if !lib_source.is_some_and(|s| s.contains("#[contract]") || s.contains("#[contractimpl]")) {
        return Vec::new();
    }
    let Ok(parsed) = manifest_source.parse::<toml::Value>() else {
        return Vec::new();
    };
    let banned = ["rand", "getrandom", "tokio", "reqwest", "chrono"];
    let mut out = Vec::new();
    if let Some(deps) = parsed.get("dependencies").and_then(|d| d.as_table()) {
        for key in deps.keys() {
            if banned.iter().any(|b| key == b) {
                let line = manifest_source.lines().position(|l| l.contains(key)).unwrap_or(0) + 1;
                out.push(mk_finding(
                    line,
                    "Cargo.toml",
                    &format!("WASM-incompatible dependency `{key}` in [dependencies]"),
                    "Move to dev-dependencies or use soroban-sdk APIs (e.g. env.prng())",
                ));
            }
        }
    }
    out
}

}


#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn flags_rand() {
        let m = "[dependencies]\nrand = \"0.8\"\n";
        let hits = WasmIncompatibleDependency.run_on_manifest(m, None, Some("#[contract]"));
        assert_eq!(hits.len(), 1);
    }
    #[test]
    fn clean_manifest() {
        let m = "[dependencies]\nsoroban-sdk = \"22\"\n";
        let hits = WasmIncompatibleDependency.run_on_manifest(m, None, Some("#[contract]"));
        assert!(hits.is_empty());
    }
    #[test]
    fn no_contract() {
        let hits = WasmIncompatibleDependency.run_on_manifest("[dependencies]\nrand=\"1\"\n", None, Some("fn main(){"));
        assert!(hits.is_empty());
    }
    #[test]
    fn run_empty() {
        let f = syn::parse_file("fn y(){}").unwrap();
        assert!(WasmIncompatibleDependency.run(&f, "").is_empty());
    }
    #[test]
    fn rule_url_set() {
        let hits = WasmIncompatibleDependency.run_on_manifest("[dependencies]\nrand=\"1\"\n", None, Some("#[contract]"));
        assert!(hits[0].rule_url.is_some());
    }
}

