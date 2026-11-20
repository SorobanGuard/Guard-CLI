//! `missing-cdylib-crate-type` check.
use crate::util::contractimpl_functions_excluding_test;
use crate::{Check, Finding, Severity};
use quote::ToTokens;
use syn::{spanned::Spanned, File};

const CHECK_NAME: &str = "missing-cdylib-crate-type";
const RULE_URL: &str = "https://github.com/SorobanGuard/Guard-CLI/blob/main/docs/checks.md#missing-cdylib-crate-type-medium";

pub struct MissingCdylibCrateType;

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

impl Check for MissingCdylibCrateType {
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
    let has_contract =
        lib_source.is_some_and(|s| s.contains("#[contract]") || s.contains("#[contractimpl]"));
    if !has_contract {
        return Vec::new();
    }
    let Ok(parsed) = manifest_source.parse::<toml::Value>() else {
        return Vec::new();
    };
    let has_cdylib = parsed
        .get("lib")
        .and_then(|l| l.get("crate-type"))
        .and_then(|c| c.as_array())
        .map(|a| a.iter().any(|v| v.as_str() == Some("cdylib")))
        .unwrap_or(false);
    if has_cdylib {
        return Vec::new();
    }
    let line = manifest_source
        .lines()
        .position(|l| l.trim() == "[lib]")
        .unwrap_or(0)
        + 1;
    vec![mk_finding(
        line,
        "Cargo.toml",
        "Contract crate missing cdylib in crate-type",
        "Set [lib] crate-type = [\"cdylib\"] (optionally add \"rlib\" for tests)",
    )]
}

}


#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn check_name() { assert_eq!(CHECK_NAME, "missing-cdylib-crate-type"); }
    #[test]
    fn manifest_missing_cdylib() {
        let manifest = "[package]\nname = \"x\"\n\n[lib]\ncrate-type = [\"rlib\"]\n";
        let lib = "#[contract]\nstruct C;\n";
        let hits = MissingCdylibCrateType.run_on_manifest(manifest, None, Some(lib));
        assert_eq!(hits.len(), 1);
    }
    #[test]
    fn manifest_has_cdylib() {
        let manifest = "[lib]\ncrate-type = [\"cdylib\"]\n";
        let lib = "#[contractimpl]";
        let hits = MissingCdylibCrateType.run_on_manifest(manifest, None, Some(lib));
        assert!(hits.is_empty());
    }
    #[test]
    fn no_contract_crate() {
        let hits = MissingCdylibCrateType.run_on_manifest("[lib]\n", None, Some("fn main() {}"));
        assert!(hits.is_empty());
    }
    #[test]
    fn run_on_rust_empty() {
        let f: File = syn::parse_file("fn x() {}").unwrap();
        assert!(MissingCdylibCrateType.run(&f, "").is_empty());
    }
    #[test]
    fn suggestion_present() {
        let manifest = "[lib]\ncrate-type = [\"rlib\"]\n";
        let hits = MissingCdylibCrateType.run_on_manifest(manifest, None, Some("#[contract]"));
        assert!(hits[0].suggestion.is_some());
    }
}

