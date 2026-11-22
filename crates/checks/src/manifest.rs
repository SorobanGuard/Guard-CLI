//! Manifest-level checks run against `Cargo.toml` files (closes #979).

use crate::{Finding, ManifestCheck, Severity};
use std::path::Path;

/// Flags a `Cargo.toml` that does not list `cdylib` in `[lib] crate-type`.
///
/// Soroban contracts must be compiled as `cdylib` to produce a `.wasm` file.
/// A missing `cdylib` means the contract will never deploy on-chain, while still
/// compiling cleanly as a Rust library — a common silent misconfiguration.
pub struct MissingCdylibCheck;

const CHECK_NAME: &str = "missing-cdylib";

impl ManifestCheck for MissingCdylibCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, manifest: &toml::Value, path: &Path) -> Vec<Finding> {
        let has_cdylib = manifest
            .get("lib")
            .and_then(|lib| lib.get("crate-type"))
            .and_then(|ct| ct.as_array())
            .map(|arr| {
                arr.iter()
                    .any(|v| v.as_str() == Some("cdylib"))
            })
            .unwrap_or(false);

        if has_cdylib {
            return vec![];
        }

        // Workspace manifests (`[workspace]` without `[package]`) don't need cdylib.
        let is_workspace_root = manifest.get("workspace").is_some()
            && manifest.get("package").is_none();
        if is_workspace_root {
            return vec![];
        }

        // If there is no `[package]` at all, skip (virtual manifest or partial parse).
        if manifest.get("package").is_none() {
            return vec![];
        }

        let file_path = path.to_string_lossy().replace(std::path::MAIN_SEPARATOR, "/");
        vec![Finding {
            check_name: CHECK_NAME.to_string(),
            severity: Severity::Medium,
            file_path,
            line: 1,
            function_name: String::new(),
            description: "`[lib] crate-type` does not include `\"cdylib\"`. \
                Soroban contracts must be compiled as a C dynamic library to \
                produce a deployable `.wasm` artifact."
                .to_string(),
            rule_url: Some(
                "https://github.com/SorobanGuard/Guard-CLI/blob/main/docs/checks.md#missing-cdylib-medium"
                    .to_string(),
            ),
            suggestion: Some(
                "Add `crate-type = [\"cdylib\"]` under `[lib]` in Cargo.toml.".to_string(),
            ),
        }]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(toml_src: &str) -> toml::Value {
        toml_src.parse().expect("parse toml")
    }

    fn path() -> std::path::PathBuf {
        std::path::PathBuf::from("src/Cargo.toml")
    }

    #[test]
    fn passes_when_cdylib_present() {
        let m = parse(
            r#"
[package]
name = "my-contract"
version = "0.1.0"
edition = "2021"
[lib]
crate-type = ["cdylib"]
"#,
        );
        assert!(MissingCdylibCheck.run(&m, &path()).is_empty());
    }

    #[test]
    fn flags_when_cdylib_absent() {
        let m = parse(
            r#"
[package]
name = "my-contract"
version = "0.1.0"
edition = "2021"
"#,
        );
        let findings = MissingCdylibCheck.run(&m, &path());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].check_name, CHECK_NAME);
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn flags_when_cdylib_not_in_crate_type_array() {
        let m = parse(
            r#"
[package]
name = "my-contract"
version = "0.1.0"
[lib]
crate-type = ["rlib"]
"#,
        );
        let findings = MissingCdylibCheck.run(&m, &path());
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn passes_for_workspace_root_without_package() {
        let m = parse(
            r#"
[workspace]
members = ["crates/*"]
"#,
        );
        assert!(MissingCdylibCheck.run(&m, &path()).is_empty());
    }

    #[test]
    fn passes_when_cdylib_alongside_other_types() {
        let m = parse(
            r#"
[package]
name = "my-contract"
version = "0.1.0"
[lib]
crate-type = ["rlib", "cdylib"]
"#,
        );
        assert!(MissingCdylibCheck.run(&m, &path()).is_empty());
    }
}
