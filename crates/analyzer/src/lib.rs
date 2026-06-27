//! Walk Rust sources, parse with `syn`, and run all registered checks.
//!
//! Each [`Check`](soroban_guard_checks::Check) runs independently on the same parsed file;
//! findings are concatenated with **no shared mutable state** between checks.

use rayon::prelude::*;
use soroban_guard_checks::{default_checks, Finding};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use thiserror::Error;
use walkdir::WalkDir;

#[derive(Error, Debug)]
pub enum ScanError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Failed to parse {path}: {message}")]
    Parse { path: PathBuf, message: String },
    #[error("Check `{check}` panicked on {path}: {message}")]
    CheckPanic {
        check: String,
        path: PathBuf,
        message: String,
    },
}

/// Recursively scan `.rs` files under `root` and aggregate findings from every check.
///
/// `excludes` are glob patterns (e.g. `vendor/**`, `**/generated/*.rs`) matched against each
/// file's path relative to `root`; matching files are skipped entirely.
///
/// `includes` are glob patterns; when non-empty only files matching at least one pattern are
/// scanned. When `includes` is empty all `.rs` files (minus excludes) are scanned.
pub fn scan_directory(
    root: &Path,
    excludes: &[String],
    includes: &[String],
) -> Result<(Vec<Finding>, usize), ScanError> {
    let root = root.canonicalize()?;
    let exclude_patterns: Vec<glob::Pattern> = excludes
        .iter()
        .filter_map(|pattern| glob::Pattern::new(pattern).ok())
        .collect();
    let include_patterns: Vec<glob::Pattern> = includes
        .iter()
        .filter_map(|pattern| glob::Pattern::new(pattern).ok())
        .collect();
    let checks = default_checks();

    let entries: Vec<_> = WalkDir::new(&root)
        // Never follow symlinks: prevents infinite loops on symlink cycles.
        .follow_links(false)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| {
            if !entry.file_type().is_file() {
                return false;
            }

            let path = entry.path();
            if path
                .components()
                .any(|component| matches!(component.as_os_str().to_str(), Some("target" | ".git")))
            {
                return false;
            }
            if path.extension().and_then(|extension| extension.to_str()) != Some("rs") {
                return false;
            }

            let file_label = path.strip_prefix(&root).unwrap_or(path);

            if exclude_patterns
                .iter()
                .any(|pattern| pattern.matches_path(file_label) || pattern.matches_path(path))
            {
                return false;
            }

            if !include_patterns.is_empty()
                && !include_patterns
                    .iter()
                    .any(|pattern| pattern.matches_path(file_label) || pattern.matches_path(path))
            {
                return false;
            }

            true
        })
        .map(|entry| entry.path().to_path_buf())
        .collect();
    let files_scanned = entries.len();

    let mut findings: Vec<Finding> = entries
        .par_iter()
        .map(|path| {
            let content = std::fs::read_to_string(path)?;
            let syn_file = syn::parse_file(&content).map_err(|error| ScanError::Parse {
                path: path.to_path_buf(),
                message: error.to_string(),
            })?;

            let file_label = path
                .strip_prefix(&root)
                .unwrap_or(path)
                .to_string_lossy()
                .to_string();

            let file_findings = checks
                .iter()
                .flat_map(|check| {
                    let check_name = check.name().to_string();
                    let from_check = catch_unwind(AssertUnwindSafe(|| check.run(&syn_file, &content)));
                    let mut findings = match from_check {
                        Ok(mut hits) => {
                            for finding in &mut hits {
                                finding.file_path.clone_from(&file_label);
                            }
                            hits
                        }
                        Err(payload) => {
                            let message = if let Some(msg) = payload.downcast_ref::<&str>() {
                                msg.to_string()
                            } else if let Some(msg) = payload.downcast_ref::<String>() {
                                msg.clone()
                            } else {
                                "panic payload was not a string".to_string()
                            };
                            let scan_error = ScanError::CheckPanic {
                                check: check_name.clone(),
                                path: path.to_path_buf(),
                                message,
                            };
                            eprintln!("warning: {}", scan_error);
                            Vec::new()
                        }
                    };
                    findings
                })
                .collect();

            Ok(file_findings)
        })
        .collect::<Result<Vec<Vec<Finding>>, ScanError>>()?
        .into_iter()
        .flatten()
        .collect();

    findings.sort_by(|a, b| {
        a.file_path
            .cmp(&b.file_path)
            .then_with(|| a.line.cmp(&b.line))
    });

    Ok((findings, files_scanned))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn scan_error_check_panic_format() {
        let err = ScanError::CheckPanic {
            check: "example-check".to_string(),
            path: PathBuf::from("src/lib.rs"),
            message: "unexpected AST shape".to_string(),
        };

        assert_eq!(
            err.to_string(),
            "Check `example-check` panicked on src/lib.rs: unexpected AST shape"
        );
    }

    #[test]
    fn reports_scanned_rust_file_count_after_filters() {
        let root = std::env::temp_dir().join(format!(
            "soroban-guard-analyzer-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(root.join("src")).unwrap();
        fs::create_dir_all(root.join("target")).unwrap();
        fs::write(root.join("src/lib.rs"), "pub fn included() {}").unwrap();
        fs::write(root.join("src/excluded.rs"), "pub fn excluded() {}").unwrap();
        fs::write(root.join("target/generated.rs"), "pub fn generated() {}").unwrap();
        fs::write(root.join("README.md"), "not Rust").unwrap();

        let (_, files_scanned) =
            scan_directory(&root, &["src/excluded.rs".to_string()], &[]).unwrap();

        assert_eq!(files_scanned, 1);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn include_filter_limits_scanned_files() {
        let root = std::env::temp_dir().join(format!(
            "soroban-guard-include-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(root.join("src/lib.rs"), "pub fn a() {}").unwrap();
        fs::write(root.join("src/other.rs"), "pub fn b() {}").unwrap();

        let (_, files_scanned) =
            scan_directory(&root, &[], &["src/lib.rs".to_string()]).unwrap();

        assert_eq!(files_scanned, 1);
        fs::remove_dir_all(root).unwrap();
    }
}
