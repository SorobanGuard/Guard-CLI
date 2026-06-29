//! Walk Rust sources, parse with `syn`, and run all registered checks.
//!
//! Each [`Check`](soroban_guard_checks::Check) runs independently on the same parsed file;
//! findings are concatenated with **no shared mutable state** between checks.

use rayon::prelude::*;
use soroban_guard_checks::{default_checks, Finding};
use std::io::BufRead;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use thiserror::Error;
use walkdir::WalkDir;

fn has_generated_file_header(path: &Path) -> Result<bool, std::io::Error> {
    let file = std::fs::File::open(path)?;
    let mut reader = std::io::BufReader::new(file);
    let mut line = String::new();

    for _ in 0..5 {
        line.clear();
        if reader.read_line(&mut line)? == 0 {
            break;
        }
        let trimmed = line.trim_start();
        if trimmed.starts_with("// @generated")
            || trimmed.starts_with("// Code generated")
            || trimmed.starts_with("// DO NOT EDIT")
        {
            return Ok(true);
        }
    }

    Ok(false)
}

#[derive(Error, Debug)]
pub enum ScanError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Permission denied reading {path}")]
    PermissionDenied { path: PathBuf },
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
/// `root` may be a directory **or a single `.rs` file**. When a file path is given it is scanned
/// directly without any directory walk.
///
/// `excludes` are glob patterns (e.g. `vendor/**`, `**/generated/*.rs`) matched against each
/// file's path relative to `root`; matching files are skipped entirely.
///
/// `includes` are glob patterns; when non-empty only files matching at least one pattern are
/// scanned. When `includes` is empty all `.rs` files (minus excludes and generated-file
/// headers) are scanned.
pub fn scan_directory(
    root: &Path,
    excludes: &[String],
    includes: &[String],
) -> Result<(Vec<Finding>, usize, usize), ScanError> {
/// `root` is used only to compute relative file labels in findings (same convention as
/// [`scan_directory`]). `excludes` are glob patterns matched against each file's path
/// relative to `root`; matching files are skipped.
pub fn scan_files(
    paths: &[PathBuf],
    root: &Path,
    excludes: &[String],
) -> Result<(Vec<Finding>, usize), ScanError> {
    let root = root.canonicalize()?;

    // Single-file fast path: skip the directory walk entirely.
    if root.is_file() {
        let content = std::fs::read_to_string(&root)?;
        let syn_file = syn::parse_file(&content).map_err(|error| ScanError::Parse {
            path: root.clone(),
            message: error.to_string(),
        })?;
        let file_label = root.file_name().unwrap_or_default().to_string_lossy().to_string();
        let checks = default_checks();
        let mut findings: Vec<Finding> = checks
            .iter()
            .flat_map(|check| {
                let mut hits = check.run(&syn_file, &content);
                for f in &mut hits {
                    f.file_path.clone_from(&file_label);
                }
                hits
            })
            .collect();
        findings.sort_by(|a, b| a.line.cmp(&b.line));
        return Ok((findings, 1));
    }
    let exclude_patterns: Vec<glob::Pattern> = excludes
        .iter()
        .filter_map(|p| glob::Pattern::new(p).ok())
        .collect();

    let filtered: Vec<&PathBuf> = paths
        .iter()
        .filter(|path| {
            let label = path.strip_prefix(root).unwrap_or(path);
            !exclude_patterns
                .iter()
                .any(|pat| pat.matches_path(label) || pat.matches_path(path))
        })
        .map(|entry| entry.path().to_path_buf())
        .collect();

    let mut files_skipped = 0;
    let mut scan_entries = Vec::new();
    for entry in entries {
        let path = entry.path();
        if has_generated_file_header(path)? {
            files_skipped += 1;
            continue;
        }
        scan_entries.push(entry);
    }
    let files_scanned = scan_entries.len();

    let mut findings: Vec<Finding> = scan_entries
    let files_scanned = filtered.len();
    let checks = default_checks();

    let mut findings: Vec<Finding> = filtered
        .par_iter()
        .map(|entry| {
            let path = entry.path();
            let content = std::fs::read_to_string(path)?;
            let syn_file = syn::parse_file(&content).map_err(|e| ScanError::Parse {
                path: path.to_path_buf(),
                message: e.to_string(),
            })?;

            let file_label = path
                .strip_prefix(root)
                .unwrap_or(path)
                .to_string_lossy()
                .to_string();

            let file_findings: Vec<Finding> = checks
                .iter()
                .flat_map(|check| {
                    let check_name = check.name().to_string();
                    match catch_unwind(AssertUnwindSafe(|| check.run(&syn_file, &content))) {
                        Ok(mut hits) => {
                            for f in &mut hits {
                                f.file_path.clone_from(&file_label);
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
                            eprintln!("warning: {}", ScanError::CheckPanic {
                                check: check_name,
                                path: path.to_path_buf(),
                                message,
                            });
                            Vec::new()
                        }
                    }
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

    Ok((findings, files_scanned, files_skipped))
}

/// Findings for a single source file.
#[derive(Debug)]
pub struct FileScanResult {
    pub file_path: String,
    pub findings: Vec<Finding>,
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
) -> Result<(Vec<FileScanResult>, usize), ScanError> {
    let root = root.canonicalize()?;
    let exclude_patterns: Vec<glob::Pattern> = excludes
        .iter()
        .filter_map(|p| glob::Pattern::new(p).ok())
        .collect();
    let include_patterns: Vec<glob::Pattern> = includes
        .iter()
        .filter_map(|p| glob::Pattern::new(p).ok())
        .collect();

    let paths: Vec<PathBuf> = WalkDir::new(&root)
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
                .any(|c| matches!(c.as_os_str().to_str(), Some("target" | ".git")))
            {
                return false;
            }
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                return false;
            }
            let label = path.strip_prefix(&root).unwrap_or(path);
            if exclude_patterns
                .iter()
                .any(|p| p.matches_path(label) || p.matches_path(path))
            {
                return false;
            }
            if !include_patterns.is_empty()
                && !include_patterns
                    .iter()
                    .any(|p| p.matches_path(label) || p.matches_path(path))
            {
                return false;
            }
            true
        })
        .map(|e| e.path().to_path_buf())
        .collect();

    // Excludes already applied above; pass empty slice to avoid double-filtering.
    scan_files(&paths, &root, &[])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn scan_single_rs_file_directly() {
        let dir = std::env::temp_dir().join(format!(
            "soroban-guard-singlefile-{}-{}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        let file_path = dir.join("lib.rs");
        fs::write(&file_path, "pub fn f() {}").unwrap();

        let (_, files_scanned) = scan_directory(&file_path, &[], &[]).unwrap();
        assert_eq!(files_scanned, 1);
        fs::remove_dir_all(dir).unwrap();
    }

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

        let (_, files_scanned, files_skipped) =
            scan_directory(&root, &["src/excluded.rs".to_string()], &[]).unwrap();

        assert_eq!(files_scanned, 1);
        assert_eq!(files_skipped, 0);
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

        let (_, files_scanned, files_skipped) =
            scan_directory(&root, &[], &["src/lib.rs".to_string()]).unwrap();

        assert_eq!(files_scanned, 1);
        assert_eq!(files_skipped, 0);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn skips_generated_files_with_header() {
        let root = std::env::temp_dir().join(format!(
            "soroban-guard-generated-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(
            root.join("src/lib.rs"),
            "// @generated\npub fn generated() {}\n",
        )
        .unwrap();

        let (_, files_scanned, files_skipped) = scan_directory(&root, &[], &[]).unwrap();

        assert_eq!(files_scanned, 0);
        assert_eq!(files_skipped, 1);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn scan_files_returns_findings_for_explicit_paths() {
        let root = std::env::temp_dir().join(format!(
            "soroban-guard-scan-files-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(root.join("src")).unwrap();
        let included = root.join("src/lib.rs");
        let excluded = root.join("src/other.rs");
        fs::write(&included, "pub fn a() {}").unwrap();
        fs::write(&excluded, "pub fn b() {}").unwrap();

        let (_, files_scanned) = scan_files(&[included, excluded.clone()], &root, &[]).unwrap();
        assert_eq!(files_scanned, 2);

        // Exclude one file via glob
        let (_, files_scanned) =
            scan_files(&[excluded], &root, &["src/other.rs".to_string()]).unwrap();
        assert_eq!(files_scanned, 0);

        fs::remove_dir_all(root).unwrap();
    }
}
