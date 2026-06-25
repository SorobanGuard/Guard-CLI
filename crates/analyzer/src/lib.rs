//! Walk Rust sources, parse with `syn`, and run all registered checks.
//!
//! Each [`Check`](soroban_guard_checks::Check) runs independently on the same parsed file;
//! findings are concatenated with **no shared mutable state** between checks.

use rayon::prelude::*;
use soroban_guard_checks::{default_checks, Finding};
use std::path::{Path, PathBuf};
use thiserror::Error;
use walkdir::WalkDir;

#[derive(Error, Debug)]
pub enum ScanError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Failed to parse {path}: {message}")]
    Parse { path: PathBuf, message: String },
}

/// Recursively scan `.rs` files under `root` and aggregate findings from every check.
///
/// `excludes` are glob patterns (e.g. `vendor/**`, `**/generated/*.rs`) matched against each
/// file's path relative to `root`; matching files are skipped entirely.
pub fn scan_directory(root: &Path, excludes: &[String]) -> Result<Vec<Finding>, ScanError> {
    let root = root.canonicalize()?;
    let exclude_patterns: Vec<glob::Pattern> = excludes
        .iter()
        .filter_map(|p| glob::Pattern::new(p).ok())
        .collect();
    let checks = default_checks();
    let mut findings = Vec::new();

    for entry in WalkDir::new(&root)
        // Never follow symlinks: prevents infinite loops on symlink cycles (issue #43).
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        if path
            .components()
            .any(|c| matches!(c.as_os_str().to_str(), Some("target" | ".git")))
        {
            continue;
        }
        if path.extension().and_then(|s| s.to_str()) != Some("rs") {
            continue;
        }

        let file_label = path
            .strip_prefix(&root)
            .unwrap_or(path)
            .to_string_lossy()
            .to_string();

        if exclude_patterns
            .iter()
            .any(|p| p.matches(&file_label) || p.matches_path(path))
        {
            continue;
        }

        let content = std::fs::read_to_string(path)?;
        let syn_file = syn::parse_file(&content).map_err(|e| ScanError::Parse {
            path: path.to_path_buf(),
            message: e.to_string(),
        })?;

        for check in &checks {
            let mut from_check = check.run(&syn_file, &content);
            for f in &mut from_check {
                f.file_path = file_label.clone();
            }
            path.extension().and_then(|s| s.to_str()) == Some("rs")
        })
        .collect();

    let mut findings: Vec<Finding> = entries
        .par_iter()
        .map(|entry| {
            let path = entry.path();
            let content = std::fs::read_to_string(path)?;
            let syn_file = syn::parse_file(&content).map_err(|e| ScanError::Parse {
                path: path.to_path_buf(),
                message: e.to_string(),
            })?;

            let file_label = path
                .strip_prefix(&root)
                .unwrap_or(path)
                .to_string_lossy()
                .to_string();

            let file_findings: Vec<Finding> = checks
                .iter()
                .flat_map(|check| {
                    let mut from_check = check.run(&syn_file, &content);
                    for f in &mut from_check {
                        f.file_path.clone_from(&file_label);
                    }
                    from_check
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

    Ok(findings)
}
