//! Walk Rust sources, parse with `syn`, and run all registered checks.
//!
//! Each [`Check`](soroban_guard_checks::Check) runs independently on the same parsed file;
//! findings are concatenated with **no shared mutable state** between checks.

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
pub fn scan_directory(root: &Path) -> Result<Vec<Finding>, ScanError> {
    let root = root.canonicalize()?;
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

        let content = std::fs::read_to_string(path)?;
        // The file is parsed once here and the resulting `syn::File` is shared across all checks
        // (issue #42). No check re-parses the source; each receives a reference to the same AST.
        let syn_file = syn::parse_file(&content).map_err(|e| ScanError::Parse {
            path: path.to_path_buf(),
            message: e.to_string(),
        })?;

        let file_label = path
            .strip_prefix(&root)
            .unwrap_or(path)
            .to_string_lossy()
            .to_string();

        for check in &checks {
            let mut from_check = check.run(&syn_file, &content);
            for f in &mut from_check {
                f.file_path = file_label.clone();
            }
            findings.extend(from_check);
        }
    }

    Ok(findings)
}
