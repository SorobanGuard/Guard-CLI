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
///
/// When `files` is `Some`, only those relative paths are scanned instead of walking `root`.
/// When `verbose` is `true`, each file path is printed to stderr before scanning.
pub fn scan_directory(
    root: &Path,
    excludes: &[String],
    verbose: bool,
    files: Option<&[PathBuf]>,
) -> Result<(Vec<Finding>, usize), ScanError> {
    let root = root.canonicalize()?;
    let exclude_patterns: Vec<glob::Pattern> = excludes
        .iter()
        .filter_map(|pattern| glob::Pattern::new(pattern).ok())
        .collect();
    let checks = default_checks();

    let entries: Vec<PathBuf> = if let Some(specific_files) = files {
        specific_files
            .iter()
            .filter_map(|f| {
                let full_path = root.join(f);
                if !full_path.is_file() {
                    return None;
                }
                if full_path
                    .components()
                    .any(|c| matches!(c.as_os_str().to_str(), Some("target" | ".git")))
                {
                    return None;
                }
                if full_path.extension().and_then(|e| e.to_str()) != Some("rs") {
                    return None;
                }
                let file_label = full_path.strip_prefix(&root).unwrap_or(&full_path);
                if exclude_patterns
                    .iter()
                    .any(|p| p.matches_path(file_label) || p.matches_path(&full_path))
                {
                    return None;
                }
                Some(full_path)
            })
            .collect()
    } else {
        WalkDir::new(&root)
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
                let file_label = path.strip_prefix(&root).unwrap_or(path);
                !exclude_patterns
                    .iter()
                    .any(|p| p.matches_path(file_label) || p.matches_path(path))
            })
            .map(|entry| entry.path().to_path_buf())
            .collect()
    };
    let files_scanned = entries.len();

    let mut findings: Vec<Finding> = entries
        .par_iter()
        .map(|path| {
            if verbose {
                let label = path.strip_prefix(&root).unwrap_or(path);
                eprintln!("scanning {}", label.display());
            }
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
                    let mut from_check = check.run(&syn_file, &content);
                    for finding in &mut from_check {
                        finding.file_path.clone_from(&file_label);
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

    Ok((findings, files_scanned))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

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

        let (_, files_scanned) = scan_directory(&root, &["src/excluded.rs".to_string()], false, None).unwrap();

        assert_eq!(files_scanned, 1);
        fs::remove_dir_all(root).unwrap();
    }
}
