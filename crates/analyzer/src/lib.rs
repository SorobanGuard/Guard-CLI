//! Walk Rust sources, parse with `syn`, and run registered checks.
//!
//! Each [`Check`](soroban_guard_checks::Check) runs independently on the same parsed file;
//! findings are concatenated with no shared mutable state between checks.

use rayon::prelude::*;
use serde::Serialize;
use soroban_guard_checks::util::contractimpl_functions_with_type_excluding_test;
use soroban_guard_checks::{default_checks, Check, Finding};
use std::collections::HashSet;
use std::io::BufRead;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use syn::spanned::Spanned;
use thiserror::Error;
use walkdir::WalkDir;

const SUPPRESSION_PREFIX: &str = "// soroban-guard: allow(";

/// The source line range of one `#[contractimpl]` method, paired with its enclosing type's
/// name — used to scope function-level suppressions to the specific `impl` block they were
/// written above, instead of matching any same-named method anywhere in the file.
struct FnSpan {
    impl_type: String,
    function_name: String,
    start_line: usize,
    end_line: usize,
}

fn build_fn_spans(file: &syn::File) -> Vec<FnSpan> {
    contractimpl_functions_with_type_excluding_test(file)
        .into_iter()
        .map(|(impl_type, method)| FnSpan {
            impl_type,
            function_name: method.sig.ident.to_string(),
            start_line: method.sig.ident.span().start().line,
            end_line: method.block.span().end().line,
        })
        .collect()
}

#[derive(Error, Debug)]
pub enum ScanError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Permission denied reading {path}")]
    PermissionDenied { path: PathBuf },
    #[error("IO error reading {path}: {source}")]
    IoRead {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("Failed to parse {path}: {message}")]
    Parse { path: PathBuf, message: String },
    #[error("Check `{check}` panicked on {path}: {message}")]
    CheckPanic {
        check: String,
        path: PathBuf,
        message: String,
    },
    #[error("Invalid glob pattern `{pattern}`: {reason}")]
    InvalidGlobPattern { pattern: String, reason: String },
    /// A WalkDir traversal error (e.g. permission-denied on a subdirectory).
    /// The scan is incomplete and must not be treated as clean.
    #[error("Directory traversal error at {path}: {reason}")]
    Traversal { path: PathBuf, reason: String },
}

/// The panic payload recovered from a [`Check`] that aborted mid-scan, in
/// serializable form so it can be surfaced to CI consumers via `--json`/`--sarif`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckPanic {
    /// Name of the check that panicked.
    pub check: String,
    /// Path of the file being analyzed when the check panicked.
    pub path: PathBuf,
    /// The recovered panic message (or a placeholder when it was not a string).
    pub message: String,
}

impl From<&ScanError> for CheckPanic {
    fn from(err: &ScanError) -> Self {
        match err {
            ScanError::CheckPanic { check, path, message } => CheckPanic {
                check: check.clone(),
                path: path.clone(),
                message: message.clone(),
            },
            // Only CheckPanic errors are ever converted; fall back to a best-effort
            // representation for any other variant so callers never panic.
            other => CheckPanic {
                check: "unknown".to_string(),
                path: PathBuf::new(),
                message: other.to_string(),
            },
        }
    }
}

/// Information about check panics encountered during a scan, alongside the findings.
///
/// A degraded scan (one or more checks panicked) is distinguishable from a clean one
/// by [`CheckPanicReport::is_degraded`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckPanicReport {
    /// Every check that panicked during the scan.
    pub panics: Vec<CheckPanic>,
}

impl CheckPanicReport {
    /// Whether any check panicked while the scan ran.
    pub fn is_degraded(&self) -> bool {
        !self.panics.is_empty()
    }

    /// Number of checks that panicked during the scan.
    pub fn len(&self) -> usize {
        self.panics.len()
    }

    /// Whether the report carries no panics.
    pub fn is_empty(&self) -> bool {
        self.panics.is_empty()
    }
}

impl From<&ScanError> for CheckPanicReport {
    fn from(err: &ScanError) -> Self {
        match err {
            ScanError::CheckPanic { .. } => CheckPanicReport {
                panics: vec![CheckPanic::from(err)],
            },
            _ => CheckPanicReport::default(),
        }
    }
}

#[derive(Default)]
struct Suppressions {
    line_checks: HashSet<(usize, String)>,
    /// Keyed on `(impl_type, function_name, check_name)` so a suppression above one
    /// `#[contractimpl]` method doesn't also silence a same-named method on a different type.
    function_checks: HashSet<(String, String, String)>,
}

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

fn parse_allow_checks(line: &str) -> Option<Vec<String>> {
    let trimmed = line.trim_start();
    let rest = trimmed.strip_prefix(SUPPRESSION_PREFIX)?;
    let (inside, _) = rest.split_once(')')?;
    let checks: Vec<String> = inside
        .split(',')
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(ToOwned::to_owned)
        .collect();
    (!checks.is_empty()).then_some(checks)
}

/// Index of the first line at or after `from` that carries actual code, skipping the
/// lines rustfmt and normal documentation routinely insert between a suppression
/// comment and the item it applies to: blank lines, `//` / `///` / `//!` comments, and
/// `#[...]` / `#![...]` attribute lines.
fn next_substantive_line(lines: &[&str], from: usize) -> Option<usize> {
    (from..lines.len()).find(|&i| {
        let t = lines[i].trim_start();
        !(t.is_empty() || t.starts_with("//") || t.starts_with("#[") || t.starts_with("#!["))
    })
}

fn parse_suppressions(source: &str, fn_spans: &[FnSpan]) -> Suppressions {
    let lines: Vec<&str> = source.lines().collect();
    let mut suppressions = Suppressions::default();

    for (idx, line) in lines.iter().enumerate() {
        let Some(checks) = parse_allow_checks(line) else {
            continue;
        };
        let Some(target_idx) = next_substantive_line(&lines, idx + 1) else {
            continue;
        };
        let target_line_number = target_idx + 1;
        // Resolve the target from the parsed `#[contractimpl]` spans, keyed on the line
        // the method starts on - never by scanning the raw text for `"fn "`, which also
        // matches comments, string literals, and type positions.
        if let Some(span) = fn_spans.iter().find(|s| s.start_line == target_line_number) {
            for check in checks {
                suppressions.function_checks.insert((
                    span.impl_type.clone(),
                    span.function_name.clone(),
                    check,
                ));
            }
        } else {
            for check in checks {
                suppressions.line_checks.insert((target_line_number, check));
            }
        }
    }

    suppressions
}

fn is_suppressed(finding: &Finding, suppressions: &Suppressions, fn_spans: &[FnSpan]) -> bool {
    if suppressions
        .line_checks
        .contains(&(finding.line, finding.check_name.clone()))
    {
        return true;
    }
    let impl_type = fn_spans
        .iter()
        .find(|s| {
            // When a check leaves function_name empty (e.g. unchecked-divisor,
            // symbol-key-collision, mutable-global-state), fall back to line-range
            // containment so a function-scoped suppression above the enclosing method
            // still silences the finding.
            (finding.function_name.is_empty() || s.function_name == finding.function_name)
                && s.start_line <= finding.line
                && finding.line <= s.end_line
        })
        .map(|s| s.impl_type.clone())
        .unwrap_or_default();
    suppressions.function_checks.contains(&(
        impl_type,
        finding.function_name.clone(),
        finding.check_name.clone(),
    ))
}

/// Drop only findings that are identical in everything a reader would use to tell
/// them apart. Keying on `(file, line, check_name)` alone collapsed distinct
/// same-line findings from checks that legitimately report more than once per line
/// (e.g. one `unchecked-arithmetic` hit per operator).
fn dedup_findings(findings: &mut Vec<Finding>) {
    let mut seen = HashSet::new();
    findings.retain(|f| {
        seen.insert((
            f.file_path.clone(),
            f.line,
            f.check_name.clone(),
            f.function_name.clone(),
            f.description.clone(),
            f.severity,
        ))
    });
}

/// Drop the medium-severity `integer-division-truncation` finding when the same
/// file/line/function already has a high-severity `unchecked-divisor` finding.
/// Both checks fire on the exact same non-literal `a / b` expression, so reporting
/// both is redundant signal for one underlying division.
fn suppress_redundant_division_finding(findings: &mut Vec<Finding>) {
    let divisor_hits: HashSet<(String, usize, String)> = findings
        .iter()
        .filter(|f| f.check_name == "unchecked-divisor")
        .map(|f| (f.file_path.clone(), f.line, f.function_name.clone()))
        .collect();
    findings.retain(|f| {
        f.check_name != "integer-division-truncation"
            || !divisor_hits.contains(&(f.file_path.clone(), f.line, f.function_name.clone()))
    });
}

/// Compile a list of glob source strings into `glob::Pattern`s, surfacing the first
/// invalid pattern as `ScanError::InvalidGlobPattern`. Shared by the exclude and
/// include filters so `--include`/`--exclude` stay behaviourally identical.
fn compile_globs(patterns: &[String]) -> Result<Vec<glob::Pattern>, ScanError> {
    let mut compiled = Vec::with_capacity(patterns.len());
    for p in patterns {
        match glob::Pattern::new(p) {
            Ok(pattern) => compiled.push(pattern),
            Err(e) => {
                return Err(ScanError::InvalidGlobPattern {
                    pattern: p.clone(),
                    reason: e.to_string(),
                })
            }
        }
    }
    Ok(compiled)
}

/// Result of applying the shared source-file filter to one candidate path.
enum PathVerdict {
    /// A `.rs` file that passed every filter and should be scanned.
    Scan,
    /// A `.rs` file omitted because it carries a generated-file header.
    GeneratedSkip,
    /// Not a `.rs` file, or excluded by an exclude/include glob.
    Reject,
}

fn glob_hit(patterns: &[glob::Pattern], label: &Path, path: &Path) -> bool {
    patterns
        .iter()
        .any(|p| p.matches_path(label) || p.matches_path(path))
}

/// The single filter every scan entry point applies to a candidate source file:
/// `.rs` extension, exclude globs, include globs (when non-empty), then the
/// generated-file header check. `label` is the path relative to the scan root.
fn classify_rust_path(
    path: &Path,
    label: &Path,
    exclude_patterns: &[glob::Pattern],
    include_patterns: &[glob::Pattern],
) -> Result<PathVerdict, ScanError> {
    if path.extension().and_then(|e| e.to_str()) != Some("rs") {
        return Ok(PathVerdict::Reject);
    }
    if glob_hit(exclude_patterns, label, path) {
        return Ok(PathVerdict::Reject);
    }
    if !include_patterns.is_empty() && !glob_hit(include_patterns, label, path) {
        return Ok(PathVerdict::Reject);
    }
    if has_generated_file_header(path)? {
        return Ok(PathVerdict::GeneratedSkip);
    }
    Ok(PathVerdict::Scan)
}

/// Collect `.rs` paths under `root`, applying exclude/include glob filters and skipping
/// files that carry a generated-file header. Returns `(paths, files_skipped)` where
/// `files_skipped` is the count of files omitted due to the generated-file header.
fn collect_rust_paths(
    root: &Path,
    excludes: &[String],
    includes: &[String],
) -> Result<(Vec<PathBuf>, usize), ScanError> {
    let exclude_patterns = compile_globs(excludes)?;
    let include_patterns = compile_globs(includes)?;

    if root.is_file() {
        return Ok((vec![root.to_path_buf()], 0));
    }

    let mut files_skipped = 0;
    let mut paths = Vec::new();
    for entry in WalkDir::new(root).follow_links(false).into_iter() {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                // Surface traversal errors (permission-denied on a directory,
                // vanished path, symlink loop, etc.) as a hard failure.  A
                // deploy-gating tool must not present an incomplete scan as clean.
                let path = e
                    .path()
                    .map(|p| p.to_path_buf())
                    .unwrap_or_else(|| root.to_path_buf());
                return Err(ScanError::Traversal {
                    path,
                    reason: e.to_string(),
                });
            }
        };
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        if path
            .components()
            .any(|c| matches!(c.as_os_str().to_str(), Some("target" | ".git")))
        {
            continue;
        }
        let label = path.strip_prefix(root).unwrap_or(path);
        match classify_rust_path(path, label, &exclude_patterns, &include_patterns) {
            Ok(PathVerdict::Scan) => paths.push(path.to_path_buf()),
            Ok(PathVerdict::GeneratedSkip) => files_skipped += 1,
            Ok(PathVerdict::Reject) => {}
            // An unreadable file must not abort the whole scan (a `0600` file in a shared
            // checkout, a broken symlink, a race with WalkDir's listing). Warn naming the
            // path and skip it, matching the warn-and-continue precedent for check panics.
            Err(e) => {
                let err = match &e {
                    ScanError::Io(io)
                        if io.kind() == std::io::ErrorKind::PermissionDenied =>
                    {
                        ScanError::PermissionDenied {
                            path: path.to_path_buf(),
                        }
                    }
                    _ => e,
                };
                eprintln!("warning: {err}, skipping file");
                continue;
            }
        }
        paths.push(path.to_path_buf());
    }

    Ok((paths, files_skipped))
}

fn run_checks_for_file(
    path: &Path,
    root: &Path,
    checks: &[Box<dyn Check + Send + Sync>],
) -> Result<(Vec<Finding>, Vec<ScanError>), ScanError> {
    let content = std::fs::read_to_string(path).map_err(|e| ScanError::IoRead {
        path: path.to_path_buf(),
        source: e,
    })?;
    let syn_file = syn::parse_file(&content).map_err(|e| ScanError::Parse {
        path: path.to_path_buf(),
        message: e.to_string(),
    })?;
    let file_label = if root.is_file() {
        path.file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string()
    } else {
        path.strip_prefix(root)
            .unwrap_or(path)
            .to_string_lossy()
            .to_string()
    };
    let fn_spans = build_fn_spans(&syn_file);
    let suppressions = parse_suppressions(&content, &fn_spans);

    let mut findings: Vec<Finding> = Vec::new();
    let mut check_panics: Vec<ScanError> = Vec::new();
    for check in checks {
        let check_name = check.name().to_string();
        match catch_unwind(AssertUnwindSafe(|| check.run(&syn_file, &content))) {
            Ok(mut hits) => {
                for finding in &mut hits {
                    finding.file_path.clone_from(&file_label);
                }
                findings.extend(
                    hits.into_iter()
                        .filter(|finding| !is_suppressed(finding, &suppressions, &fn_spans)),
                );
            }
            Err(payload) => {
                let message = if let Some(msg) = payload.downcast_ref::<&str>() {
                    msg.to_string()
                } else if let Some(msg) = payload.downcast_ref::<String>() {
                    msg.clone()
                } else {
                    "panic payload was not a string".to_string()
                };
                check_panics.push(ScanError::CheckPanic {
                    check: check_name,
                    path: path.to_path_buf(),
                    message,
                });
            }
        }
    }

    findings.sort_by_key(|f| f.line);
    suppress_redundant_division_finding(&mut findings);
    dedup_findings(&mut findings);
    Ok((findings, check_panics))
}

/// Findings for a single source file.
#[derive(Debug, Clone)]
pub struct FileScanResult {
    pub file_path: String,
    pub findings: Vec<Finding>,
}

/// Recursively scan `.rs` files under `root` and aggregate findings from every default check.
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
///
/// Returns `(findings, files_scanned, files_skipped, check_panics)` where `files_skipped`
/// counts files omitted because they carry a generated-file header, and `check_panics`
/// lists every check that panicked during the scan (see [`CheckPanicReport`]).
pub fn scan_directory(
    root: &Path,
    excludes: &[String],
    includes: &[String],
) -> Result<(Vec<Finding>, usize, usize, Vec<ScanError>), ScanError> {
    let root = root.canonicalize()?;
    let checks = default_checks();
    let (paths, files_skipped) = collect_rust_paths(&root, excludes, includes)?;
    let files_scanned = paths.len();

    let (collected, panics): (Vec<Vec<Finding>>, Vec<Vec<ScanError>>) = paths
        .par_iter()
        .map(|path| run_checks_for_file(path, &root, &checks))
        .collect::<Result<Vec<_>, ScanError>>()?
        .into_iter()
        .unzip();

    let mut findings: Vec<Finding> = collected.into_iter().flatten().collect();
    let check_panics: Vec<ScanError> = panics.into_iter().flatten().collect();

    findings.sort_by(|a, b| {
        a.file_path
            .cmp(&b.file_path)
            .then_with(|| a.line.cmp(&b.line))
    });
    dedup_findings(&mut findings);
    Ok((findings, files_scanned, files_skipped, check_panics))
}

/// Like [`scan_directory`] but runs `checks` instead of [`default_checks`].
///
/// Returns `(results, files_scanned, files_skipped, check_panics)` where each element of
/// `results` groups findings by source file, `files_skipped` counts files omitted due to
/// generated-file headers, and `check_panics` lists every check that panicked during the
/// scan (see [`CheckPanicReport`]).
pub fn scan_directory_with_checks(
    root: &Path,
    excludes: &[String],
    includes: &[String],
    checks: &[Box<dyn Check + Send + Sync>],
) -> Result<(Vec<FileScanResult>, usize, usize, Vec<ScanError>), ScanError> {
    let root = root.canonicalize()?;
    let (paths, files_skipped) = collect_rust_paths(&root, excludes, includes)?;
    let files_scanned = paths.len();

    let per_file = paths
        .par_iter()
        .map(|path| {
            let (findings, check_panics) = run_checks_for_file(path, &root, checks)?;
            let file_label = if root.is_file() {
                path.file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string()
            } else {
                path.strip_prefix(&root)
                    .unwrap_or(path)
                    .to_string_lossy()
                    .to_string()
            };
            Ok((FileScanResult { file_path: file_label, findings }, check_panics))
        })
        .collect::<Result<Vec<_>, ScanError>>()?;

    let mut results: Vec<FileScanResult> =
        per_file.iter().map(|(r, _)| r.clone()).collect();
    results.sort_by(|a, b| a.file_path.cmp(&b.file_path));

    let check_panics: Vec<ScanError> = per_file
        .into_iter()
        .flat_map(|(_, panics)| panics)
        .collect();

    Ok((results, files_scanned, files_skipped, check_panics))
}

/// Scan an explicit list of `.rs` file paths and aggregate findings from every default check.
///
/// Applies the same per-file filter as [`scan_directory`] via [`classify_rust_path`]:
/// non-`.rs` paths and paths matching an exclude glob (or, when `includes` is non-empty,
/// not matching any include glob) are dropped; files carrying a generated-file header are
/// counted in `files_skipped` and not scanned. Findings are deduplicated before returning.
///
/// `root` is used to compute the relative label matched against the globs and shown in
/// findings. The one difference from [`scan_directory`] is that this does not walk a
/// directory: only the paths passed in are considered.
///
/// Returns `(findings, files_scanned, files_skipped, check_panics)` where `check_panics`
/// lists every check that panicked during the scan (see [`CheckPanicReport`]).
pub fn scan_files(
    paths: &[PathBuf],
    root: &Path,
    excludes: &[String],
    includes: &[String],
) -> Result<(Vec<Finding>, usize, usize, Vec<ScanError>), ScanError> {
    let root = root.canonicalize()?;
    let exclude_patterns = compile_globs(excludes)?;
    let include_patterns = compile_globs(includes)?;

    let mut selected = Vec::new();
    let mut files_skipped = 0;
    for path in paths {
        let path_canon = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
        let label = path_canon.strip_prefix(&root).unwrap_or(&path_canon);
        match classify_rust_path(&path_canon, label, &exclude_patterns, &include_patterns)? {
            PathVerdict::Scan => selected.push(path_canon),
            PathVerdict::GeneratedSkip => files_skipped += 1,
            PathVerdict::Reject => {}
        }
    }

    let files_scanned = selected.len();
    let checks = default_checks();

    let (collected, panics): (Vec<Vec<Finding>>, Vec<Vec<ScanError>>) = selected
        .par_iter()
        .map(|path| run_checks_for_file(path, &root, &checks))
        .collect::<Result<Vec<_>, ScanError>>()?
        .into_iter()
        .unzip();

    let mut findings: Vec<Finding> = collected.into_iter().flatten().collect();
    let check_panics: Vec<ScanError> = panics.into_iter().flatten().collect();

    findings.sort_by(|a, b| {
        a.file_path
            .cmp(&b.file_path)
            .then_with(|| a.line.cmp(&b.line))
    });
    dedup_findings(&mut findings);

    Ok((findings, files_scanned, files_skipped, check_panics))
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

        let (_, files_scanned, files_skipped, check_panics) =
            scan_directory(&file_path, &[], &[]).unwrap();
        assert_eq!(files_scanned, 1);
        assert_eq!(files_skipped, 0);
        assert!(check_panics.is_empty());
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

        let (_, files_scanned, files_skipped, _) =
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

        let (_, files_scanned, files_skipped, _) =
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

        let (_, files_scanned, files_skipped, _) = scan_directory(&root, &[], &[]).unwrap();

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

        let (_, files_scanned, files_skipped, _) =
            scan_files(&[included.clone(), excluded.clone()], &root, &[], &[]).unwrap();
        assert_eq!(files_scanned, 2);
        assert_eq!(files_skipped, 0);

        // Exclude one file via glob
        let (_, files_scanned, _, _) =
            scan_files(&[excluded], &root, &["src/other.rs".to_string()], &[]).unwrap();
        assert_eq!(files_scanned, 0);

        // includes now compose the same way as scan_directory
        let (_, files_scanned, _, _) =
            scan_files(&[included], &root, &[], &["src/other*.rs".to_string()]).unwrap();
        assert_eq!(files_scanned, 0);

        fs::remove_dir_all(root).unwrap();
    }

    /// One unreadable `.rs` file must not abort the scan: findings for the readable
    /// files are still returned. Unix-only (relies on POSIX mode bits); skipped when
    /// running as root, where the mode bits do not deny access.
    #[cfg(unix)]
    #[test]
    fn unreadable_file_does_not_abort_scan() {
        use std::os::unix::fs::PermissionsExt;

        let root = std::env::temp_dir().join(format!(
            "soroban-guard-unreadable-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(root.join("src")).unwrap();

        let readable = root.join("src/readable.rs");
        fs::write(
            &readable,
            "#[contract]\npub struct C;\n#[contractimpl]\nimpl C {\n    pub fn bump(env: Env) {\n        env.storage().instance().set(&1u32, &2u32);\n    }\n}\n",
        )
        .unwrap();

        let unreadable = root.join("src/unreadable.rs");
        fs::write(&unreadable, "pub fn secret() {}").unwrap();
        fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o000)).unwrap();

        // If the process can still read the file (running as root), the scenario
        // under test does not exist; skip rather than assert a false negative.
        if fs::read_to_string(&unreadable).is_ok() {
            let _ = fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o644));
            fs::remove_dir_all(&root).unwrap();
            return;
        }

        let (findings, files_scanned, _, check_panics) = scan_directory(&root, &[], &[]).unwrap();
        assert_eq!(
            files_scanned, 1,
            "the readable file should still be scanned"
        );
        assert!(
            findings
                .iter()
                .any(|f| f.check_name == "missing-require-auth"),
            "expected a finding from the readable file, got {findings:?}"
        );

        let _ = fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o644));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn scan_files_matches_scan_directory_findings_and_filters_generated() {
        let root = std::env::temp_dir().join(format!(
            "soroban-guard-scan-files-parity-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(root.join("src")).unwrap();
        let vulnerable = root.join("src/lib.rs");
        let generated = root.join("src/generated.rs");
        fs::write(
            &vulnerable,
            "#[contract]\npub struct C;\n#[contractimpl]\nimpl C {\n    pub fn bump(env: Env) {\n        env.storage().instance().set(&1u32, &2u32);\n    }\n}\n",
        )
        .unwrap();
        fs::write(
            &generated,
            "// @generated\n#[contractimpl]\nimpl G {\n    pub fn go(env: Env) { env.storage().instance().set(&1u32, &2u32); }\n}\n",
        )
        .unwrap();

        let (dir_findings, _, dir_skipped, _) = scan_directory(&root, &[], &[]).unwrap();
        let (file_findings, files_scanned, file_skipped, _) =
            scan_files(&[vulnerable, generated], &root, &[], &[]).unwrap();

        assert_eq!(files_scanned, 1, "the generated file must not be scanned");
        assert_eq!(file_skipped, 1);
        assert_eq!(file_skipped, dir_skipped);

        let names = |fs: &[Finding]| {
            let mut v: Vec<(String, usize)> =
                fs.iter().map(|f| (f.check_name.clone(), f.line)).collect();
            v.sort();
            v
        };
        assert!(
            !file_findings.is_empty(),
            "expected findings from the readable file"
        );
        assert_eq!(names(&file_findings), names(&dir_findings));
    }

    /// An unreadable **subdirectory** must cause the scan to fail with
    /// `ScanError::Traversal` — not silently succeed with a clean result.
    ///
    /// This is the fix for #484: `filter_map(Result::ok)` used to drop the WalkDir
    /// traversal error, leaving the subtree silently unscanned while the exit code
    /// remained 0.
    ///
    /// Unix-only (relies on POSIX mode bits); skipped when running as root.
    #[cfg(unix)]
    #[test]
    fn unreadable_subdirectory_is_not_silently_skipped() {
        use std::os::unix::fs::PermissionsExt;

        let root = std::env::temp_dir().join(format!(
            "soroban-guard-unreadable-dir-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(root.join("src")).unwrap();
        fs::create_dir_all(root.join("src/private")).unwrap();

        // A readable file at the top level.
        fs::write(root.join("src/lib.rs"), "pub fn f() {}").unwrap();
        // A file inside the unreadable subdirectory.
        fs::write(root.join("src/private/secret.rs"), "pub fn secret() {}").unwrap();

        // Remove read+execute permission from the subdirectory so WalkDir cannot
        // list its contents.
        fs::set_permissions(
            root.join("src/private"),
            fs::Permissions::from_mode(0o000),
        )
        .unwrap();

        // If the process can still read the dir (running as root), the scenario
        // under test does not apply; skip gracefully.
        if root.join("src/private").read_dir().is_ok() {
            let _ = fs::set_permissions(
                root.join("src/private"),
                fs::Permissions::from_mode(0o755),
            );
            fs::remove_dir_all(&root).unwrap();
            return;
        }

        let result = scan_directory(&root, &[], &[]);

        // Restore permissions before any assertion so the temp dir can be cleaned up.
        let _ = fs::set_permissions(
            root.join("src/private"),
            fs::Permissions::from_mode(0o755),
        );
        fs::remove_dir_all(&root).unwrap();

        assert!(
            result.is_err(),
            "scan_directory must return Err when a subdirectory is unreadable, \
             not silently succeed — got Ok"
        );
        let err = result.unwrap_err();
        assert!(
            matches!(err, ScanError::Traversal { .. }),
            "expected ScanError::Traversal, got: {err}"
        );
        assert!(
            err.to_string().contains("traversal") || err.to_string().contains("private"),
            "error message should mention the path or 'traversal', got: {err}"
        );
    }

    #[test]
    fn scan_directory_rejects_invalid_exclude_glob() {
        let root = std::env::temp_dir().join(format!(
            "soroban-guard-invalid-glob-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(root.join("src/lib.rs"), "pub fn f() {}").unwrap();

        let result = scan_directory(&root, &["src/[foo.rs".to_string()], &[]);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("Invalid glob pattern") || err_msg.contains("src/[foo.rs"));

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn scan_directory_rejects_invalid_include_glob() {
        let root = std::env::temp_dir().join(format!(
            "soroban-guard-invalid-include-glob-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(root.join("src/lib.rs"), "pub fn f() {}").unwrap();

        let result = scan_directory(&root, &[], &["src/[invalid.rs".to_string()]);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("Invalid glob pattern") || err_msg.contains("src/[invalid.rs"));

        fs::remove_dir_all(root).unwrap();
    }

    /// A check that panics unconditionally when it runs.
    struct PanickingCheck;
    impl soroban_guard_checks::Check for PanickingCheck {
        fn name(&self) -> &str {
            "panic-check"
        }
        fn run(&self, _file: &syn::File, _src: &str) -> Vec<Finding> {
            panic!("boom from panic-check");
        }
    }

    /// A check that never panics and always returns one finding.
    struct OkCheck;
    impl soroban_guard_checks::Check for OkCheck {
        fn name(&self) -> &str {
            "ok-check"
        }
        fn run(&self, _file: &syn::File, _src: &str) -> Vec<Finding> {
            vec![Finding {
                check_name: "ok-check".into(),
                severity: soroban_guard_checks::Severity::Low,
                file_path: String::new(),
                line: 1,
                function_name: "f".into(),
                description: "ok".into(),
                rule_url: None,
                suggestion: None,
            }]
        }
    }

    /// A panicking check must not abort the scan, but must be reported to the caller
    /// alongside the findings instead of being swallowed (issue #410).
    #[test]
    fn panicking_check_is_reported_not_swallowed() {
        let root = std::env::temp_dir().join(format!(
            "soroban-guard-panic-propagation-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(root.join("src/lib.rs"), "pub fn f() {}").unwrap();

        let checks: Vec<Box<dyn soroban_guard_checks::Check + Send + Sync>> = vec![
            Box::new(PanickingCheck),
            Box::new(OkCheck),
        ];
        let (results, _, _, check_panics) =
            scan_directory_with_checks(&root, &[], &[], &checks).unwrap();

        let total: usize = results.iter().map(|r| r.findings.len()).sum();
        assert_eq!(total, 1, "the non-panicking check's finding must survive");

        assert_eq!(check_panics.len(), 1, "the panic must be returned to the caller");
        match &check_panics[0] {
            ScanError::CheckPanic { check, path, message } => {
                assert_eq!(check, "panic-check");
                assert!(path.to_string_lossy().ends_with("src/lib.rs"));
                assert!(message.contains("boom from panic-check"), "got {message}");
            }
            other => panic!("expected CheckPanic, got {other:?}"),
        }

        let report: CheckPanicReport = CheckPanicReport {
            panics: check_panics.iter().map(CheckPanic::from).collect(),
        };
        assert!(report.is_degraded());

        fs::remove_dir_all(root).unwrap();
    }
}

#[cfg(test)]
mod suppression_tests {
    use super::*;

    fn suppressions_for(src: &str) -> Suppressions {
        let file = syn::parse_file(src).expect("fixture should parse");
        let fn_spans = build_fn_spans(&file);
        parse_suppressions(src, &fn_spans)
    }

    fn has_fn_suppression(s: &Suppressions, func: &str, check: &str) -> bool {
        let key = (String::from("C"), func.to_string(), check.to_string());
        s.function_checks.contains(&key)
    }

    #[test]
    fn suppression_binds_across_an_attribute_line() {
        let src = "\
#[contract]
pub struct C;
#[contractimpl]
impl C {
    // soroban-guard: allow(missing-require-auth)
    #[allow(dead_code)]
    pub fn set_admin(env: Env, a: Address) { let _ = (env, a); }
}
";
        let s = suppressions_for(src);
        assert!(has_fn_suppression(&s, "set_admin", "missing-require-auth"));
    }

    #[test]
    fn suppression_binds_across_a_blank_line() {
        let src = "\
#[contractimpl]
impl C {
    // soroban-guard: allow(unchecked-arithmetic)

    pub fn accrue(env: Env) { let _ = env; }
}
";
        let s = suppressions_for(src);
        assert!(has_fn_suppression(&s, "accrue", "unchecked-arithmetic"));
    }

    #[test]
    fn suppression_binds_across_a_doc_comment() {
        let src = "\
#[contractimpl]
impl C {
    // soroban-guard: allow(missing-event-emission)
    /// Updates the fee schedule.
    pub fn set_fee(env: Env, bps: u32) { let _ = (env, bps); }
}
";
        let s = suppressions_for(src);
        assert!(has_fn_suppression(&s, "set_fee", "missing-event-emission"));
    }

    #[test]
    fn suppression_directly_above_a_non_fn_statement_stays_line_level() {
        let src = "\
#[contractimpl]
impl C {
    pub fn go(env: Env) {
        // soroban-guard: allow(unchecked-arithmetic)
        let x = 1 + 2;
        let _ = (env, x);
    }
}
";
        let s = suppressions_for(src);
        // line 5 is `let x = 1 + 2;`
        assert!(s
            .line_checks
            .contains(&(5, "unchecked-arithmetic".to_string())));
        assert!(s.function_checks.is_empty());
    }

    #[test]
    fn fn_in_a_string_literal_registers_no_function_suppression() {
        let src = "\
#[contractimpl]
impl C {
    pub fn go(env: Env) {
        // soroban-guard: allow(hardcoded-address)
        let msg = \"call fn later\";
        let _ = (env, msg);
    }
}
";
        let s = suppressions_for(src);
        assert!(s.function_checks.is_empty());
        assert!(s
            .line_checks
            .contains(&(5, "hardcoded-address".to_string())));
    }

    #[test]
    fn fn_in_a_type_position_registers_no_function_suppression() {
        let src = "\
#[contractimpl]
impl C {
    pub fn go(env: Env) {
        // soroban-guard: allow(unchecked-arithmetic)
        let handler: fn(u32) -> u32 = double;
        let _ = (env, handler);
    }
}
";
        let s = suppressions_for(src);
        assert!(s.function_checks.is_empty());
        assert!(s
            .line_checks
            .contains(&(5, "unchecked-arithmetic".to_string())));
    }

    /// Regression test for #501: a function-scoped suppression above a method
    /// must silence that method's findings even when the check leaves function_name
    /// empty (e.g. unchecked-divisor, mutable-global-state, symbol-key-collision).
    #[test]
    fn function_scoped_suppression_silences_empty_function_name_findings() {
        let src = "\
#[contract]
pub struct C;
#[contractimpl]
impl C {
    // soroban-guard: allow(unchecked-divisor)
    pub fn divide(env: Env, a: u128, b: u128) -> u128 {
        let _ = env;
        a / b
    }
}
";
        let file = syn::parse_file(src).expect("fixture should parse");
        let fn_spans = build_fn_spans(&file);
        let suppressions = parse_suppressions(src, &fn_spans);

        // Simulate an unchecked-divisor finding with an empty function_name,
        // as some checks emit.
        let finding = Finding {
            check_name: "unchecked-divisor".to_string(),
            severity: soroban_guard_checks::Severity::High,
            file_path: String::new(),
            line: 8,
            function_name: String::new(),
            description: "divisor not validated".to_string(),
            rule_url: None,
            suggestion: None,
        };
        assert!(
            is_suppressed(&finding, &suppressions, &fn_spans),
            "function-scoped suppression should silence finding with empty function_name"
        );
    }
}

#[cfg(test)]
mod dedup_tests {
    use super::*;
    use soroban_guard_checks::{Finding, Severity};
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    /// A check that always returns two identical findings for every file it sees.
    struct DuplicatingCheck;
    impl soroban_guard_checks::Check for DuplicatingCheck {
        fn name(&self) -> &str { "dup-check" }
        fn run(&self, _file: &syn::File, _src: &str) -> Vec<Finding> {
            let f = Finding {
                check_name: "dup-check".into(),
                severity: Severity::Low,
                file_path: String::new(),
                line: 1,
                function_name: "f".into(),
                description: "duplicate".into(),
                rule_url: None,
                suggestion: None,
            };
            vec![f.clone(), f]
        }
    }

    #[test]
    fn deduplicates_findings_with_same_file_line_check() {
        let root = std::env::temp_dir().join(format!(
            "soroban-guard-dedup-{}-{}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
        ));
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(root.join("src/lib.rs"), "pub fn f() {}").unwrap();

        let checks: Vec<Box<dyn soroban_guard_checks::Check + Send + Sync>> =
            vec![Box::new(DuplicatingCheck)];
        let (results, _, _, _) = scan_directory_with_checks(&root, &[], &[], &checks).unwrap();

        let total: usize = results.iter().map(|r| r.findings.len()).sum();
        assert_eq!(total, 1, "expected 1 finding after dedup, got {}", total);

        fs::remove_dir_all(root).unwrap();
    }

    /// A check that returns two findings at different lines, intentionally reversed.
    struct ReversedCheck;
    impl soroban_guard_checks::Check for ReversedCheck {
        fn name(&self) -> &str { "reversed-check" }
        fn run(&self, _file: &syn::File, _src: &str) -> Vec<Finding> {
            vec![
                Finding {
                    check_name: "reversed-check".into(),
                    severity: Severity::Low,
                    file_path: String::new(),
                    line: 20,
                    function_name: "b".into(),
                    description: "second".into(),
                    rule_url: None,
                    suggestion: None,
                },
                Finding {
                    check_name: "reversed-check".into(),
                    severity: Severity::Low,
                    file_path: String::new(),
                    line: 5,
                    function_name: "a".into(),
                    description: "first".into(),
                    rule_url: None,
                    suggestion: None,
                },
            ]
        }
    }

    #[test]
    fn findings_sorted_by_file_path_then_line() {
        let root = std::env::temp_dir().join(format!(
            "soroban-guard-sort-{}-{}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
        ));
        fs::create_dir_all(root.join("src")).unwrap();
        // Two files — rayon may process them in any order.
        fs::write(root.join("src/b_module.rs"), "pub fn b() {}").unwrap();
        fs::write(root.join("src/a_module.rs"), "pub fn a() {}").unwrap();

        let checks: Vec<Box<dyn soroban_guard_checks::Check + Send + Sync>> =
            vec![Box::new(ReversedCheck)];
        let (results, _, _, _) = scan_directory_with_checks(&root, &[], &[], &checks).unwrap();

        // Files must be in lexicographic order.
        let file_paths: Vec<&str> = results.iter().map(|r| r.file_path.as_str()).collect();
        assert!(
            file_paths.windows(2).all(|w| w[0] <= w[1]),
            "files not in sorted order: {:?}",
            file_paths
        );

        // Within each file, findings must be sorted by line.
        for r in &results {
            let lines: Vec<usize> = r.findings.iter().map(|f| f.line).collect();
            assert!(
                lines.windows(2).all(|w| w[0] <= w[1]),
                "findings in {} not sorted by line: {:?}",
                r.file_path,
                lines
            );
        }

        fs::remove_dir_all(root).unwrap();
    }

    /// A check that reports two findings at the same `(file, line, check_name)` that
    /// differ only in their description — the shape produced by per-operator checks
    /// like `unchecked-arithmetic` on a single source line.
    struct DistinctSameLineCheck;
    impl soroban_guard_checks::Check for DistinctSameLineCheck {
        fn name(&self) -> &str {
            "distinct-same-line"
        }
        fn run(&self, _file: &syn::File, _src: &str) -> Vec<Finding> {
            let base = Finding {
                check_name: "distinct-same-line".into(),
                severity: Severity::Medium,
                file_path: String::new(),
                line: 3,
                function_name: "f".into(),
                description: String::new(),
                rule_url: None,
                suggestion: None,
            };
            vec![
                Finding {
                    description: "addition may overflow".into(),
                    ..base.clone()
                },
                Finding {
                    description: "multiplication may overflow".into(),
                    ..base
                },
            ]
        }
    }

    #[test]
    fn keeps_distinct_findings_on_the_same_line() {
        let root = std::env::temp_dir().join(format!(
            "soroban-guard-dedup-distinct-{}-{}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
        ));
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(root.join("src/lib.rs"), "pub fn f() {}").unwrap();

        let checks: Vec<Box<dyn soroban_guard_checks::Check + Send + Sync>> =
            vec![Box::new(DistinctSameLineCheck)];
        let (results, _, _, _) = scan_directory_with_checks(&root, &[], &[], &checks).unwrap();

        let total: usize = results.iter().map(|r| r.findings.len()).sum();
        assert_eq!(total, 2, "distinct same-line findings must both survive dedup, got {total}");

        fs::remove_dir_all(root).unwrap();
    }
}
