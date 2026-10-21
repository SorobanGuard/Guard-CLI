//! `soroban-guard.toml` configuration file support.

use serde::Deserialize;
use std::path::{Path, PathBuf};

/// Top-level config file structure.
///
/// `deny_unknown_fields` turns a typo'd or misplaced key (e.g. `[check]`
/// instead of `[checks]`) into the same malformed-config error as invalid
/// TOML, instead of silently parsing and doing nothing.
#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct GuardConfig {
    pub scan: ScanConfig,
    pub checks: ChecksConfig,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ScanConfig {
    /// Default scan path (overridden by the CLI positional argument).
    pub path: Option<String>,
    /// Severity threshold for the `--fail-on` exit gate ("high" | "medium" | "low").
    ///
    /// Equivalent to the `--fail-on` flag (the flag wins if both are set): the
    /// process exits `1` when a finding at or above this severity is present.
    /// This does **not** filter findings out of the printed output.
    pub min_severity: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ChecksConfig {
    /// Check names to skip.
    pub disabled: Vec<String>,
    pub sensitive_names: SensitiveNamesConfig,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SensitiveNamesConfig {
    /// Extra function names added to the built-in `SENSITIVE_NAMES` list.
    pub extra: Vec<String>,
}

/// Search upward from `scan_path` for the nearest `soroban-guard.toml`.
///
/// `scan_path` may be a file (single-file scans are supported) or a
/// directory; when it's a file, the search starts at its parent directory.
/// The search climbs through parent directories, checking each for
/// `soroban-guard.toml`, and stops — without finding one — at the
/// filesystem root or at the first directory that itself contains `.git`
/// (the project root; a config above it belongs to a different project and
/// must not be picked up by a scan inside this one).
///
/// Returns `None` when no config file is found before either stopping
/// condition is reached.
pub fn find_config_path(scan_path: &Path) -> Option<PathBuf> {
    let mut dir = if scan_path.is_file() {
        scan_path.parent().unwrap_or_else(|| Path::new(".")).to_path_buf()
    } else {
        scan_path.to_path_buf()
    };

    loop {
        let candidate = dir.join("soroban-guard.toml");
        if candidate.is_file() {
            return Some(candidate);
        }
        // `.git` may be a directory (a normal checkout) or a file (a
        // worktree/submodule's gitdir pointer) — `.exists()` covers both,
        // `.is_dir()` alone would miss the file case.
        if dir.join(".git").exists() {
            return None;
        }
        dir = dir.parent()?.to_path_buf();
    }
}

/// Load and parse the nearest `soroban-guard.toml` found by searching
/// upward from `scan_path` (see [`find_config_path`]).
///
/// Returns `(None, None)` when no config file exists anywhere up the tree.
/// Returns an error string (for exit-2 reporting) when a config file is
/// found but is malformed. On success, the second element of the tuple is
/// the path of the config file that was used — `None` only when no config
/// was found at all — so a caller can report it (e.g. under `--verbose`).
pub fn load(scan_path: &Path) -> Result<(Option<GuardConfig>, Option<PathBuf>), String> {
    let Some(config_path) = find_config_path(scan_path) else {
        return Ok((None, None));
    };
    load_from_path(&config_path)
}

/// Load and parse exactly the given config file, skipping discovery.
///
/// Used for the explicit `--config <PATH>` flag. A missing or malformed
/// file is a hard error (for exit-2 reporting) — never silently ignored.
pub fn load_from_path(config_path: &Path) -> Result<(Option<GuardConfig>, Option<PathBuf>), String> {
    let raw = std::fs::read_to_string(config_path)
        .map_err(|e| format!("could not read {}: {e}", config_path.display()))?;
    let cfg: GuardConfig = toml::from_str(&raw)
        .map_err(|e| format!("{}: {e}", config_path.display()))?;
    Ok((Some(cfg), Some(config_path.to_path_buf())))
}

/// Resolve the config to use, honoring the CLI flags.
///
/// Precedence: an explicit `--config <PATH>` wins and skips discovery;
/// `--no-config` disables discovery entirely (returns `(None, None)`);
/// otherwise the nearest `soroban-guard.toml` is discovered by walking up
/// from `scan_path` (see [`find_config_path`]).
pub fn resolve(
    scan_path: &Path,
    explicit: Option<&Path>,
    no_config: bool,
) -> Result<(Option<GuardConfig>, Option<PathBuf>), String> {
    if let Some(path) = explicit {
        return load_from_path(path);
    }
    if no_config {
        return Ok((None, None));
    }
    load(scan_path)
}

/// Validate a config file without scanning.
///
/// Uses the same discovery rules as [`resolve`] (explicit `--config` wins,
/// otherwise walk up from `scan_path`). On top of the TOML/unknown-key
/// checks performed by the loader, this verifies that every name in
/// `[checks].disabled` refers to a known check, so a typo'd check name is
/// reported with the file and offending key rather than silently ignored.
///
/// Returns the resolved config and the path it came from on success, or a
/// human-readable error (for exit-2 reporting) on failure.
pub fn validate(
    scan_path: &Path,
    explicit: Option<&Path>,
    known_checks: &[&str],
) -> Result<(GuardConfig, PathBuf), String> {
    let (cfg, path) = resolve(scan_path, explicit, false)?;
    let (Some(cfg), Some(path)) = (cfg, path) else {
        return Err(format!(
            "no soroban-guard.toml found searching upward from {}",
            scan_path.display()
        ));
    };

    for name in &cfg.checks.disabled {
        if !known_checks.contains(&name.as_str()) {
            return Err(format!(
                "{}: unknown check name `{name}` in [checks].disabled (known checks: {})",
                path.display(),
                known_checks.join(", ")
            ));
        }
    }

    Ok((cfg, path))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    /// A fresh, empty temp directory this test owns exclusively — never
    /// under any real project's tree, so `.git`/`soroban-guard.toml`
    /// belonging to *this* repo's own checkout can't leak into a result.
    fn temp_root(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "soroban-guard-config-{label}-{}-{}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn finds_config_in_the_scan_directory() {
        let root = temp_root("scandir");
        fs::write(root.join("soroban-guard.toml"), "[scan]\n").unwrap();

        assert_eq!(find_config_path(&root), Some(root.join("soroban-guard.toml")));

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn finds_config_in_a_parent_directory() {
        let root = temp_root("parent");
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(root.join("soroban-guard.toml"), "[scan]\n").unwrap();

        assert_eq!(
            find_config_path(&root.join("src")),
            Some(root.join("soroban-guard.toml"))
        );

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn none_found_stops_at_a_git_root_without_erroring() {
        let root = temp_root("gitstop");
        fs::create_dir_all(root.join("repo/src")).unwrap();
        fs::create_dir_all(root.join("repo/.git")).unwrap();
        // No soroban-guard.toml anywhere under `repo/`.

        assert_eq!(find_config_path(&root.join("repo/src")), None);

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn does_not_search_above_a_git_root_even_if_a_config_exists_there() {
        let root = temp_root("gitboundary");
        fs::create_dir_all(root.join("repo/src")).unwrap();
        fs::create_dir_all(root.join("repo/.git")).unwrap();
        // A config exists *above* the repo root — must not be picked up by
        // a scan inside `repo/`, since that would apply an unrelated
        // project's settings.
        fs::write(root.join("soroban-guard.toml"), "[scan]\n").unwrap();

        assert_eq!(find_config_path(&root.join("repo/src")), None);

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn works_when_scan_path_is_a_file() {
        let root = temp_root("singlefile");
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(root.join("soroban-guard.toml"), "[scan]\n").unwrap();
        fs::write(root.join("src/lib.rs"), "pub fn f() {}").unwrap();

        assert_eq!(
            find_config_path(&root.join("src/lib.rs")),
            Some(root.join("soroban-guard.toml"))
        );

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn load_returns_the_config_and_the_path_it_came_from() {
        let root = temp_root("load-ok");
        fs::write(
            root.join("soroban-guard.toml"),
            "[scan]\nmin_severity = \"medium\"\n",
        )
        .unwrap();

        let (cfg, path) = load(&root).unwrap();
        let cfg = cfg.expect("config should be present");
        assert_eq!(path, Some(root.join("soroban-guard.toml")));
        assert_eq!(cfg.scan.min_severity.as_deref(), Some("medium"));

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn validate_accepts_a_valid_config() {
        let root = temp_root("validate-ok");
        fs::write(
            root.join("soroban-guard.toml"),
            "[scan]\nmin_severity = \"high\"\n\n[checks]\ndisabled = [\"auth\"]\n",
        )
        .unwrap();

        let (cfg, path) = validate(&root, None, &["auth", "overflow"]).unwrap();
        assert_eq!(path, root.join("soroban-guard.toml"));
        assert_eq!(cfg.checks.disabled, vec!["auth".to_string()]);

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn validate_reports_unknown_key_with_file() {
        let root = temp_root("validate-unknown-key");
        fs::write(
            root.join("soroban-guard.toml"),
            "[scan]\nmin_severty = \"high\"\n",
        )
        .unwrap();

        let err = validate(&root, None, &["auth"]).unwrap_err();
        assert!(err.contains("soroban-guard.toml"), "error should name the file: {err}");
        assert!(err.contains("min_severty"), "error should name the key: {err}");

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn validate_reports_unknown_check_name_with_file_and_key() {
        let root = temp_root("validate-unknown-check");
        fs::write(
            root.join("soroban-guard.toml"),
            "[checks]\ndisabled = [\"not-a-check\"]\n",
        )
        .unwrap();

        let err = validate(&root, None, &["auth", "overflow"]).unwrap_err();
        assert!(err.contains("soroban-guard.toml"), "error should name the file: {err}");
        assert!(err.contains("not-a-check"), "error should name the check: {err}");
        assert!(err.contains("[checks].disabled"), "error should name the key: {err}");

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn validate_reports_malformed_toml_with_file() {
        let root = temp_root("validate-malformed");
        fs::write(root.join("soroban-guard.toml"), "[scan\nmin_severity =\n").unwrap();

        let err = validate(&root, None, &["auth"]).unwrap_err();
        assert!(err.contains("soroban-guard.toml"), "error should name the file: {err}");

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn validate_errors_when_no_config_is_found() {
        let root = temp_root("validate-missing");
        fs::create_dir_all(root.join("repo/.git")).unwrap();

        let err = validate(&root.join("repo"), None, &["auth"]).unwrap_err();
        assert!(err.contains("no soroban-guard.toml"), "unexpected error: {err}");

        fs::remove_dir_all(root).unwrap();
    }
}
