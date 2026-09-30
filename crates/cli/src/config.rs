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
    let raw = std::fs::read_to_string(&config_path)
        .map_err(|e| format!("could not read {}: {e}", config_path.display()))?;
    let cfg: GuardConfig = toml::from_str(&raw)
        .map_err(|e| format!("{}: {e}", config_path.display()))?;
    Ok((Some(cfg), Some(config_path)))
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
        assert_eq!(cfg.unwrap().scan.min_severity.as_deref(), Some("medium"));
        assert_eq!(path, Some(root.join("soroban-guard.toml")));

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn load_returns_none_none_when_nothing_is_found() {
        let root = temp_root("load-none");
        fs::create_dir_all(root.join(".git")).unwrap();

        let (cfg, path) = load(&root).unwrap();
        assert!(cfg.is_none());
        assert!(path.is_none());

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn load_reports_a_malformed_config_as_an_error() {
        let root = temp_root("load-bad");
        fs::write(root.join("soroban-guard.toml"), "not valid toml [[[").unwrap();

        let err = load(&root).unwrap_err();
        assert!(err.contains("soroban-guard.toml"), "{err}");

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn unknown_top_level_table_is_rejected() {
        let root = temp_root("unknown-top-level");
        fs::write(root.join("soroban-guard.toml"), "[check]\ndisabled = []\n").unwrap();

        let err = load(&root).unwrap_err();
        assert!(err.contains("check"), "{err}");

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn unknown_key_under_scan_is_rejected() {
        let root = temp_root("unknown-scan-key");
        fs::write(
            root.join("soroban-guard.toml"),
            "[scan]\nmin_severity_level = \"high\"\n",
        )
        .unwrap();

        let err = load(&root).unwrap_err();
        assert!(err.contains("min_severity_level"), "{err}");

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn unknown_key_under_checks_sensitive_names_is_rejected() {
        let root = temp_root("unknown-sensitive-names-key");
        fs::write(
            root.join("soroban-guard.toml"),
            "[checks.sensitive_names]\nextras = [\"drain\"]\n",
        )
        .unwrap();

        let err = load(&root).unwrap_err();
        assert!(err.contains("extras"), "{err}");

        fs::remove_dir_all(root).unwrap();
    }
}
