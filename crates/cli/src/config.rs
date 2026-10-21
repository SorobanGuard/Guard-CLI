//! `soroban-guard.toml` configuration file support.

use serde::Deserialize;
use std::collections::BTreeMap;
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
    /// Per-path rule overrides (`[[overrides]]`). Each entry disables a set
    /// of checks for files matching its globs. Overrides stack in file
    /// order: for a matching path, the union of every matching override's
    /// `disabled` list is applied.
    pub overrides: Vec<OverrideConfig>,
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
    /// Cap on analyzer parallelism (equivalent to the `--jobs` flag; the flag
    /// wins if both are set). `0` or unset means rayon's default parallelism.
    pub jobs: Option<usize>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ChecksConfig {
    /// Check names to skip.
    pub disabled: Vec<String>,
    pub sensitive_names: SensitiveNamesConfig,
    /// Per-check severity overrides (`[checks.severity]`), mapping a check
    /// name to the severity it should report instead of its built-in one.
    ///
    /// Applied after a check runs and before `--fail-on` evaluation and
    /// output formatting, so every output format agrees. For multi-severity
    /// checks (e.g. `unchecked-arithmetic`) the override replaces **all**
    /// levels. Unknown check names or severities are config errors (exit 2).
    pub severity: BTreeMap<String, String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SensitiveNamesConfig {
    /// Extra function names added to the built-in `SENSITIVE_NAMES` list.
    pub extra: Vec<String>,
}

/// A single `[[overrides]]` entry: disable `disabled` checks for files whose
/// path matches any of the `paths` globs.
///
/// Globs use the same matcher as `--include`/`--exclude`. Findings are
/// filtered after the check runs, so other checks still apply to those
/// files. Overrides stack in file order (union of `disabled` for matching
/// paths).
#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct OverrideConfig {
    /// Glob patterns (same matcher as `--include`/`--exclude`) selecting the
    /// files this override applies to.
    pub paths: Vec<String>,
    /// Check names to drop for files matching `paths`.
    pub disabled: Vec<String>,
}

impl GuardConfig {
    /// Return the set of check names disabled for `file_path` by every
    /// matching `[[overrides]]` entry, stacked in file order.
    ///
    /// `matches` is the same glob predicate used by `--include`/`--exclude`
    /// (it receives the override glob and the candidate path). Returns an
    /// empty set when no override matches.
    pub fn disabled_checks_for<F>(&self, file_path: &Path, matches: F) -> Vec<String>
    where
        F: Fn(&str, &Path) -> bool,
    {
        let mut disabled: Vec<String> = Vec::new();
        for ov in &self.overrides {
            if ov.paths.iter().any(|glob| matches(glob, file_path)) {
                for name in &ov.disabled {
                    if !disabled.iter().any(|d| d == name) {
                        disabled.push(name.clone());
                    }
                }
            }
        }
        disabled
    }
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
    fn parses_overrides_section() {
        let raw = r#"
[[overrides]]
paths = ["src/legacy/**"]
disabled = ["unchecked-arithmetic"]

[[overrides]]
paths = ["vendor/**"]
disabled = ["unchecked-arithmetic", "missing-auth"]
"#;
        let cfg: GuardConfig = toml::from_str(raw).unwrap();
        assert_eq!(cfg.overrides.len(), 2);
        assert_eq!(cfg.overrides[0].paths, vec!["src/legacy/**"]);
        assert_eq!(cfg.overrides[0].disabled, vec!["unchecked-arithmetic"]);
        assert_eq!(cfg.overrides[1].disabled.len(), 2);
    }

    #[test]
    fn overrides_stack_for_matching_paths() {
        let raw = r#"
[[overrides]]
paths = ["src/**"]
disabled = ["unchecked-arithmetic"]

[[overrides]]
paths = ["src/legacy/**"]
disabled = ["missing-auth"]
"#;
        let cfg: GuardConfig = toml::from_str(raw).unwrap();
        // A simple prefix matcher standing in for the shared glob matcher.
        let matches = |glob: &str, path: &Path| {
            let prefix = glob.trim_end_matches("**").trim_end_matches('/');
            path.to_string_lossy().starts_with(prefix)
        };

        let legacy = cfg.disabled_checks_for(Path::new("src/legacy/old.rs"), matches);
        assert!(legacy.contains(&"unchecked-arithmetic".to_string()));
        assert!(legacy.contains(&"missing-auth".to_string()));

        let other = cfg.disabled_checks_for(Path::new("src/main.rs"), matches);
        assert_eq!(other, vec!["unchecked-arithmetic".to_string()]);

        let none = cfg.disabled_checks_for(Path::new("tests/foo.rs"), matches);
        assert!(none.is_empty());
    }
}
