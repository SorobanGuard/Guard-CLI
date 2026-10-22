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
    /// Optional path to a base config file to extend (relative to this file).
    /// When set, the base config is loaded first and this config's values
    /// are merged on top (override/extend).
    pub extends: Option<String>,
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
    let mut cfg: GuardConfig = toml::from_str(&raw)
        .map_err(|e| format!("{}: {e}", config_path.display()))?;
    
    // Handle `extends` key - load base config and merge
    if let Some(extends_path) = &cfg.extends {
        let base_path = config_path.parent().unwrap_or(Path::new(".")).join(extends_path);
        let base_raw = std::fs::read_to_string(&base_path)
            .map_err(|e| format!("could not read extended config {}: {e}", base_path.display()))?;
        let mut base_cfg: GuardConfig = toml::from_str(&base_raw)
            .map_err(|e| format!("{}: {e}", base_path.display()))?;
        
        // Merge: base config first, then override with current config
        base_cfg.scan = merge_scan_config(base_cfg.scan, cfg.scan);
        base_cfg.checks = merge_checks_config(base_cfg.checks, cfg.checks);
        // Note: we don't merge `extends` from current config to avoid chains
        cfg = base_cfg;
    }
    
    Ok((Some(cfg), Some(config_path.to_path_buf())))
}

/// Merge scan configs: values from `override` take precedence over `base`.
fn merge_scan_config(base: ScanConfig, override_: ScanConfig) -> ScanConfig {
    ScanConfig {
        path: override_.path.or(base.path),
        min_severity: override_.min_severity.or(base.min_severity),
    }
}

/// Merge checks configs: values from `override` take precedence over `base`.
fn merge_checks_config(base: ChecksConfig, override_: ChecksConfig) -> ChecksConfig {
    ChecksConfig {
        disabled: {
            let mut merged = base.disabled;
            for item in override_.disabled {
                if !merged.contains(&item) {
                    merged.push(item);
                }
            }
            merged
        },
        sensitive_names: SensitiveNamesConfig {
            extra: {
                let mut merged = base.sensitive_names.extra;
                for item in override_.sensitive_names.extra {
                    if !merged.contains(&item) {
                        merged.push(item);
                    }
                }
                merged
            },
        },
    }
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
    fn load_from_path_uses_exactly_the_given_file() {
        let root = temp_root("explicit");
        fs::create_dir_all(root.join("src")).unwrap();
        // A discovered config that must be ignored in favor of the explicit one.
        fs::write(root.join("soroban-guard.toml"), "[scan]\nmin_severity = \"low\"\n").unwrap();
        let explicit = root.join("shared-policy.toml");
        fs::write(&explicit, "[scan]\nmin_severity = \"high\"\n").unwrap();

        let (cfg, path) = resolve(&root.join("src"), Some(&explicit), false).unwrap();
        assert_eq!(cfg.unwrap().scan.min_severity.as_deref(), Some("high"));
        assert_eq!(path, Some(explicit));

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn resolve_reports_a_missing_explicit_config_as_an_error() {
        let root = temp_root("explicit-missing");
        let missing = root.join("nope.toml");

        let err = resolve(&root, Some(&missing), false).unwrap_err();
        assert!(err.contains("nope.toml"), "{err}");

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn resolve_reports_a_malformed_explicit_config_as_an_error() {
        let root = temp_root("explicit-bad");
        let bad = root.join("bad.toml");
        fs::write(&bad, "not valid toml [[[").unwrap();

        let err = resolve(&root, Some(&bad), false).unwrap_err();
        assert!(err.contains("bad.toml"), "{err}");

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn resolve_with_no_config_skips_discovery() {
        let root = temp_root("no-config");
        fs::write(root.join("soroban-guard.toml"), "[scan]\n").unwrap();

        let (cfg, path) = resolve(&root, None, true).unwrap();
        assert!(cfg.is_none());
        assert!(path.is_none());

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn unknown_top_level_table_is_rejected() {
        let root = temp_root("unknown-table");
        fs::write(root.join("soroban-guard.toml"), "[check]\n").unwrap();

        let err = load(&root).unwrap_err();
        assert!(err.contains("soroban-guard.toml"), "{err}");

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn extends_loads_base_config_and_merges() {
        let root = temp_root("extends");

        // Base config
        fs::write(
            root.join("base.toml"),
            r#"
[scan]
min_severity = "low"
path = "src/contracts"

[checks]
disabled = ["forbidden-std-imports"]
sensitive_names.extra = ["admin_only"]
"#,
        )
        .unwrap();

        // Child config extending base
        fs::write(
            root.join("soroban-guard.toml"),
            r#"
extends = "base.toml"

[scan]
min_severity = "high"

[checks]
disabled = ["hardcoded-address"]
sensitive_names.extra = ["custom_admin"]
"#,
        )
        .unwrap();

        let (cfg, _path) = load(&root).unwrap();
        let cfg = cfg.unwrap();

        // scan.path should come from base
        assert_eq!(cfg.scan.path.as_deref(), Some("src/contracts"));
        // scan.min_severity should be overridden by child
        assert_eq!(cfg.scan.min_severity.as_deref(), Some("high"));

        // checks.disabled should merge (both from base and child)
        assert!(cfg.checks.disabled.contains(&"forbidden-std-imports".to_string()));
        assert!(cfg.checks.disabled.contains(&"hardcoded-address".to_string()));

        // sensitive_names.extra should merge
        assert!(cfg.checks.sensitive_names.extra.contains(&"admin_only".to_string()));
        assert!(cfg.checks.sensitive_names.extra.contains(&"custom_admin".to_string()));

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn extends_with_relative_path() {
        let root = temp_root("extends-rel");

        // Create subdirectory structure
        fs::create_dir_all(root.join("config")).unwrap();

        // Base config in config/
        fs::write(
            root.join("config/base.toml"),
            r#"
[scan]
min_severity = "medium"
"#,
        )
        .unwrap();

        // Child config in root extending config/base.toml
        fs::write(
            root.join("soroban-guard.toml"),
            r#"
extends = "config/base.toml"

[scan]
min_severity = "high"
"#,
        )
        .unwrap();

        let (cfg, _path) = load(&root).unwrap();
        let cfg = cfg.unwrap();

        // Child overrides base
        assert_eq!(cfg.scan.min_severity.as_deref(), Some("high"));

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn extends_nonexistent_file_returns_error() {
        let root = temp_root("extends-missing");

        fs::write(
            root.join("soroban-guard.toml"),
            r#"
extends = "does-not-exist.toml"
"#,
        )
        .unwrap();

        let err = load(&root).unwrap_err();
        assert!(err.contains("does-not-exist.toml") || err.contains("could not read"));

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn load_from_path_handles_extends() {
        let root = temp_root("load-from-path-extends");

        fs::write(
            root.join("base.toml"),
            r#"
[scan]
min_severity = "low"
"#,
        )
        .unwrap();

        let child = root.join("child.toml");
        fs::write(
            &child,
            r#"
extends = "base.toml"

[scan]
min_severity = "high"
"#,
        )
        .unwrap();

        let (cfg, path) = load_from_path(&child).unwrap();
        let cfg = cfg.unwrap();

        assert_eq!(cfg.scan.min_severity.as_deref(), Some("high"));
        assert_eq!(path, Some(child));

        fs::remove_dir_all(root).unwrap();
    }
}
