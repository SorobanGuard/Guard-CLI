//! `soroban-guard.toml` configuration file support.

use serde::Deserialize;
use std::path::Path;

/// Top-level config file structure.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct GuardConfig {
    pub scan: ScanConfig,
    pub checks: ChecksConfig,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct ScanConfig {
    /// Default scan path (overridden by the CLI positional argument).
    pub path: Option<String>,
    /// Filter out findings below this severity ("high" | "medium" | "low").
    pub min_severity: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct ChecksConfig {
    /// Check names to skip.
    pub disabled: Vec<String>,
    pub sensitive_names: SensitiveNamesConfig,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct SensitiveNamesConfig {
    /// Extra function names added to the built-in `SENSITIVE_NAMES` list.
    pub extra: Vec<String>,
}

/// Load and parse `soroban-guard.toml` from `scan_root` if present.
///
/// Returns `None` when no config file exists.
/// Returns an error string (for exit-2 reporting) when the file is malformed.
pub fn load(scan_root: &Path) -> Result<Option<GuardConfig>, String> {
    let config_path = scan_root.join("soroban-guard.toml");
    if !config_path.exists() {
        return Ok(None);
    }
    let raw = std::fs::read_to_string(&config_path)
        .map_err(|e| format!("could not read {}: {e}", config_path.display()))?;
    let cfg: GuardConfig = toml::from_str(&raw)
        .map_err(|e| format!("{}: {e}", config_path.display()))?;
    Ok(Some(cfg))
}
