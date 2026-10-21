pub mod baseline;
pub mod config;

use std::path::{Path, PathBuf};

use config::Config;

/// Result of loading and validating a `soroban-guard.toml`.
pub struct LoadedConfig {
    pub path: PathBuf,
    pub config: Config,
}

/// Shared config loader used by both `scan` and `check-config`.
///
/// Applies the same discovery rules as `scan`: an explicit `--config` path is
/// used verbatim, otherwise `soroban-guard.toml` is looked up in the current
/// directory. Errors are reported with the file and offending key.
pub fn load_config(explicit: Option<&Path>) -> Result<LoadedConfig, String> {
    let path = match explicit {
        Some(p) => p.to_path_buf(),
        None => PathBuf::from("soroban-guard.toml"),
    };

    let raw = std::fs::read_to_string(&path)
        .map_err(|e| format!("{}: failed to read config: {e}", path.display()))?;

    let config = Config::from_toml_str(&raw)
        .map_err(|e| format!("{}: {e}", path.display()))?;

    Ok(LoadedConfig { path, config })
}

/// Validate a config file without scanning. Returns `Ok` on success and a
/// human-readable error (including file and key) on failure.
pub fn check_config(explicit: Option<&Path>, verbose: bool) -> Result<(), String> {
    let loaded = load_config(explicit)?;

    if verbose {
        println!("config: {}", loaded.path.display());
        println!("{}", loaded.config.describe());
    } else {
        println!("{}: ok", loaded.path.display());
    }

    Ok(())
}
