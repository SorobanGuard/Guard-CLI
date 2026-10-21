pub mod baseline;
pub mod config;

use std::path::{Path, PathBuf};

use config::Config;

/// Output format selected on the command line.
///
/// `--format <pretty|json|sarif|markdown>` is the canonical way to pick an
/// output format. The legacy `--json`, `--sarif` and `--markdown` booleans are
/// kept as aliases that map onto the corresponding variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OutputFormat {
    #[default]
    Pretty,
    Json,
    Sarif,
    Markdown,
}

impl OutputFormat {
    /// Parse a `--format` value. Returns `None` for unknown values.
    pub fn from_str(value: &str) -> Option<Self> {
        match value {
            "pretty" => Some(OutputFormat::Pretty),
            "json" => Some(OutputFormat::Json),
            "sarif" => Some(OutputFormat::Sarif),
            "markdown" => Some(OutputFormat::Markdown),
            _ => None,
        }
    }

    /// Canonical string form, matching the accepted `--format` values.
    pub fn as_str(&self) -> &'static str {
        match self {
            OutputFormat::Pretty => "pretty",
            OutputFormat::Json => "json",
            OutputFormat::Sarif => "sarif",
            OutputFormat::Markdown => "markdown",
        }
    }

    /// Whether this format is the human-readable default.
    pub fn is_pretty(&self) -> bool {
        matches!(self, OutputFormat::Pretty)
    }
}

/// Resolve the effective output format from the `--format` value and the
/// legacy boolean aliases.
///
/// `--format` takes precedence when present; otherwise the first enabled
/// legacy boolean selects the format. The argument parser is responsible for
/// rejecting combinations of `--format` with the legacy booleans, so this
/// helper only needs to pick a winner.
pub fn resolve_output_format(
    format: Option<OutputFormat>,
    json: bool,
    sarif: bool,
    markdown: bool,
) -> OutputFormat {
    if let Some(fmt) = format {
        return fmt;
    }
    if json {
        OutputFormat::Json
    } else if sarif {
        OutputFormat::Sarif
    } else if markdown {
        OutputFormat::Markdown
    } else {
        OutputFormat::Pretty
    }
}

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
