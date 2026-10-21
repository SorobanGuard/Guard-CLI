pub mod baseline;
pub mod config;

use clap::Parser;
use std::path::PathBuf;

/// Command-line arguments for the CLI.
#[derive(Debug, Parser)]
#[command(name = "handsoff", version, about)]
pub struct Args {
    /// Paths to check.
    #[arg(value_name = "PATH")]
    pub paths: Vec<PathBuf>,

    /// Disable a specific check by name (repeatable).
    #[arg(long = "disable-check", value_name = "NAME")]
    pub disable_check: Vec<String>,

    /// Run only the named checks (repeatable). Inverse of `--disable-check`.
    #[arg(long = "only-check", value_name = "NAME")]
    pub only_check: Vec<String>,
}

/// Validate the parsed arguments, returning an error message on failure.
pub fn validate_args(args: &Args, known_checks: &[&str]) -> Result<(), String> {
    for name in &args.disable_check {
        if !known_checks.contains(&name.as_str()) {
            return Err(format!("unknown check: {name}"));
        }
    }

    for name in &args.only_check {
        if !known_checks.contains(&name.as_str()) {
            return Err(format!("unknown check: {name}"));
        }
    }

    for name in &args.only_check {
        if args.disable_check.contains(name) {
            return Err(format!(
                "check `{name}` cannot be both enabled via --only-check and disabled via --disable-check"
            ));
        }
    }

    Ok(())
}

/// Determine which checks should run given the arguments.
pub fn selected_checks<'a>(args: &Args, known_checks: &[&'a str]) -> Vec<&'a str> {
    if args.only_check.is_empty() {
        known_checks
            .iter()
            .copied()
            .filter(|name| !args.disable_check.iter().any(|d| d == name))
            .collect()
    } else {
        known_checks
            .iter()
            .copied()
            .filter(|name| args.only_check.iter().any(|o| o == name))
            .collect()
    }
}
