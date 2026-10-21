pub mod baseline;
pub mod config;

use clap::{ArgAction, Parser, ValueEnum};

/// When to emit ANSI colour in CLI output.
///
/// Precedence: an explicit `--color`/`--no-color` flag always wins over the
/// `NO_COLOR` environment variable. `auto` (the default) leaves the decision
/// to `colored`, which honours `NO_COLOR` and TTY detection.
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum ColorWhen {
    /// Emit colour only when stdout is a TTY and `NO_COLOR` is unset.
    Auto,
    /// Always emit colour, even when stdout is not a TTY.
    Always,
    /// Never emit colour.
    Never,
}

impl Default for ColorWhen {
    fn default() -> Self {
        ColorWhen::Auto
    }
}

impl ColorWhen {
    /// Apply this mode to `colored`'s global override.
    ///
    /// `auto` clears any override so `colored` falls back to its default
    /// behaviour (TTY detection plus the `NO_COLOR` env var).
    pub fn apply(self) {
        match self {
            ColorWhen::Auto => colored::control::unset_override(),
            ColorWhen::Always => colored::control::set_override(true),
            ColorWhen::Never => colored::control::set_override(false),
        }
    }
}

/// Resolve the effective colour mode from the parsed flags.
///
/// An explicit `--color <WHEN>` wins; otherwise `--no-color` maps to
/// `never`; otherwise the default `auto` is used.
pub fn resolve_color(color: Option<ColorWhen>, no_color: bool) -> ColorWhen {
    match color {
        Some(when) => when,
        None if no_color => ColorWhen::Never,
        None => ColorWhen::Auto,
    }
}

/// Shared colour-related CLI arguments.
#[derive(Debug, Clone, Parser)]
pub struct ColorArgs {
    /// When to use ANSI colour: auto, always, or never.
    ///
    /// An explicit value wins over the `NO_COLOR` environment variable.
    #[arg(long, value_enum, value_name = "WHEN", default_value_t = ColorWhen::Auto)]
    pub color: ColorWhen,

    /// Disable ANSI colour (alias for `--color never`).
    #[arg(long = "no-color", action = ArgAction::SetTrue, conflicts_with = "color")]
    pub no_color: bool,
}

impl ColorArgs {
    /// Resolve and apply the effective colour mode.
    pub fn apply(&self) {
        resolve_color(Some(self.color), self.no_color).apply();
    }
}

/// Shared stats-related CLI arguments.
#[derive(Debug, Clone, Parser)]
pub struct StatsArgs {
    /// Print per-check timing and finding counts to stderr after the scan.
    ///
    /// Goes to stderr so structured stdout stays clean. Timing is only
    /// measured when this flag is set, so there is zero overhead otherwise.
    #[arg(long, action = ArgAction::SetTrue)]
    pub stats: bool,
}

/// Per-check statistics collected during a scan.
///
/// `findings` is the number of findings the check produced and `elapsed`
/// is the cumulative wall time spent inside `Check::run` across all files.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CheckStats {
    /// Name of the check.
    pub name: String,
    /// Number of findings produced by the check.
    pub findings: usize,
    /// Cumulative wall time spent running the check across all files.
    pub elapsed: std::time::Duration,
}

/// Render a per-check stats table to `stderr`.
///
/// The table lists each check's name, finding count, and cumulative wall
/// time. Output goes to stderr so structured stdout stays clean.
pub fn print_stats(stats: &[CheckStats]) {
    use std::io::Write;

    let stderr = std::io::stderr();
    let mut out = stderr.lock();

    let _ = writeln!(out, "{:<32} {:>10} {:>14}", "check", "findings", "time");
    for stat in stats {
        let _ = writeln!(
            out,
            "{:<32} {:>10} {:>14.3}ms",
            stat.name,
            stat.findings,
            stat.elapsed.as_secs_f64() * 1000.0,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_color_wins_over_no_color() {
        assert_eq!(resolve_color(Some(ColorWhen::Always), true), ColorWhen::Always);
        assert_eq!(resolve_color(Some(ColorWhen::Never), false), ColorWhen::Never);
    }

    #[test]
    fn no_color_maps_to_never() {
        assert_eq!(resolve_color(None, true), ColorWhen::Never);
    }

    #[test]
    fn default_is_auto() {
        assert_eq!(resolve_color(None, false), ColorWhen::Auto);
    }

    #[test]
    fn parses_color_flag() {
        let args = ColorArgs::try_parse_from(["test", "--color", "always"]).unwrap();
        assert_eq!(args.color, ColorWhen::Always);
        assert!(!args.no_color);
    }

    #[test]
    fn parses_no_color_flag() {
        let args = ColorArgs::try_parse_from(["test", "--no-color"]).unwrap();
        assert!(args.no_color);
        assert_eq!(resolve_color(Some(args.color), args.no_color), ColorWhen::Never);
    }

    #[test]
    fn parses_stats_flag() {
        let args = StatsArgs::try_parse_from(["test", "--stats"]).unwrap();
        assert!(args.stats);
    }

    #[test]
    fn stats_defaults_to_off() {
        let args = StatsArgs::try_parse_from(["test"]).unwrap();
        assert!(!args.stats);
    }
}
