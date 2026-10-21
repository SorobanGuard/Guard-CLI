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

/// Compute the Levenshtein edit distance between two strings.
fn levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut curr = vec![0usize; b.len() + 1];
    for (i, ca) in a.iter().enumerate() {
        curr[0] = i + 1;
        for (j, cb) in b.iter().enumerate() {
            let cost = if ca == cb { 0 } else { 1 };
            curr[j + 1] = (prev[j] + cost).min(prev[j + 1] + 1).min(curr[j] + 1);
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[b.len()]
}

/// Suggest up to three registered check names closest to `unknown`.
fn suggest_checks(unknown: &str, known_checks: &[&str]) -> Vec<String> {
    let max_distance = 3;
    let mut scored: Vec<(usize, &str)> = known_checks
        .iter()
        .copied()
        .map(|name| (levenshtein(unknown, name), name))
        .filter(|(dist, name)| {
            *dist <= max_distance
                || (!unknown.is_empty()
                    && (name.starts_with(unknown) || unknown.starts_with(*name)))
        })
        .collect();
    scored.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(b.1)));
    scored
        .into_iter()
        .take(3)
        .map(|(_, name)| name.to_string())
        .collect()
}

/// Build an error message for an unknown check name, including suggestions.
fn unknown_check_error(name: &str, known_checks: &[&str]) -> String {
    let suggestions = suggest_checks(name, known_checks);
    if suggestions.is_empty() {
        format!("unknown check: {name}")
    } else {
        let hint = suggestions
            .iter()
            .map(|s| format!("`{s}`"))
            .collect::<Vec<_>>()
            .join(", ");
        format!("unknown check: {name} (did you mean {hint}?)")
    }
}

/// Validate the parsed arguments, returning an error message on failure.
pub fn validate_args(args: &Args, known_checks: &[&str]) -> Result<(), String> {
    for name in &args.disable_check {
        if !known_checks.contains(&name.as_str()) {
            return Err(unknown_check_error(name, known_checks));
        }
    }

    for name in &args.only_check {
        if !known_checks.contains(&name.as_str()) {
            return Err(unknown_check_error(name, known_checks));
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
