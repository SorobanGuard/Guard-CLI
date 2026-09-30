use soroban_guard_cli::config;

use clap::{ArgGroup, CommandFactory, Parser, Subcommand};
use clap_complete::{generate, Shell};
use colored::Colorize;
use notify::{Event, EventKind, RecursiveMode, Watcher};
use soroban_guard_analyzer::{is_ignored_path, scan_directory_with_checks, ScanError};
use soroban_guard_checks::{default_checks, default_checks_with_config, Finding, Severity};
use std::collections::HashSet;
use std::fs;
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc;

#[derive(Parser)]
#[command(name = "soroban-guard")]
#[command(
    about = "Soroban Guard Core — static analyzer for Soroban smart contracts",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan a directory tree for vulnerability patterns
    #[command(group(
        ArgGroup::new("output_format")
            .args(["json", "sarif", "markdown"])
            .multiple(false)
    ))]
    Scan {
        /// Path to the contract crate or folder containing Rust sources (or use path from soroban-guard.toml)
        path: Option<PathBuf>,
        /// Print findings as JSON (`{ "summary": {...}, "findings": [...] }`)
        #[arg(long)]
        json: bool,
        /// Print findings as a SARIF 2.1.0 document
        #[arg(long)]
        sarif: bool,
        /// Print findings as a Markdown table
        #[arg(long)]
        markdown: bool,
        /// Write output to a file instead of stdout (applies to --json, --sarif, and --markdown)
        #[arg(long)]
        output: Option<PathBuf>,
        /// Suppress all output unless a finding meets the --fail-on threshold
        #[arg(long)]
        quiet: bool,
        /// Disable colored output
        #[arg(long)]
        no_color: bool,
        /// Print additional scan statistics such as skipped generated files
        #[arg(long)]
        verbose: bool,
        /// Only scan files matching this glob pattern (e.g. `src/token*.rs`); may be repeated
        #[arg(long, value_name = "PATTERN")]
        include: Vec<String>,
        /// Exclude files matching this glob pattern (e.g. `src/proxy.rs`); may be repeated
        #[arg(long, value_name = "PATTERN")]
        exclude: Vec<String>,
        /// Exit code 1 when findings at or above this severity are found (high|medium|low, default: high)
        #[arg(long)]
        fail_on: Option<String>,
        /// Disable a named check (may be repeated)
        #[arg(long, value_name = "CHECK")]
        disable_check: Vec<String>,
        /// Watch for .rs file changes and re-run the scan automatically
        #[arg(long, short = 'w')]
        watch: bool,
        /// Do not clear the terminal between watch-mode scans
        #[arg(long, hide = true)]
        /// Don't clear the terminal between watch-mode re-scans
        #[arg(long)]
        no_clear: bool,
        /// Cap the number of findings printed to stdout (0 = unlimited, default: 0)
        #[arg(long, value_name = "N", default_value_t = 0)]
        max_findings: usize,
    },
    /// List the checks that are enabled by default
    ListChecks {
        /// Emit machine-readable JSON instead of the default table
        #[arg(long)]
        json: bool,
    },
    /// Write a commented starter soroban-guard.toml file
    Init {
        /// Directory where soroban-guard.toml should be created
        #[arg(default_value = ".")]
        path: PathBuf,
        /// Overwrite an existing soroban-guard.toml
        #[arg(long)]
        force: bool,
    },
    /// Print full documentation for a named check
    Explain {
        /// Name of the check (e.g. `missing-require-auth`)
        check_name: String,
    },
    /// Print shell completion scripts for Bash, Zsh, Fish, or PowerShell
    Completions {
        /// Shell to generate completions for
        shell: Shell,
    },
    /// Print version and build information
    Version,
}

/// Parameters passed to the core scan-and-print routine.
struct ScanOptions {
    path: PathBuf,
    json: bool,
    sarif: bool,
    markdown: bool,
    output: Option<PathBuf>,
    quiet: bool,
    verbose: bool,
    fail_threshold: Severity,
    exclude: Vec<String>,
    includes: Vec<String>,
    max_findings: usize,
}

/// Whether scan results should be printed. `--quiet` suppresses output only while the
/// run is passing: as soon as a finding meets the `--fail-on` threshold (`should_fail`),
/// output is shown regardless. The gate is the `--fail-on` threshold, not High severity.
fn should_print_results(quiet: bool, should_fail: bool) -> bool {
    !quiet || should_fail
}

/// Run a single scan and print its results.
/// Returns the exit code that would normally be passed to `std::process::exit`
/// (0 = pass, 1 = findings above threshold, 2 = I/O error).
fn run_scan(
    opts: &ScanOptions,
    active_checks: &[Box<dyn soroban_guard_checks::Check + Send + Sync>],
) -> i32 {
    match scan_directory_with_checks(&opts.path, &opts.exclude, &opts.includes, active_checks) {
        Ok((results, files_scanned, files_skipped, _check_panics)) => {
            let findings: Vec<Finding> =
                results.into_iter().flat_map(|r| r.findings).collect();
            let should_fail = findings
                .iter()
                .any(|f| f.severity <= opts.fail_threshold);

            // Produce the serialized payload for the selected structured format,
            // then emit it via a single shared write-or-print path (Issue #430).
            // All three formats use println! (trailing newline) as the convention.
            let structured_payload: Option<Result<String, String>> = if opts.json {
                Some(
                    json_payload(&findings, files_scanned, files_skipped)
                        .map_err(|e| e.to_string()),
                )
            } else if opts.sarif {
                Some(
                    serde_json::to_string_pretty(&build_sarif(&findings, files_skipped))
                        .map_err(|e| e.to_string()),
                )
            } else if opts.markdown {
                Some(Ok(render_markdown(&findings)))
            } else {
                None
            };

            if let Some(result) = structured_payload {
                match result {
                    Ok(payload) => {
                        // `--quiet` suppresses console text only; a requested `--output`
                        // file is a build artifact and must always be written, whether
                        // the scan passes or fails (Issue #625).
                        if let Some(ref out_path) = opts.output {
                            if let Err(e) = write_output(out_path, &payload) {
                                eprintln!("{} {}", "error:".red().bold(), e);
                                return 2;
                            }
                        }
                        if opts.output.is_none() && should_print_results(opts.quiet, should_fail) {
                            println!("{payload}");
                        }
                    }
                    Err(e) => {
                        eprintln!("{} {}", "error:".red().bold(), e);
                        return 2;
                    }
                }
            } else if should_print_results(opts.quiet, should_fail) {
                let (display, truncated) = truncate(&findings, opts.max_findings);
                print_pretty(
                    &findings,
                    display,
                    files_scanned,
                    opts.path.display().to_string(),
                    truncated,
                );
            }

            if opts.verbose {
                eprintln!("Scanned {} file(s).", files_scanned);
                if files_skipped > 0 {
                    eprintln!("Skipped {} generated file(s) from analysis.", files_skipped);
                }
            }

            if should_fail {
                1
            } else {
                0
            }
        }
        Err(e) => {
            // A directory with several unparseable/unreadable files surfaces every
            // one of them (issue #629) instead of just the first one rayon happened
            // to observe; every other error prints as the single message it is.
            let messages: Vec<String> = match &e {
                ScanError::Multiple(errs) => errs.iter().map(ToString::to_string).collect(),
                other => vec![other.to_string()],
            };
            if opts.json {
                let envelope = serde_json::json!({ "error": e.to_string(), "errors": messages });
                match serde_json::to_string_pretty(&envelope) {
                    Ok(payload) => {
                        // #669: --output must be written even when the scan errors so that
                        // CI pipelines that unconditionally upload the output artifact get a
                        // machine-readable error document instead of a missing file.
                        if let Some(ref out_path) = opts.output {
                            if let Err(write_err) = write_output(out_path, &payload) {
                                eprintln!("{} {}", "error:".red().bold(), write_err);
                            }
                        } else {
                            println!("{}", payload);
                        }
                    }
                    Err(json_err) => eprintln!("{} {}", "error:".red().bold(), json_err),
                }
            } else {
                for message in &messages {
                    eprintln!("{} {}", "error:".red().bold(), message);
                }
            }
            2
        }
    }
}

/// Returns a UTC time string like "23:09:36 UTC" without any external date crate.
fn chrono_timestamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let s = secs % 60;
    let m = (secs / 60) % 60;
    let h = (secs / 3600) % 24;
    let days = secs / 86400;
    let (year, month, day) = days_to_ymd(days);
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        year, month, day, h, m, s
    )
}

/// Convert days since Unix epoch (1970-01-01) to (year, month, day).
fn days_to_ymd(mut days: u64) -> (u64, u64, u64) {
    let mut year = 1970u64;
    loop {
        let days_in_year = if is_leap(year) { 366 } else { 365 };
        if days < days_in_year {
            break;
        }
        days -= days_in_year;
        year += 1;
    }
    let months: [u64; 12] = [
        31,
        if is_leap(year) { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut month = 1u64;
    for &dim in &months {
        if days < dim {
            break;
        }
        days -= dim;
        month += 1;
    }
    (year, month, days + 1)
}

fn is_leap(year: u64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

/// Emit a setup-time error in the correct format and exit with code 2.
///
/// When `use_json` is true (i.e. `--json` was passed) the message is wrapped in
/// the same `{"error":…,"errors":[…]}` envelope used by scan-time errors so
/// that automation parsing `--json` output always gets machine-readable JSON,
/// regardless of whether the failure happened during setup or scanning (#670).
/// Otherwise the message is printed to stderr as plain text.
fn emit_setup_error(message: &str, use_json: bool) -> ! {
    if use_json {
        let envelope = serde_json::json!({ "error": message, "errors": [message] });
        match serde_json::to_string_pretty(&envelope) {
            Ok(payload) => println!("{}", payload),
            Err(e) => eprintln!("{} {}", "error:".red().bold(), e),
        }
    } else {
        eprintln!("{} {}", "error:".red().bold(), message);
    }
    std::process::exit(2)
}

/// Parse a `--fail-on` / `min_severity` string into a `Severity`.
///
/// Returns `Ok(Severity)` for `"high"`, `"medium"`, or `"low"` (case-insensitive).
/// Returns `Err(original_value)` for anything else so the caller can emit a
/// helpful `error:` message and exit 2.
fn parse_fail_on(value: &str) -> Result<Severity, &str> {
    match value.to_lowercase().as_str() {
        "high" => Ok(Severity::High),
        "medium" => Ok(Severity::Medium),
        "low" => Ok(Severity::Low),
        _ => Err(value),
    }
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::Scan {
            path,
            json,
            sarif,
            markdown,
            output,
            quiet,
            no_color,
            verbose,
            include,
            exclude,
            fail_on,
            disable_check,
            watch,
            no_clear,
            max_findings,
        } => {
            if no_color || std::env::var_os("NO_COLOR").is_some() {
                colored::control::set_override(false);
            }
            // Mutual exclusion
            let format_count = [json, sarif, markdown].iter().filter(|&&b| b).count();
            if format_count > 1 {
                eprintln!(
                    "{} --json, --sarif, and --markdown are mutually exclusive",
                    "error:".red().bold()
                );
                std::process::exit(2);
            }
            // Try to load soroban-guard.toml from current directory to get default path.
            let config_for_default = match config::load(&PathBuf::from(".")) {
                Ok((c, _)) => c.unwrap_or_default(),
                Err(e) => {
                    eprintln!("{} {}", "error:".red().bold(), e);
                    std::process::exit(2);
                }
            };

            // Resolve scan path: CLI argument takes precedence, then config, then error.
            // The current-directory config is only needed as a fallback for the scan
            // path itself, so it's only loaded when no path argument was given -
            // otherwise a malformed `./soroban-guard.toml` would abort scans of an
            // unrelated, explicitly-provided path (Issue #626).
            let scan_path = if let Some(p) = path {
                p
            } else {
                // Try to load soroban-guard.toml from current directory to get default path.
                let config_for_default = match config::load(&PathBuf::from(".")) {
                    Ok(c) => c.unwrap_or_default(),
                    Err(e) => {
                        eprintln!("{} {}", "error:".red().bold(), e);
                        std::process::exit(2);
                    }
                };
                if let Some(config_path) = &config_for_default.scan.path {
                    PathBuf::from(config_path)
                } else {
                    eprintln!(
                        "{} no scan path provided and none found in soroban-guard.toml",
                        "error:".red().bold()
                    );
                    std::process::exit(2);
                }
            };

            // Load soroban-guard.toml, searching upward from the scan path.
            let cfg = match config::load(&scan_path) {
                Ok((c, config_path)) => {
                    if verbose {
                        match &config_path {
                            Some(p) => eprintln!("Using config file {}", p.display()),
                            None => eprintln!("No soroban-guard.toml found"),
                        }
                    }
                    c.unwrap_or_default()
                }
                Err(e) => {
                    emit_setup_error(&e.to_string(), json);
                }
            };

            // CLI --fail-on takes precedence over config min_severity.
            // Because --fail-on is now Option<String>, Some(_) always means the
            // user explicitly set the flag (even --fail-on high), while None means
            // they did not — so we can correctly fall back to the config value
            // without the old `!= "high"` hack that broke explicit --fail-on high
            // (issue #667).
            let effective_fail_on = if let Some(ref flag) = fail_on {
                flag.clone()
            } else {
                cfg.scan.min_severity.clone().unwrap_or_else(|| "high".to_string())
            };
            let fail_threshold = match parse_fail_on(&effective_fail_on) {
                Ok(sev) => sev,
                Err(bad) => {
                    emit_setup_error(
                        &format!(
                            "unknown --fail-on value `{}`. Expected one of: high, medium, low",
                            bad
                        ),
                        json,
                    );
                }
            };

            // Merge config disabled list with --disable-check flags.
            let mut all_disabled: Vec<String> = cfg.checks.disabled.clone();
            for name in &disable_check {
                if !all_disabled.contains(name) {
                    all_disabled.push(name.clone());
                }
            }

            // Validate disabled names against known checks.
            let known_checks = default_checks();
            {
                let known_names: HashSet<&str> = known_checks.iter().map(|c| c.name()).collect();
                for name in &all_disabled {
                    if !known_names.contains(name.as_str()) {
                        emit_setup_error(
                            &format!(
                                "unknown check `{}`. Run `soroban-guard list-checks` to see available checks.",
                                name
                            ),
                            json,
                        );
                    }
                }
            }
            if !all_disabled.is_empty() && !quiet {
                eprintln!("note: disabled check(s): {}", all_disabled.join(", "));
            }

            let extra_sensitive = &cfg.checks.sensitive_names.extra;
            let active_checks = default_checks_with_config(&all_disabled, extra_sensitive);

            // Build a ScanOptions struct to pass around cleanly.
            let opts = ScanOptions {
                path: scan_path.clone(),
                json,
                sarif,
                markdown,
                output: output.clone(),
                quiet,
                verbose,
                fail_threshold,
                exclude: exclude.clone(),
                includes: include.clone(),
                max_findings,
            };

            // #671: --output without a structured format flag writes nothing and
            // produces no visible output — warn the user so the mistake is obvious.
            if output.is_some() && !json && !sarif && !markdown {
                eprintln!(
                    "{} --output has no effect without --json, --sarif, or --markdown",
                    "warning:".yellow().bold()
                );
            }

            // Run the initial scan.
            let exit_code = run_scan(&opts, &active_checks);

            if !watch {
                // Not in watch mode — preserve original exit-code behaviour.
                if exit_code != 0 {
                    std::process::exit(exit_code);
                }
            } else {
                // Watch mode: set up a notify watcher, block until Ctrl-C.
                eprintln!(
                    "{}",
                    format!(
                        "\nWatching {} for .rs file changes. Press Ctrl-C to exit.",
                        scan_path.display()
                    )
                    .dimmed()
                );

                let (tx, rx) = mpsc::channel::<notify::Result<Event>>();

                let mut watcher = notify::recommended_watcher(move |res| {
                    let _ = tx.send(res);
                })
                .unwrap_or_else(|e| {
                    eprintln!(
                        "{} failed to create file watcher: {}",
                        "error:".red().bold(),
                        e
                    );
                    std::process::exit(2);
                });

                watcher
                    .watch(&scan_path, RecursiveMode::Recursive)
                    .unwrap_or_else(|e| {
                        eprintln!("{} failed to watch path: {}", "error:".red().bold(), e);
                        std::process::exit(2);
                    });

                // Debounce window: coalesce filesystem events arriving within this
                // duration into a single re-scan. A single atomic editor save produces
                // Create + several Modify events for the same path, so without this we
                // would re-walk the whole tree once per event.
                const DEBOUNCE_DURATION: std::time::Duration =
                    std::time::Duration::from_millis(300);

                while let Ok(res) = rx.recv() {
                    match res {
                        Ok(event) => {
                            // React to create/modify/remove events on .rs files, skipping
                            // paths the scanner itself would skip (target/, .git/) so a
                            // `cargo build` running elsewhere doesn't trigger a re-scan
                            // (issue #627). --exclude/--include globs are not applied to
                            // watch events; only this ignore-list is.
                            let is_relevant = matches!(
                                event.kind,
                                EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_)
                            ) && event
                                .paths
                                .iter()
                                .any(|p| p.extension().map(|e| e == "rs").unwrap_or(false) && !is_ignored_path(p));

                            if !is_relevant {
                                continue;
                            }

                            // Drain any additional events that land within the debounce
                            // window so bursty saves collapse into a single scan.
                            let deadline = std::time::Instant::now() + DEBOUNCE_DURATION;
                            while std::time::Instant::now() < deadline {
                                match rx.recv_timeout(deadline - std::time::Instant::now()) {
                                    Ok(Ok(e)) => {
                                        let relevant = matches!(
                                            e.kind,
                                            EventKind::Create(_)
                                                | EventKind::Modify(_)
                                                | EventKind::Remove(_)
                                        ) && e.paths.iter().any(|p| {
                                            p.extension().map(|x| x == "rs").unwrap_or(false)
                                                && !is_ignored_path(p)
                                        });
                                        if !relevant {
                                            continue;
                                        }
                                    }
                                    Ok(Err(e)) => {
                                        eprintln!("{} watcher error: {}", "error:".red().bold(), e);
                                        continue;
                                    }
                                    Err(_) => break,
                                }
                            }

                            // Clear terminal for a clean view — only when output is
                            // going to a human-readable TTY and is not a structured
                            // format (--json / --sarif / --output).  Send to stderr so
                            // stdout stays clean for machine consumers.
                            let stdout_is_tty = std::io::stdout().is_terminal();
                            let should_clear =
                                !no_clear && !json && !sarif && output.is_none() && stdout_is_tty;
                            if should_clear {
                                eprint!("\x1B[2J\x1B[1;1H");
                                let _ = io::stderr().flush();
                            }

                            // Print a timestamped re-scan header.
                            let now = chrono_timestamp();
                            eprintln!(
                                "{}",
                                format!("[{}] File changed — re-scanning...", now)
                                    .cyan()
                                    .bold()
                            );

                            run_scan(&opts, &active_checks);
                            // In watch mode we never exit on findings — keep watching.
                        }
                        Err(e) => {
                            eprintln!("{} watcher error: {}", "error:".red().bold(), e);
                        }
                    }
                }
            }
        }
        Commands::ListChecks { json } => {
            if json {
                match list_checks_json() {
                    Ok(payload) => println!("{payload}"),
                    Err(e) => {
                        eprintln!("{} {}", "error:".red().bold(), e);
                        std::process::exit(2);
                    }
                }
            } else {
                for check in default_checks() {
                    let (severity, description) = describe_check(check.name());
                    println!("{} | {} | {}", check.name(), severity, description);
                }
                println!();
                println!(
                    "Run `soroban-guard explain <check-name>` for detailed documentation on any check."
                );
            }
        }
        Commands::Init { path, force } => {
            let config_path = path.join("soroban-guard.toml");
            if config_path.exists() && !force {
                eprintln!(
                    "{} {} already exists. Re-run with --force to overwrite it.",
                    "error:".red().bold(),
                    config_path.display()
                );
                std::process::exit(2);
            }
            if let Err(e) = fs::create_dir_all(&path) {
                eprintln!(
                    "{} could not create {}: {}",
                    "error:".red().bold(),
                    path.display(),
                    e
                );
                std::process::exit(2);
            }
            if let Err(e) = write_output(&config_path, STARTER_CONFIG) {
                eprintln!(
                    "{} could not write {}: {}",
                    "error:".red().bold(),
                    config_path.display(),
                    e
                );
                std::process::exit(2);
            }
            println!("Wrote {}", config_path.display());
        }
        Commands::Explain { check_name } => {
            let known = default_checks();
            if !known.iter().any(|c| c.name() == check_name) {
                eprintln!(
                    "{} unknown check `{}`. Run `soroban-guard list-checks` to see available checks.",
                    "error:".red().bold(),
                    check_name
                );
                std::process::exit(2);
            }
            let (severity, summary) = describe_check(&check_name);
            let details = explain_details(&check_name);
            println!("Name:      {}", check_name);
            println!("Severity:  {}", severity.to_uppercase());
            println!("Summary:   {}", summary);
            println!("Details:");
            println!("  {}", details);
        }
        Commands::Completions { shell } => {
            let mut cmd = Cli::command();
            let bin_name = cmd.get_name().to_string();
            generate(shell, &mut cmd, bin_name, &mut io::stdout());
        }
        Commands::Version => {
            println!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
            println!(
                "target: {}-{}",
                std::env::consts::ARCH,
                std::env::consts::OS
            );
        }
    }
}

const STARTER_CONFIG: &str = r#"# Soroban Guard project defaults.
# CLI flags override values from this file.

[scan]
# Fail the scan when findings at or above this severity are present.
# Allowed values: "high", "medium", "low".
min_severity = "high"

[checks]
# Check names to skip entirely, as shown by `soroban-guard list-checks`.
disabled = []

[checks.sensitive_names]
# Extra privileged function names for the unprotected-admin check.
extra = []
"#;

/// Returns (slice to display, count of truncated findings).
fn truncate(findings: &[Finding], max: usize) -> (&[Finding], usize) {
    if max == 0 || findings.len() <= max {
        (findings, 0)
    } else {
        (&findings[..max], findings.len() - max)
    }
}

fn build_sarif(findings: &[Finding], files_skipped: usize) -> serde_json::Value {
    // Collect the highest severity observed for each check name so that
    // defaultConfiguration.level reflects the worst-case rule level rather than
    // whichever finding happens to appear first in the slice.
    let mut rule_severity: std::collections::BTreeMap<&str, Severity> =
        std::collections::BTreeMap::new();
    for finding in findings {
        let entry = rule_severity
            .entry(finding.check_name.as_str())
            .or_insert(finding.severity);
        if finding.severity < *entry {
            // Severity::High < Medium < Low (rank 0 < 1 < 2), so a smaller
            // rank means higher severity — keep the most severe.
            *entry = finding.severity;
        }
    }
    let rules: Vec<serde_json::Value> = rule_severity
        .iter()
        .map(|(name, &sev)| {
            serde_json::json!({
                "id": name,
                "shortDescription": { "text": describe_rule(name) },
                "fullDescription": { "text": describe_rule(name) },
                "defaultConfiguration": { "level": severity_to_sarif_level(sev) },
                "helpUri": "https://github.com/SorobanGuard/Guard-CLI"
            })
        })
        .collect();
    let results = findings
        .iter()
        .map(|finding| {
            serde_json::json!({
                "ruleId": finding.check_name,
                "level": severity_to_sarif_level(finding.severity),
                "message": { "text": finding.description },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": finding.file_path },
                        "region": { "startLine": finding.line }
                    }
                }]
            })
        })
        .collect::<Vec<_>>();

    serde_json::json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "soroban-guard",
                    "informationUri": "https://github.com/SorobanGuard/Guard-CLI",
                    "rules": rules,
                    "version": env!("CARGO_PKG_VERSION"),
                    "semanticVersion": env!("CARGO_PKG_VERSION")
                }
            },
            "invocations": [{
                "executionSuccessful": true,
                "properties": {
                    "files_skipped": files_skipped
                }
            }],
            "results": results
        }]
    })
}

fn severity_to_sarif_level(severity: Severity) -> &'static str {
    match severity {
        Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low => "note",
    }
}

/// Static metadata for a single built-in check.
struct CheckMeta {
    /// `list-checks` name.
    name: &'static str,
    /// Severity string as surfaced by `list-checks` / `explain` (`"high" | "medium" | "low"`).
    severity: &'static str,
    /// One-line summary for `list-checks` / `explain` (`describe_check`).
    short: &'static str,
    /// One-line rule description for SARIF output (`describe_rule`).
    rule: &'static str,
    /// Long-form explanation for `explain` (`explain_details`); `None` falls back to a
    /// generic string.
    long: Option<&'static str>,
}

/// Single source of truth for check metadata read by `describe_check`, `describe_rule`,
/// and `explain_details`. Keep in sync with `default_checks()` (enforced by the
/// `check_metadata_covers_all_default_checks` test).
const CHECK_METADATA: &[CheckMeta] = &[
    CheckMeta {
        name: "missing-require-auth",
        severity: "high",
        short: "Missing env.require_auth() before storage writes",
        rule: "Method writes to storage without env.require_auth()",
        long: Some("Reports contract methods that mutate storage without calling require_auth or require_auth_for_args."),
    },
    CheckMeta {
        name: "unchecked-arithmetic",
        severity: "high",
        short: "Flags unchecked arithmetic on contract state (High / Medium / Low per operand)",
        rule: "Wrapping arithmetic operations may overflow",
        long: Some("Reports wrapping +, -, *, and compound arithmetic in contract methods; prefer checked_* or saturating_* APIs. Severity is computed per call site: High for financial-named operands (e.g. amount, balance, price), Low for index-named operands, Medium otherwise."),
    },
    CheckMeta {
        name: "unprotected-admin",
        severity: "high",
        short: "Flags privileged entrypoints without auth",
        rule: "Sensitive admin entrypoints lack an authorization gate",
        long: Some("Reports public admin-like entrypoints such as set_owner, pause, migrate, or upgrade when they lack an auth gate."),
    },
    CheckMeta {
        name: "unsafe-storage-patterns",
        severity: "medium",
        short: "Flags temporary storage and dynamic Symbol keys",
        rule: "Temporary storage or dynamic Symbol keys are risky",
        long: Some("Reports temporary storage mutations and dynamic Symbol keys that may expire unexpectedly or collide."),
    },
    CheckMeta {
        name: "missing-ttl-extension",
        severity: "low",
        short: "Flags persistent storage entries without TTL extension",
        rule: "Persistent entries may expire without TTL bump",
        long: Some("Reports persistent storage writes that do not extend TTL in the same function."),
    },
    CheckMeta {
        name: "forbidden-std-imports",
        severity: "high",
        short: "Flags use of std in no_std Soroban contracts",
        rule: "Crate imports std which is forbidden in no_std contracts",
        long: Some("Reports std imports in Soroban contract files because deployable contracts must compile for no_std WASM."),
    },
    CheckMeta {
        name: "hardcoded-address",
        severity: "medium",
        short: "Flags hardcoded Stellar address literals",
        rule: "Contract contains a hardcoded Stellar address string",
        long: Some("Reports Stellar public-key-shaped string literals embedded directly in source."),
    },
    CheckMeta {
        name: "unsafe-cross-contract-input",
        severity: "high",
        short: "Flags unvalidated return values from cross-contract calls",
        rule: "Cross-contract call return value used without validation",
        long: Some("Reports invoke_contract return values stored directly without local validation."),
    },
    CheckMeta {
        name: "missing-contract-annotation",
        severity: "low",
        short: "Flags structs missing the #[contract] attribute",
        rule: "Struct missing #[contract] annotation",
        long: Some("Reports contractimpl blocks without a sibling struct annotated with #[contract]."),
    },
    CheckMeta {
        name: "delegate-call-risk",
        severity: "high",
        short: "Flags delegate-call patterns that transfer execution control",
        rule: "Delegate-style call pattern can transfer control unexpectedly",
        long: Some("Reports storage-derived cross-contract callees that can redirect execution if storage is poisoned."),
    },
    CheckMeta {
        name: "integer-division-truncation",
        severity: "medium",
        short: "Flags integer division that silently truncates",
        rule: "Integer division silently truncates the remainder",
        long: Some("Reports integer division where truncation may silently change financial or accounting results."),
    },
    CheckMeta {
        name: "missing-event-emission",
        severity: "medium",
        short: "Flags state-mutating functions with no event emission",
        rule: "State-mutating function emits no events",
        long: Some("Reports state-mutating functions that do not publish events for off-chain indexers."),
    },
    CheckMeta {
        name: "symbol-key-collision",
        severity: "medium",
        short: "Flags storage keys that share the same Symbol value",
        rule: "Multiple storage keys share the same Symbol value",
        long: Some("Reports duplicate symbol_short! keys in the same impl block."),
    },
    CheckMeta {
        name: "self-transfer",
        severity: "medium",
        short: "Flags token transfers where sender may equal receiver",
        rule: "Token transfer destination may equal the sender",
        long: Some("Reports transfer-like functions that do not guard against sender and recipient being equal."),
    },
    CheckMeta {
        name: "missing-zero-address-check",
        severity: "medium",
        short: "Flags Address parameters not checked for the zero address",
        rule: "Address argument not validated against the zero address",
        long: Some("Reports Address parameters stored or used without checking for default or zero-address values."),
    },
    CheckMeta {
        name: "mutable-global-state",
        severity: "high",
        short: "Flags mutable global state in contract code",
        rule: "Mutable global state is unsafe and not persisted on-chain",
        long: Some("Reports static mut items, which are unsafe and not valid persistent contract state."),
    },
    CheckMeta {
        name: "re-initialization-risk",
        severity: "high",
        short: "Flags initializer-like functions without re-init guards",
        rule: "Initializer-like function can overwrite critical state",
        long: Some("Reports initializer-like methods that write state without checking whether initialization already happened."),
    },
    CheckMeta {
        name: "unchecked-invoke-return",
        severity: "medium",
        short: "Flags discarded cross-contract call return values",
        rule: "Cross-contract invocation result is discarded",
        long: Some("Reports bare invoke_contract statements whose return values are discarded."),
    },
    CheckMeta {
        name: "missing-balance-check",
        severity: "high",
        short: "Flags token transfers without balance or authorization checks",
        rule: "Token transfer occurs without a balance or authorization check",
        long: Some("Reports token transfer calls that lack a preceding balance or authorization check."),
    },
    CheckMeta {
        name: "unbounded-vec-growth",
        severity: "medium",
        short: "Flags storage-backed Vec growth without a length cap",
        rule: "Storage-backed Vec can grow without a bound",
        long: Some("Reports storage-backed Vec values pushed and written back without an apparent length cap."),
    },
    CheckMeta {
        name: "unsafe-randomness",
        severity: "high",
        short: "Flags ledger timestamp or sequence as randomness",
        rule: "Ledger data is used as a randomness source",
        long: Some("Reports ledger timestamp or sequence usage as a randomness source."),
    },
    CheckMeta {
        name: "unchecked-divisor",
        severity: "high",
        short: "Flags division by runtime values without zero guards",
        rule: "Division uses a runtime divisor without a zero guard",
        long: Some("Reports division by runtime values without an apparent non-zero guard."),
    },
    CheckMeta {
        name: "reentrancy-risk",
        severity: "high",
        short: "Flags storage writes followed by cross-contract calls",
        rule: "Storage write followed by cross-contract invocation risks reentrancy",
        long: Some("Reports contract methods that write to storage and then perform a cross-contract invocation, leaving state observable to a reentrant callee."),
    },
    CheckMeta {
        name: "panic-in-contract",
        severity: "medium",
        short: "Flags panic!, unwrap, and expect in contract methods",
        rule: "Contract uses panic!, unwrap, or expect which abort the WASM execution",
        long: Some("Reports panic!, unwrap(), expect(), and unreachable!() in contract methods, all of which trap and abort WASM execution."),
    },
    CheckMeta {
        name: "unprotected-upgrade",
        severity: "high",
        short: "Flags upgrade entrypoints without authorization",
        rule: "Contract upgrade entrypoint lacks an authorization gate",
        long: Some("Reports contract upgrade entrypoints that swap the contract WASM without an authorization gate."),
    },
    CheckMeta {
        name: "unprotected-token-mint",
        severity: "high",
        short: "Flags token mint entrypoints without authorization",
        rule: "Token mint entrypoint lacks an authorization gate",
        long: Some("Reports token mint entrypoints that create new supply without an authorization gate."),
    },
    CheckMeta {
        name: "unprotected-contract-deployment",
        severity: "high",
        short: "Flags contract deployment calls without authorization",
        rule: "Contract deployment call lacks an authorization gate",
        long: Some("Reports contract deployment calls that are reachable without an authorization gate."),
    },
    CheckMeta {
        name: "unchecked-token-amount",
        severity: "medium",
        short: "Flags token amounts used without validation",
        rule: "Token amount used without validation",
        long: Some("Reports token amount parameters passed to transfers or mints without a positivity or bounds check."),
    },
    CheckMeta {
        name: "large-loop",
        severity: "medium",
        short: "Flags loops over unbounded collections",
        rule: "Loop may iterate over an unbounded collection",
        long: Some("Reports loops that iterate over collections whose length is not bounded by a constant or validated input."),
    },
    CheckMeta {
        name: "missing-nonce",
        severity: "medium",
        short: "Flags functions susceptible to replay attacks",
        rule: "Function susceptible to replay attacks lacks a nonce check",
        long: Some("Reports replay-sensitive entrypoints that do not consume or verify a nonce."),
    },
    CheckMeta {
        name: "uninitialized-storage-read",
        severity: "high",
        short: "Flags storage reads without initialization checks",
        rule: "Storage value read without checking if it has been initialized",
        long: Some("Reports storage reads that are not guarded by a has() check or a default value."),
    },
    CheckMeta {
        name: "missing-event-for-admin-change",
        severity: "medium",
        short: "Flags admin changes with no event emission",
        rule: "Admin-state change emits no event for off-chain indexers",
        long: Some("Reports functions that change admin or ownership state without publishing an event for off-chain indexers."),
    },
    CheckMeta {
        name: "missing-input-length-bound",
        severity: "medium",
        short: "Flags input collections without length bound checks",
        rule: "Input collection used without a length bound check",
        long: Some("Reports input collection parameters used without checking their length against an upper bound."),
    },
    CheckMeta {
        name: "auth-after-storage-write",
        severity: "high",
        short: "Flags authorization checks after storage writes",
        rule: "Authorization check occurs after a storage write",
        long: Some("Reports functions that perform a storage write before their require_auth call, so unauthorized callers can still cause state changes."),
    },
];

fn check_meta(name: &str) -> Option<&'static CheckMeta> {
    CHECK_METADATA.iter().find(|m| m.name == name)
}

fn explain_details(name: &str) -> &'static str {
    check_meta(name)
        .and_then(|m| m.long)
        .unwrap_or("No detailed explanation is available for this custom check.")
}

fn describe_rule(name: &str) -> &'static str {
    check_meta(name).map(|m| m.rule).unwrap_or("Custom check")
}

fn describe_check(name: &str) -> (&'static str, &'static str) {
    check_meta(name)
        .map(|m| (m.severity, m.short))
        .unwrap_or(("low", "Custom detector"))
}

fn list_checks_json() -> Result<String, serde_json::Error> {
    let checks = default_checks()
        .into_iter()
        .map(|check| {
            let (severity, description) = describe_check(check.name());
            serde_json::json!({
                "name": check.name(),
                "severity": severity,
                "description": description,
                "rule": describe_rule(check.name()),
            })
        })
        .collect::<Vec<_>>();
    serde_json::to_string_pretty(&serde_json::json!({ "checks": checks }))
}

fn write_output(path: &Path, payload: &str) -> Result<(), std::io::Error> {
    // Match the println! convention used for stdout: append a trailing newline
    // so file contents are byte-for-byte identical to what would be printed.
    fs::write(path, format!("{payload}\n"))
}

/// Count findings bucketed by severity, returned as `(high, medium, low)`.
///
/// Single source of truth for the High / Medium / Low histogram shared by
/// `json_payload`, `render_markdown`, and `summary_text`.
fn severity_counts(findings: &[Finding]) -> (usize, usize, usize) {
    let mut high = 0;
    let mut medium = 0;
    let mut low = 0;
    for f in findings {
        match f.severity {
            Severity::High => high += 1,
            Severity::Medium => medium += 1,
            Severity::Low => low += 1,
        }
    }
    (high, medium, low)
}

fn json_payload(
    findings: &[Finding],
    files_scanned: usize,
    files_skipped: usize,
) -> Result<String, serde_json::Error> {
    let (high, medium, low) = severity_counts(findings);

    let envelope = serde_json::json!({
        "tool": {
            "name": "soroban-guard",
            "version": env!("CARGO_PKG_VERSION")
        },
        "schema_version": 1,
        "summary": {
            "total": findings.len(),
            "high": high,
            "medium": medium,
            "low": low,
            "files_scanned": files_scanned,
            "files_skipped": files_skipped
        },
        "findings": findings
    });

    serde_json::to_string_pretty(&envelope)
}

fn render_markdown(findings: &[Finding]) -> String {
    let mut out = String::new();
    out.push_str("## Soroban Guard Findings\n\n");
    if findings.is_empty() {
        out.push_str("No issues found.\n");
        return out;
    }
    out.push_str("| # | Severity | File | Line | Check | Function | Description | Suggestion |\n");
    out.push_str("|---|----------|------|------|-------|----------|-------------|------------|\n");
    for (i, f) in findings.iter().enumerate() {
        let sev = match f.severity {
            Severity::High => "**HIGH**",
            Severity::Medium => "MEDIUM",
            Severity::Low => "LOW",
        };
        // Link the check name to rule_url when available, else plain text.
        let check_cell = if let Some(ref url) = f.rule_url {
            format!("[{}]({})", escape_md_cell(&f.check_name), url)
        } else {
            escape_md_cell(&f.check_name)
        };
        let description_cell = escape_md_cell(&f.description);
        let suggestion_cell = f
            .suggestion
            .as_deref()
            .map(escape_md_cell)
            .unwrap_or_default();
        out.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} | {} |\n",
            i + 1,
            sev,
            escape_md_cell(&f.file_path),
            f.line,
            check_cell,
            escape_md_cell(&f.function_name),
            description_cell,
            suggestion_cell,
        ));
    }
    let (high, medium, low) = severity_counts(findings);
    out.push_str(&format!(
        "\n**{} finding(s): {} High, {} Medium, {} Low**\n",
        findings.len(),
        high,
        medium,
        low
    ));
    out
}

/// Escape `|` and newlines so interpolated values cannot break the Markdown table.
fn escape_md_cell(s: &str) -> String {
    s.replace('|', "\\|").replace('\n', " ").replace('\r', "")
}

fn summary_text(findings: &[Finding], files_scanned: usize) -> String {
    let (high, medium, low) = severity_counts(findings);
    format!("{high} High, {medium} Medium, {low} Low — across {files_scanned} file(s)")
}

/// Returns true if OSC 8 hyperlinks should be emitted (color is on).
fn use_hyperlinks() -> bool {
    std::env::var("NO_COLOR").is_err() && colored::control::SHOULD_COLORIZE.should_colorize()
}

/// Wrap `text` in an OSC 8 hyperlink for `url` when hyperlinks are enabled.
fn hyperlink(url: &str, text: &str) -> String {
    if use_hyperlinks() {
        format!("\x1b]8;;{}\x1b\\{}\x1b]8;;\x1b\\", url, text)
    } else {
        text.to_string()
    }
}

fn style_check_name(check_name: &str, severity: Severity) -> String {
    match severity {
        Severity::High => check_name.red().bold().to_string(),
        Severity::Medium => check_name.magenta().to_string(),
        Severity::Low => check_name.dimmed().to_string(),
    }
}

fn print_pretty(
    findings: &[Finding],
    display: &[Finding],
    files_scanned: usize,
    root_label: String,
    truncated_count: usize,
) {
    println!();
    println!(
        "{} {}",
        "Soroban Guard Core".cyan().bold(),
        format!("(scan: {})", root_label).dimmed()
    );
    println!();

    if display.is_empty() && truncated_count == 0 {
        println!("  {}", "No issues found.".green());
        println!();
    } else {
        let total = display.len() + truncated_count;
        println!("  {} finding(s):\n", total.to_string().yellow().bold());

        for (i, f) in display.iter().enumerate() {
            let sev = match f.severity {
                Severity::High => "HIGH".red().bold(),
                Severity::Medium => "MEDIUM".magenta().bold(),
                Severity::Low => "LOW".white(),
            };
            let check = style_check_name(&f.check_name, f.severity);
            println!(
                "  {}  {}  {}  {}",
                format!("[{}]", i + 1).dimmed(),
                sev,
                format!("{}:{}", f.file_path, f.line).bright_white(),
                check
            );
            println!("         {} `{}`", "function:".dimmed(), f.function_name);
            println!("         {}", f.description);
            if let Some(suggestion) = &f.suggestion {
                println!("         {} {}", "suggestion:".dimmed(), suggestion);
            }
            if let Some(url) = &f.rule_url {
                let link = hyperlink(url, url.as_str());
                println!("         {} {}", "docs:".dimmed(), link);
            }
            println!();
        }

        if truncated_count > 0 {
            println!(
                "  {}",
                format!(
                    "... (truncated — {} more finding(s) not shown, use --max-findings 0 for all)",
                    truncated_count
                )
                .yellow()
            );
            println!();
        }
    }

    println!("  {}", summary_text(findings, files_scanned));
    println!();
}

#[cfg(test)]
mod tests {
    use super::*;
    use colored::control;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn sample_finding(check_name: &str, severity: Severity, line: usize) -> Finding {
        Finding {
            check_name: check_name.to_string(),
            severity,
            file_path: "src/lib.rs".to_string(),
            line,
            function_name: "f".to_string(),
            description: "desc".to_string(),
            rule_url: None,
            suggestion: None,
        }
    }

    #[test]
    fn sarif_payload_has_expected_schema_and_result() {
        let findings = vec![Finding {
            check_name: "missing-require-auth".to_string(),
            severity: Severity::High,
            file_path: "src/lib.rs".to_string(),
            line: 10,
            function_name: "set_balance".to_string(),
            description: "Missing auth".to_string(),
            rule_url: None,
            suggestion: None,
        }];

        let payload = build_sarif(&findings, 0);
        assert_eq!(payload["version"], "2.1.0");
        assert_eq!(
            payload["runs"][0]["tool"]["driver"]["name"],
            "soroban-guard"
        );
        assert_eq!(
            payload["runs"][0]["tool"]["driver"]["version"],
            env!("CARGO_PKG_VERSION")
        );
        assert_eq!(
            payload["runs"][0]["tool"]["driver"]["semanticVersion"],
            env!("CARGO_PKG_VERSION")
        );
        assert_eq!(
            payload["runs"][0]["results"][0]["ruleId"],
            "missing-require-auth"
        );
    }

    #[test]
    fn json_payload_includes_rule_url() {
        let rule_url =
            "https://github.com/SorobanGuard/Guard-CLI/blob/main/docs/checks.md#missing-require-auth-high";
        let findings = vec![Finding {
            check_name: "missing-require-auth".to_string(),
            severity: Severity::High,
            file_path: "src/lib.rs".to_string(),
            line: 10,
            function_name: "set_balance".to_string(),
            description: "Missing auth".to_string(),
            rule_url: Some(rule_url.to_string()),
            suggestion: None,
        }];

        let payload: serde_json::Value =
            serde_json::from_str(&json_payload(&findings, 1, 0).unwrap()).unwrap();
        assert_eq!(payload["findings"][0]["rule_url"], rule_url);
    }

    #[test]
    fn json_payload_includes_summary_keys() {
        let findings = vec![
            Finding {
                check_name: "missing-require-auth".to_string(),
                severity: Severity::High,
                file_path: "src/lib.rs".to_string(),
                line: 10,
                function_name: "set_balance".to_string(),
                description: "Missing auth".to_string(),
                rule_url: None,
                suggestion: None,
            },
            Finding {
                check_name: "unchecked-arithmetic".to_string(),
                severity: Severity::Medium,
                file_path: "src/lib.rs".to_string(),
                line: 20,
                function_name: "update".to_string(),
                description: "Unchecked arithmetic".to_string(),
                rule_url: None,
                suggestion: None,
            },
        ];

        let payload: serde_json::Value =
            serde_json::from_str(&json_payload(&findings, 3, 2).unwrap()).unwrap();
        assert_eq!(payload["summary"]["total"], 2);
        assert_eq!(payload["summary"]["high"], 1);
        assert_eq!(payload["summary"]["medium"], 1);
        assert_eq!(payload["summary"]["low"], 0);
        assert_eq!(payload["summary"]["files_scanned"], 3);
        assert_eq!(payload["summary"]["files_skipped"], 2);
    }

    #[test]
    fn json_payload_includes_tool_metadata_and_schema_version() {
        let findings = vec![Finding {
            check_name: "missing-require-auth".to_string(),
            severity: Severity::High,
            file_path: "src/lib.rs".to_string(),
            line: 10,
            function_name: "set_balance".to_string(),
            description: "Missing auth".to_string(),
            rule_url: None,
            suggestion: None,
        }];

        let payload: serde_json::Value =
            serde_json::from_str(&json_payload(&findings, 1, 0).unwrap()).unwrap();
        assert_eq!(payload["tool"]["name"], "soroban-guard");
        assert_eq!(payload["tool"]["version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(payload["schema_version"], 1);
    }

    #[test]
    fn writes_payload_to_file() {
        let path = std::env::temp_dir().join(format!(
            "soroban-guard-test-{}-{}.json",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        write_output(&path, "{\"ok\":true}").unwrap();
        assert!(path.exists());
        let contents = fs::read_to_string(&path).unwrap();
        assert!(contents.contains("ok"));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn sarif_written_to_file_when_output_provided() {
        let findings = vec![Finding {
            check_name: "missing-require-auth".to_string(),
            severity: Severity::High,
            file_path: "src/lib.rs".to_string(),
            line: 10,
            function_name: "set_balance".to_string(),
            description: "Missing auth".to_string(),
            rule_url: None,
            suggestion: None,
        }];

        let path = std::env::temp_dir().join(format!(
            "soroban-guard-sarif-{}-{}.sarif",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let payload = serde_json::to_string_pretty(&build_sarif(&findings, 1)).unwrap();
        write_output(&path, &payload).unwrap();
        assert!(path.exists());
        let contents = fs::read_to_string(&path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&contents).unwrap();
        assert_eq!(parsed["version"], "2.1.0");
        assert_eq!(
            parsed["runs"][0]["invocations"][0]["properties"]["files_skipped"],
            1
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn markdown_written_to_file_when_output_provided() {
        let rule_url = "https://github.com/SorobanGuard/Guard-CLI/blob/main/docs/checks.md#missing-require-auth-high";
        let findings = vec![
            Finding {
                check_name: "missing-require-auth".to_string(),
                severity: Severity::High,
                file_path: "src/lib.rs".to_string(),
                line: 10,
                function_name: "set_balance".to_string(),
                description: "Missing require_auth".to_string(),
                rule_url: Some(rule_url.to_string()),
                suggestion: Some("Add env.require_auth();".to_string()),
            },
            Finding {
                check_name: "unchecked-arithmetic".to_string(),
                severity: Severity::Medium,
                file_path: "src/lib.rs".to_string(),
                line: 20,
                function_name: "update".to_string(),
                description: "Unchecked arithmetic".to_string(),
                rule_url: None,
                suggestion: None,
            },
        ];

        let path = std::env::temp_dir().join(format!(
            "soroban-guard-markdown-{}-{}.md",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));

        // render_markdown produces the correct Markdown table
        let payload = render_markdown(&findings);

        // Write to file via write_output (the same helper used by --json and --sarif)
        write_output(&path, &payload).unwrap();

        assert!(path.exists(), "output file should have been created");

        let contents = fs::read_to_string(&path).unwrap();

        // Structural checks on the rendered Markdown
        assert!(
            contents.contains("## Soroban Guard Findings"),
            "should contain the heading"
        );
        assert!(
            contents.contains("**HIGH**"),
            "High severity should be bold in Markdown"
        );
        // Check name linked to rule_url when present
        assert!(
            contents.contains(&format!("[missing-require-auth]({})", rule_url)),
            "check name should be linked to rule_url"
        );
        assert!(
            contents.contains("unchecked-arithmetic"),
            "should contain the second check name"
        );
        // New Description column
        assert!(
            contents.contains("Missing require_auth"),
            "should contain the description"
        );
        // New Suggestion column
        assert!(
            contents.contains("Add env.require_auth();"),
            "should contain the suggestion"
        );
        // Column headers
        assert!(
            contents.contains("Description"),
            "should have a Description column header"
        );
        assert!(
            contents.contains("Suggestion"),
            "should have a Suggestion column header"
        );
        assert!(
            contents.contains("2 finding(s): 1 High, 1 Medium, 0 Low"),
            "should contain the summary line"
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn summary_includes_severity_counts_and_files_scanned() {
        let findings = vec![
            Finding {
                check_name: "high-check".to_string(),
                severity: Severity::High,
                file_path: "src/lib.rs".to_string(),
                line: 1,
                function_name: "high".to_string(),
                description: "High finding".to_string(),
                rule_url: None,
                suggestion: None,
            },
            Finding {
                check_name: "medium-check".to_string(),
                severity: Severity::Medium,
                file_path: "src/lib.rs".to_string(),
                line: 2,
                function_name: "medium".to_string(),
                description: "Medium finding".to_string(),
                rule_url: None,
                suggestion: None,
            },
        ];

        assert_eq!(
            summary_text(&findings, 6),
            "1 High, 1 Medium, 0 Low — across 6 file(s)"
        );
    }

    #[test]
    fn truncate_limits_display_when_max_is_smaller_than_findings() {
        let findings = vec![
            sample_finding("check-a", Severity::High, 1),
            sample_finding("check-b", Severity::Medium, 2),
            sample_finding("check-c", Severity::Low, 3),
        ];

        let (display, truncated) = truncate(&findings, 2);
        assert_eq!(display.len(), 2, "only max findings should be displayed");
        assert_eq!(truncated, 1, "the rest should be reported as truncated");
        assert_eq!(display[0].check_name, "check-a");
        assert_eq!(display[1].check_name, "check-b");
    }

    #[test]
    fn truncate_zero_returns_all_findings_untouched() {
        let findings = vec![
            sample_finding("check-a", Severity::High, 1),
            sample_finding("check-b", Severity::Medium, 2),
        ];

        let (display, truncated) = truncate(&findings, 0);
        assert_eq!(display.len(), 2, "max 0 must not truncate");
        assert_eq!(truncated, 0);
        assert!(
            std::ptr::eq(display, &findings[..]),
            "max 0 should return the full slice"
        );
    }

    #[test]
    fn truncate_is_a_no_op_when_findings_fit_within_max() {
        let findings = vec![sample_finding("check-a", Severity::High, 1)];

        let (display, truncated) = truncate(&findings, 5);
        assert_eq!(display.len(), 1);
        assert_eq!(truncated, 0);
    }

    #[test]
    fn summary_line_counts_full_result_set_after_truncation() {
        let findings = vec![
            sample_finding("check-a", Severity::High, 1),
            sample_finding("check-b", Severity::Medium, 2),
            sample_finding("check-c", Severity::Low, 3),
        ];

        let (display, truncated) = truncate(&findings, 2);
        assert_eq!(display.len(), 2);
        assert_eq!(truncated, 1);
        // The summary must be computed over the complete findings list, not the
        // truncated slice shown to the user (Issue #414).
        assert_eq!(
            summary_text(&findings, 4),
            "1 High, 1 Medium, 1 Low — across 4 file(s)"
        );
    }

    #[test]
    fn check_name_styling_is_bold_for_high_and_dimmed_for_low() {
        control::set_override(true);
        let high = style_check_name("high-check", Severity::High);
        let low = style_check_name("low-check", Severity::Low);

        assert!(
            high.contains("\u{1b}[1;31m"),
            "high check name should be bold red"
        );
        assert!(
            low.contains("\u{1b}[2;37m"),
            "low check name should be dimmed white"
        );
    }

    #[test]
    fn describe_check_covers_all_default_checks() {
        for check in default_checks() {
            let (sev, desc) = describe_check(check.name());
            assert!(
                matches!(sev, "high" | "medium" | "low"),
                "check {} has invalid severity metadata",
                check.name()
            );
            assert_ne!(
                desc,
                "Custom detector",
                "check {} has fallback description",
                check.name()
            );
        }
    }

    #[test]
    fn describe_rule_covers_all_default_checks() {
        for check in default_checks() {
            let desc = describe_rule(check.name());
            assert_ne!(
                desc,
                "Custom check",
                "check {} has fallback rule description",
                check.name()
            );
        }
    }

    /// Every `default_checks()` entry must have a real `CHECK_METADATA` row: a valid
    /// severity, a non-fallback `short`, a non-fallback `rule`, and a non-fallback `long`.
    /// This is the single-source-of-truth guarantee for `describe_check`, `describe_rule`,
    /// and `explain_details` (issue #526).
    #[test]
    fn check_metadata_covers_all_default_checks() {
        for check in default_checks() {
            let name = check.name();
            let (sev, short) = describe_check(name);
            assert!(
                matches!(sev, "high" | "medium" | "low"),
                "check {name} has invalid severity metadata"
            );
            assert_ne!(
                short, "Custom detector",
                "check {name} has fallback short description"
            );
            assert_ne!(
                describe_rule(name),
                "Custom check",
                "check {name} has fallback rule description"
            );
            assert_ne!(
                explain_details(name),
                "No detailed explanation is available for this custom check.",
                "check {name} has fallback long description"
            );
        }
    }

    /// `describe_check`'s severity must match the severity `docs/checks.md` documents
    /// for the same check (the `## \`name\` (Severity)` header). This is the drift that
    /// let `uninitialized-storage-read` report `medium` while the check emits `High`.
    #[test]
    fn describe_check_severity_matches_docs() {
        let docs =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/checks.md"))
                .expect("docs/checks.md should be readable from the workspace");

        let mut documented: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();
        for line in docs.lines() {
            let Some(rest) = line.strip_prefix("## `") else {
                continue;
            };
            let Some((name, tail)) = rest.split_once('`') else {
                continue;
            };
            let Some(sev) = tail
                .trim()
                .strip_prefix('(')
                .and_then(|s| s.strip_suffix(')'))
            else {
                continue;
            };
            documented.insert(name.to_string(), sev.to_ascii_lowercase());
        }

        for check in default_checks() {
            let name = check.name();
            // unchecked-arithmetic uses per-call-site severity inference (High/Medium/Low)
            // so it is intentionally skipped from the docs-header comparison below — the
            // docs page documents all three levels and there is no single canonical value.
            // CHECK_METADATA.severity is set to "high" (the worst-case level) so that
            // list-checks --json and explain report the most safety-conservative answer.
            if name == "unchecked-arithmetic" {
                let (table_sev, _) = describe_check(name);
                assert_eq!(
                    table_sev, "high",
                    "unchecked-arithmetic CHECK_METADATA.severity should be \"high\" (worst-case)"
                );
                continue;
            }
            let Some(doc_sev) = documented.get(name) else {
                continue;
            };
            let (table_sev, _) = describe_check(name);
            assert_eq!(
                table_sev, doc_sev,
                "describe_check says `{table_sev}` for `{name}` but docs/checks.md says `{doc_sev}`"
            );
        }
    }

    /// `--quiet` is gated on the `--fail-on` threshold, not on High severity:
    /// `--quiet --fail-on low` must still print output when only a Low finding exists.
    #[test]
    fn quiet_still_prints_when_low_finding_meets_fail_on_low() {
        let findings = [sample_finding("some-check", Severity::Low, 1)];
        let fail_threshold = Severity::Low;
        let should_fail = findings.iter().any(|f| f.severity <= fail_threshold);

        assert!(should_fail, "a Low finding must trip --fail-on low");
        assert!(
            should_print_results(true, should_fail),
            "--quiet must not suppress output once the --fail-on threshold is met"
        );
        // And it does stay silent when nothing meets the (default High) threshold.
        let passing = [sample_finding("some-check", Severity::Low, 1)];
        let passes_high = passing.iter().any(|f| f.severity <= Severity::High);
        assert!(!should_print_results(true, passes_high));
    }

    // ── parse_fail_on ────────────────────────────────────────────────────────

    #[test]
    fn parse_fail_on_accepts_known_values() {
        assert_eq!(parse_fail_on("high"), Ok(Severity::High));
        assert_eq!(parse_fail_on("medium"), Ok(Severity::Medium));
        assert_eq!(parse_fail_on("low"), Ok(Severity::Low));
    }

    #[test]
    fn parse_fail_on_is_case_insensitive() {
        assert_eq!(parse_fail_on("HIGH"), Ok(Severity::High));
        assert_eq!(parse_fail_on("Medium"), Ok(Severity::Medium));
        assert_eq!(parse_fail_on("LOW"), Ok(Severity::Low));
    }

    #[test]
    fn parse_fail_on_rejects_unknown_string() {
        assert!(parse_fail_on("medim").is_err(), "typo should be rejected");
        assert!(parse_fail_on("none").is_err(), "'none' should be rejected");
        assert!(
            parse_fail_on("critical").is_err(),
            "'critical' should be rejected"
        );
        assert!(
            parse_fail_on("").is_err(),
            "empty string should be rejected"
        );
    }

    // ── CLI integration: bad --fail-on exits 2 ───────────────────────────────

    #[test]
    fn bad_fail_on_flag_exits_2() {
        // Build the binary path relative to the workspace root.
        let mut bin = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        bin.push("../../target/debug/soroban-guard");

        // If the binary hasn't been built yet, skip rather than panic.
        if !bin.exists() {
            eprintln!(
                "note: skipping bad_fail_on_flag_exits_2 — binary not found at {}",
                bin.display()
            );
            return;
        }

        let output = std::process::Command::new(&bin)
            .args(["scan", ".", "--fail-on", "medim"])
            .output()
            .expect("failed to run soroban-guard binary");

        assert_eq!(
            output.status.code(),
            Some(2),
            "bad --fail-on value should exit 2, stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("unknown --fail-on value"),
            "stderr should contain 'unknown --fail-on value', got: {stderr}"
        );
    }
}
