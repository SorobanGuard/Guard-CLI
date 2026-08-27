mod config;

use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::{generate, Shell};
use colored::Colorize;
use notify::{Event, EventKind, RecursiveMode, Watcher};
use soroban_guard_analyzer::scan_directory_with_checks;
use soroban_guard_checks::{default_checks, default_checks_with_config, Finding, Severity};
use std::collections::HashSet;
use std::fs;
use std::io;
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
        /// Suppress all output when there are zero findings at or above the configured threshold
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
        #[arg(long, default_value = "high")]
        fail_on: String,
        /// Disable a named check (may be repeated)
        #[arg(long, value_name = "CHECK")]
        disable_check: Vec<String>,
        /// Watch for .rs file changes and re-run the scan automatically
        #[arg(long, short = 'w')]
        watch: bool,
    },
    /// List the checks that are enabled by default
    ListChecks,
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
}

/// Run a single scan and print its results.
/// Returns the exit code that would normally be passed to `std::process::exit`
/// (0 = pass, 1 = findings above threshold, 2 = I/O error).
fn run_scan(
    opts: &ScanOptions,
    active_checks: &[Box<dyn soroban_guard_checks::Check + Send + Sync>],
) -> i32 {
    match scan_directory_with_checks(&opts.path, &opts.exclude, &opts.includes, active_checks) {
        Ok((results, files_scanned, files_skipped)) => {
            let findings: Vec<Finding> =
                results.into_iter().flat_map(|r| r.findings).collect();
            let should_fail = findings
                .iter()
                .any(|f| f.severity <= opts.fail_threshold);

            if opts.json {
                if !opts.quiet || should_fail {
                    match json_payload(&findings, files_scanned) {
                        Ok(payload) => {
                            if let Some(ref out_path) = opts.output {
                                if let Err(e) = write_output(out_path, &payload) {
                                    eprintln!("{} {}", "error:".red().bold(), e);
                                    return 2;
                                }
                            } else {
                                println!("{payload}");
                            }
                        }
                        Err(e) => {
                            eprintln!("{} {}", "error:".red().bold(), e);
                            return 2;
                        }
                    }
                }
            } else if opts.sarif {
                if !opts.quiet || should_fail {
                    match serde_json::to_string_pretty(&build_sarif(&findings)) {
                        Ok(payload) => {
                            if let Some(ref out_path) = opts.output {
                                if let Err(e) = write_output(out_path, &payload) {
                                    eprintln!("{} {}", "error:".red().bold(), e);
                                    return 2;
                                }
                            } else {
                                println!("{payload}");
                            }
                        }
                        Err(e) => {
                            eprintln!("{} {}", "error:".red().bold(), e);
                            return 2;
                        }
                    }
                }
            } else if opts.markdown {
                if !opts.quiet || should_fail {
                    let payload = render_markdown(&findings);
                    if let Some(ref out_path) = opts.output {
                        if let Err(e) = write_output(out_path, &payload) {
                            eprintln!("{} {}", "error:".red().bold(), e);
                            return 2;
                        }
                    } else {
                        print!("{payload}");
                    }
                }
            } else if !opts.quiet || should_fail {
                let (display, truncated) = truncate(&findings, 0);
                print_pretty(
                    display,
                    files_scanned,
                    opts.path.display().to_string(),
                    truncated,
                );
            }

            if opts.verbose {
                eprintln!("Scanned {} file(s).", files_scanned);
                if files_skipped > 0 {
                    eprintln!(
                        "Skipped {} generated file(s) from analysis.",
                        files_skipped
                    );
                }
            }

            if should_fail { 1 } else { 0 }
        }
        Err(e) => {
            if opts.json {
                let envelope = serde_json::json!({ "error": e.to_string() });
                match serde_json::to_string_pretty(&envelope) {
                    Ok(payload) => println!("{}", payload),
                    Err(json_err) => eprintln!("{} {}", "error:".red().bold(), json_err),
                }
            } else {
                eprintln!("{} {}", "error:".red().bold(), e);
            }
            2
        }
    }
}

/// Returns a UTC timestamp string like "2026-07-28 23:09:36" without any
/// external date crate.
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
        31, 30, 31, 30, 31, 31, 30, 31, 30, 31,
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
                Ok(c) => c.unwrap_or_default(),
                Err(e) => {
                    eprintln!("{} {}", "error:".red().bold(), e);
                    std::process::exit(2);
                }
            };

            // Resolve scan path: CLI argument takes precedence, then config, then error.
            let scan_path = if let Some(p) = path {
                p
            } else if let Some(config_path) = &config_for_default.scan.path {
                PathBuf::from(config_path)
            } else {
                eprintln!(
                    "{} no scan path provided and none found in soroban-guard.toml",
                    "error:".red().bold()
                );
                std::process::exit(2);
            };

            // Load soroban-guard.toml from the scan root (if present).
            let cfg = match config::load(&scan_path) {
                Ok(c) => c.unwrap_or_default(),
                Err(e) => {
                    eprintln!("{} {}", "error:".red().bold(), e);
                    std::process::exit(2);
                }
            };

            // CLI --fail-on takes precedence; fall back to config min_severity.
            let effective_fail_on = if fail_on != "high" {
                fail_on.clone()
            } else {
                cfg.scan.min_severity.clone().unwrap_or(fail_on.clone())
            };
            let fail_threshold = match effective_fail_on.to_lowercase().as_str() {
                "medium" => Severity::Medium,
                "low" => Severity::Low,
                _ => Severity::High,
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
                        eprintln!(
                            "{} unknown check `{}`. Run `soroban-guard list-checks` to see available checks.",
                            "error:".red().bold(),
                            name
                        );
                        std::process::exit(2);
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
            };

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

                let mut watcher =
                    notify::recommended_watcher(move |res| {
                        let _ = tx.send(res);
                    })
                    .unwrap_or_else(|e| {
                        eprintln!("{} failed to create file watcher: {}", "error:".red().bold(), e);
                        std::process::exit(2);
                    });

                watcher
                    .watch(&scan_path, RecursiveMode::Recursive)
                    .unwrap_or_else(|e| {
                        eprintln!("{} failed to watch path: {}", "error:".red().bold(), e);
                        std::process::exit(2);
                    });

                for res in rx {
                    match res {
                        Ok(event) => {
                            // Only react to create/modify events on .rs files.
                            let is_relevant = matches!(
                                event.kind,
                                EventKind::Create(_) | EventKind::Modify(_)
                            ) && event.paths.iter().any(|p| {
                                p.extension().map(|e| e == "rs").unwrap_or(false)
                            });

                            if is_relevant {
                                // Clear terminal for a clean view.
                                print!("\x1B[2J\x1B[1;1H");

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
                        }
                        Err(e) => {
                            eprintln!("{} watcher error: {}", "error:".red().bold(), e);
                        }
                    }
                }
            }
        }
        Commands::ListChecks => {
            for check in default_checks() {
                let (severity, description) = describe_check(check.name());
                println!("{} | {} | {}", check.name(), severity, description);
            }
            println!();
            println!("Run `soroban-guard explain <check-name>` for detailed documentation on any check.");
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
            println!("target: {}-{}", std::env::consts::ARCH, std::env::consts::OS);
        }
    }
}


/// Returns (slice to display, count of truncated findings).
fn truncate(findings: &[Finding], max: usize) -> (&[Finding], usize) {
    if max == 0 || findings.len() <= max {
        (findings, 0)
    } else {
        (&findings[..max], findings.len() - max)
    }
}

fn build_sarif(findings: &[Finding]) -> serde_json::Value {
    let mut rules = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for finding in findings {
        if seen.insert(finding.check_name.clone()) {
            rules.push(serde_json::json!({
                "id": finding.check_name,
                "shortDescription": { "text": describe_rule(&finding.check_name) },
                "fullDescription": { "text": describe_rule(&finding.check_name) },
                "defaultConfiguration": { "level": severity_to_sarif_level(finding.severity) },
                "helpUri": "https://github.com/SorobanGuard/Guard-CLI"
            }));
        }
    }
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
                    "rules": rules
                }
            },
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

fn explain_details(name: &str) -> &'static str {
    match name {
        "missing-require-auth" => {
            "Reports contract methods that mutate storage without calling require_auth or require_auth_for_args."
        }
        "unchecked-arithmetic" => {
            "Reports wrapping +, -, *, and compound arithmetic in contract methods; prefer checked_* or saturating_* APIs."
        }
        "unprotected-admin" => {
            "Reports public admin-like entrypoints such as set_owner, pause, migrate, or upgrade when they lack an auth gate."
        }
        "unsafe-storage-patterns" => {
            "Reports temporary storage mutations and dynamic Symbol keys that may expire unexpectedly or collide."
        }
        "missing-ttl-extension" => {
            "Reports persistent storage writes that do not extend TTL in the same function."
        }
        "forbidden-std-imports" => {
            "Reports std imports in Soroban contract files because deployable contracts must compile for no_std WASM."
        }
        "hardcoded-address" => {
            "Reports Stellar public-key-shaped string literals embedded directly in source."
        }
        "unsafe-cross-contract-input" => {
            "Reports invoke_contract return values stored directly without local validation."
        }
        "missing-contract-annotation" => {
            "Reports contractimpl blocks without a sibling struct annotated with #[contract]."
        }
        "delegate-call-risk" => {
            "Reports storage-derived cross-contract callees that can redirect execution if storage is poisoned."
        }
        "integer-division-truncation" => {
            "Reports integer division where truncation may silently change financial or accounting results."
        }
        "missing-event-emission" => {
            "Reports state-mutating functions that do not publish events for off-chain indexers."
        }
        "symbol-key-collision" => {
            "Reports duplicate symbol_short! keys in the same impl block."
        }
        "self-transfer" => {
            "Reports transfer-like functions that do not guard against sender and recipient being equal."
        }
        "missing-zero-address-check" => {
            "Reports Address parameters stored or used without checking for default or zero-address values."
        }
        "mutable-global-state" => {
            "Reports static mut items, which are unsafe and not valid persistent contract state."
        }
        "re-initialization-risk" => {
            "Reports initializer-like methods that write state without checking whether initialization already happened."
        }
        "unchecked-invoke-return" => {
            "Reports bare invoke_contract statements whose return values are discarded."
        }
        "missing-balance-check" => {
            "Reports token transfer calls that lack a preceding balance or authorization check."
        }
        "unbounded-vec-growth" => {
            "Reports storage-backed Vec values pushed and written back without an apparent length cap."
        }
        "unsafe-randomness" => {
            "Reports ledger timestamp or sequence usage as a randomness source."
        }
        "unchecked-divisor" => {
            "Reports division by runtime values without an apparent non-zero guard."
        }
        _ => "No detailed explanation is available for this custom check.",
    }
}

fn describe_rule(name: &str) -> &'static str {
    match name {
        "missing-require-auth" => "Method writes to storage without env.require_auth()",
        "unchecked-arithmetic" => "Wrapping arithmetic operations may overflow",
        "unprotected-admin" => "Sensitive admin entrypoints lack an authorization gate",
        "unsafe-storage-patterns" => "Temporary storage or dynamic Symbol keys are risky",
        "missing-ttl-extension" => "Persistent entries may expire without TTL bump",
        "forbidden-std-imports" => "Crate imports std which is forbidden in no_std contracts",
        "hardcoded-address" => "Contract contains a hardcoded Stellar address string",
        "unsafe-cross-contract-input" => "Cross-contract call return value used without validation",
        "missing-contract-annotation" => "Struct missing #[contract] annotation",
        "delegate-call-risk" => "Delegate-style call pattern can transfer control unexpectedly",
        "integer-division-truncation" => "Integer division silently truncates the remainder",
        "missing-event-emission" => "State-mutating function emits no events",
        "symbol-key-collision" => "Multiple storage keys share the same Symbol value",
        "self-transfer" => "Token transfer destination may equal the sender",
        "missing-zero-address-check" => "Address argument not validated against the zero address",
        "mutable-global-state" => "Mutable global state is unsafe and not persisted on-chain",
        "re-initialization-risk" => "Initializer-like function can overwrite critical state",
        "unchecked-invoke-return" => "Cross-contract invocation result is discarded",
        "missing-balance-check" => "Token transfer occurs without a balance or authorization check",
        "unbounded-vec-growth" => "Storage-backed Vec can grow without a bound",
        "unsafe-randomness" => "Ledger data is used as a randomness source",
        "unchecked-divisor" => "Division uses a runtime divisor without a zero guard",
        "reentrancy-risk" => "Storage write followed by cross-contract invocation risks reentrancy",
        "panic-in-contract" => "Contract uses panic!, unwrap, or expect which abort the WASM execution",
        "unprotected-upgrade" => "Contract upgrade entrypoint lacks an authorization gate",
        "unprotected-token-mint" => "Token mint entrypoint lacks an authorization gate",
        "unprotected-contract-deployment" => "Contract deployment call lacks an authorization gate",
        "unchecked-token-amount" => "Token amount used without validation",
        "large-loop" => "Loop may iterate over an unbounded collection",
        "missing-nonce" => "Function susceptible to replay attacks lacks a nonce check",
        "uninitialized-storage-read" => "Storage value read without checking if it has been initialized",
        "missing-event-for-admin-change" => "Admin-state change emits no event for off-chain indexers",
        "missing-input-length-bound" => "Input collection used without a length bound check",
        "auth-after-storage-write" => "Authorization check occurs after a storage write",
        _ => "Custom check",
    }
}

fn describe_check(name: &str) -> (&'static str, &'static str) {
    match name {
        "missing-require-auth" => ("high", "Missing env.require_auth() before storage writes"),
        "unchecked-arithmetic" => ("medium", "Flags unchecked arithmetic on contract state"),
        "unprotected-admin" => ("high", "Flags privileged entrypoints without auth"),
        "unsafe-storage-patterns" => ("medium", "Flags temporary storage and dynamic Symbol keys"),
        "missing-ttl-extension" => ("low", "Flags persistent storage entries without TTL extension"),
        "forbidden-std-imports" => ("high", "Flags use of std in no_std Soroban contracts"),
        "hardcoded-address" => ("medium", "Flags hardcoded Stellar address literals"),
        "unsafe-cross-contract-input" => ("high", "Flags unvalidated return values from cross-contract calls"),
        "missing-contract-annotation" => ("low", "Flags structs missing the #[contract] attribute"),
        "delegate-call-risk" => ("high", "Flags delegate-call patterns that transfer execution control"),
        "integer-division-truncation" => ("medium", "Flags integer division that silently truncates"),
        "missing-event-emission" => ("medium", "Flags state-mutating functions with no event emission"),
        "symbol-key-collision" => ("medium", "Flags storage keys that share the same Symbol value"),
        "self-transfer" => ("medium", "Flags token transfers where sender may equal receiver"),
        "missing-zero-address-check" => ("medium", "Flags Address parameters not checked for the zero address"),
        "mutable-global-state" => ("high", "Flags mutable global state in contract code"),
        "re-initialization-risk" => ("high", "Flags initializer-like functions without re-init guards"),
        "unchecked-invoke-return" => ("medium", "Flags discarded cross-contract call return values"),
        "missing-balance-check" => ("high", "Flags token transfers without balance or authorization checks"),
        "unbounded-vec-growth" => ("medium", "Flags storage-backed Vec growth without a length cap"),
        "unsafe-randomness" => ("high", "Flags ledger timestamp or sequence as randomness"),
        "unchecked-divisor" => ("high", "Flags division by runtime values without zero guards"),
        "reentrancy-risk" => ("high", "Flags storage writes followed by cross-contract calls"),
        "panic-in-contract" => ("medium", "Flags panic!, unwrap, and expect in contract methods"),
        "unprotected-upgrade" => ("high", "Flags upgrade entrypoints without authorization"),
        "unprotected-token-mint" => ("high", "Flags token mint entrypoints without authorization"),
        "unprotected-contract-deployment" => ("high", "Flags contract deployment calls without authorization"),
        "unchecked-token-amount" => ("medium", "Flags token amounts used without validation"),
        "large-loop" => ("medium", "Flags loops over unbounded collections"),
        "missing-nonce" => ("medium", "Flags functions susceptible to replay attacks"),
        "uninitialized-storage-read" => ("high", "Flags storage reads without initialization checks"),
        "missing-event-for-admin-change" => ("medium", "Flags admin changes with no event emission"),
        "missing-input-length-bound" => ("medium", "Flags input collections without length bound checks"),
        "auth-after-storage-write" => ("high", "Flags authorization checks after storage writes"),
        _ => ("low", "Custom detector"),
    }
}

fn write_output(path: &Path, payload: &str) -> Result<(), std::io::Error> {
    fs::write(path, payload)
}

fn json_payload(findings: &[Finding], files_scanned: usize) -> Result<String, serde_json::Error> {
    let high = findings
        .iter()
        .filter(|f| matches!(f.severity, Severity::High))
        .count();
    let medium = findings
        .iter()
        .filter(|f| matches!(f.severity, Severity::Medium))
        .count();
    let low = findings
        .iter()
        .filter(|f| matches!(f.severity, Severity::Low))
        .count();

    let envelope = serde_json::json!({
        "summary": {
            "total": findings.len(),
            "high": high,
            "medium": medium,
            "low": low,
            "files_scanned": files_scanned
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
    out.push_str("| # | Severity | File | Line | Check | Function |\n");
    out.push_str("|---|----------|------|------|-------|----------|\n");
    for (i, f) in findings.iter().enumerate() {
        let sev = match f.severity {
            Severity::High => "**HIGH**",
            Severity::Medium => "MEDIUM",
            Severity::Low => "LOW",
        };
        out.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} |\n",
            i + 1,
            sev,
            f.file_path,
            f.line,
            f.check_name,
            f.function_name
        ));
    }
    let high = findings
        .iter()
        .filter(|f| matches!(f.severity, Severity::High))
        .count();
    let medium = findings
        .iter()
        .filter(|f| matches!(f.severity, Severity::Medium))
        .count();
    let low = findings
        .iter()
        .filter(|f| matches!(f.severity, Severity::Low))
        .count();
    out.push_str(&format!(
        "\n**{} finding(s): {} High, {} Medium, {} Low**\n",
        findings.len(),
        high,
        medium,
        low
    ));
    out
}

fn summary_text(findings: &[Finding], files_scanned: usize) -> String {
    let high = findings
        .iter()
        .filter(|f| matches!(f.severity, Severity::High))
        .count();
    let medium = findings
        .iter()
        .filter(|f| matches!(f.severity, Severity::Medium))
        .count();
    let low = findings
        .iter()
        .filter(|f| matches!(f.severity, Severity::Low))
        .count();
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
        Severity::Low => check_name.white().dimmed().to_string(),
    }
}

fn print_pretty(
    findings: &[Finding],
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

    if findings.is_empty() && truncated_count == 0 {
        println!("  {}", "No issues found.".green());
        println!();
    } else {
        let total = findings.len() + truncated_count;
        println!(
            "  {} finding(s):\n",
            total.to_string().yellow().bold()
        );

        for (i, f) in findings.iter().enumerate() {
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

        let payload = build_sarif(&findings);
        assert_eq!(payload["version"], "2.1.0");
        assert_eq!(
            payload["runs"][0]["tool"]["driver"]["name"],
            "soroban-guard"
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
            serde_json::from_str(&json_payload(&findings, 1).unwrap()).unwrap();
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
            serde_json::from_str(&json_payload(&findings, 3).unwrap()).unwrap();
        assert_eq!(payload["summary"]["total"], 2);
        assert_eq!(payload["summary"]["high"], 1);
        assert_eq!(payload["summary"]["medium"], 1);
        assert_eq!(payload["summary"]["low"], 0);
        assert_eq!(payload["summary"]["files_scanned"], 3);
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
        let payload = serde_json::to_string_pretty(&build_sarif(&findings)).unwrap();
        write_output(&path, &payload).unwrap();
        assert!(path.exists());
        let contents = fs::read_to_string(&path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&contents).unwrap();
        assert_eq!(parsed["version"], "2.1.0");
        let _ = fs::remove_file(path);
    }

    #[test]
    fn markdown_written_to_file_when_output_provided() {
        let findings = vec![
            Finding {
                check_name: "missing-require-auth".to_string(),
                severity: Severity::High,
                file_path: "src/lib.rs".to_string(),
                line: 10,
                function_name: "set_balance".to_string(),
                description: "Missing require_auth".to_string(),
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
        assert!(
            contents.contains("missing-require-auth"),
            "should contain the check name"
        );
        assert!(
            contents.contains("unchecked-arithmetic"),
            "should contain the second check name"
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
    fn check_name_styling_is_bold_for_high_and_dimmed_for_low() {
        control::set_override(true);
        let high = style_check_name("high-check", Severity::High);
        let low = style_check_name("low-check", Severity::Low);

        assert!(high.contains("\u{1b}[1m"), "high check name should be bold");
        assert!(low.contains("\u{1b}[2m"), "low check name should be dimmed");
    }

    #[test]
    fn describe_check_covers_all_default_checks() {
        for check in default_checks() {
            let (sev, desc) = describe_check(check.name());
            assert_ne!(sev, "low", "check {} has fallback severity", check.name());
            assert_ne!(desc, "Custom detector", "check {} has fallback description", check.name());
        }
    }

    #[test]
    fn describe_rule_covers_all_default_checks() {
        for check in default_checks() {
            let desc = describe_rule(check.name());
            assert_ne!(desc, "Custom check", "check {} has fallback rule description", check.name());
        }
    }
}
