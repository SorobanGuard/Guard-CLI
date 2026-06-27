use clap::{Parser, Subcommand};
use colored::Colorize;
use soroban_guard_analyzer::scan_directory;
use soroban_guard_checks::{default_checks, Finding, Severity};
use std::fs;
use std::path::{Path, PathBuf};

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
        /// Path to the contract crate or folder containing Rust sources
        path: PathBuf,
        /// Print findings as JSON (`{ "summary": {...}, "findings": [...] }`)
        #[arg(long)]
        json: bool,
        /// Print findings as a SARIF 2.1.0 document
        #[arg(long)]
        sarif: bool,
        /// Print findings as a Markdown table
        #[arg(long)]
        markdown: bool,
        /// Write output to a file instead of stdout (applies to --json and --sarif)
        #[arg(long)]
        output: Option<PathBuf>,
        /// Suppress all output when there are zero High findings
        #[arg(long)]
        quiet: bool,
        /// Only scan files matching this glob pattern (e.g. `src/token*.rs`)
        #[arg(long)]
        include: Option<String>,
        /// Disable ANSI color output (equivalent to setting NO_COLOR=1)
        #[arg(long)]
        no_color: bool,
    },
    /// List the checks that are enabled by default
    ListChecks,
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
            include,
            no_color,
        } => {
            if no_color {
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

            let includes: Vec<String> = include.into_iter().collect();
            match scan_directory(&path, &[], &includes) {
                Ok((findings, files_scanned)) => {
                    let any_high = findings
                        .iter()
                        .any(|f| matches!(f.severity, Severity::High));

                    if json {
                        if !quiet || any_high {
                            match json_payload(&findings, files_scanned) {
                                Ok(payload) => {
                                    if let Some(ref out_path) = output {
                                        if let Err(e) = write_output(out_path, &payload) {
                                            eprintln!("{} {}", "error:".red().bold(), e);
                                            std::process::exit(2);
                                        }
                                    } else {
                                        println!("{payload}");
                                    }
                                }
                                Err(e) => {
                                    eprintln!("{} {}", "error:".red().bold(), e);
                                    std::process::exit(2);
                                }
                            }
                        }
                    } else if sarif {
                        if !quiet || any_high {
                            let payload =
                                serde_json::to_string_pretty(&build_sarif(&findings)).unwrap();
                            if let Some(ref out_path) = output {
                                if let Err(e) = write_output(out_path, &payload) {
                                    eprintln!("{} {}", "error:".red().bold(), e);
                                    std::process::exit(2);
                                }
                            } else {
                                println!("{payload}");
                            }
                        }
                    } else if markdown {
                        if !quiet || any_high {
                            print_markdown(&findings);
                        }
                    } else {
                        if !quiet || any_high {
                            print_pretty(&findings, files_scanned, path.display().to_string(), 0);
                        }
                    }

                    if any_high {
                        std::process::exit(1);
                    }
                }
                Err(e) => {
                    if json {
                        let envelope = serde_json::json!({ "error": e.to_string() });
                        println!("{}", serde_json::to_string_pretty(&envelope).unwrap());
                    } else {
                        eprintln!("{} {}", "error:".red().bold(), e);
                    }
                    std::process::exit(2);
                }
            }
        }
        Commands::ListChecks => {
            for check in default_checks() {
                let (severity, description) = describe_check(check.name());
                println!("{} | {} | {}", check.name(), severity, description);
            }
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

fn emit_gha_annotations(findings: &[Finding]) {
    for f in findings {
        let level = match f.severity {
            Severity::High => "error",
            Severity::Medium | Severity::Low => "warning",
        };
        println!(
            "::{} file={},line={},title={}::{}",
            level, f.file_path, f.line, f.check_name, f.description
        );
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
                "helpUri": "https://github.com/chindosunday/Guard-CLI"
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
                    "informationUri": "https://github.com/chindosunday/Guard-CLI",
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
        "reentrancy-risk" => "Storage write followed by cross-contract invocation risks reentrancy",
        "panic-in-contract" => "Contract uses panic!, unwrap, or expect which abort the WASM execution",
        _ => "Custom check",
    }
}

fn describe_check(name: &str) -> (&'static str, &'static str) {
    match name {
        "missing-require-auth" => ("high", "Missing env.require_auth() before storage writes"),
        "unchecked-arithmetic" => ("medium", "Flags unchecked arithmetic on contract state"),
        "unprotected-admin" => ("high", "Flags privileged entrypoints without auth"),
        "unsafe-storage-patterns" => ("medium", "Flags temporary storage and dynamic Symbol keys"),
        "missing-ttl-extension" => ("medium", "Flags persistent storage entries without TTL extension"),
        "forbidden-std-imports" => ("high", "Flags use of std in no_std Soroban contracts"),
        "hardcoded-address" => ("medium", "Flags hardcoded Stellar address literals"),
        "unsafe-cross-contract-input" => ("high", "Flags unvalidated return values from cross-contract calls"),
        "missing-contract-annotation" => ("low", "Flags structs missing the #[contract] attribute"),
        "delegate-call-risk" => ("high", "Flags delegate-call patterns that transfer execution control"),
        "integer-division-truncation" => ("low", "Flags integer division that silently truncates"),
        "missing-event-emission" => ("low", "Flags state-mutating functions with no event emission"),
        "symbol-key-collision" => ("medium", "Flags storage keys that share the same Symbol value"),
        "self-transfer" => ("medium", "Flags token transfers where sender may equal receiver"),
        "missing-zero-address-check" => ("medium", "Flags Address parameters not checked for the zero address"),
        "reentrancy-risk" => ("high", "Flags storage writes followed by cross-contract calls"),
        "panic-in-contract" => ("medium", "Flags panic!, unwrap, and expect in contract methods"),
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

fn print_markdown(findings: &[Finding]) {
    println!("## Soroban Guard Findings\n");
    if findings.is_empty() {
        println!("No issues found.");
        return;
    }
    println!("| # | Severity | File | Line | Check | Function |");
    println!("|---|----------|------|------|-------|----------|");
    for (i, f) in findings.iter().enumerate() {
        let sev = match f.severity {
            Severity::High => "**HIGH**".to_string(),
            Severity::Medium => "MEDIUM".to_string(),
            Severity::Low => "LOW".to_string(),
        };
        println!(
            "| {} | {} | {} | {} | {} | {} |",
            i + 1,
            sev,
            f.file_path,
            f.line,
            f.check_name,
            f.function_name
        );
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
    println!(
        "\n**{} finding(s): {} High, {} Medium, {} Low**",
        findings.len(),
        high,
        medium,
        low
    );
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
            let check = match f.severity {
                Severity::High => f.check_name.red(),
                Severity::Medium => f.check_name.magenta(),
                Severity::Low => f.check_name.white(),
            };
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
