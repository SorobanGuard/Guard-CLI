use clap::{Parser, Subcommand};
use colored::Colorize;
use soroban_guard_analyzer::scan_directory;
use soroban_guard_checks::{default_checks, Check, Finding, Severity};
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
        /// Print findings as JSON (`{ "findings": [...] }`)
        #[arg(long)]
        json: bool,
        /// Print findings as SARIF 2.1.0 JSON
        #[arg(long)]
        sarif: bool,
        /// Write JSON output to a file instead of stdout
        #[arg(long)]
        output: Option<PathBuf>,
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
            output,
        } => match scan_directory(&path) {
            Ok(findings) => {
                if json && sarif {
                    eprintln!("{} choose one output format", "error:".red().bold());
                    std::process::exit(2);
                }
                if output.is_some() && !json && !sarif {
                    eprintln!(
                        "{} --output requires --json or --sarif",
                        "error:".red().bold()
                    );
                    std::process::exit(2);
                }
                let payload = if sarif {
                    serde_json::to_string_pretty(&build_sarif(&findings)).unwrap_or_else(|e| {
                        eprintln!("{} {e}", "error:".red().bold());
                        std::process::exit(2);
                    })
                } else if json || output.is_some() {
                    serde_json::to_string_pretty(&serde_json::json!({ "findings": &findings }))
                        .unwrap_or_else(|e| {
                            eprintln!("{} {e}", "error:".red().bold());
                            std::process::exit(2);
                        })
                } else {
                    String::new()
                };

                if sarif || json || output.is_some() {
                    if let Some(output_path) = output.as_deref() {
                        if let Err(e) = fs::write(output_path, payload) {
                            eprintln!("{} {}", "error:".red().bold(), e);
                            std::process::exit(2);
                        }
                    } else {
                        println!("{payload}");
                    }
                } else {
                    print_pretty(&findings, path.display().to_string());
                }

                let any_high = findings
                    .iter()
                    .any(|f| matches!(f.severity, Severity::High));
                if any_high {
                    std::process::exit(1);
                }
            }
            Err(e) => {
                eprintln!("{} {}", "error:".red().bold(), e);
                std::process::exit(2);
            }
        },
        Commands::ListChecks => {
            for check in default_checks() {
                let (severity, description) = describe_check(check.name());
                println!("{} | {} | {}", check.name(), severity, description);
            }
        }
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
        _ => "Custom check",
    }
}

fn describe_check(name: &str) -> (&'static str, &'static str) {
    match name {
        "missing-require-auth" => ("high", "Missing env.require_auth() before storage writes"),
        "unchecked-arithmetic" => ("medium", "Flags unchecked arithmetic on contract state"),
        "unprotected-admin" => ("high", "Flags privileged entrypoints without auth"),
        "unsafe-storage-patterns" => ("medium", "Flags temporary storage and dynamic Symbol keys"),
        _ => ("low", "Custom detector"),
    }
}

fn write_output(path: &Path, payload: &str) -> Result<(), std::io::Error> {
    fs::write(path, payload)
}

fn print_pretty(findings: &[Finding], root_label: String) {
    println!();
    println!(
        "{} {}",
        "Soroban Guard Core".cyan().bold(),
        format!("(scan: {})", root_label).dimmed()
    );
    println!();

    if findings.is_empty() {
        println!("  {}", "No issues found.".green());
        println!();
        return;
    }

    println!(
        "  {} finding(s):\n",
        findings.len().to_string().yellow().bold()
    );

    for (i, f) in findings.iter().enumerate() {
        let sev = match f.severity {
            Severity::High => "HIGH".red().bold(),
            Severity::Medium => "MEDIUM".yellow().bold(),
            Severity::Low => "LOW".white(),
        };
        println!(
            "  {}  {}  {}  {}",
            format!("[{}]", i + 1).dimmed(),
            sev,
            format!("{}:{}", f.file_path, f.line).bright_white(),
            f.check_name.cyan()
        );
        println!("         {} `{}`", "function:".dimmed(), f.function_name);
        println!("         {}", f.description);
        println!();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn sarif_payload_has_expected_schema_and_result() {
        let findings = vec![Finding {
            check_name: "missing-require-auth".to_string(),
            severity: Severity::High,
            file_path: "src/lib.rs".to_string(),
            line: 10,
            function_name: "set_balance".to_string(),
            description: "Missing auth".to_string(),
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
}
