use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::{generate, Shell};
use colored::Colorize;
use soroban_guard_analyzer::scan_directory;
use soroban_guard_checks::{default_checks, Finding, Severity};
use std::fs;
use std::io;
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
        } => {
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
        "reentrancy-risk" => "Cross-contract call followed by state mutation risks reentrancy",
        "panic-in-contract" => "Explicit panic or unwrap inside contract code",
        "mutable-global-state" => "Contract uses mutable static or global state",
        "unchecked-invoke-return" => "Cross-contract invoke return value is discarded unchecked",
        "missing-balance-check" => "Balance not validated before transfer or arithmetic",
        "unbounded-vec-growth" => "Vec grows in a loop without a length cap",
        "re-initialization-risk" => "Contract init function can be called more than once",
        "auth-after-storage-write" => "env.require_auth() called after a storage write",
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
        "missing-contract-annotation" => ("medium", "Flags structs missing the #[contract] attribute"),
        "delegate-call-risk" => ("high", "Flags delegate-call patterns that transfer execution control"),
        "integer-division-truncation" => ("medium", "Flags integer division that silently truncates"),
        "missing-event-emission" => ("medium", "Flags state-mutating functions with no event emission"),
        "symbol-key-collision" => ("medium", "Flags storage keys that share the same Symbol value"),
        "self-transfer" => ("medium", "Flags token transfers where sender may equal receiver"),
        "missing-zero-address-check" => ("medium", "Flags Address parameters not checked for the zero address"),
        "reentrancy-risk" => ("high", "Flags cross-contract calls followed by state mutations"),
        "panic-in-contract" => ("medium", "Flags explicit panics and unwraps inside contract code"),
        "mutable-global-state" => ("high", "Flags use of mutable static or global state"),
        "unchecked-invoke-return" => ("high", "Flags discarded cross-contract invoke return values"),
        "missing-balance-check" => ("high", "Flags transfers or arithmetic without prior balance validation"),
        "unbounded-vec-growth" => ("medium", "Flags Vecs that grow in a loop without a size cap"),
        "re-initialization-risk" => ("high", "Flags init functions that can be called more than once"),
        "auth-after-storage-write" => ("high", "Flags methods where require_auth() follows a storage write"),
        _ => ("medium", "Custom detector"),
    }
}

fn explain_details(name: &str) -> &'static str {
    match name {
        "missing-require-auth" => {
            "In a #[contractimpl] block, any function that calls .set()/.remove() on \
             env.storage() but never calls env.require_auth() is flagged. \
             Callers can mutate contract state without proving authorization. \
             Limitation: auth hidden inside helper functions is not detected."
        }
        "auth-after-storage-write" => {
            "In a #[contractimpl] block, any function that calls env.require_auth() \
             after a storage write (.set()/.remove()) is flagged. Although Soroban \
             transactions are atomic, state has already been mutated before the caller \
             was verified — this breaks the authorize-then-execute invariant and can \
             cause issues in composed contract calls. \
             Fix: move env.require_auth() to the very first line of the function. \
             Limitation: line-number heuristic; control flow is not modeled."
        }
        "unchecked-arithmetic" => {
            "Flags binary +, -, * and compound assignments (+=, -=, *=) inside \
             #[contractimpl] methods where at least one operand is not a literal. \
             Severity scales with variable name: amount/balance/fee → High; \
             index/count/len → Low; everything else → Medium. \
             Limitation: operator overloads and checked_* calls are not tracked."
        }
        "unprotected-admin" => {
            "Flags #[contractimpl] functions whose name contains admin-like keywords \
             (set_admin, upgrade, pause, etc.) but never call env.require_auth(). \
             Limitation: naming heuristic only; semantics are not checked."
        }
        "unsafe-storage-patterns" => {
            "Flags use of env.storage().temporary() or Symbol keys constructed at runtime \
             inside #[contractimpl] methods. Temporary storage silently expires; dynamic \
             keys risk collision. Limitation: static analysis only."
        }
        "missing-ttl-extension" => {
            "Flags persistent storage writes (.set()) not followed by a .extend_ttl() or \
             .bump() call on the same key. Without TTL extension the entry may expire. \
             Limitation: key aliasing is not tracked."
        }
        "forbidden-std-imports" => {
            "Flags `use std::` imports in files that also contain #[contractimpl]. \
             Soroban contracts run in no_std WASM environments. \
             Limitation: macro-generated imports are not visible to the AST."
        }
        "hardcoded-address" => {
            "Flags string literals inside #[contractimpl] methods that look like Stellar \
             address strings (starting with G and 56 chars long). Hardcoded addresses \
             make contracts non-portable and hard to audit. Limitation: only string \
             literals are checked, not computed values."
        }
        "unsafe-cross-contract-input" => {
            "Flags return values from cross-contract calls (invoke_contract) that are \
             used directly without validation. Untrusted values from external contracts \
             should always be validated. Limitation: data-flow is not fully modeled."
        }
        "missing-contract-annotation" => {
            "Flags files containing a #[contractimpl] block but no struct annotated with \
             #[contract]. This is almost always a copy-paste error. \
             Limitation: only checks within a single file."
        }
        "delegate-call-risk" => {
            "Flags call patterns that forward execution to an arbitrary callee address \
             (delegate-call style). This can transfer control and storage context \
             unexpectedly. Limitation: pattern matching only."
        }
        "integer-division-truncation" => {
            "Flags integer division (/) inside #[contractimpl] methods where both operands \
             are non-literal. Division silently truncates the remainder and can lead to \
             unexpected rounding in financial calculations. Limitation: type inference \
             is not performed; all divisions are flagged."
        }
        "missing-event-emission" => {
            "Flags #[contractimpl] functions that mutate storage but never call \
             env.events().publish(). Events are the primary off-chain observability \
             mechanism. Limitation: helper-based event emission is not detected."
        }
        "symbol-key-collision" => {
            "Flags cases where two or more storage keys share the same Symbol string \
             value. Collisions silently overwrite each other. \
             Limitation: only Symbol::new / symbol_short! literals are compared."
        }
        "self-transfer" => {
            "Flags token transfer calls where the destination parameter name or type \
             suggests it could equal the source. Self-transfers are usually bugs. \
             Limitation: aliasing is not modeled."
        }
        "missing-zero-address-check" => {
            "Flags Address parameters in #[contractimpl] methods that are never compared \
             against a zero or default address. Sending tokens to the zero address burns \
             them permanently. Limitation: custom zero-check helpers are not recognized."
        }
        "reentrancy-risk" => {
            "Flags #[contractimpl] methods where a cross-contract call is followed by \
             a storage mutation. Even though Soroban is not directly reentrant, this \
             pattern violates checks-effects-interactions and can cause state \
             inconsistencies in composed calls. Limitation: call ordering is inferred \
             from line numbers."
        }
        "panic-in-contract" => {
            "Flags explicit panic!(), unwrap(), and expect() calls inside #[contractimpl] \
             methods. Panics abort the transaction and leak no useful error to callers. \
             Use Result/Option propagation or env.panic_with_error() instead. \
             Limitation: panic inside closures may not be detected."
        }
        "mutable-global-state" => {
            "Flags static mut declarations or Mutex/RefCell<T> in global position inside \
             contract files. WASM is single-threaded but global mutable state is \
             non-deterministic across invocations. Limitation: Arc/Mutex in local \
             scope is not flagged."
        }
        "unchecked-invoke-return" => {
            "Flags cross-contract invoke_contract return values that are immediately \
             discarded (assigned to _ or not used). Return values often carry error codes \
             or transferred amounts. Limitation: shadowing is not tracked."
        }
        "missing-balance-check" => {
            "Flags token transfer calls not preceded by a balance query on the same \
             account within the same function body. Transferring without checking \
             balance can result in underflow errors at the ledger level. \
             Limitation: multi-function flows are not tracked."
        }
        "unbounded-vec-growth" => {
            "Flags Vec::push / vec.append / vec.extend calls inside loops within \
             #[contractimpl] methods where no length cap or early-exit guard is detected. \
             Unbounded growth can exhaust ledger entry size limits. \
             Limitation: external caps passed as parameters are not recognized."
        }
        "re-initialization-risk" => {
            "Flags #[contractimpl] functions whose name contains 'init' or 'initialize' \
             that do not first check whether the contract has already been initialized \
             (e.g. reading a flag from storage). Calling init twice can overwrite \
             existing state. Limitation: naming heuristic; custom guards are not \
             recognized."
        }
        _ => "No additional documentation available for this check.",
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
    std::env::var("NO_COLOR").is_err()
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
