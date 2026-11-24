# Guard-CLI Issue #1033: Check Panics Silently Discarded - Degraded Scan Reports as Clean

## Overview
This document tracks a **critical security regression** in Guard-CLI where security check panics are silently discarded, causing degraded scans to exit with code 0 and report "No issues found". This is a **P0 bug** in a deploy-gating security tool — incomplete security analysis presented as successful.

**Branch:** `check-panics-discarded-1033`  
**Repository:** https://github.com/oyebiyipelumi-lang/Guard-CLI  
**Base Commit:** main @ 418f39e  
**Issue Type:** Critical Security Regression  
**Related Issue:** #659 (marked closed but incomplete)

---

## Problem Statement

When a security check panics while analyzing a file:
1. The analyzer **catches the panic** (correctly)
2. The analyzer **returns `check_panics`** as the 4th tuple element (correctly)
3. The CLI **binds it as `_check_panics`** (underscore = intentionally unused)
4. The CLI **never reports it** in any output format
5. The scan **exits with code 0** and prints "No issues found"

This is a **degraded scan masquerading as a clean result**. Security checks failed to run, but the tool reports success.

### Impact

- **Silent Security Failures:** Checks that panic produce no findings, but the scan reports clean
- **False Confidence:** Developers believe their code passed security review
- **CI Gates Pass:** Vulnerable code is deployed because exit code is 0
- **No Visibility:** Operators have no way to detect check failures

### Evidence (main @ 418f39e)

**Location 1:** `crates/cli/src/main.rs:139`

```rust
// Line 139: Panic report is bound but NEVER USED
Ok((results, files_scanned, files_skipped, _check_panics)) => {
//                                          ^^^^^^^^^^^^
//                                          Underscore prefix = intentionally unused
    
    if output_format == OutputFormat::Json {
        output_json(&results, files_scanned, files_skipped);
        // No mention of check_panics
    } else {
        output_human(&results, files_scanned, files_skipped);
        // No mention of check_panics
    }
    
    std::process::exit(if results.is_empty() { 0 } else { 1 });
    // Exit 0 even if checks panicked!
}
```

**Location 2:** `crates/cli/src/main.rs:724`

```rust
// SARIF output always reports success
fn build_sarif(...) -> serde_json::Value {
    json!({
        "version": "2.1.0",
        "$schema": "...",
        "runs": [{
            "tool": { ... },
            "results": results,
            "invocations": [{
                "executionSuccessful": true,  // ← Always true!
                // No field for check panics
            }]
        }]
    })
}
```

**Location 3:** Analyzer correctly returns panics

```rust
// File: crates/analyzer/src/lib.rs

pub struct CheckPanic {
    pub file: PathBuf,
    pub check_name: String,
    pub panic_message: String,
}

pub fn scan_directory_with_checks(
    root: &Path,
    checks: Vec<Box<dyn SecurityCheck>>,
    ignored_dirs: &[String],
) -> Result<(Vec<Finding>, usize, usize, Vec<CheckPanic>), ScanError> {
    // ... scan logic catches panics per check per file ...
    
    Ok((findings, files_scanned, files_skipped, check_panics))
    //                                           ^^^^^^^^^^^^
    //                                           Returned but CLI ignores it
}
```

### Issue #659 Status

Issue #659 was **closed as completed**, but only the **analyzer** implementation was done. The **CLI integration** was never completed:
- ✅ Analyzer catches panics and returns `CheckPanic` struct
- ❌ CLI never uses the panic report
- ❌ No output format includes panics
- ❌ Exit code doesn't reflect degraded scan

---

## Root Cause Analysis

### Broken Code Flow

```
1. Security check panics on file X
   ↓
2. Analyzer catches panic via std::panic::catch_unwind
   ↓
3. Analyzer creates CheckPanic { file: X, check_name: "...", panic_message: "..." }
   ↓
4. Analyzer returns check_panics in tuple
   ↓
5. CLI binds as _check_panics (underscore = unused)
   ↓
6. CLI outputs "No issues found" ← WRONG
   ↓
7. CLI exits with code 0 ← WRONG
```

### Why This Is Critical

This is a **deploy-gating security tool**. When it reports "No issues found" with exit code 0, that signal is used to:
- Approve pull requests
- Deploy to production
- Generate compliance reports
- Make security decisions

A degraded scan that reports as successful is the **worst class of failure** — it provides false security guarantees.

---

## Proposed Solution

### Exit Code Strategy

Define three exit codes with clear semantics:

- **Exit 0:** Clean scan (no issues, no errors)
- **Exit 1:** Issues found (security vulnerabilities detected)
- **Exit 2:** Degraded scan (checks failed to complete)

This allows CI systems to distinguish between "passed security review" (0) and "security review incomplete" (2).

### Implementation

#### Fix #1: Remove Underscore and Report Panics

**File:** `crates/cli/src/main.rs` (line ~139)

```rust
// BEFORE (broken):
Ok((results, files_scanned, files_skipped, _check_panics)) => {
    if output_format == OutputFormat::Json {
        output_json(&results, files_scanned, files_skipped);
    } else {
        output_human(&results, files_scanned, files_skipped);
    }
    
    std::process::exit(if results.is_empty() { 0 } else { 1 });
}

// AFTER (fixed):
Ok((results, files_scanned, files_skipped, check_panics)) => {
    //                                        ^^^^^^^^^^^
    //                                        No underscore - must be used
    
    if output_format == OutputFormat::Json {
        output_json(&results, files_scanned, files_skipped, &check_panics);
    } else if output_format == OutputFormat::Sarif {
        let sarif = build_sarif(&results, &check_panics);
        println!("{}", serde_json::to_string_pretty(&sarif).unwrap());
    } else {
        output_human(&results, files_scanned, files_skipped, &check_panics);
    }
    
    // Exit code logic
    let exit_code = if !check_panics.is_empty() {
        2  // Degraded scan (checks failed)
    } else if !results.is_empty() {
        1  // Issues found
    } else {
        0  // Clean scan
    };
    
    std::process::exit(exit_code);
}
```

#### Fix #2: Update Human-Readable Output

**File:** `crates/cli/src/main.rs` (output_human function)

```rust
fn output_human(
    results: &[Finding],
    files_scanned: usize,
    files_skipped: usize,
    check_panics: &[CheckPanic],  // ← Add parameter
) {
    println!("\n{}", "=".repeat(70));
    println!("Guard-CLI Security Scan Results");
    println!("{}", "=".repeat(70));
    
    // ========================================
    // REPORT PANICS FIRST (most critical)
    // ========================================
    if !check_panics.is_empty() {
        println!("\n⚠️  WARNING: Some security checks failed to complete");
        println!("{}", "-".repeat(70));
        println!("The scan results below are INCOMPLETE.");
        println!("Fix these check errors and re-scan.\n");
        
        for (i, panic) in check_panics.iter().enumerate() {
            println!("{}. Check Failure", i + 1);
            println!("   File:  {}", panic.file.display());
            println!("   Check: {}", panic.check_name);
            println!("   Error: {}", panic.panic_message);
            println!();
        }
        
        println!("{}", "-".repeat(70));
        println!();
    }
    
    // ========================================
    // REPORT FINDINGS
    // ========================================
    if results.is_empty() {
        if check_panics.is_empty() {
            println!("\n✅ No security issues found");
        } else {
            println!("\n⚠️  No issues found, but scan was degraded");
            println!("The checks that failed may have missed vulnerabilities.");
        }
    } else {
        println!("\n❌ Found {} security issue(s):", results.len());
        
        for finding in results {
            println!("\n  [{}] {}", 
                match finding.severity {
                    Severity::Critical => "CRITICAL",
                    Severity::High => "HIGH",
                    Severity::Medium => "MEDIUM",
                    Severity::Low => "LOW",
                },
                finding.rule_id
            );
            println!("  {}", finding.message);
            println!("  → {}:{}:{}", 
                finding.location.file.display(),
                finding.location.line,
                finding.location.column
            );
            
            if let Some(suggestion) = &finding.suggestion {
                println!("  💡 Suggestion: {}", suggestion);
            }
        }
    }
    
    // ========================================
    // SCAN STATISTICS
    // ========================================
    println!("\n{}", "-".repeat(70));
    println!("Scan Statistics:");
    println!("  Files scanned: {}", files_scanned);
    println!("  Files skipped: {}", files_skipped);
    
    if !check_panics.is_empty() {
        println!("  Check failures: {} ⚠️", check_panics.len());
    }
    
    println!("{}", "=".repeat(70));
    
    // ========================================
    // FINAL STATUS
    // ========================================
    if !check_panics.is_empty() {
        println!("\n⚠️  SCAN INCOMPLETE - Exit code 2");
        println!("Fix check errors listed above and re-run the scan.");
    } else if !results.is_empty() {
        println!("\n❌ ISSUES FOUND - Exit code 1");
        println!("Review and fix the security issues above.");
    } else {
        println!("\n✅ SCAN PASSED - Exit code 0");
        println!("No security issues detected.");
    }
    
    println!();
}
```

#### Fix #3: Update JSON Output

**File:** `crates/cli/src/main.rs` (output_json function)

```rust
fn output_json(
    results: &[Finding],
    files_scanned: usize,
    files_skipped: usize,
    check_panics: &[CheckPanic],  // ← Add parameter
) {
    let output = json!({
        "scan_status": if check_panics.is_empty() { "complete" } else { "degraded" },
        "files_scanned": files_scanned,
        "files_skipped": files_skipped,
        "issues_count": results.len(),
        "check_panics_count": check_panics.len(),
        
        "issues": results.iter().map(|f| json!({
            "severity": format!("{:?}", f.severity),
            "rule_id": f.rule_id,
            "message": f.message,
            "file": f.location.file.to_string_lossy(),
            "line": f.location.line,
            "column": f.location.column,
            "suggestion": f.suggestion,
            "function_name": f.function_name,
        })).collect::<Vec<_>>(),
        
        "check_panics": check_panics.iter().map(|p| json!({
            "file": p.file.to_string_lossy(),
            "check_name": p.check_name,
            "panic_message": p.panic_message,
        })).collect::<Vec<_>>(),
        
        "exit_code": if !check_panics.is_empty() {
            2
        } else if !results.is_empty() {
            1
        } else {
            0
        }
    });
    
    println!("{}", serde_json::to_string_pretty(&output).unwrap());
}
```

#### Fix #4: Update SARIF Output

**File:** `crates/cli/src/main.rs` (build_sarif function)

```rust
fn build_sarif(
    results: &[Finding],
    check_panics: &[CheckPanic],  // ← Add parameter
) -> serde_json::Value {
    // Convert findings to SARIF results
    let sarif_results: Vec<serde_json::Value> = results
        .iter()
        .map(|f| {
            json!({
                "ruleId": f.rule_id,
                "level": match f.severity {
                    Severity::Critical | Severity::High => "error",
                    Severity::Medium => "warning",
                    Severity::Low => "note",
                },
                "message": {
                    "text": f.message
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": f.location.file.to_string_lossy()
                        },
                        "region": {
                            "startLine": f.location.line,
                            "startColumn": f.location.column,
                        }
                    }
                }]
            })
        })
        .collect();
    
    // Convert check panics to SARIF notifications
    let notifications: Vec<serde_json::Value> = check_panics
        .iter()
        .map(|p| json!({
            "level": "error",
            "message": {
                "text": format!(
                    "Security check '{}' panicked: {}",
                    p.check_name,
                    p.panic_message
                )
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": p.file.to_string_lossy()
                    }
                }
            }]
        }))
        .collect();
    
    json!({
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Guard-CLI",
                    "version": env!("CARGO_PKG_VERSION"),
                }
            },
            "results": sarif_results,
            "invocations": [{
                "executionSuccessful": check_panics.is_empty(),  // ← Now reflects reality!
                "toolExecutionNotifications": notifications,
            }]
        }]
    })
}
```

#### Fix #5: Update CLI Help

**File:** `crates/cli/src/main.rs` or `crates/cli/src/help.rs`

```rust
const HELP_TEXT: &str = r#"
Guard-CLI - Soroban Smart Contract Security Scanner

USAGE:
    guard-cli [OPTIONS] <COMMAND>

COMMANDS:
    scan    Scan a project directory for security issues
    watch   Watch a project and re-scan on file changes

OPTIONS:
    --format <FORMAT>    Output format: human, json, sarif [default: human]
    -h, --help          Print help information
    -V, --version       Print version information

EXIT CODES:
    0    Clean scan - No issues found, all checks completed successfully
    1    Issues found - Security vulnerabilities detected
    2    Degraded scan - Some security checks failed to complete
         (The scan results are incomplete. Fix check errors and re-scan.)

EXAMPLES:
    guard-cli scan ./my-contract
    guard-cli scan --format json ./my-contract > results.json
    guard-cli scan --format sarif ./my-contract > results.sarif

NOTES:
    - Exit code 2 indicates an incomplete scan and should fail CI gates
    - Check panics are reported in all output formats
    - Re-run the scan after fixing check errors to get complete results
"#;
```

---

## Test Strategy

### Unit Tests

**File:** `crates/cli/tests/panic_reporting.rs`

```rust
use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

#[test]
fn test_panic_reported_in_human_output() {
    let tmp = TempDir::new().unwrap();
    let project = tmp.path();
    
    // Create a file that triggers a known check panic
    setup_panic_triggering_project(project);
    
    let mut cmd = Command::cargo_bin("guard-cli").unwrap();
    let assert = cmd
        .args(&["scan", project.to_str().unwrap()])
        .assert()
        .failure()  // Should exit non-zero
        .code(2);   // Exit code 2 for degraded scan
    
    let output = assert.get_output();
    let stdout = String::from_utf8_lossy(&output.stdout);
    
    // Check for warning banner
    assert!(stdout.contains("WARNING: Some security checks failed to complete"));
    assert!(stdout.contains("INCOMPLETE"));
    
    // Check for panic details
    assert!(stdout.contains("Check:"));
    assert!(stdout.contains("File:"));
    assert!(stdout.contains("Error:"));
    
    // Check for status message
    assert!(stdout.contains("SCAN INCOMPLETE - Exit code 2"));
}

#[test]
fn test_panic_reported_in_json_output() {
    let tmp = TempDir::new().unwrap();
    let project = tmp.path();
    setup_panic_triggering_project(project);
    
    let mut cmd = Command::cargo_bin("guard-cli").unwrap();
    let assert = cmd
        .args(&["scan", "--format", "json", project.to_str().unwrap()])
        .assert()
        .failure()
        .code(2);
    
    let output = assert.get_output();
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    
    // Check scan status
    assert_eq!(json["scan_status"], "degraded");
    assert_eq!(json["exit_code"], 2);
    
    // Check panic details
    assert!(json["check_panics_count"].as_u64().unwrap() > 0);
    
    let panics = json["check_panics"].as_array().unwrap();
    assert!(panics.len() > 0);
    
    let panic = &panics[0];
    assert!(panic["file"].as_str().is_some());
    assert!(panic["check_name"].as_str().is_some());
    assert!(panic["panic_message"].as_str().is_some());
}

#[test]
fn test_panic_reported_in_sarif_output() {
    let tmp = TempDir::new().unwrap();
    let project = tmp.path();
    setup_panic_triggering_project(project);
    
    let mut cmd = Command::cargo_bin("guard-cli").unwrap();
    let assert = cmd
        .args(&["scan", "--format", "sarif", project.to_str().unwrap()])
        .assert()
        .failure()
        .code(2);
    
    let output = assert.get_output();
    let sarif: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    
    // Check invocation status
    let invocation = &sarif["runs"][0]["invocations"][0];
    assert_eq!(invocation["executionSuccessful"], false);
    
    // Check notifications
    let notifications = invocation["toolExecutionNotifications"].as_array().unwrap();
    assert!(notifications.len() > 0);
    
    let notification = &notifications[0];
    assert_eq!(notification["level"], "error");
    assert!(notification["message"]["text"].as_str().unwrap().contains("panicked"));
}

#[test]
fn test_exit_code_on_panic() {
    let tmp = TempDir::new().unwrap();
    let project = tmp.path();
    setup_panic_triggering_project(project);
    
    Command::cargo_bin("guard-cli")
        .unwrap()
        .args(&["scan", project.to_str().unwrap()])
        .assert()
        .code(2);  // Exit code 2 for degraded scan
}

#[test]
fn test_exit_code_on_findings() {
    let tmp = TempDir::new().unwrap();
    let project = tmp.path();
    setup_project_with_vulnerabilities(project);
    
    Command::cargo_bin("guard-cli")
        .unwrap()
        .args(&["scan", project.to_str().unwrap()])
        .assert()
        .code(1);  // Exit code 1 for findings
}

#[test]
fn test_exit_code_on_clean_scan() {
    let tmp = TempDir::new().unwrap();
    let project = tmp.path();
    setup_clean_project(project);
    
    Command::cargo_bin("guard-cli")
        .unwrap()
        .args(&["scan", project.to_str().unwrap()])
        .assert()
        .code(0);  // Exit code 0 for clean scan
}

#[test]
fn test_panic_and_findings_both_reported() {
    let tmp = TempDir::new().unwrap();
    let project = tmp.path();
    
    // Create project with BOTH a panic-triggering file AND a vulnerability
    setup_mixed_project(project);
    
    let mut cmd = Command::cargo_bin("guard-cli").unwrap();
    let assert = cmd
        .args(&["scan", project.to_str().unwrap()])
        .assert()
        .failure()
        .code(2);  // Degraded scan takes precedence
    
    let output = assert.get_output();
    let stdout = String::from_utf8_lossy(&output.stdout);
    
    // Should show BOTH panics and findings
    assert!(stdout.contains("WARNING: Some security checks failed"));
    assert!(stdout.contains("security issue"));
}

// Helper functions

fn setup_panic_triggering_project(path: &Path) {
    fs::create_dir_all(path.join("src")).unwrap();
    
    // Create a file with syntax that triggers a known check panic
    // (This would need to be tailored to actual Guard-CLI checks)
    fs::write(
        path.join("src/lib.rs"),
        r#"
        // Intentionally malformed code that triggers a check panic
        pub fn trigger_panic() {
            // Add code that causes a specific check to panic
        }
        "#
    ).unwrap();
}

fn setup_project_with_vulnerabilities(path: &Path) {
    fs::create_dir_all(path.join("src")).unwrap();
    fs::write(
        path.join("src/lib.rs"),
        r#"
        #[no_mangle]
        pub extern "C" fn unsafe_transfer() {
            // Known vulnerability pattern
        }
        "#
    ).unwrap();
}

fn setup_clean_project(path: &Path) {
    fs::create_dir_all(path.join("src")).unwrap();
    fs::write(
        path.join("src/lib.rs"),
        r#"
        pub fn safe_function() {
            // Clean code
        }
        "#
    ).unwrap();
}

fn setup_mixed_project(path: &Path) {
    fs::create_dir_all(path.join("src")).unwrap();
    
    // File that causes panic
    fs::write(path.join("src/panic.rs"), "/* panic trigger */").unwrap();
    
    // File with vulnerability
    fs::write(
        path.join("src/vuln.rs"),
        "#[no_mangle] pub extern \"C\" fn unsafe_transfer() {}"
    ).unwrap();
}
```

### Integration Tests with Analyzer

**File:** `crates/analyzer/tests/check_panic_simulation.rs`

```rust
use guard_analyzer::*;
use std::path::Path;

struct PanickingCheck;

impl SecurityCheck for PanickingCheck {
    fn check(&self, _file: &Path, _ast: &SyntaxTree) -> Vec<Finding> {
        panic!("Intentional test panic: simulating check failure");
    }
    
    fn name(&self) -> &str {
        "panicking_check"
    }
}

#[test]
fn test_analyzer_catches_panic_and_returns_it() {
    let tmp = tempfile::tempdir().unwrap();
    let project = tmp.path();
    std::fs::write(project.join("lib.rs"), "pub fn test() {}").unwrap();
    
    let checks: Vec<Box<dyn SecurityCheck>> = vec![
        Box::new(PanickingCheck),
    ];
    
    let result = scan_directory_with_checks(project, checks, &[]);
    
    assert!(result.is_ok(), "Analyzer should catch panics and return them");
    
    let (findings, files_scanned, files_skipped, check_panics) = result.unwrap();
    
    assert_eq!(files_scanned, 1, "Should have scanned 1 file");
    assert_eq!(check_panics.len(), 1, "Should have 1 panic record");
    
    let panic = &check_panics[0];
    assert_eq!(panic.check_name, "panicking_check");
    assert!(panic.panic_message.contains("Intentional test panic"));
    assert!(panic.file.ends_with("lib.rs"));
}

#[test]
fn test_panic_in_one_check_doesnt_stop_other_checks() {
    let tmp = tempfile::tempdir().unwrap();
    let project = tmp.path();
    std::fs::write(project.join("lib.rs"), "pub fn test() {}").unwrap();
    
    struct WorkingCheck;
    impl SecurityCheck for WorkingCheck {
        fn check(&self, _file: &Path, _ast: &SyntaxTree) -> Vec<Finding> {
            vec![] // No findings, but runs successfully
        }
        fn name(&self) -> &str { "working_check" }
    }
    
    let checks: Vec<Box<dyn SecurityCheck>> = vec![
        Box::new(PanickingCheck),
        Box::new(WorkingCheck),
    ];
    
    let result = scan_directory_with_checks(project, checks, &[]);
    
    assert!(result.is_ok());
    
    let (_, _, _, check_panics) = result.unwrap();
    
    // Only one check panicked, the other completed successfully
    assert_eq!(check_panics.len(), 1);
    assert_eq!(check_panics[0].check_name, "panicking_check");
}
```

### CI Integration Test

Add to `.github/workflows/ci.yml`:

```yaml
- name: Test panic reporting
  run: |
    # Create a test project that triggers a check panic
    mkdir -p /tmp/test-panic/src
    echo "pub fn test() { /* trigger panic */ }" > /tmp/test-panic/src/lib.rs
    
    # Run scan and capture exit code
    set +e
    ./target/release/guard-cli scan /tmp/test-panic
    EXIT_CODE=$?
    set -e
    
    # Verify exit code is 2 (degraded scan), not 0
    if [ $EXIT_CODE -eq 0 ]; then
      echo "ERROR: Panic should produce exit code 2, got 0"
      exit 1
    fi
    
    if [ $EXIT_CODE -ne 2 ]; then
      echo "ERROR: Expected exit code 2, got $EXIT_CODE"
      exit 1
    fi
    
    echo "✓ Panic reporting works correctly"
```

---

## Implementation Steps

1. **Update main.rs line 139**
   - Remove underscore from `_check_panics`
   - Add `check_panics` parameter to output functions

2. **Update output_human function**
   - Add prominent warning banner for panics
   - Report panic details before findings
   - Update status message based on panics

3. **Update output_json function**
   - Add `scan_status` field
   - Add `check_panics` array
   - Add `check_panics_count` field
   - Include `exit_code` in output

4. **Update build_sarif function**
   - Set `executionSuccessful` based on panics
   - Add `toolExecutionNotifications` for panics

5. **Update exit code logic**
   - Return 2 when panics exist
   - Return 1 when findings exist (no panics)
   - Return 0 when clean (no panics, no findings)

6. **Update CLI help text**
   - Document exit codes clearly
   - Explain degraded scan concept

7. **Write comprehensive tests**
   - Unit tests for all three output formats
   - Integration tests with analyzer
   - CI tests for exit codes

8. **Update documentation**
   - README with exit code table
   - CI integration guide
   - Troubleshooting guide for check panics

---

## Acceptance Criteria

- [ ] Check panics appear in human-readable output with warning banner
- [ ] Check panics appear in JSON output with `scan_status: "degraded"`
- [ ] Check panics appear in SARIF output as `toolExecutionNotifications`
- [ ] SARIF `executionSuccessful` is `false` when panics occur
- [ ] Exit code 2 when checks panic (degraded scan)
- [ ] Exit code 1 when issues found (normal scan)
- [ ] Exit code 0 when clean scan (no issues, no panics)
- [ ] CLI help documents all three exit codes clearly
- [ ] Tests cover all three output formats
- [ ] Tests verify exit code behavior for all scenarios
- [ ] CI tests prevent regression
- [ ] Documentation explains degraded scan concept

---

## Expected Output Examples

### Human-Readable Output (Degraded Scan)

```
======================================================================
Guard-CLI Security Scan Results
======================================================================

⚠️  WARNING: Some security checks failed to complete
----------------------------------------------------------------------
The scan results below are INCOMPLETE.
Fix these check errors and re-scan.

1. Check Failure
   File:  src/contract.rs
   Check: reentrancy_detector
   Error: thread 'main' panicked at 'attempted to access invalid AST node'

2. Check Failure
   File:  src/token.rs
   Check: overflow_checker
   Error: thread 'main' panicked at 'division by zero'

----------------------------------------------------------------------

❌ Found 3 security issue(s):

  [HIGH] unsafe-transfer
  Unsafe token transfer without validation
  → src/transfer.rs:45:8
  💡 Suggestion: Add recipient validation before transfer

  [MEDIUM] missing-auth
  Missing authorization check
  → src/admin.rs:12:4

  [LOW] unused-variable
  Unused variable may indicate incomplete logic
  → src/util.rs:67:9

----------------------------------------------------------------------
Scan Statistics:
  Files scanned: 15
  Files skipped: 3
  Check failures: 2 ⚠️
======================================================================

⚠️  SCAN INCOMPLETE - Exit code 2
Fix check errors listed above and re-run the scan.
```

### JSON Output (Degraded Scan)

```json
{
  "scan_status": "degraded",
  "files_scanned": 15,
  "files_skipped": 3,
  "issues_count": 3,
  "check_panics_count": 2,
  "issues": [
    {
      "severity": "High",
      "rule_id": "unsafe-transfer",
      "message": "Unsafe token transfer without validation",
      "file": "src/transfer.rs",
      "line": 45,
      "column": 8,
      "suggestion": "Add recipient validation before transfer",
      "function_name": "transfer_tokens"
    }
  ],
  "check_panics": [
    {
      "file": "src/contract.rs",
      "check_name": "reentrancy_detector",
      "panic_message": "thread 'main' panicked at 'attempted to access invalid AST node'"
    },
    {
      "file": "src/token.rs",
      "check_name": "overflow_checker",
      "panic_message": "thread 'main' panicked at 'division by zero'"
    }
  ],
  "exit_code": 2
}
```

### SARIF Output (Degraded Scan)

```json
{
  "version": "2.1.0",
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "runs": [{
    "tool": {
      "driver": {
        "name": "Guard-CLI",
        "version": "1.0.0"
      }
    },
    "results": [
      {
        "ruleId": "unsafe-transfer",
        "level": "error",
        "message": {
          "text": "Unsafe token transfer without validation"
        },
        "locations": [{
          "physicalLocation": {
            "artifactLocation": {
              "uri": "src/transfer.rs"
            },
            "region": {
              "startLine": 45,
              "startColumn": 8
            }
          }
        }]
      }
    ],
    "invocations": [{
      "executionSuccessful": false,
      "toolExecutionNotifications": [
        {
          "level": "error",
          "message": {
            "text": "Security check 'reentrancy_detector' panicked: thread 'main' panicked at 'attempted to access invalid AST node'"
          },
          "locations": [{
            "physicalLocation": {
              "artifactLocation": {
                "uri": "src/contract.rs"
              }
            }
          }]
        },
        {
          "level": "error",
          "message": {
            "text": "Security check 'overflow_checker' panicked: thread 'main' panicked at 'division by zero'"
          },
          "locations": [{
            "physicalLocation": {
              "artifactLocation": {
                "uri": "src/token.rs"
              }
            }
          }]
        }
      ]
    }]
  }]
}
```

### Clean Scan Output

```
======================================================================
Guard-CLI Security Scan Results
======================================================================

✅ No security issues found

----------------------------------------------------------------------
Scan Statistics:
  Files scanned: 15
  Files skipped: 3
======================================================================

✅ SCAN PASSED - Exit code 0
No security issues detected.
```

---

## CI/CD Integration Guide

### GitHub Actions

```yaml
# .github/workflows/security-scan.yml

name: Security Scan

on: [push, pull_request]

jobs:
  guard-cli:
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v3
      
      - name: Install Guard-CLI
        run: |
          cargo install guard-cli
      
      - name: Run Security Scan
        run: |
          guard-cli scan . --format sarif > results.sarif
          EXIT_CODE=$?
          
          # Exit code 0: Clean scan - proceed
          # Exit code 1: Issues found - fail
          # Exit code 2: Degraded scan - fail
          
          if [ $EXIT_CODE -eq 2 ]; then
            echo "❌ Security scan incomplete - check errors occurred"
            exit 1
          fi
          
          if [ $EXIT_CODE -eq 1 ]; then
            echo "❌ Security issues found"
            exit 1
          fi
          
          echo "✅ Security scan passed"
      
      - name: Upload SARIF to GitHub Security
        if: always()
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: results.sarif
```

### GitLab CI

```yaml
# .gitlab-ci.yml

security_scan:
  stage: test
  image: rust:latest
  
  before_script:
    - cargo install guard-cli
  
  script:
    - guard-cli scan . --format json > results.json
    - |
      EXIT_CODE=$?
      if [ $EXIT_CODE -eq 2 ]; then
        echo "Security scan incomplete - check errors occurred"
        exit 1
      fi
      if [ $EXIT_CODE -eq 1 ]; then
        echo "Security issues found"
        exit 1
      fi
  
  artifacts:
    reports:
      security: results.json
    when: always
```

### Jenkins

```groovy
pipeline {
    agent any
    
    stages {
        stage('Security Scan') {
            steps {
                script {
                    def exitCode = sh(
                        script: 'guard-cli scan . --format json > results.json',
                        returnStatus: true
                    )
                    
                    if (exitCode == 2) {
                        error("Security scan incomplete - check errors occurred")
                    } else if (exitCode == 1) {
                        error("Security issues found")
                    }
                }
            }
        }
    }
    
    post {
        always {
            archiveArtifacts artifacts: 'results.json', allowEmptyArchive: true
        }
    }
}
```

---

## Documentation Updates

### README.md

Add section on exit codes:

```markdown
## Exit Codes

Guard-CLI uses exit codes to indicate the scan result:

| Exit Code | Meaning | CI Behavior |
|-----------|---------|-------------|
| 0 | Clean scan | ✅ Pass - No issues found, all checks completed successfully |
| 1 | Issues found | ❌ Fail - Security vulnerabilities detected |
| 2 | Degraded scan | ❌ Fail - Some security checks failed to complete |

### Exit Code 2: Degraded Scan

When a security check panics or fails to complete, the scan is marked as "degraded". This means:

- **The results are incomplete** - Some checks did not run
- **Vulnerabilities may have been missed** - The failed checks could have detected issues
- **CI should fail** - Exit code 2 should block deployment

**What to do:**

1. Review the check panic errors in the output
2. Fix the underlying issue (usually a check bug or incompatible code pattern)
3. Re-run the scan to get complete results

**Common causes of check panics:**

- Check bugs (report these as Guard-CLI issues)
- Unexpected code patterns that checks don't handle
- Corrupted or malformed source files
- Resource exhaustion (stack overflow, out of memory)
```

### TROUBLESHOOTING.md

```markdown
## Check Panics

### What is a check panic?

A check panic occurs when a security check fails unexpectedly while analyzing a file. This is different from finding a security issue - it means the check itself crashed.

### How to identify check panics

**Human output:**
```
⚠️  WARNING: Some security checks failed to complete
```

**JSON output:**
```json
{
  "scan_status": "degraded",
  "check_panics_count": 1
}
```

**Exit code:** 2 (degraded scan)

### What to do

1. **Check if it's a known issue**
   - Search Guard-CLI issues for the check name
   - Look for similar panic messages

2. **Report the panic**
   - Include the full panic message
   - Include the file that triggered it (if not sensitive)
   - Include your Guard-CLI version

3. **Workaround (temporary)**
   - If the panic is in a specific check, you may be able to disable that check
   - Fix the scan to pass, but note that security coverage is reduced

4. **Wait for fix**
   - Check panics are bugs and will be fixed
   - Update Guard-CLI regularly to get fixes

### Examples

**Example 1: AST parsing error**
```
Check: reentrancy_detector
Error: attempted to access invalid AST node
```

This usually means the check has a bug with certain code patterns. Report it.

**Example 2: Resource exhaustion**
```
Check: control_flow_analyzer
Error: thread 'main' panicked at 'stack overflow'
```

This may be caused by deeply nested code. Try refactoring the code or report the issue.
```

---

## Security Impact Assessment

### Before Fix

| Scenario | Current Behavior | Security Impact |
|----------|------------------|-----------------|
| Check panics on file | Exit 0, "No issues found" | ❌ **Critical** - False sense of security |
| Multiple checks panic | Exit 0, "No issues found" | ❌ **Critical** - Multiple blind spots |
| Panic + findings | Exit 1, findings shown | ⚠️ **High** - Some issues found, but incomplete |
| CI gate | Passes (exit 0 or 1) | ❌ **Critical** - Vulnerable code deployed |
| Operator visibility | None | ❌ **Critical** - No way to detect problem |

### After Fix

| Scenario | New Behavior | Security Impact |
|----------|--------------|-----------------|
| Check panics on file | Exit 2, panic reported | ✅ **Fixed** - CI fails, operator alerted |
| Multiple checks panic | Exit 2, all panics listed | ✅ **Fixed** - Full visibility |
| Panic + findings | Exit 2, both reported | ✅ **Fixed** - Degraded scan fails CI |
| CI gate | Fails (exit 2) | ✅ **Fixed** - Deployment blocked |
| Operator visibility | Full panic details in all formats | ✅ **Fixed** - Can diagnose and fix |

---

## Related Issues

- **Issue #659:** Original issue for panic handling (marked closed but incomplete)
  - Analyzer implementation: ✅ Done
  - CLI integration: ❌ Not done (this issue)

---

## Implementation Timeline

### Day 1-2: Core Implementation
- Remove `_check_panics` underscore
- Update output functions with panic parameter
- Implement exit code logic

### Day 3: Output Formatting
- Update human-readable output with warning banner
- Update JSON output with panic fields
- Update SARIF output with notifications

### Day 4: Testing
- Write unit tests for all output formats
- Write integration tests with analyzer
- Write CI tests for exit codes

### Day 5: Documentation & Review
- Update CLI help text
- Update README with exit codes
- Write troubleshooting guide
- Code review and refinement

**Total Timeline:** 1 week

---

## Success Metrics

After this fix is deployed, the following metrics should be tracked:

1. **Zero false negatives:** No degraded scans reported as clean (exit 0)
2. **100% panic visibility:** All check panics visible in all output formats
3. **CI gate effectiveness:** Exit code 2 blocks deployment in all CI systems
4. **Operator awareness:** Check panic reports enable debugging and fixes

---

## Conclusion

This is a **critical security regression** that must be fixed immediately. The fix is straightforward:

1. Use the `check_panics` data that's already available
2. Report it in all output formats
3. Exit with code 2 to fail CI gates

The impact is high (security tool reporting incomplete scans as successful), but the fix is low-risk (doesn't change analyzer behavior, only CLI reporting).

**Priority: P0 - Fix before next release**
