use soroban_guard_analyzer::{scan_directory, scan_directory_with_checks};
use soroban_guard_checks::default_checks_with_config;
use std::path::PathBuf;

#[path = "../src/config.rs"]
mod config;

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("test-contracts")
        .join(name)
}

fn assert_fixture_pair(base: &str, expected_check: &str) {
    let (vulnerable, _, _, vulnerable_panics) =
        scan_directory(&fixture_path(&format!("{base}-vulnerable")), &[], &[])
            .unwrap_or_else(|error| panic!("failed to scan {base}-vulnerable: {error}"));
    assert!(
        vulnerable_panics.is_empty(),
        "no check should panic on {base}-vulnerable; got: {vulnerable_panics:#?}"
    );
    assert!(
        vulnerable
            .iter()
            .any(|finding| finding.check_name == expected_check),
        "{base}-vulnerable did not produce {expected_check}; findings: {vulnerable:#?}"
    );

    let (safe, _, _, safe_panics) =
        scan_directory(&fixture_path(&format!("{base}-safe")), &[], &[])
            .unwrap_or_else(|error| panic!("failed to scan {base}-safe: {error}"));
    assert!(
        safe_panics.is_empty(),
        "no check should panic on {base}-safe; got: {safe_panics:#?}"
    );
    assert!(
        safe.iter()
            .all(|finding| finding.check_name != expected_check),
        "{base}-safe unexpectedly produced {expected_check}; findings: {safe:#?}"
    );
}

#[test]
fn missing_require_auth_fixtures() {
    let (vulnerable, _, _, _) = scan_directory(&fixture_path("vulnerable"), &[], &[])
        .unwrap_or_else(|error| panic!("failed to scan vulnerable: {error}"));
    assert!(
        vulnerable
            .iter()
            .any(|finding| finding.check_name == "missing-require-auth"),
        "vulnerable did not produce missing-require-auth; findings: {vulnerable:#?}"
    );

    let (safe, _, _, _) = scan_directory(&fixture_path("safe"), &[], &[])
        .unwrap_or_else(|error| panic!("failed to scan safe: {error}"));
    assert!(
        safe.iter()
            .all(|finding| finding.check_name != "missing-require-auth"),
        "safe unexpectedly produced missing-require-auth; findings: {safe:#?}"
    );
}

#[test]
fn admin_fixtures() {
    assert_fixture_pair("admin", "unprotected-admin");
}

#[test]
fn arithmetic_fixtures() {
    assert_fixture_pair("arithmetic", "unchecked-arithmetic");
}

#[test]
fn division_fixtures() {
    assert_fixture_pair("division", "integer-division-truncation");
}

#[test]
fn global_state_fixtures() {
    assert_fixture_pair("global-state", "mutable-global-state");
}

#[test]
fn panic_fixtures() {
    assert_fixture_pair("panic", "panic-in-contract");
}

#[test]
fn reentrancy_fixtures() {
    assert_fixture_pair("reentrancy", "reentrancy-risk");
}

#[test]
fn contract_deployment_vulnerable_still_triggers_check() {
    let (findings, _, _, _) =
        scan_directory(&fixture_path("contract-deployment-vulnerable"), &[], &[]).unwrap_or_else(
            |error| panic!("failed to scan contract-deployment-vulnerable: {error}"),
        );
    assert!(
        findings
            .iter()
            .any(|f| f.check_name == "unprotected-contract-deployment"),
        "contract-deployment-vulnerable did not produce unprotected-contract-deployment; findings: {findings:#?}"
    );
}

#[test]
fn token_amount_vulnerable_still_triggers_check() {
    let (findings, _, _, _) = scan_directory(&fixture_path("token-amount-vulnerable"), &[], &[])
        .unwrap_or_else(|error| panic!("failed to scan token-amount-vulnerable: {error}"));
    assert!(
        findings
            .iter()
            .any(|f| f.check_name == "unchecked-token-amount"),
        "token-amount-vulnerable did not produce unchecked-token-amount; findings: {findings:#?}"
    );
}

#[test]
fn upgrade_vulnerable_still_triggers_check() {
    let (findings, _, _, _) = scan_directory(&fixture_path("upgrade-vulnerable"), &[], &[])
        .unwrap_or_else(|error| panic!("failed to scan upgrade-vulnerable: {error}"));
    assert!(
        findings
            .iter()
            .any(|f| f.check_name == "unprotected-upgrade"),
        "upgrade-vulnerable did not produce unprotected-upgrade; findings: {findings:#?}"
    );
}

#[test]
fn cli_scan_path_does_not_emit_duplicate_findings() {
    let checks = default_checks_with_config(&[], &[]);
    let (results, _, _, _) =
        scan_directory_with_checks(&fixture_path("reentrancy-vulnerable"), &[], &[], &checks)
            .expect("failed to scan reentrancy-vulnerable");

    let findings: Vec<_> = results
        .into_iter()
        .flat_map(|result| result.findings)
        .collect();
    let mut keys = std::collections::HashSet::new();
    for finding in findings {
        let key = (
            finding.file_path.clone(),
            finding.line,
            finding.check_name.clone(),
        );
        assert!(
            keys.insert(key),
            "CLI scan emitted duplicate finding: {finding:?}"
        );
    }
}

#[test]
fn delegate_call_risk_fixtures() {
    assert_fixture_pair("delegate", "delegate-call-risk");
}

#[test]
fn self_transfer_fixtures() {
    assert_fixture_pair("self-transfer", "self-transfer");
}

#[test]
fn std_imports_fixtures() {
    assert_fixture_pair("std-imports", "forbidden-std-imports");
}

#[test]
fn contract_annotation_fixtures() {
    assert_fixture_pair("contract-annotation", "missing-contract-annotation");
}

#[test]
fn key_collision_fixtures() {
    assert_fixture_pair("key-collision", "symbol-key-collision");
}

#[test]
fn storage_fixtures() {
    assert_fixture_pair("storage", "unsafe-storage-patterns");
}

#[test]
fn auth_order_fixtures() {
    assert_fixture_pair("auth-order", "auth-after-storage-write");
}

#[test]
fn token_mint_fixtures() {
    assert_fixture_pair("token-mint", "unprotected-token-mint");
}

#[test]
fn token_amount_fixtures() {
    assert_fixture_pair("token-amount", "unchecked-token-amount");
}

#[test]
fn contract_deployment_safe_produces_no_findings() {
    let (findings, _, _, _) = scan_directory(&fixture_path("contract-deployment-safe"), &[], &[])
        .unwrap_or_else(|error| panic!("failed to scan contract-deployment-safe: {error}"));
    assert!(
        findings
            .iter()
            .all(|f| f.check_name != "unprotected-contract-deployment"),
        "contract-deployment-safe unexpectedly produced unprotected-contract-deployment; findings: {findings:#?}"
    );
}

#[test]
fn upgrade_fixtures() {
    assert_fixture_pair("upgrade", "unprotected-upgrade");
}

#[test]
fn vec_growth_fixtures() {
    assert_fixture_pair("vec-growth", "unbounded-vec-growth");
}

#[test]
fn invoke_return_fixtures() {
    assert_fixture_pair("invoke-return", "unchecked-invoke-return");
}

#[test]
fn event_fixtures() {
    assert_fixture_pair("event", "missing-event-emission");
}

#[test]
fn admin_event_safe_produces_no_findings() {
    let (findings, _, _, _) = scan_directory(&fixture_path("admin-event-safe"), &[], &[])
        .unwrap_or_else(|error| panic!("failed to scan admin-event-safe: {error}"));
    assert!(
        findings
            .iter()
            .all(|f| f.check_name != "missing-event-for-admin-change"),
        "admin-event-safe unexpectedly produced missing-event-for-admin-change; findings: {findings:#?}"
    );
}

#[test]
fn admin_event_fixtures() {
    assert_fixture_pair("admin-event", "missing-event-for-admin-change");
}

#[test]
fn nonce_fixtures() {
    assert_fixture_pair("nonce", "missing-nonce");
}

#[test]
fn zero_address_fixtures() {
    assert_fixture_pair("zero-address", "missing-zero-address-check");
}

#[test]
fn uninitialized_storage_read_fixtures() {
    assert_fixture_pair("uninitialized-storage-read", "uninitialized-storage-read");
}

#[test]
fn ttl_fixtures() {
    assert_fixture_pair("ttl", "missing-ttl-extension");
}

#[test]
fn input_length_fixtures() {
    assert_fixture_pair("input-length", "missing-input-length-bound");
}

#[test]
fn large_loop_fixtures() {
    assert_fixture_pair("large-loop", "large-loop");
}

mod baseline_flow {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::Command;

    fn cli_binary() -> PathBuf {
        PathBuf::from(env!("CARGO_BIN_EXE_soroban-guard"))
    }

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "soroban-guard-baseline-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        fs::create_dir_all(&dir).expect("failed to create temp dir");
        dir
    }

    fn write_contract(dir: &Path, source: &str) -> PathBuf {
        let contract_dir = dir.join("contract");
        fs::create_dir_all(&contract_dir).expect("failed to create contract dir");
        let path = contract_dir.join("lib.rs");
        fs::write(&path, source).expect("failed to write contract");
        path
    }

    fn run_scan(args: &[&str]) -> std::process::Output {
        Command::new(cli_binary())
            .arg("scan")
            .args(args)
            .output()
            .expect("failed to run soroban-guard scan")
    }

    const BASELINE_SOURCE: &str = r#"
use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct Token;

#[contractimpl]
impl Token {
    pub fn set_admin(env: Env, admin: Address) {
        env.storage().instance().set(&"admin", &admin);
    }
}
"#;

    const MODIFIED_SOURCE: &str = r#"
use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct Token;

#[contractimpl]
impl Token {
    pub fn set_admin(env: Env, admin: Address) {
        env.storage().instance().set(&"admin", &admin);
    }

    pub fn transfer(env: Env, to: Address, amount: i128) {
        let total: i128 = 100;
        let _ = total + amount;
        let _ = to;
    }
}
"#;

    #[test]
    fn write_baseline_then_scan_reports_only_new_findings() {
        let dir = temp_dir("flow");
        let contract = write_contract(&dir, BASELINE_SOURCE);
        let baseline = dir.join("baseline.json");

        let write = run_scan(&[
            contract.to_str().unwrap(),
            "--write-baseline",
            baseline.to_str().unwrap(),
        ]);
        assert!(
            write.status.success(),
            "write-baseline failed: {}",
            String::from_utf8_lossy(&write.stderr)
        );
        assert!(baseline.exists(), "baseline file was not written");

        fs::write(&contract, MODIFIED_SOURCE).expect("failed to modify contract");

        let scan = run_scan(&[
            contract.to_str().unwrap(),
            "--baseline",
            baseline.to_str().unwrap(),
            "--format",
            "json",
        ]);
        assert!(
            scan.status.success(),
            "scan with baseline failed: {}",
            String::from_utf8_lossy(&scan.stderr)
        );
        let stdout = String::from_utf8_lossy(&scan.stdout);
        let json: serde_json::Value =
            serde_json::from_str(&stdout).expect("scan output was not valid JSON");

        let summary = json
            .get("summary")
            .expect("JSON output missing summary object");
        assert!(
            summary.get("hidden_count").is_some(),
            "JSON summary missing hidden_count: {summary}"
        );

        let findings = json
            .get("findings")
            .and_then(|value| value.as_array())
            .expect("JSON output missing findings array");
        assert!(
            !findings.is_empty(),
            "expected the newly introduced finding to be reported"
        );
        for finding in findings {
            let check = finding
                .get("check_name")
                .and_then(|value| value.as_str())
                .unwrap_or_default();
            assert_ne!(
                check, "missing-event-for-admin-change",
                "baselined finding was not hidden: {finding}"
            );
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn scan_exits_zero_when_only_baselined_findings_remain() {
        let dir = temp_dir("only-baselined");
        let contract = write_contract(&dir, BASELINE_SOURCE);
        let baseline = dir.join("baseline.json");

        let write = run_scan(&[
            contract.to_str().unwrap(),
            "--write-baseline",
            baseline.to_str().unwrap(),
        ]);
        assert!(
            write.status.success(),
            "write-baseline failed: {}",
            String::from_utf8_lossy(&write.stderr)
        );

        let scan = run_scan(&[
            contract.to_str().unwrap(),
            "--baseline",
            baseline.to_str().unwrap(),
            "--format",
            "json",
        ]);
        assert_eq!(
            scan.status.code(),
            Some(0),
            "expected exit 0 when only baselined findings remain; stderr: {}",
            String::from_utf8_lossy(&scan.stderr)
        );

        let stdout = String::from_utf8_lossy(&scan.stdout);
        let json: serde_json::Value =
            serde_json::from_str(&stdout).expect("scan output was not valid JSON");
        let summary = json
            .get("summary")
            .expect("JSON output missing summary object");
        assert!(
            summary.get("hidden_count").is_some(),
            "JSON summary missing hidden_count: {summary}"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_baseline_file_exits_two() {
        let dir = temp_dir("missing");
        let contract = write_contract(&dir, BASELINE_SOURCE);
        let baseline = dir.join("does-not-exist.json");

        let scan = run_scan(&[
            contract.to_str().unwrap(),
            "--baseline",
            baseline.to_str().unwrap(),
        ]);
        assert_eq!(
            scan.status.code(),
            Some(2),
            "expected exit 2 for missing baseline; stderr: {}",
            String::from_utf8_lossy(&scan.stderr)
        );
        let stderr = String::from_utf8_lossy(&scan.stderr);
        assert!(
            stderr.to_lowercase().contains("baseline"),
            "error message should mention the baseline: {stderr}"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn corrupt_baseline_file_exits_two() {
        let dir = temp_dir("corrupt");
        let contract = write_contract(&dir, BASELINE_SOURCE);
        let baseline = dir.join("baseline.json");
        fs::write(&baseline, "{ this is not valid json").expect("failed to write corrupt baseline");

        let scan = run_scan(&[
            contract.to_str().unwrap(),
            "--baseline",
            baseline.to_str().unwrap(),
        ]);
        assert_eq!(
            scan.status.code(),
            Some(2),
            "expected exit 2 for corrupt baseline; stderr: {}",
            String::from_utf8_lossy(&scan.stderr)
        );
        let stderr = String::from_utf8_lossy(&scan.stderr);
        assert!(
            stderr.to_lowercase().contains("baseline"),
            "error message should mention the baseline: {stderr}"
        );

        let _ = fs::remove_dir_all(&dir);
    }
}
