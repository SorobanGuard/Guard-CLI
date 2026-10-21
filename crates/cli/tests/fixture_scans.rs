use soroban_guard_analyzer::{scan_directory, scan_directory_with_checks};
use soroban_guard_checks::default_checks_with_config;
use std::path::PathBuf;
use std::process::Command;

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

/// Runs the CLI binary with `--json` over the given fixture and returns the
/// parsed JSON document. Panics with the fixture name on any failure.
fn run_cli_json(fixture: &str) -> serde_json::Value {
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-guard"))
        .arg("scan")
        .arg(fixture_path(fixture))
        .arg("--json")
        .output()
        .unwrap_or_else(|error| panic!("failed to run CLI on {fixture}: {error}"));
    assert!(
        output.status.success(),
        "CLI failed on {fixture}: status {:?}, stderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|error| panic!("CLI emitted invalid JSON for {fixture}: {error}"))
}

/// Asserts that `value` at `pointer` is a JSON integer (not a float/string).
fn assert_integer(doc: &serde_json::Value, fixture: &str, pointer: &str) {
    let value = doc
        .pointer(pointer)
        .unwrap_or_else(|| panic!("{fixture}: missing JSON pointer {pointer}"));
    assert!(
        value.is_i64() || value.is_u64(),
        "{fixture}: JSON pointer {pointer} must be an integer, got {value}"
    );
}

/// Asserts that `value` at `pointer` is a JSON string.
fn assert_string(doc: &serde_json::Value, fixture: &str, pointer: &str) {
    let value = doc
        .pointer(pointer)
        .unwrap_or_else(|| panic!("{fixture}: missing JSON pointer {pointer}"));
    assert!(
        value.is_string(),
        "{fixture}: JSON pointer {pointer} must be a string, got {value}"
    );
}

/// Validates a single `--json` document against the field types documented in
/// `docs/json-schema.md`. Hand-rolled assertions only; no schema crate.
fn assert_json_schema(fixture: &str, doc: &serde_json::Value) {
    // summary.* integers
    assert_integer(doc, fixture, "/summary/total");
    assert_integer(doc, fixture, "/summary/high");
    assert_integer(doc, fixture, "/summary/medium");
    assert_integer(doc, fixture, "/summary/low");

    // findings[] array with documented field types
    let findings = doc
        .pointer("/findings")
        .unwrap_or_else(|| panic!("{fixture}: missing JSON pointer /findings"));
    let findings = findings
        .as_array()
        .unwrap_or_else(|| panic!("{fixture}: /findings must be an array"));

    for (index, finding) in findings.iter().enumerate() {
        let base = format!("/findings/{index}");
        assert_string(doc, fixture, &format!("{base}/check_name"));
        assert_string(doc, fixture, &format!("{base}/message"));
        assert_string(doc, fixture, &format!("{base}/file_path"));
        assert_integer(doc, fixture, &format!("{base}/line"));

        let severity = finding
            .pointer("/severity")
            .unwrap_or_else(|| panic!("{fixture}: missing JSON pointer {base}/severity"));
        let severity = severity
            .as_str()
            .unwrap_or_else(|| panic!("{fixture}: {base}/severity must be a string"));
        assert!(
            matches!(severity, "High" | "Medium" | "Low"),
            "{fixture}: {base}/severity must be one of High, Medium, Low; got {severity}"
        );
    }
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
    assert_fixture_pair("input-length", "missing-input-length-check");
}

/// Every vulnerable fixture's `--json` output must validate against the field
/// types documented in `docs/json-schema.md`.
#[test]
fn json_output_matches_documented_schema_for_all_fixtures() {
    let fixtures = [
        "vulnerable",
        "admin-vulnerable",
        "arithmetic-vulnerable",
        "division-vulnerable",
        "global-state-vulnerable",
        "panic-vulnerable",
        "reentrancy-vulnerable",
        "contract-deployment-vulnerable",
        "token-amount-vulnerable",
        "upgrade-vulnerable",
        "delegate-vulnerable",
        "self-transfer-vulnerable",
        "std-imports-vulnerable",
        "contract-annotation-vulnerable",
        "key-collision-vulnerable",
        "storage-vulnerable",
        "auth-order-vulnerable",
        "token-mint-vulnerable",
        "vec-growth-vulnerable",
        "invoke-return-vulnerable",
        "event-vulnerable",
        "admin-event-vulnerable",
        "nonce-vulnerable",
        "zero-address-vulnerable",
        "uninitialized-storage-read-vulnerable",
        "ttl-vulnerable",
        "input-length-vulnerable",
    ];

    for fixture in fixtures {
        let doc = run_cli_json(fixture);
        assert_json_schema(fixture, &doc);
    }
}
