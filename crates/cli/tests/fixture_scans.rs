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

fn test_contracts_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("test-contracts")
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

/// Regression suite of real-world-shaped, idiomatic, *safe* contracts.
///
/// These fixtures live under `test-contracts/realistic/{token,amm,escrow,voting}`
/// and are modelled on the public Soroban examples (re-written, licence-compatible).
/// The goal is to measure the false-positive rate of the full default check set on
/// realistic code with helpers, nested blocks and idioms.
///
/// Acceptance criteria (#1022): the full default check set must report **zero High**
/// findings across all realistic fixtures. Any Medium/Low finding must be listed in
/// `REALISTIC_ALLOW_LIST` below, with a comment explaining why it is acceptable.
const REALISTIC_FIXTURES: &[&str] = &["token", "amm", "escrow", "voting"];

/// Documented allow-list of acceptable Medium/Low findings on the realistic fixtures.
///
/// Each entry is `(fixture, check_name)` and MUST be commented with the reason it is
/// tolerated. Keep this list as small as possible: a new entry here is a signal that
/// the corresponding check may be producing a false positive on realistic code.
const REALISTIC_ALLOW_LIST: &[(&str, &str)] = &[
    // ("token", "some-medium-check"), // reason: ...
];

fn is_high_severity(severity: &str) -> bool {
    severity.eq_ignore_ascii_case("high")
}

#[test]
fn realistic_fixtures_report_zero_high_findings() {
    let checks = default_checks_with_config(&[], &[]);

    for fixture in REALISTIC_FIXTURES {
        let path = fixture_path(&format!("realistic/{fixture}"));
        assert!(
            path.is_dir(),
            "realistic fixture `{fixture}` is missing at {path:?}"
        );

        let (results, _, _, panics) = scan_directory_with_checks(&path, &[], &[], &checks)
            .unwrap_or_else(|error| panic!("failed to scan realistic/{fixture}: {error}"));
        assert!(
            panics.is_empty(),
            "no check should panic on realistic/{fixture}; got: {panics:#?}"
        );

        let findings: Vec<_> = results
            .into_iter()
            .flat_map(|result| result.findings)
            .collect();

        let high: Vec<_> = findings
            .iter()
            .filter(|finding| is_high_severity(&finding.severity.to_string()))
            .collect();
        assert!(
            high.is_empty(),
            "realistic/{fixture} produced High findings (false positives): {high:#?}"
        );

        for finding in &findings {
            let allowed = REALISTIC_ALLOW_LIST.iter().any(|(allowed_fixture, allowed_check)| {
                *allowed_fixture == *fixture && *allowed_check == finding.check_name
            });
            assert!(
                allowed,
                "realistic/{fixture} produced undocumented finding `{}` ({}); \
                 add it to REALISTIC_ALLOW_LIST with a reason if it is acceptable: {finding:#?}",
                finding.check_name,
                finding.severity
            );
        }
    }
}
