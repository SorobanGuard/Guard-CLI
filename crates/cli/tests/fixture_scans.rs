use soroban_guard_analyzer::scan_directory;
use std::path::PathBuf;

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("test-contracts")
        .join(name)
}

fn assert_fixture_pair(base: &str, expected_check: &str) {
    let (vulnerable, _) = scan_directory(&fixture_path(&format!("{base}-vulnerable")), &[], false, None)
        .unwrap_or_else(|error| panic!("failed to scan {base}-vulnerable: {error}"));
    assert!(
        vulnerable
            .iter()
            .any(|finding| finding.check_name == expected_check),
        "{base}-vulnerable did not produce {expected_check}; findings: {vulnerable:#?}"
    );

    let (safe, _) = scan_directory(&fixture_path(&format!("{base}-safe")), &[], false, None)
        .unwrap_or_else(|error| panic!("failed to scan {base}-safe: {error}"));
    assert!(
        safe.iter()
            .all(|finding| finding.check_name != expected_check),
        "{base}-safe unexpectedly produced {expected_check}; findings: {safe:#?}"
    );
}

#[test]
fn missing_require_auth_fixtures() {
    let (vulnerable, _) = scan_directory(&fixture_path("vulnerable"), &[], false, None)
        .unwrap_or_else(|error| panic!("failed to scan vulnerable: {error}"));
    assert!(
        vulnerable
            .iter()
            .any(|finding| finding.check_name == "missing-require-auth"),
        "vulnerable did not produce missing-require-auth; findings: {vulnerable:#?}"
    );

    let (safe, _) = scan_directory(&fixture_path("safe"), &[], false, None)
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
fn storage_fixtures() {
    assert_fixture_pair("storage", "unsafe-storage-patterns");
}

#[test]
fn zero_address_fixtures() {
    assert_fixture_pair("zero-address", "missing-zero-address-check");
}
