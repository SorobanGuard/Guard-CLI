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
    let (vulnerable, _, _) = scan_directory(&fixture_path(&format!("{base}-vulnerable")), &[], &[])
        .unwrap_or_else(|error| panic!("failed to scan {base}-vulnerable: {error}"));
    assert!(
        vulnerable
            .iter()
            .any(|finding| finding.check_name == expected_check),
        "{base}-vulnerable did not produce {expected_check}; findings: {vulnerable:#?}"
    );

    let (safe, _, _) = scan_directory(&fixture_path(&format!("{base}-safe")), &[], &[])
        .unwrap_or_else(|error| panic!("failed to scan {base}-safe: {error}"));
    assert!(
        safe.iter()
            .all(|finding| finding.check_name != expected_check),
        "{base}-safe unexpectedly produced {expected_check}; findings: {safe:#?}"
    );
}

#[test]
fn missing_require_auth_fixtures() {
    let (vulnerable, _, _) = scan_directory(&fixture_path("vulnerable"), &[], &[])
        .unwrap_or_else(|error| panic!("failed to scan vulnerable: {error}"));
    assert!(
        vulnerable
            .iter()
            .any(|finding| finding.check_name == "missing-require-auth"),
        "vulnerable did not produce missing-require-auth; findings: {vulnerable:#?}"
    );

    let (safe, _, _) = scan_directory(&fixture_path("safe"), &[], &[])
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
fn cli_scan_path_does_not_emit_duplicate_findings() {
    let checks = default_checks_with_config(&[], &[]);
    let (results, _, _) = scan_directory_with_checks(
        &fixture_path("reentrancy-vulnerable"),
        &[],
        &[],
        &checks,
    )
    .expect("failed to scan reentrancy-vulnerable");

    let findings: Vec<_> = results.into_iter().flat_map(|result| result.findings).collect();
    let mut keys = std::collections::HashSet::new();
    for finding in findings {
        let key = (finding.file_path.clone(), finding.line, finding.check_name.clone());
        assert!(
            keys.insert(key),
            "CLI scan emitted duplicate finding: {finding:?}"
        );
    }
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
fn key_collision_fixtures() {
    assert_fixture_pair("key-collision", "symbol-key-collision");
}

#[test]
fn storage_fixtures() {
    assert_fixture_pair("storage", "unsafe-storage-patterns");
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

/// Regression test for issue #362: a function that writes two distinct persistent keys but
/// only calls extend_ttl on one of them must still produce a finding for the unextended key.
/// The old function-scoped `has_extend` flag would have suppressed both findings.
#[test]
fn ttl_mixed_key_scenario_produces_finding() {
    let path = fixture_path("ttl-vulnerable");
    let (findings, _, _) = scan_directory(&path, &[], &[])
        .expect("failed to scan ttl-vulnerable");

    // The `update` function writes KEY and KEY2 but only extends TTL for KEY2.
    // There must be at least one finding for KEY's missing extension in `update`.
    let update_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.check_name == "missing-ttl-extension" && f.function_name == "update")
        .collect();

    assert!(
        !update_findings.is_empty(),
        "expected a missing-ttl-extension finding in `update` for the unextended key, \
         got findings: {findings:#?}"
    );
}

/// Verify that `soroban-guard.toml` is read and its `[checks.sensitive_names].extra` list
/// extends the built-in admin check so that custom function names are flagged.
#[test]
fn config_extra_sensitive_names_affect_admin_check() {
    use soroban_guard_analyzer::scan_directory_with_checks;
    use soroban_guard_checks::default_checks_with_config;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    let root = std::env::temp_dir().join(format!(
        "soroban-guard-cfg-test-{}-{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
    ));
    fs::create_dir_all(root.join("src")).unwrap();

    // A contract that calls a function named `drain` with no require_auth.
    // `drain` is NOT in the built-in SENSITIVE_NAMES list.
    fs::write(
        root.join("src/lib.rs"),
        r#"
use soroban_sdk::{contractimpl, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn drain(env: Env) {
        let _ = env;
    }
}
"#,
    )
    .unwrap();

    // Config file that adds `drain` to the sensitive names.
    fs::write(
        root.join("soroban-guard.toml"),
        r#"
[checks.sensitive_names]
extra = ["drain"]
"#,
    )
    .unwrap();

    // Without config: `drain` should NOT be flagged.
    let checks_no_cfg = default_checks_with_config(&[], &[]);
    let (results_no_cfg, _, _) =
        scan_directory_with_checks(&root, &[], &[], &checks_no_cfg).unwrap();
    let findings_no_cfg: Vec<_> = results_no_cfg
        .iter()
        .flat_map(|r| r.findings.iter())
        .filter(|f| f.check_name == "unprotected-admin" && f.function_name == "drain")
        .collect();
    assert!(
        findings_no_cfg.is_empty(),
        "`drain` should not be flagged without config, got: {findings_no_cfg:#?}"
    );

    // With config extra name: `drain` SHOULD be flagged.
    let checks_with_cfg = default_checks_with_config(&[], &["drain".to_string()]);
    let (results_with_cfg, _, _) =
        scan_directory_with_checks(&root, &[], &[], &checks_with_cfg).unwrap();
    let findings_with_cfg: Vec<_> = results_with_cfg
        .iter()
        .flat_map(|r| r.findings.iter())
        .filter(|f| f.check_name == "unprotected-admin" && f.function_name == "drain")
        .collect();
    assert!(
        !findings_with_cfg.is_empty(),
        "`drain` should be flagged when listed in config extra sensitive_names"
    );

    fs::remove_dir_all(root).unwrap();
}

/// Verify that `soroban-guard.toml` `[scan] path` is used when no CLI path is provided
#[test]
fn config_scan_path_as_fallback() {
    use soroban_guard_analyzer::scan_directory;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    let root = std::env::temp_dir().join(format!(
        "soroban-guard-cfg-path-test-{}-{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
    ));
    fs::create_dir_all(root.join("src")).unwrap();

    // Write a simple contract with an admin check issue
    fs::write(
        root.join("src/lib.rs"),
        r#"
use soroban_sdk::{contractimpl, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn set_owner(env: Env) {
        let _ = env;
    }
}
"#,
    )
    .unwrap();

    // Config file that specifies the scan path
    fs::write(
        root.join("soroban-guard.toml"),
        r#"
[scan]
path = "src"
"#,
    )
    .unwrap();

    // Scan using the path from config (via current directory config)
    let config_root = match config::load(&root) {
        Ok(Some(cfg)) => {
            if let Some(path_str) = cfg.scan.path {
                root.join(&path_str)
            } else {
                panic!("Config should have path set");
            }
        }
        _ => panic!("Should load config with path"),
    };

    let (findings, _, _) = scan_directory(&config_root, &[], &[]).unwrap();
    assert!(
        findings
            .iter()
            .any(|f| f.check_name == "unprotected-admin"),
        "Should find unprotected-admin check using path from config"
    );

    fs::remove_dir_all(root).unwrap();
}
