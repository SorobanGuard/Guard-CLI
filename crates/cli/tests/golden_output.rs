//! Golden-file tests for the machine-readable scan outputs (Issue #608).
//!
//! `scan test-contracts/vulnerable` is run through the real binary in each
//! structured format and compared byte-for-byte with `tests/golden/`. Path
//! separators and line endings are normalised so the files match on every OS.

use std::path::{Path, PathBuf};
use std::process::Command;

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn normalise(text: &str) -> String {
    text.replace("\r\n", "\n").replace('\\', "/")
}

fn scan_vulnerable(format_flag: &str) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-guard"))
        .current_dir(workspace_root())
        .args(["scan", "test-contracts/vulnerable", format_flag])
        .env("NO_COLOR", "1")
        .output()
        .expect("failed to run soroban-guard");
    // Exit code 1 is expected: the fixture has High findings.
    assert_eq!(
        output.status.code(),
        Some(1),
        "unexpected exit status; stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    normalise(&String::from_utf8(output.stdout).expect("stdout is UTF-8"))
}

fn assert_matches_golden(format_flag: &str, golden_file: &str) {
    let golden_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/golden")
        .join(golden_file);
    let expected = normalise(
        &std::fs::read_to_string(&golden_path)
            .unwrap_or_else(|e| panic!("reading {}: {e}", golden_path.display())),
    );
    let actual = scan_vulnerable(format_flag);
    assert!(
        actual == expected,
        "`scan test-contracts/vulnerable {format_flag}` no longer matches {}.\n\
         If the change is intended, update the golden file.\n--- expected\n{expected}\n--- actual\n{actual}",
        golden_path.display()
    );
}

#[test]
fn json_output_matches_golden() {
    assert_matches_golden("--json", "scan-vulnerable.json");
}

#[test]
fn sarif_output_matches_golden() {
    assert_matches_golden("--sarif", "scan-vulnerable.sarif");
}

#[test]
fn markdown_output_matches_golden() {
    assert_matches_golden("--markdown", "scan-vulnerable.md");
}

/// Golden test for `explain <check> --json` (Issue #881).
///
/// Asserts the JSON object exposes exactly the documented keys so editors and
/// dashboards can rely on a stable shape, and that it is sourced from the same
/// `CheckMeta` data used by the text output.
#[test]
fn explain_json_matches_golden() {
    let golden_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/golden")
        .join("explain-json.json");
    let expected = normalise(
        &std::fs::read_to_string(&golden_path)
            .unwrap_or_else(|e| panic!("reading {}: {e}", golden_path.display())),
    );

    let output = Command::new(env!("CARGO_BIN_EXE_soroban-guard"))
        .current_dir(workspace_root())
        .args(["explain", "unprotected-upgrade", "--json"])
        .env("NO_COLOR", "1")
        .output()
        .expect("failed to run soroban-guard");
    assert_eq!(
        output.status.code(),
        Some(0),
        "unexpected exit status; stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let actual = normalise(&String::from_utf8(output.stdout).expect("stdout is UTF-8"));
    assert!(
        actual == expected,
        "`explain unprotected-upgrade --json` no longer matches {}.\n\
         If the change is intended, update the golden file.\n--- expected\n{expected}\n--- actual\n{actual}",
        golden_path.display()
    );
}

/// Unknown checks must exit `2` and, with `--json`, emit a JSON error object
/// (consistent with #670).
#[test]
fn explain_json_unknown_check_errors() {
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-guard"))
        .current_dir(workspace_root())
        .args(["explain", "definitely-not-a-check", "--json"])
        .env("NO_COLOR", "1")
        .output()
        .expect("failed to run soroban-guard");
    assert_eq!(
        output.status.code(),
        Some(2),
        "unknown check should exit 2; stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("stdout is UTF-8");
    let value: serde_json::Value =
        serde_json::from_str(&stdout).expect("stdout should be a JSON error object");
    assert!(
        value.get("error").is_some(),
        "JSON error object should contain an `error` field, got: {stdout}"
    );
}
