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
    scan_vulnerable_with(format_flag, &[])
}

fn scan_vulnerable_with(format_flag: &str, extra_args: &[&str]) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-guard"))
        .current_dir(workspace_root())
        .args(["scan", "test-contracts/vulnerable", format_flag])
        .args(extra_args)
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
    assert_matches_golden_with(format_flag, &[], golden_file);
}

fn assert_matches_golden_with(format_flag: &str, extra_args: &[&str], golden_file: &str) {
    let golden_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/golden")
        .join(golden_file);
    let expected = normalise(
        &std::fs::read_to_string(&golden_path)
            .unwrap_or_else(|e| panic!("reading {}: {e}", golden_path.display())),
    );
    let actual = scan_vulnerable_with(format_flag, extra_args);
    assert!(
        actual == expected,
        "`scan test-contracts/vulnerable {format_flag} {}` no longer matches {}.\n\
         If the change is intended, update the golden file.\n--- expected\n{expected}\n--- actual\n{actual}",
        extra_args.join(" "),
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

#[test]
fn json_output_sorted_by_severity_matches_golden() {
    assert_matches_golden_with(
        "--json",
        &["--sort-by", "severity"],
        "scan-vulnerable-sort-severity.json",
    );
}

#[test]
fn json_output_sorted_by_check_matches_golden() {
    assert_matches_golden_with(
        "--json",
        &["--sort-by", "check"],
        "scan-vulnerable-sort-check.json",
    );
}
