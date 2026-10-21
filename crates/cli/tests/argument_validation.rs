use std::process::Command;

fn run(arguments: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_soroban-guard"))
        .args(arguments)
        .env("NO_COLOR", "1")
        .output()
        .expect("failed to run soroban-guard")
}

#[test]
fn clap_rejects_multiple_output_formats() {
    let output = run(&["scan", ".", "--json", "--sarif"]);
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("cannot be used with"), "{stderr}");
    assert!(stderr.contains("--json"), "{stderr}");
    assert!(stderr.contains("--sarif"), "{stderr}");
}

#[test]
fn clap_rejects_output_without_structured_format() {
    let output = run(&["scan", ".", "--output", "findings.txt"]);
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("required"), "{stderr}");
    assert!(stderr.contains("--output"), "{stderr}");
}

#[test]
fn only_check_accepts_known_check() {
    let output = run(&["scan", ".", "--only-check", "panics"]);
    assert_ne!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.contains("unknown check"), "{stderr}");
}

#[test]
fn only_check_rejects_unknown_check() {
    let output = run(&["scan", ".", "--only-check", "not-a-real-check"]);
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("not-a-real-check"), "{stderr}");
}

#[test]
fn only_check_suggests_closest_name_for_typo() {
    let output = run(&["scan", ".", "--only-check", "panic"]);
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("did you mean"), "{stderr}");
    assert!(stderr.contains("panics"), "{stderr}");
}

#[test]
fn disable_check_suggests_closest_name_for_typo() {
    let output = run(&["scan", ".", "--disable-check", "panic"]);
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("did you mean"), "{stderr}");
    assert!(stderr.contains("panics"), "{stderr}");
}

#[test]
fn explain_suggests_closest_name_for_typo() {
    let output = run(&["explain", "panic"]);
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("did you mean"), "{stderr}");
    assert!(stderr.contains("panics"), "{stderr}");
}

#[test]
only_check_conflicts_with_disable_check() {
    let output = run(&[
        "scan",
        ".",
        "--only-check",
        "panics",
        "--disable-check",
        "panics",
    ]);
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("panics"), "{stderr}");
}
