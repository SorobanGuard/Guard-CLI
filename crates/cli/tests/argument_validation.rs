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
fn clap_accepts_color_auto() {
    let output = run(&["scan", ".", "--color", "auto", "--help"]);
    // --help short-circuits; the flag must parse without a clap error.
    assert_ne!(output.status.code(), Some(2));
}

#[test]
fn clap_accepts_color_always() {
    let output = run(&["scan", ".", "--color", "always", "--help"]);
    assert_ne!(output.status.code(), Some(2));
}

#[test]
fn clap_accepts_color_never() {
    let output = run(&["scan", ".", "--color", "never", "--help"]);
    assert_ne!(output.status.code(), Some(2));
}

#[test]
fn clap_rejects_invalid_color_value() {
    let output = run(&["scan", ".", "--color", "sometimes"]);
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--color"), "{stderr}");
}

#[test]
fn clap_accepts_no_color_alias() {
    let output = run(&["scan", ".", "--no-color", "--help"]);
    assert_ne!(output.status.code(), Some(2));
}
