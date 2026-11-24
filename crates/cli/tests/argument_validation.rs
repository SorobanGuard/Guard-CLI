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
fn clap_accepts_fail_on_none() {
    let output = run(&["scan", ".", "--fail-on", "none"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    // `none` must be a valid value: clap must not emit a usage error.
    assert!(
        !stderr.contains("invalid value"),
        "clap rejected `--fail-on none`: {stderr}"
    );
    assert!(
        !stderr.contains("possible values"),
        "clap rejected `--fail-on none`: {stderr}"
    );
    // Argument parsing succeeded, so the exit code must not be a clap usage error.
    assert_ne!(
        output.status.code(),
        Some(2),
        "`--fail-on none` produced a usage error: {stderr}"
    );
}