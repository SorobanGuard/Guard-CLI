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
fn clap_accepts_format_flag() {
    for format in ["pretty", "json", "sarif", "markdown"] {
        let output = run(&["scan", ".", "--format", format]);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !stderr.contains("unexpected argument") && !stderr.contains("invalid value"),
            "--format {format} was rejected: {stderr}"
        );
    }
}

#[test]
fn clap_rejects_format_with_legacy_boolean() {
    let output = run(&["scan", ".", "--format", "json", "--sarif"]);
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("cannot be used with"), "{stderr}");
    assert!(stderr.contains("--format"), "{stderr}");
    assert!(stderr.contains("--sarif"), "{stderr}");
}

#[test]
fn clap_rejects_output_with_pretty_format() {
    let output = run(&["scan", ".", "--format", "pretty", "--output", "findings.txt"]);
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("required"), "{stderr}");
    assert!(stderr.contains("--output"), "{stderr}");
}

#[test]
fn man_page_includes_subcommands_and_flags() {
    let output = run(&["man"]);
    assert!(
        output.status.success(),
        "man command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("scan"), "man page missing scan: {stdout}");
    assert!(
        stdout.contains("--fail-on"),
        "man page missing --fail-on: {stdout}"
    );
}
