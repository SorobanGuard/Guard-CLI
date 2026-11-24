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
fn invalid_fail_on_flag_value_blames_the_flag() {
    let output = run(&["scan", ".", "--fail-on", "critical"]);
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--fail-on"), "{stderr}");
    assert!(stderr.contains("critical"), "{stderr}");
    assert!(
        !stderr.contains("soroban-guard.toml"),
        "flag-originated error should not blame the config file: {stderr}"
    );
}