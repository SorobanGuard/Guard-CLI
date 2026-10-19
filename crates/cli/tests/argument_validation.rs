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
fn explain_suggests_closest_check_on_typo() {
    let output = run(&["explain", "missing-require-aut"]);
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("unknown check `missing-require-aut`"), "{stderr}");
    assert!(stderr.contains("Did you mean `missing-require-auth`?"), "{stderr}");
}

#[test]
fn scan_disable_check_suggests_closest_check_on_typo() {
    let output = run(&["scan", ".", "--disable-check", "missing-require-aut"]);
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("unknown check `missing-require-aut`"), "{stderr}");
    assert!(stderr.contains("Did you mean `missing-require-auth`?"), "{stderr}");
}
