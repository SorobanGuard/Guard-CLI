use std::process::Command;

fn run(arguments: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_soroban-guard"))
        .args(arguments)
        .env("NO_COLOR", "1")
        .env_remove("SOROBAN_GUARD_CONFIG")
        .env_remove("SOROBAN_GUARD_FAIL_ON")
        .output()
        .expect("failed to run soroban-guard")
}

fn run_with_env(arguments: &[&str], envs: &[(&str, &str)]) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_soroban-guard"));
    command
        .args(arguments)
        .env("NO_COLOR", "1")
        .env_remove("SOROBAN_GUARD_CONFIG")
        .env_remove("SOROBAN_GUARD_FAIL_ON");
    for (key, value) in envs {
        command.env(key, value);
    }
    command.output().expect("failed to run soroban-guard")
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
fn clap_rejects_csv_with_json() {
    let output = run(&["scan", ".", "--csv", "--json"]);
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("cannot be used with"), "{stderr}");
    assert!(stderr.contains("--csv"), "{stderr}");
    assert!(stderr.contains("--json"), "{stderr}");
}

#[test]
fn clap_rejects_csv_with_sarif() {
    let output = run(&["scan", ".", "--csv", "--sarif"]);
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("cannot be used with"), "{stderr}");
    assert!(stderr.contains("--csv"), "{stderr}");
    assert!(stderr.contains("--sarif"), "{stderr}");
}

#[test]
fn clap_rejects_csv_with_markdown() {
    let output = run(&["scan", ".", "--csv", "--markdown"]);
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("cannot be used with"), "{stderr}");
    assert!(stderr.contains("--csv"), "{stderr}");
    assert!(stderr.contains("--markdown"), "{stderr}");
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
fn config_env_var_is_accepted() {
    let output = run_with_env(
        &["scan", "."],
        &[("SOROBAN_GUARD_CONFIG", "missing-config.toml")],
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("missing-config.toml"),
        "expected env config path to be used: {stderr}"
    );
}

#[test]
fn config_flag_overrides_env_var() {
    let output = run_with_env(
        &["scan", ".", "--config", "flag-config.toml"],
        &[("SOROBAN_GUARD_CONFIG", "env-config.toml")],
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("flag-config.toml"),
        "expected flag config path to win: {stderr}"
    );
    assert!(
        !stderr.contains("env-config.toml"),
        "env config path should be ignored: {stderr}"
    );
}

#[test]
fn empty_config_env_var_is_treated_as_unset() {
    let output = run_with_env(&["scan", "."], &[("SOROBAN_GUARD_CONFIG", "")]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("SOROBAN_GUARD_CONFIG"),
        "empty env var should behave as unset: {stderr}"
    );
}

#[test]
fn fail_on_env_var_is_accepted() {
    let output = run_with_env(&["scan", "."], &[("SOROBAN_GUARD_FAIL_ON", "high")]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("invalid value"),
        "valid env fail-on value should be accepted: {stderr}"
    );
}

#[test]
fn fail_on_flag_overrides_env_var() {
    let output = run_with_env(
        &["scan", ".", "--fail-on", "low"],
        &[("SOROBAN_GUARD_FAIL_ON", "high")],
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("invalid value"),
        "flag fail-on value should win: {stderr}"
    );
}

#[test]
fn invalid_fail_on_env_var_matches_flag_error() {
    let env_output = run_with_env(&["scan", "."], &[("SOROBAN_GUARD_FAIL_ON", "bogus")]);
    let flag_output = run(&["scan", ".", "--fail-on", "bogus"]);
    assert_eq!(env_output.status.code(), Some(2));
    assert_eq!(flag_output.status.code(), Some(2));
    let env_stderr = String::from_utf8_lossy(&env_output.stderr);
    let flag_stderr = String::from_utf8_lossy(&flag_output.stderr);
    assert!(env_stderr.contains("invalid value"), "{env_stderr}");
    assert!(flag_stderr.contains("invalid value"), "{flag_stderr}");
}

#[test]
fn empty_fail_on_env_var_is_treated_as_unset() {
    let output = run_with_env(&["scan", "."], &[("SOROBAN_GUARD_FAIL_ON", "")]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("invalid value"),
        "empty env var should behave as unset: {stderr}"
    );
}
