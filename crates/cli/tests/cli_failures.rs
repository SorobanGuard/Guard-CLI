use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn temporary_directory(label: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "soroban-guard-{label}-{}-{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
    ));
    std::fs::create_dir_all(&path).unwrap();
    path
}

#[test]
fn nonexistent_scan_path_exits_two_with_clear_message() {
    let root = temporary_directory("missing-path");
    let missing = root.join("does-not-exist");
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-guard"))
        .args(["scan", missing.to_str().unwrap()])
        .env("NO_COLOR", "1")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains(&missing.display().to_string()));
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn config_path_is_used_when_scan_argument_is_absent() {
    let root = temporary_directory("config-path");
    std::fs::create_dir_all(root.join("contract/src")).unwrap();
    std::fs::write(root.join("contract/src/lib.rs"), "pub fn harmless() {}\n").unwrap();
    std::fs::write(root.join("soroban-guard.toml"), "[scan]\npath = \"contract\"\n").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-guard"))
        .arg("scan")
        .current_dir(&root)
        .env("NO_COLOR", "1")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0), "{}", String::from_utf8_lossy(&output.stderr));
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn explicit_config_flag_loads_given_file() {
    let root = temporary_directory("explicit-config");
    std::fs::create_dir_all(root.join("contract/src")).unwrap();
    std::fs::write(root.join("contract/src/lib.rs"), "pub fn harmless() {}\n").unwrap();
    let config = root.join("shared-policy.toml");
    std::fs::write(&config, "[scan]\npath = \"contract\"\n").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-guard"))
        .args(["scan", "--config", config.to_str().unwrap()])
        .current_dir(&root)
        .env("NO_COLOR", "1")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0), "{}", String::from_utf8_lossy(&output.stderr));
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn missing_explicit_config_exits_two() {
    let root = temporary_directory("missing-config");
    std::fs::create_dir_all(root.join("contract/src")).unwrap();
    std::fs::write(root.join("contract/src/lib.rs"), "pub fn harmless() {}\n").unwrap();
    let missing = root.join("absent.toml");
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-guard"))
        .args(["scan", "--config", missing.to_str().unwrap()])
        .current_dir(&root)
        .env("NO_COLOR", "1")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains(&missing.display().to_string()));
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn malformed_explicit_config_exits_two() {
    let root = temporary_directory("malformed-config");
    std::fs::create_dir_all(root.join("contract/src")).unwrap();
    std::fs::write(root.join("contract/src/lib.rs"), "pub fn harmless() {}\n").unwrap();
    let config = root.join("broken.toml");
    std::fs::write(&config, "[scan\npath = \"contract\"\n").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-guard"))
        .args(["scan", "--config", config.to_str().unwrap()])
        .current_dir(&root)
        .env("NO_COLOR", "1")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn no_config_flag_disables_discovery() {
    let root = temporary_directory("no-config");
    std::fs::create_dir_all(root.join("contract/src")).unwrap();
    std::fs::write(root.join("contract/src/lib.rs"), "pub fn harmless() {}\n").unwrap();
    // A malformed discovered config would be a hard error if discovery ran.
    std::fs::write(root.join("soroban-guard.toml"), "[scan\npath = \"contract\"\n").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-guard"))
        .args(["scan", "--no-config", "contract"])
        .current_dir(&root)
        .env("NO_COLOR", "1")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0), "{}", String::from_utf8_lossy(&output.stderr));
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn missing_scan_argument_without_config_exits_two() {
    let root = temporary_directory("no-path-no-config");
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-guard"))
        .arg("scan")
        .current_dir(&root)
        .env("NO_COLOR", "1")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("no scan path provided and none found in soroban-guard.toml"));
    std::fs::remove_dir_all(root).unwrap();
}
