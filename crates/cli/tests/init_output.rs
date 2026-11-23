use std::fs;
use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_soroban-guard")
}

#[test]
fn init_writes_schema_directive_at_top() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("soroban-guard.toml");

    let status = Command::new(bin())
        .args(["init", "--path", path.to_str().unwrap()])
        .status()
        .expect("run init");
    assert!(status.success(), "init should succeed");

    let contents = fs::read_to_string(&path).expect("read generated config");
    let first_line = contents.lines().next().unwrap_or_default();
    assert_eq!(
        first_line,
        "#:schema https://raw.githubusercontent.com/SorobanGuard/Guard-CLI/main/schemas/soroban-guard.schema.json",
        "generated config must start with the schema directive"
    );
}

#[test]
fn schema_subcommand_emits_valid_json() {
    let output = Command::new(bin())
        .arg("schema")
        .output()
        .expect("run schema");
    assert!(output.status.success(), "schema should succeed");

    let stdout = String::from_utf8(output.stdout).expect("utf8 schema");
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("schema is valid JSON");
    assert!(
        value.get("properties").is_some(),
        "schema should expose top-level properties"
    );
}
