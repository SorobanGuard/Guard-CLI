use std::path::PathBuf;
use std::process::Command;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn contracts_dir() -> PathBuf {
    repo_root().join("test-contracts")
}

fn run_scan_json(threads: &str) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_handsoff"))
        .arg("scan")
        .arg(contracts_dir())
        .arg("--json")
        .env("RAYON_NUM_THREADS", threads)
        .output()
        .expect("failed to run handsoff scan");

    assert!(
        output.status.success(),
        "scan failed with RAYON_NUM_THREADS={}: {}",
        threads,
        String::from_utf8_lossy(&output.stderr)
    );

    String::from_utf8(output.stdout).expect("scan output was not valid UTF-8")
}

#[test]
fn findings_are_deterministic_across_thread_counts() {
    let single = run_scan_json("1");
    let multi = run_scan_json("8");

    assert_eq!(
        single, multi,
        "scan output differed between RAYON_NUM_THREADS=1 and RAYON_NUM_THREADS=8"
    );
}

#[test]
fn findings_are_sorted_by_file_line_check_name() {
    let json = run_scan_json("8");
    let value: serde_json::Value =
        serde_json::from_str(&json).expect("scan output was not valid JSON");

    let findings = value
        .get("findings")
        .and_then(|f| f.as_array())
        .expect("scan JSON output missing `findings` array");

    let mut keys: Vec<(String, u64, String)> = findings
        .iter()
        .map(|finding| {
            let file = finding
                .get("file")
                .and_then(|v| v.as_str())
                .expect("finding missing `file`")
                .to_string();
            let line = finding
                .get("line")
                .and_then(|v| v.as_u64())
                .expect("finding missing `line`");
            let check_name = finding
                .get("check_name")
                .and_then(|v| v.as_str())
                .expect("finding missing `check_name`")
                .to_string();
            (file, line, check_name)
        })
        .collect();

    let mut sorted = keys.clone();
    sorted.sort();

    assert_eq!(
        keys, sorted,
        "findings are not sorted by (file, line, check_name)"
    );

    keys.dedup();
}
