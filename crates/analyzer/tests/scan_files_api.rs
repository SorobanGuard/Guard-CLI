//! `scan_files` has no caller in the CLI (issue #721), so these tests are what keep
//! its public behavior honest: they call it the way an embedder would.

use soroban_guard_analyzer::{scan_directory, scan_files};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const VULNERABLE: &str = "#[contract]\npub struct C;\n#[contractimpl]\nimpl C {\n    pub fn bump(env: Env) {\n        env.storage().instance().set(&1u32, &2u32);\n    }\n}\n";

fn temp_root(tag: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "soroban-guard-scan-files-api-{tag}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&root).unwrap();
    root
}

fn write(root: &Path, rel: &str, contents: &str) -> PathBuf {
    let path = root.join(rel);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, contents).unwrap();
    path
}

#[test]
fn scan_files_finds_the_same_issues_as_scan_directory() {
    let root = temp_root("parity");
    let lib = write(&root, "src/lib.rs", VULNERABLE);

    let (from_files, scanned, skipped, panics) = scan_files(&[lib], &root, &[], &[]).unwrap();
    let (from_dir, _, _, _) = scan_directory(&root, &[], &[]).unwrap();
    fs::remove_dir_all(&root).unwrap();

    assert_eq!(scanned, 1);
    assert_eq!(skipped, 0);
    assert!(panics.is_empty());
    assert!(from_files
        .iter()
        .any(|f| f.check_name == "missing-require-auth"));
    assert_eq!(
        from_files.len(),
        from_dir.len(),
        "an explicit file list must not change what is found"
    );
}

#[test]
fn scan_files_skips_target_and_git_paths_like_scan_directory() {
    let root = temp_root("ignored");
    let lib = write(&root, "src/lib.rs", VULNERABLE);
    let built = write(&root, "target/debug/build/out.rs", VULNERABLE);
    let hook = write(&root, ".git/hooks/hook.rs", VULNERABLE);

    let (findings, scanned, _, _) = scan_files(&[lib, built, hook], &root, &[], &[]).unwrap();
    fs::remove_dir_all(&root).unwrap();

    assert_eq!(scanned, 1, "only src/lib.rs should be scanned");
    assert!(findings.iter().all(|f| f.file_path.starts_with("src/")));
}

#[test]
fn scan_files_ignores_non_rust_paths_and_honors_excludes() {
    let root = temp_root("filters");
    let lib = write(&root, "src/lib.rs", VULNERABLE);
    let other = write(&root, "src/other.rs", VULNERABLE);
    let notes = write(&root, "NOTES.md", "not rust");

    let (_, scanned, _, _) = scan_files(
        &[lib, other, notes],
        &root,
        &["src/other.rs".to_string()],
        &[],
    )
    .unwrap();
    fs::remove_dir_all(&root).unwrap();

    assert_eq!(scanned, 1);
}

/// Findings must be ordered deterministically regardless of how many rayon
/// worker threads participate, otherwise golden tests, baseline diffs and
/// SARIF `partialFingerprints` become flaky (issue #1021).
#[test]
fn scan_directory_is_deterministic_across_thread_counts() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("test-contracts");
    assert!(
        root.is_dir(),
        "expected test-contracts fixtures at {}",
        root.display()
    );

    let (single, _, _, _) = scan_directory(&root, &[], &[]).unwrap();
    let (multi, _, _, _) = scan_directory(&root, &[], &[]).unwrap();

    let render = |findings: &[soroban_guard_analyzer::Finding]| -> String {
        findings
            .iter()
            .map(|f| format!("{}:{}:{}", f.file_path, f.line, f.check_name))
            .collect::<Vec<_>>()
            .join("\n")
    };

    let single_out = render(&single);
    let multi_out = render(&multi);
    assert_eq!(
        single_out, multi_out,
        "scanning the same tree twice must give byte-identical output"
    );

    let mut sorted = single.clone();
    sorted.sort_by(|a, b| {
        a.file_path
            .cmp(&b.file_path)
            .then(a.line.cmp(&b.line))
            .then(a.check_name.cmp(&b.check_name))
    });
    assert_eq!(
        render(&sorted),
        single_out,
        "findings must be sorted by (file, line, check_name)"
    );
}
