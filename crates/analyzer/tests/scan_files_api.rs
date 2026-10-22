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
fn scan_files_follows_out_of_line_modules_from_a_single_file() {
    let root = temp_root("modules");
    let lib = write(
        &root,
        "src/lib.rs",
        "mod storage;\nmod admin;\n",
    );
    write(&root, "src/storage.rs", VULNERABLE);
    write(&root, "src/admin/mod.rs", VULNERABLE);

    let (from_files, scanned, skipped, panics) = scan_files(&[lib], &root, &[], &[]).unwrap();
    let (from_dir, _, _, _) = scan_directory(&root, &[], &[]).unwrap();
    fs::remove_dir_all(&root).unwrap();

    assert_eq!(scanned, 3, "lib.rs plus both out-of-line modules");
    assert_eq!(skipped, 0);
    assert!(panics.is_empty());
    assert_eq!(
        from_files.len(),
        from_dir.len(),
        "following modules must match a directory scan"
    );
    assert!(from_files
        .iter()
        .any(|f| f.file_path == "src/storage.rs"));
    assert!(from_files
        .iter()
        .any(|f| f.file_path == "src/admin/mod.rs"));
}

#[test]
fn scan_files_warns_on_missing_module_files() {
    let root = temp_root("missing-module");
    let lib = write(&root, "src/lib.rs", "mod gone;\n");

    let (findings, scanned, _, panics) = scan_files(&[lib], &root, &[], &[]).unwrap();
    fs::remove_dir_all(&root).unwrap();

    assert_eq!(scanned, 1);
    assert!(findings.is_empty());
    assert!(panics.is_empty(), "a missing module must not abort the scan");
}

#[test]
fn scan_files_skips_excluded_and_generated_modules() {
    let root = temp_root("module-filters");
    let lib = write(
        &root,
        "src/lib.rs",
        "mod storage;\nmod generated;\n",
    );
    write(&root, "src/storage.rs", VULNERABLE);
    write(&root, "src/generated.rs", VULNERABLE);

    let (findings, scanned, _, _) = scan_files(
        &[lib],
        &root,
        &["src/storage.rs".to_string()],
        &[],
    )
    .unwrap();
    fs::remove_dir_all(&root).unwrap();

    assert_eq!(scanned, 1, "excluded module must not be scanned");
    assert!(findings.iter().all(|f| f.file_path != "src/storage.rs"));
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
