# Architecture

Guard CLI is a Rust workspace split into three crates with one primary scan dependency path:

```text
cli → analyzer → checks
```

- **`crates/cli`** parses commands, invokes scans, formats findings, and selects the process exit
  code. It also imports shared result types from `checks` for reporting.
- **`crates/analyzer`** discovers Rust source files, parses them, and coordinates the enabled
  checks.
- **`crates/checks`** defines the check interface and result types, and implements the built-in
  detectors.

## Data flow

1. The CLI calls `scan_directory_with_checks` with the requested path and the config/CLI-filtered
   `active_checks` list — not `scan_directory`, since the CLI needs to honor `--disable-check` and
   `soroban-guard.toml`. `scan_directory` (the config-free variant) is used only by tests and the
   fixture test helper. `scan_files`, which scans an explicit list of paths instead of walking a
   directory, is library API for embedders (pre-commit hooks scanning staged files, editor
   integrations). No CLI subcommand calls it, so its behavior is covered by
   `crates/analyzer/tests/scan_files_api.rs` rather than by the CLI tests.
2. The analyzer walks the directory and filters it to applicable `.rs` files.
3. Each file is read and parsed with `syn::parse_file` into a `syn::File`.
4. The analyzer calls `Check::run` for every check in `active_checks`.
5. Findings from all files and checks are collected into a `Vec<Finding>`, assigned relative file
   paths, sorted, and returned to the CLI.
6. The CLI renders terminal or JSON output and exits according to the highest severity found.

```text
source directory
    → scan_directory_with_checks
    → Rust files
    → syn::parse_file
    → each Check::run
    → Vec<Finding>
    → CLI output
```

## Key types

- **`Check`** — the detector trait. Each implementation supplies a stable name and a `run` method
  that receives the parsed file and original source, then returns zero or more findings.
- **`Finding`** — one reported issue, including its check name, location, severity, description,
  documentation URL, and optional remediation suggestion.
- **`Severity`** — the `High`, `Medium`, or `Low` classification used for reporting and exit-code
  decisions.

These types and the built-in check registry live in
[`crates/checks/src/lib.rs`](../crates/checks/src/lib.rs).

## Extension points

New detectors are added to `crates/checks/src/`, exported and registered in `default_checks()`,
documented in `docs/checks.md`, and covered by unit tests and fixtures.

See [How to add a new check](../CONTRIBUTING.md#how-to-add-a-new-check-copy-authrs-as-a-template)
for the complete contributor workflow.

## ScanContext — path- and crate-aware checks (closes #980)

`Check::run` only receives the parsed file and its raw source. `ScanContext` carries
the extra information needed for path-aware detectors:

```rust
pub struct ScanContext<'a> {
    pub path: &'a Path,          // absolute path of the .rs file
    pub root: &'a Path,          // root of the scan
    pub crate_name: Option<&'a str>, // from the nearest Cargo.toml
}
```

Implement `Check::run_with_context` on a check to receive this context. The default
implementation delegates to `Check::run`, so existing checks need no changes. The
analyzer calls `run_with_context` for every file.

## ManifestCheck — Cargo.toml scanning pipeline (closes #979)

A parallel check pipeline runs against `Cargo.toml` manifests via the
`ManifestCheck` trait:

```rust
pub trait ManifestCheck {
    fn name(&self) -> &str;
    fn run(&self, manifest: &toml::Value, path: &Path) -> Vec<Finding>;
}
```

Built-in manifest checks are registered in `manifest_checks()` in
`crates/checks/src/lib.rs`. The analyzer discovers the root manifest and any
workspace member manifests, parses them with `toml`, and runs every active
manifest check. `--disable-check` and `[checks] disabled` apply to both source
and manifest checks.

The first built-in manifest check is `missing-cdylib`, which flags a `Cargo.toml`
that does not list `cdylib` in `[lib] crate-type`.
