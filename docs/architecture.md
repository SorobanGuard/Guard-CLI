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
2. The analyzer walks the directory and filters it to applicable `.rs` files. When the target is a
   single `.rs` file instead of a directory, the analyzer follows its out-of-line `mod name;`
   declarations recursively: each module is resolved relative to the declaring file as `name.rs` or
   `name/mod.rs`, honouring `#[path = "..."]` attributes. Files reached this way are subject to the
   same `--exclude` and generated-file filtering as directory walks, are de-duplicated against files
   already scanned, and are protected against module cycles. A `mod` declaration whose file cannot
   be found produces a warning rather than aborting the scan, so single-file and directory scans
   report the same findings for the same contract.
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
