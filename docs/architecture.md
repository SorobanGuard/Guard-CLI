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

1. The CLI calls `scan_directory` with the requested path.
2. The analyzer walks the directory and filters it to applicable `.rs` files.
3. Each file is read and parsed with `syn::parse_file` into a `syn::File`.
4. The analyzer calls `Check::run` for every check returned by `default_checks()`.
5. Findings from all files and checks are collected into a `Vec<Finding>`, assigned relative file
   paths, sorted, and returned to the CLI.
6. The CLI renders terminal or JSON output and exits according to the highest severity found.

```text
source directory
    → scan_directory
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
