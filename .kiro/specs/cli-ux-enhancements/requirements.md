# Requirements Document

## Introduction

This document specifies four incremental UX improvements to the `soroban-guard` CLI tool's `scan` subcommand. The improvements target developer-experience pain points in CI/CD pipelines and day-to-day contract auditing workflows:

1. **`--changed-files` flag** — limits scanning to files changed relative to `HEAD`, reducing scan time in CI.
2. **Severity-matched `check_name` colorization** — makes the pretty-print output more scannable by colouring each `check_name` token to match its severity badge.
3. **`--fail-on-any` flag** — allows callers to gate on any finding (not only High-severity ones), enabling stricter CI policies.
4. **`--verbose` / `-v` flag** — streams per-file progress to stderr so developers can monitor long scans without polluting JSON stdout.

All four changes are confined to `crates/cli/src/main.rs` and the integration between the CLI and `soroban_guard_analyzer::scan_directory`.

## Glossary

- **CLI**: The `soroban-guard` command-line binary defined in `crates/cli/src/main.rs`.
- **Scan_Command**: The `scan` subcommand of the CLI.
- **Scanner**: The `scan_directory` function in `crates/analyzer/src/lib.rs`, which walks `.rs` files and runs checks.
- **Finding**: A single vulnerability report produced by a check, containing `check_name`, `severity`, `file_path`, `line`, `function_name`, `description`, and optional `suggestion`.
- **Severity**: An enum with three variants — `High`, `Medium`, and `Low`.
- **Pretty_Printer**: The `print_pretty` function in `crates/cli/src/main.rs` responsible for the human-readable terminal output.
- **Exit_Code**: The integer returned to the calling shell. `0` = success/no qualifying findings; `1` = qualifying findings present; `2` = error.
- **NO_COLOR**: An environment variable whose presence (regardless of value) instructs the `colored` crate to suppress all ANSI colour sequences.
- **Git_Diff_Files**: The set of relative file paths produced by running `git diff --name-only HEAD` in the working directory.
- **Changed_File_Set**: The subset of Git_Diff_Files that end with the `.rs` extension and exist on disk.

---

## Requirements

### Requirement 1: `--changed-files` Flag — Scoped Git-diff Scan

**User Story:** As a CI pipeline engineer, I want to scan only the Rust files changed since the last commit, so that pull-request checks complete faster without losing coverage on modified code.

#### Acceptance Criteria

1. WHEN the `--changed-files` flag is supplied to the Scan_Command, THE CLI SHALL invoke `git diff --name-only HEAD` in the working directory to obtain the list of changed file paths.
2. WHEN the `--changed-files` flag is supplied, THE CLI SHALL filter the output of `git diff --name-only HEAD` to retain only paths whose file-name extension is `.rs`, producing the Changed_File_Set.
3. WHEN the `--changed-files` flag is supplied and the Changed_File_Set is non-empty, THE CLI SHALL pass only the files in the Changed_File_Set to the Scanner instead of scanning the full directory tree.
4. WHEN the `--changed-files` flag is supplied and the Changed_File_Set is empty (no `.rs` files changed), THE CLI SHALL print a notice to stderr stating that no changed Rust files were found and SHALL exit with Exit_Code 0 without invoking the Scanner.
5. WHEN the `--changed-files` flag is supplied and the working directory is not a git repository (i.e., `git diff` exits with a non-zero status), THE CLI SHALL print a warning to stderr and SHALL fall back to scanning the full directory tree supplied via the `path` argument.
6. WHEN the `--changed-files` flag is not supplied, THE CLI SHALL perform a full directory scan as per existing behaviour, unaffected by this requirement.
7. THE Scan_Command SHALL accept `--changed-files` as an optional boolean flag with no required argument value.

---

### Requirement 2: Severity-Matched `check_name` Colorization

**User Story:** As a smart-contract auditor, I want the `check_name` field in terminal output to share the colour of the severity badge, so that I can visually associate findings with their risk level at a glance.

#### Acceptance Criteria

1. WHEN the Pretty_Printer renders a Finding whose severity is `High`, THE Pretty_Printer SHALL display `check_name` in bold red.
2. WHEN the Pretty_Printer renders a Finding whose severity is `Medium`, THE Pretty_Printer SHALL display `check_name` in magenta.
3. WHEN the Pretty_Printer renders a Finding whose severity is `Low`, THE Pretty_Printer SHALL display `check_name` in white (dim).
4. THE Pretty_Printer SHALL NOT apply cyan colouring to `check_name` for any severity level.
5. WHILE the `NO_COLOR` environment variable is set, THE Pretty_Printer SHALL suppress all ANSI colour codes, including the severity-matched colours applied to `check_name`.
6. WHEN the Pretty_Printer renders findings, THE severity badge colours SHALL remain unchanged: `High` → bold red, `Medium` → bold magenta, `Low` → white.

---

### Requirement 3: `--fail-on-any` Flag — Extended Exit-Code Policy

**User Story:** As a CI pipeline engineer, I want the scan to exit with code 1 whenever any finding is present (regardless of severity), so that I can enforce a zero-findings policy in strict pipelines.

#### Acceptance Criteria

1. WHEN the `--fail-on-any` flag is supplied and the Scanner returns one or more Findings of any Severity, THE CLI SHALL exit with Exit_Code 1.
2. WHEN the `--fail-on-any` flag is supplied and the Scanner returns zero Findings, THE CLI SHALL exit with Exit_Code 0.
3. WHEN the `--fail-on-any` flag is not supplied, THE CLI SHALL preserve existing exit-code behaviour: Exit_Code 1 only when at least one Finding with severity `High` is present, Exit_Code 0 otherwise.
4. IF the Scanner returns an error, THEN THE CLI SHALL exit with Exit_Code 2 regardless of whether `--fail-on-any` is set.
5. THE Scan_Command SHALL accept `--fail-on-any` as an optional boolean flag with no required argument value.
6. WHEN both `--fail-on-any` and `--quiet` are supplied and the Scanner returns only Medium or Low Findings, THE CLI SHALL suppress output (honouring `--quiet`) and SHALL exit with Exit_Code 1 (honouring `--fail-on-any`).

---

### Requirement 4: `--verbose` / `-v` Flag — Per-File Scan Progress

**User Story:** As a developer running long scans on large contract workspaces, I want to see each file name printed as it is scanned, so that I can monitor progress and identify slow or hanging files.

#### Acceptance Criteria

1. WHEN the `--verbose` flag (long form) or `-v` flag (short form) is supplied to the Scan_Command, THE CLI SHALL print a progress line to stderr for each `.rs` file immediately before that file is scanned.
2. WHEN the `--verbose` flag is supplied, THE CLI SHALL format each progress line as `scanning <relative_file_path>`, where `<relative_file_path>` is the path relative to the `path` argument supplied to the Scan_Command.
3. WHEN the `--verbose` flag is supplied, THE CLI SHALL write all progress lines to stderr and SHALL NOT write them to stdout.
4. WHEN the `--verbose` flag is supplied and `--json` is also supplied, THE CLI SHALL continue to write the JSON findings envelope exclusively to stdout, with no progress lines interleaved.
5. WHEN the `--verbose` flag is not supplied, THE CLI SHALL produce no per-file progress output, preserving existing behaviour.
6. THE Scan_Command SHALL accept `--verbose` as the long-form flag and `-v` as the short-form alias, both with no required argument value.
7. IF an error occurs while scanning a file and `--verbose` is set, THEN THE CLI SHALL still print the `scanning <path>` line for that file before reporting the error, so the operator can identify which file caused the failure.
