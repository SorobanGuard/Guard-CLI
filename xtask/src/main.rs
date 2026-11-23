//! Repository automation tasks.
//!
//! Run with `cargo xtask <task>`. Currently supports generating the check
//! reference tables (`docs/checks.md` and the README check list) from the
//! check registry metadata so they no longer drift by hand.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const BEGIN_MARKER: &str = "<!-- BEGIN GENERATED CHECKS -->";
const END_MARKER: &str = "<!-- END GENERATED CHECKS -->";

/// A single check's registry metadata, mirroring `CHECK_METADATA` in the
/// `sloplint` binary. Kept in sync via the registry-consistency test.
struct CheckMeta {
    name: &'static str,
    severity: &'static str,
    one_liner: &'static str,
    description: &'static str,
}

/// The canonical check registry metadata used to render the docs.
const CHECKS: &[CheckMeta] = &[
    CheckMeta {
        name: "unused-import",
        severity: "warn",
        one_liner: "An import is never used.",
        description: "Flags `use` items whose imported names are never referenced in the module.",
    },
    CheckMeta {
        name: "unused-variable",
        severity: "warn",
        one_liner: "A binding is never read.",
        description: "Flags `let` bindings that are never read after being introduced.",
    },
    CheckMeta {
        name: "todo-comment",
        severity: "info",
        one_liner: "A TODO/FIXME marker is left in the source.",
        description: "Flags `TODO`, `FIXME`, and `XXX` markers left in comments.",
    },
];

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let task = args.next();
    let check_only = args.any(|a| a == "--check");

    match task.as_deref() {
        Some("docs") => run_docs(check_only),
        Some(other) => {
            eprintln!("unknown xtask: {other}");
            eprintln!("usage: cargo xtask docs [--check]");
            ExitCode::FAILURE
        }
        None => {
            eprintln!("usage: cargo xtask docs [--check]");
            ExitCode::FAILURE
        }
    }
}

fn run_docs(check_only: bool) -> ExitCode {
    let root = workspace_root();
    let targets = [
        (root.join("README.md"), render_readme_block()),
        (root.join("docs/checks.md"), render_checks_block()),
    ];

    let mut stale = false;
    for (path, block) in targets {
        match update_file(&path, &block, check_only) {
            Ok(changed) => {
                if changed {
                    stale = true;
                    if check_only {
                        eprintln!("out of date: {}", path.display());
                    } else {
                        println!("updated {}", path.display());
                    }
                }
            }
            Err(err) => {
                eprintln!("error updating {}: {err}", path.display());
                return ExitCode::FAILURE;
            }
        }
    }

    if check_only && stale {
        eprintln!("generated check docs are stale; run `cargo xtask docs`");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

/// Replace the content between the generated markers, returning whether the
/// file changed. In `check_only` mode the file is never written.
fn update_file(path: &Path, block: &str, check_only: bool) -> std::io::Result<bool> {
    let original = fs::read_to_string(path)?;
    let updated = replace_block(&original, block).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "missing generated checks markers",
        )
    })?;

    if updated == original {
        return Ok(false);
    }
    if !check_only {
        fs::write(path, updated)?;
    }
    Ok(true)
}

fn replace_block(source: &str, block: &str) -> Option<String> {
    let begin = source.find(BEGIN_MARKER)?;
    let after_begin = begin + BEGIN_MARKER.len();
    let end_rel = source[after_begin..].find(END_MARKER)?;
    let end = after_begin + end_rel;

    let mut out = String::with_capacity(source.len() + block.len());
    out.push_str(&source[..after_begin]);
    out.push('\n');
    out.push_str(block);
    out.push('\n');
    out.push_str(&source[end..]);
    Some(out)
}

fn render_checks_block() -> String {
    let mut out = String::new();
    out.push_str("| Name | Severity | Description |\n");
    out.push_str("| --- | --- | --- |\n");
    for check in CHECKS {
        out.push_str(&format!(
            "| `{}` | {} | {} |\n",
            check.name, check.severity, check.one_liner
        ));
    }
    out.push('\n');
    for check in CHECKS {
        out.push_str(&format!("### `{}`\n\n{}\n\n", check.name, check.description));
    }
    out.trim_end().to_string()
}

fn render_readme_block() -> String {
    let mut out = String::new();
    for check in CHECKS {
        out.push_str(&format!(
            "- `{}` ({}) — {}\n",
            check.name, check.severity, check.one_liner
        ));
    }
    out.trim_end().to_string()
}

fn workspace_root() -> PathBuf {
    // `xtask` lives directly under the workspace root.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."))
}
