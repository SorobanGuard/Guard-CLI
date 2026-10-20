# Integrations

Ready-to-copy snippets for wiring Soroban Guard into the tools you already use.
Each integration relies on the installed `soroban-guard` binary — build it once and reuse it everywhere:

```bash
cargo build --release
# binary: target/release/soroban-guard
```

Add `target/release/soroban-guard` to your `PATH`, or replace `soroban-guard` in the snippets below with `cargo run -p soroban-guard-cli --`.

---

## Pre-commit hook

Blocks a commit whenever any **High** finding is present. Drop the snippet into
`.git/hooks/pre-commit` and make it executable.

```bash
#!/usr/bin/env bash
# .git/hooks/pre-commit
# Blocks commits when soroban-guard finds High severity issues.

set -euo pipefail

echo "→ Running Soroban Guard scan…"

# Scan the repository root; adjust the path if your contract lives elsewhere.
# `|| STATUS=$?` keeps set -e from aborting on a non-zero exit, so the
# branches below are actually reachable.
STATUS=0
soroban-guard scan . || STATUS=$?

if [ $STATUS -eq 1 ]; then
  echo ""
  echo "✖  Soroban Guard: High findings detected. Commit blocked."
  echo "   Fix the issues above or suppress false positives before committing."
  exit 1
elif [ $STATUS -eq 2 ]; then
  echo ""
  echo "✖  Soroban Guard: Scan error (I/O or parse failure). Commit blocked."
  exit 2
fi

echo "✔  Soroban Guard: No High findings. Proceeding with commit."
exit 0
```

```bash
chmod +x .git/hooks/pre-commit
```

> **Tip:** commit this file as `scripts/pre-commit` and document the one-time
> `cp scripts/pre-commit .git/hooks/pre-commit` step in your `CONTRIBUTING.md` so
> every contributor installs it.

---

## GitHub Actions

Add a dedicated scan step early in your workflow — before the WASM build — so the
job fails fast on High findings without wasting build minutes.

```yaml
# .github/workflows/ci.yml (add this step before your build step)

- name: Install Rust toolchain
  uses: actions-rust-lang/setup-rust-toolchain@v1
  with:
    toolchain: stable

- name: Build soroban-guard
  run: cargo build --release -p soroban-guard-cli

- name: Soroban Guard scan
  run: soroban-guard scan . --fail-on low
  # Exit code 1 on any finding (High, Medium, or Low) — use --fail-on high
  # (the default) to block on High findings only.
```

### SARIF upload for GitHub Code Scanning

If your repository has GitHub Advanced Security enabled, upload findings as SARIF
to see them inline in pull requests:

```yaml
- name: Soroban Guard scan (SARIF)
  run: soroban-guard scan . --sarif --output findings.sarif
  # Continues even on exit 1 so the upload step runs.
  continue-on-error: true

- name: Upload SARIF to GitHub Code Scanning
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: findings.sarif
```

---

## VS Code tasks

Add a **Soroban Guard: Scan** task so you can run the scan from the Command Palette
(`Ctrl+Shift+B` / `Cmd+Shift+B`) and see findings routed to the **Problems** panel.

```jsonc
// .vscode/tasks.json
{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "Soroban Guard: Scan",
      "type": "shell",
      "command": "soroban-guard scan ${workspaceFolder}",
      "group": {
        "kind": "build",
        "isDefault": true
      },
      "presentation": {
        "reveal": "always",
        "panel": "shared"
      },
      // Pattern captures: file  line  col  severity  message
      "problemMatcher": {
        "owner": "soroban-guard",
        "fileLocation": ["relative", "${workspaceFolder}"],
        "pattern": {
          "regexp": "^(.+):(\\d+):(\\d+):\\s+(high|medium|low)\\s+(.+)$",
          "file": 1,
          "line": 2,
          "column": 3,
          "severity": 4,
          "message": 5
        }
      }
    }
  ]
}
```

> **Note:** The problem matcher above assumes the plain-text output format
> (`file:line:col: severity message`). If the terminal output format changes in a
> future release, update the `regexp` accordingly. Use `--json` output and a
> custom parser task if you need a stable machine-readable format.

---

## cargo-make / Makefile

### Makefile

```makefile
# Makefile
.PHONY: guard

## guard: Run Soroban Guard static analysis on the workspace.
guard:
	soroban-guard scan .
```

Run with:

```bash
make guard
```

### cargo-make (`Makefile.toml`)

```toml
# Makefile.toml
[tasks.guard]
description = "Run Soroban Guard static analysis"
command = "soroban-guard"
args = ["scan", "."]
```

Run with:

```bash
cargo make guard
```

Combine with other tasks using `dependencies`:

```toml
[tasks.pre-deploy]
description = "Scan, then build the WASM artifact"
dependencies = ["guard", "build-wasm"]

[tasks.build-wasm]
command = "cargo"
args = ["build", "--target", "wasm32-unknown-unknown", "--release"]
```

---

## Scanning from stdin (editor and pre-commit integrations)

Editors, language-server wrappers and some pre-commit setups pipe the unsaved buffer
to a tool. `soroban-guard scan -` reads a single Rust source from stdin so these
integrations do not need to write temp files.

```bash
# Pipe the current buffer from the editor:
cat src/contract.rs | soroban-guard scan - --stdin-filename src/contract.rs --json

# Or a pre-commit hook that pipes the staged version of a file:
git show :src/contract.rs | soroban-guard scan - --stdin-filename src/contract.rs
```

### `--stdin-filename <NAME>`

Sets the label used in findings, SARIF output, and suppression handling.
Defaults to `<stdin>` when omitted.

All output formats (`--json`, `--sarif`, `--markdown`, `--junit`) and `--fail-on` work
exactly as they do for a normal single-file scan.

Reading **empty** stdin or content that cannot be parsed as valid UTF-8 exits with
code 2 (scan error).

### VS Code integration

Add a task that pipes the active file to `soroban-guard scan -` using the
`${file}` variable and the built-in `processExecution` type:

```jsonc
// .vscode/tasks.json
{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "Soroban Guard: Scan current file (stdin)",
      "type": "shell",
      "command": "cat ${file} | soroban-guard scan - --stdin-filename ${relativeFile} --json",
      "group": "build"
    }
  ]
}
```

---

## Exit codes quick reference

| Code | Meaning | Recommended action |
|------|---------|-------------------|
| `0` | No High severity findings | Safe to continue |
| `1` | At least one High finding | Block deploy / commit |
| `2` | Scan error (I/O or parse failure) | Investigate and fix |

Use `--fail-on medium` or `--fail-on low` to treat Medium and/or Low findings as blocking in security-sensitive pipelines.
