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
soroban-guard scan .

STATUS=$?

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
  run: soroban-guard scan . --fail-on-any
  # Exit code 1 on any finding (High, Medium, or Low) — remove --fail-on-any
  # to block on High findings only (the default behaviour).
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

## Exit codes quick reference

| Code | Meaning | Recommended action |
|------|---------|-------------------|
| `0` | No High severity findings | Safe to continue |
| `1` | At least one High finding | Block deploy / commit |
| `2` | Scan error (I/O or parse failure) | Investigate and fix |

Use `--fail-on-any` to treat Medium and Low findings as blocking in security-sensitive pipelines.
