# Troubleshooting & FAQ

Common questions, pitfalls, and copy-pasteable solutions when using Soroban Guard.

---

## 1. "Scanned 0 files" / No Files Found

### Symptom
Running `soroban-guard scan .` completes with `Scanned 0 files` even though Rust contract files exist.

### Causes & Fixes
1. **Target or Generated Directories**:
   Soroban Guard automatically skips the `target/` build directory, hidden folders (e.g. `.git/`), and common build output paths. Ensure your contract source files reside inside a standard crate structure (`src/lib.rs` or `src/*.rs`).
2. **Exclude Filters in `soroban-guard.toml`**:
   Check if your project's `soroban-guard.toml` defines exclude patterns:
   ```toml
   [scan]
   exclude = ["tests/**", "benches/**"]
   ```
   If a glob matches your source path, files will be skipped. Run with `--verbose` to inspect discovery:
   ```bash
   soroban-guard scan . --verbose
   ```
3. **Explicit Paths**:
   Specify the directory or file directly:
   ```bash
   soroban-guard scan ./contracts/my-contract
   ```

---

## 2. Configuration Discovery & Precedence

### How `soroban-guard.toml` is Discovered
Soroban Guard searches for `soroban-guard.toml` starting from the directory being scanned and walks upward toward the repository root.

### Precedence Rules
CLI flags **always override** settings in `soroban-guard.toml`:
- Flag `--fail-on <severity>` overrides `[scan] min_severity`.
- Flag `--disable-check <name>` is appended to `[checks] disabled`.
- Flag `--include <glob>` overrides `[scan] include`.

To verify which configuration file is being loaded:
```bash
soroban-guard scan . --verbose
```

---

## 3. Exit Codes & CI Configuration

### Exit Codes Reference
| Exit Code | Meaning |
|---|---|
| `0` | Scan passed cleanly (no findings meeting or exceeding the failure threshold) |
| `1` | One or more findings met or exceeded the failure threshold (default: **High**) |
| `2` | Execution or syntax error (invalid CLI arguments, unreadable file, bad config) |

### Making CI Ignore Low or Medium Findings
By default, Soroban Guard only fails the build (exit code `1`) on **High** severity findings:
- To strictly block on High severity only:
  ```bash
  soroban-guard scan . --fail-on high
  ```
- To make CI block on **Medium** as well:
  ```bash
  soroban-guard scan . --fail-on medium
  ```
- To fail on any finding including informational **Low** findings:
  ```bash
  soroban-guard scan . --fail-on low
  ```

---

## 4. Suppressing Findings (False Positives)

### A. Suppress a Single Finding in Code
Place an inline suppression comment immediately above the flagged function or statement:
```rust
// soroban-guard:ignore missing-auth Reason: Authorization is checked by calling proxy
pub fn withdraw(env: Env, to: Address, amount: i128) {
    ...
}
```

### B. Disable a Specific Check Project-Wide
In your `soroban-guard.toml`:
```toml
[checks]
disabled = ["hardcoded-address"]
```
Or via CLI:
```bash
soroban-guard scan . --disable-check hardcoded-address
```

### C. Suppress an Entire File or Test Module
Exclude test suites or generated mock contracts in `soroban-guard.toml`:
```toml
[scan]
exclude = ["tests/**", "src/mock_*.rs"]
```

---

## 5. Garbled Output or ANSI Colors in CI Logs

### Symptom
CI logs (e.g. GitHub Actions, GitLab CI, Jenkins) show raw escape sequences like `\u001b[31m` or strange characters.

### Fix
Pass the `--no-color` flag or set the standard `NO_COLOR` environment variable:
```bash
soroban-guard scan . --no-color
```
Or export the standard environment variable:
```bash
export NO_COLOR=1
soroban-guard scan .
```
For automated parsing in CI, prefer structured output:
```bash
soroban-guard scan . --json > findings.json
# Or for GitHub Advanced Security code scanning:
soroban-guard scan . --sarif --output findings.sarif
```
