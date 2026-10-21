# Troubleshooting & FAQ

Common questions and fixes for `soroban-guard`. If your problem isn't covered here, run `soroban-guard scan --verbose` first — it prints how many files were scanned and how many generated files were skipped.

## "Scanned 0 files"

If the scan reports `Scanned 0 file(s).` (visible with `--verbose`), no `.rs` files matched your filters. Check the following, in order:

1. **Path is correct.** Point the scan at the crate root or a folder containing Rust sources:

   ```bash
   soroban-guard scan ./contracts/token --verbose
   ```

2. **Include globs are too narrow.** `--include` restricts the scan to matching files. A pattern like `src/token*.rs` will skip everything else. Drop it or widen it:

   ```bash
   soroban-guard scan ./contracts/token --include 'src/**/*.rs' --verbose
   ```

3. **Exclude globs are too broad.** `--exclude` removes matching files. A pattern like `src/*.rs` excludes the whole `src/` directory:

   ```bash
   soroban-guard scan ./contracts/token --exclude 'src/proxy.rs' --verbose
   ```

4. **Generated files are skipped automatically.** Files that look generated (e.g. contain a `@generated` marker) are not analyzed. `--verbose` reports how many were skipped:

   ```bash
   soroban-guard scan ./contracts/token --verbose
   # Skipped 3 generated file(s) from analysis.
   ```

5. **`target/` is filtered.** Build output under `target/` is never scanned. If your sources live under a directory named `target`, move them or scan the parent explicitly.

## Which `soroban-guard.toml` is used?

Configuration is discovered by walking up from the scan path. The nearest `soroban-guard.toml` wins. To create a starter file in the current directory:

```bash
soroban-guard init
```

Overwrite an existing one with:

```bash
soroban-guard init --force
```

**Precedence with flags:** command-line flags override the config file. For example, if `soroban-guard.toml` sets `fail_on = "medium"` but you pass `--fail-on high`, the flag wins for that run:

```bash
soroban-guard scan ./contracts/token --fail-on high
```

Likewise `--disable-check` and `--exclude` add to (and take precedence over) the config for that invocation.

## Exit codes: 1 vs 2

- **`0`** — scan completed, no findings at or above the `--fail-on` threshold.
- **`1`** — scan completed and at least one finding met the `--fail-on` threshold (default: `high`).
- **`2`** — the scan could not complete (I/O error, unreadable path, serialization failure).

### Making CI ignore Low findings

By default only `high` findings fail the build. To fail on `medium` but ignore `low`:

```bash
soroban-guard scan ./contracts/token --fail-on medium
```

To never fail the build on findings (still report them), set the threshold to `low` and inspect output, or gate on exit code `2` only:

```bash
soroban-guard scan ./contracts/token --fail-on low || [ $? -eq 2 ]
```

## Suppressing findings

### A single finding

Add an inline suppression comment on the line above the finding:

```rust
// soroban-guard: ignore-next-line missing-require-auth
pub fn transfer(env: Env) { /* ... */ }
```

### A whole check

Disable a named check for the run:

```bash
soroban-guard scan ./contracts/token --disable-check missing-require-auth
```

Or persist it in `soroban-guard.toml`:

```toml
disable_checks = ["missing-require-auth"]
```

### A whole file

Exclude the file from the scan:

```bash
soroban-guard scan ./contracts/token --exclude 'src/proxy.rs'
```

Or add it to `soroban-guard.toml`:

```toml
exclude = ["src/proxy.rs"]
```

## Output looks garbled in CI

Colored output relies on ANSI escape codes, which some CI log viewers render as literal characters. Disable colour:

```bash
soroban-guard scan ./contracts/token --no-color
```

For machine-readable output, prefer a structured format and write it to a file:

```bash
soroban-guard scan ./contracts/token --json --output findings.json
soroban-guard scan ./contracts/token --sarif --output findings.sarif
soroban-guard scan ./contracts/token --markdown --output findings.md
```

`--quiet` suppresses console output while the run is passing; output is still shown once a finding meets the `--fail-on` threshold.
