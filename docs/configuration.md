# Configuration file

`soroban-guard` reads an optional `soroban-guard.toml`. It lets you pin
project-wide defaults so contributors and CI don't have to repeat CLI flags.

- The search starts at the scan path (its parent directory, when the scan
  path is a single file) and climbs through parent directories looking for
  `soroban-guard.toml`, using the nearest one found. The search stops at the
  filesystem root or at the first directory that itself contains `.git` — a
  config file above your project's repository root is never picked up.
  Pass `--verbose` to see which config file was used, or that none was found.
- If no config file is found anywhere in that search, defaults are unchanged
  (no min severity override, no disabled checks, no extra sensitive names).
- If a config file is found but fails to parse — including an unknown key
  anywhere in the file, see below — the scan exits with code `2` and an error
  message pointing at the file and the offending key.
- CLI flags always take precedence over the config file. `--fail-on` overrides
  `[scan] min_severity`; `--disable-check` is merged with `[checks] disabled`.

## Schema

Every table below rejects unknown keys: a typo (`disable` instead of
`disabled`) or a misplaced section (`[check]` instead of `[checks]`) is
treated as a malformed config — the scan exits `2` naming the offending key,
rather than silently ignoring it.

```toml
[scan]
# Severity threshold for the `--fail-on` exit gate. One of "high", "medium", "low".
# Equivalent to the `--fail-on` flag; the flag wins if both are set.
# Does not filter findings out of the printed output.
min_severity = "medium"

[checks]
# Check names to skip entirely, by their `list-checks` name.
disabled = ["unsafe-randomness", "reentrancy"]

[checks.sensitive_names]
# Extra function-name patterns to treat as sensitive (admin/privileged),
# on top of the built-in list used exclusively by the `unprotected-admin` check.
# Note: other checks that have their own sensitive-name lists do NOT currently
# read this option. Today this includes `missing-zero-address-check`,
# `unprotected-upgrade`, `unprotected-token-mint`, and
# `unprotected-contract-deployment`.
extra = ["drain", "sweep", "rescue_funds"]
```

## Field reference

| Key | Type | Default | Effect |
|-----|------|---------|--------|
| `[scan] min_severity` | `"high"` \| `"medium"` \| `"low"` | unset | Same as `--fail-on`: exit `1` when a finding at or above this severity is present. |
| `[checks] disabled` | list of strings | `[]` | Check names to skip, merged with any `--disable-check` flags. Unknown names cause the scan to exit `2`. |
| `[checks.sensitive_names] extra` | list of strings | `[]` | Additional function-name patterns treated as privileged/admin-like, appended to the built-in list used **only** by `unprotected-admin`. Other checks (`missing-zero-address-check`, `unprotected-upgrade`, `unprotected-token-mint`, `unprotected-contract-deployment`) maintain their own separate hardcoded lists and are not affected by this option. |

## Example

A contract crate that wants CI to fail on Medium findings, skip the
randomness check (it uses an audited off-chain oracle instead), and flag a
custom `drain` function as sensitive:

```toml
# soroban-guard.toml
[scan]
min_severity = "medium"

[checks]
disabled = ["unsafe-randomness"]

[checks.sensitive_names]
extra = ["drain"]
```

```bash
soroban-guard scan .
```
