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
  `[scan] min_severity`; `--disable-check` is merged with `[checks] disabled`;
  a positional scan path overrides `[scan] path`.

## Schema

Every table below rejects unknown keys: a typo (`disable` instead of
`disabled`) or a misplaced section (`[check]` instead of `[checks]`) is
treated as a malformed config — the scan exits `2` naming the offending key,
rather than silently ignoring it.

```toml
[scan]
# Directory or file to scan when `soroban-guard scan` is run with no path
# argument. Only read from the config found from the current directory, and a
# relative value is resolved against the current directory.
path = "contracts/token"

# Severity threshold for the `--fail-on` exit gate. One of "high", "medium", "low".
# Equivalent to the `--fail-on` flag; the flag wins if both are set.
# Does not filter findings out of the printed output.
min_severity = "medium"

[checks]
# Check names to skip entirely, by their `list-checks` name.
disabled = ["unsafe-randomness", "reentrancy"]

[checks.sensitive_names]
# Extra function-name patterns to treat as sensitive (admin/privileged),
# on top of the built-in lists used by every name-gated check:
# `unprotected-admin`, `missing-zero-address-check`, `unprotected-upgrade`,
# `unprotected-token-mint`, and `missing-event-for-admin-change`.
extra = ["drain", "sweep", "rescue_funds"]

# Per-check extras: extend only the named check, on top of the global `extra`
# and that check's built-in list. The table key is the check's `list-checks`
# name.
[checks.sensitive_names.unprotected-token-mint]
extra_names = ["mint_rewards"]

[checks.sensitive_names.unprotected-admin]
extra_names = ["rotate_owner"]
```

### Matching semantics

Each entry in `extra` (and in a per-check `extra_names` list) is matched
against a function name as follows:

- An entry that ends with `*` is a **prefix** match: `drain*` matches
  `drain`, `drain_funds`, and `drainAll`.
- Any other entry is an **exact** match: `drain` matches only `drain`.

Matching is case-sensitive and applies to the function's simple name (no
module path). The effective name set for a check is its built-in list, plus
the global `extra` entries, plus that check's own `extra_names` entries.
=======

## Field reference

| Key | Type | Default | Effect |
|-----|------|---------|--------|
| `[scan] path` | string | unset | Scan path used when `scan` is given no positional path. The config is looked up from the current directory (same upward search as above), and a relative value is resolved against the current directory, not the config file's location. If neither a path argument nor this key is set, the scan exits `2`. |
| `[scan] min_severity` | `"high"` \| `"medium"` \| `"low"` | unset | Same as `--fail-on`: exit `1` when a finding at or above this severity is present. |
| `[checks] disabled` | list of strings | `[]` | Check names to skip, merged with any `--disable-check` flags. Unknown names cause the scan to exit `2`. |
| `[checks.sensitive_names] extra` | list of strings | `[]` | Additional function-name patterns treated as privileged/admin-like, appended to the built-in list of **every** name-gated check (`unprotected-admin`, `missing-zero-address-check`, `unprotected-upgrade`, `unprotected-token-mint`, `missing-event-for-admin-change`). An entry ending in `*` is a prefix match; any other entry is an exact match (case-sensitive). |
| `[checks.sensitive_names.<check>] extra_names` | list of strings | `[]` | Additional function-name patterns applied **only** to the check named `<check>` (a `list-checks` name), on top of the global `extra` and that check's built-in list. Same exact/prefix matching rules as `extra`. |

## Example

A contract crate that wants CI to fail on Medium findings, skip the
randomness check (it uses an audited off-chain oracle instead), and flag a
custom `drain` function as sensitive across all name-gated checks, plus a
`mint_rewards` function as sensitive only for `unprotected-token-mint`:

```toml
# soroban-guard.toml
[scan]
min_severity = "medium"

[checks]
disabled = ["unsafe-randomness"]

[checks.sensitive_names]
extra = ["drain"]

[checks.sensitive_names.unprotected-token-mint]
extra_names = ["mint_rewards"]
```

```bash
soroban-guard scan .
```

To make a bare `soroban-guard scan` work from the repository root, set the
default path as well:

```toml
[scan]
path = "contracts/token"
min_severity = "medium"
```

```bash
soroban-guard scan            # scans contracts/token
soroban-guard scan other/dir  # the argument wins over [scan] path
```
