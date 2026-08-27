# Configuration file

`soroban-guard` reads an optional `soroban-guard.toml` from the scan root (the
directory you pass to `scan`). It lets you pin project-wide defaults so
contributors and CI don't have to repeat CLI flags.

- If the file is absent, defaults are unchanged (no min severity override, no
  disabled checks, no extra sensitive names).
- If the file exists but fails to parse, the scan exits with code `2` and an
  error message pointing at the file.
- CLI flags always take precedence over the config file. `--fail-on` overrides
  `[scan] min_severity`; `--disable-check` is merged with `[checks] disabled`.
- Version checks are opt-in and read `[frontend].version` and
  `[contract].version` from the same file.

## Schema

```toml
[scan]
# Filter out findings below this severity. One of "high", "medium", "low".
# Equivalent to the `--fail-on` flag; the flag wins if both are set.
min_severity = "medium"

[checks]
# Check names to skip entirely, by their `list-checks` name.
disabled = ["unsafe-randomness", "reentrancy"]

[checks.sensitive_names]
# Extra function-name patterns to treat as sensitive (admin/privileged),
# on top of the built-in list used exclusively by the `unprotected-admin` check.
# Note: other checks that have their own sensitive-name lists (e.g.
# `missing-zero-address-check`, `unprotected-upgrade`) do NOT currently
# read this option; see the follow-up issue for potential expansion.
extra = ["drain", "sweep", "rescue_funds"]

[contract]
# API version exposed by the deployed contract.
version = "2"

[frontend]
# API version used by the frontend.
version = "1"
```

## Field reference

| Key | Type | Default | Effect |
|-----|------|---------|--------|
| `[scan] min_severity` | `"high"` \| `"medium"` \| `"low"` | unset | Same as `--fail-on`: exit `1` when a finding at or above this severity is present. |
| `[checks] disabled` | list of strings | `[]` | Check names to skip, merged with any `--disable-check` flags. Unknown names cause the scan to exit `2`. |
| `[checks.sensitive_names] extra` | list of strings | `[]` | Additional function-name patterns treated as privileged/admin-like, appended to the built-in list used **only** by `unprotected-admin`. Other checks (`missing-zero-address-check`, `unprotected-upgrade`) maintain their own separate hardcoded lists and are not affected by this option. |
| `[contract] version` | string | unset | API version exposed by the deployed contract. Required by `check-version` unless passed as `--contract-version`. |
| `[frontend] version` | string | unset | API version used by the frontend. Required by `check-version` unless passed as `--frontend-version`. |

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

## Version compatibility

The compatibility matrix is intentionally explicit and fails closed:

| Frontend API version | Contract API version | Status |
|----------------------|----------------------|--------|
| `1` | `2` | Supported |

Run the check during application startup or deployment verification:

```bash
soroban-guard check-version --config-path .
# Or override values supplied by the config file:
soroban-guard check-version --frontend-version 1 --contract-version 2
```

Exit code `0` means compatible, `1` means a mismatch or unknown version, and
`2` means the check could not be performed. Use `--json` when the caller needs
to render its own warning. The command compares configured values; it does not
query the network or select a contract automatically.
