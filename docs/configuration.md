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
# on top of the built-in list used exclusively by the `unprotected-admin` check.
# Note: other checks that have their own sensitive-name lists do NOT currently
# read this option. Today this includes `missing-zero-address-check`,
# `unprotected-upgrade`, `unprotected-token-mint`, and
# `unprotected-contract-deployment`.
extra = ["drain", "sweep", "rescue_funds"]

[checks.getter_names]
# Extra function-name patterns to treat as read-only getters, on top of the
# built-in list used exclusively by the `view-function-writes-storage` check.
# A `#[contractimpl]` method whose name matches one of these patterns and whose
# body writes storage is reported (pure TTL extension is ignored).
extra = ["peek", "snapshot", "stats"]
```

## Field reference

| Key | Type | Default | Effect |
|-----|------|---------|--------|
| `[scan] path` | string | unset | Scan path used when `scan` is given no positional path. The config is looked up from the current directory (same upward search as above), and a relative value is resolved against the current directory, not the config file's location. If neither a path argument nor this key is set, the scan exits `2`. |
| `[scan] min_severity` | `"high"` \| `"medium"` \| `"low"` | unset | Same as `--fail-on`: exit `1` when a finding at or above this severity is present. |
| `[checks] disabled` | list of strings | `[]` | Check names to skip, merged with any `--disable-check` flags. Unknown names cause the scan to exit `2`. |
| `[checks.sensitive_names] extra` | list of strings | `[]` | Additional function-name patterns treated as privileged/admin-like, appended to the built-in list used **only** by `unprotected-admin`. Other checks (`missing-zero-address-check`, `unprotected-upgrade`, `unprotected-token-mint`, `unprotected-contract-deployment`) maintain their own separate hardcoded lists and are not affected by this option. |
| `[checks.getter_names] extra` | list of strings | `[]` | Additional function-name patterns treated as read-only getters, appended to the built-in list used **only** by `view-function-writes-storage`. The built-in list matches names like `get_*`, `balance`, `total_supply`, `is_*`, `view_*`, and `*_of`. A matching `#[contractimpl]` method whose body mutates storage is reported (Low severity); pure TTL extension (`extend_ttl`/`bump`) is not treated as a mutation. Other checks are not affected by this option. |

## Example

A contract crate that wants CI to fail on Medium findings, skip the
randomness check (it uses an audited off-chain oracle instead), flag a
custom `drain` function as sensitive, and treat `peek`/`snapshot` as getters
for `view-function-writes-storage`:

```toml
# soroban-guard.toml
[scan]
min_severity = "medium"

[checks]
disabled = ["unsafe-randomness"]

[checks.sensitive_names]
extra = ["drain"]

[checks.getter_names]
extra = ["peek", "snapshot"]
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