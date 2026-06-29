# Finding JSON schema

This document is the stable schema reference for the JSON output produced by
`soroban-guard scan --json`. Third-party tools (dashboards, IDE plugins, CI
parsers) should build against this spec.

---

## Invoking JSON output

```bash
soroban-guard scan ./my-contract --json
```

To write to a file instead of stdout:

```bash
soroban-guard scan ./my-contract --json --output findings.json
```

---

## Top-level envelope

Every `--json` response is a single JSON object with two keys.

```jsonc
{
  "summary":  { /* ScanSummary — see below */ },
  "findings": [ /* Finding[] — see below */ ]
}
```

On a scan error (I/O failure or parse error) the tool exits with code `2` and
emits a reduced envelope instead:

```json
{ "error": "failed to read src/lib.rs: permission denied" }
```

### `ScanSummary` object

| Field | Type | Description |
|---|---|---|
| `total` | integer | Total number of findings across all severities |
| `high` | integer | Count of `"high"` findings |
| `medium` | integer | Count of `"medium"` findings |
| `low` | integer | Count of `"low"` findings |
| `files_scanned` | integer | Number of `.rs` files that were parsed |

All fields are always present; counts are `0` when there are no findings of
that severity.

```jsonc
"summary": {
  "total": 3,
  "high": 1,
  "medium": 1,
  "low": 1,
  "files_scanned": 4
}
```

---

## `Finding` object

```jsonc
{
  "check_name":    "missing-require-auth",
  "severity":      "high",
  "file_path":     "src/lib.rs",
  "line":          12,
  "function_name": "set_balance",
  "description":   "Public function writes to storage without calling env.require_auth().",
  "rule_url":      "https://github.com/SorobanGuard/Guard-CLI/blob/main/docs/checks.md#missing-require-auth-high",
  "suggestion":    "Add env.require_auth(); at the top of the function body."
}
```

### Field reference

| Field | Type | Required | Description |
|---|---|---|---|
| `check_name` | string | yes | Stable kebab-case identifier for the rule that produced this finding. Values match the names listed in `soroban-guard list-checks` and the anchors in `docs/checks.md`. |
| `severity` | string | yes | One of `"high"`, `"medium"`, or `"low"` (always lowercase). |
| `file_path` | string | yes | Path to the source file, relative to the directory passed to `scan`. See [file_path notes](#file_path-notes) below. |
| `line` | integer | yes | 1-based source line number where the issue was detected. |
| `function_name` | string | yes | Name of the enclosing function or method. Empty string (`""`) when the issue occurs outside any function body. |
| `description` | string | yes | Human-readable explanation of the finding. The text is not stable across releases; do not parse it programmatically — use `check_name` for logic branching. |
| `rule_url` | string | no | URL to the relevant section of `docs/checks.md`. Omitted from the object entirely when not set (the key does not appear as `null`). |
| `suggestion` | string | no | One-liner fix hint. Omitted entirely when not set. |

### Optional field behaviour

`rule_url` and `suggestion` use `#[serde(skip_serializing_if = "Option::is_none")]`
in the Rust source, so they are **absent from the JSON object** when not populated
rather than serialized as `null`. Parsers should treat a missing key and a `null`
value identically (i.e. use an optional/nullable field type, not a required one).

```jsonc
// Both of the following are valid Finding objects:

// With optional fields present:
{ "check_name": "unchecked-arithmetic", "severity": "high", "file_path": "src/token.rs",
  "line": 34, "function_name": "mint", "description": "...",
  "rule_url": "https://...", "suggestion": "Use checked_add()" }

// Without optional fields:
{ "check_name": "unchecked-arithmetic", "severity": "high", "file_path": "src/token.rs",
  "line": 34, "function_name": "mint", "description": "..." }
```

### `file_path` notes

- The path is **always relative** to the directory passed to `scan`. If you ran
  `soroban-guard scan ./contracts/token`, a finding in
  `./contracts/token/src/lib.rs` will have `file_path: "src/lib.rs"`.
- Directory separators follow the platform convention of the machine running the
  scan (`/` on Linux/macOS, `\` on Windows). Normalize before comparing paths
  across platforms.
- The path does not start with `./` or `/`.

### `severity` values

| JSON value | Meaning | CLI exit code |
|---|---|---|
| `"high"` | Critical — block deploy / commit | `1` |
| `"medium"` | Notable — review before release | `0` (unless `--fail-on-any`) |
| `"low"` | Informational | `0` (unless `--fail-on-any`) |

---

## Complete example

```json
{
  "summary": {
    "total": 2,
    "high": 1,
    "medium": 1,
    "low": 0,
    "files_scanned": 3
  },
  "findings": [
    {
      "check_name": "missing-require-auth",
      "severity": "high",
      "file_path": "src/lib.rs",
      "line": 12,
      "function_name": "set_balance",
      "description": "Public function writes to storage without calling env.require_auth().",
      "rule_url": "https://github.com/SorobanGuard/Guard-CLI/blob/main/docs/checks.md#missing-require-auth-high",
      "suggestion": "Add env.require_auth(); at the top of the function body."
    },
    {
      "check_name": "unchecked-arithmetic",
      "severity": "medium",
      "file_path": "src/token.rs",
      "line": 47,
      "function_name": "mint",
      "description": "Wrapping addition on `count` may overflow.",
      "suggestion": "Use checked_add() or saturating_add() instead of +"
    }
  ]
}
```

---

## Stability guarantees

| What is stable | What may change |
|---|---|
| All required field names | `description` text (human-readable prose) |
| `severity` string values (`"high"` / `"medium"` / `"low"`) | `rule_url` domain/path if docs are reorganized |
| `line` being 1-based | Additional optional fields may be added in future releases |
| `check_name` values for shipped checks | Order of findings within the array |
| Envelope shape (`summary` + `findings`) | |

Parsers should treat unknown JSON keys as ignored (forward compatibility).

---

## Related output formats

| Flag | Format | Schema reference |
|---|---|---|
| *(none)* | Coloured terminal text | N/A — not machine-readable |
| `--json` | JSON (this document) | `docs/json-schema.md` |
| `--sarif` | SARIF 2.1.0 | [schemastore.org/sarif-2.1.0](https://json.schemastore.org/sarif-2.1.0.json) |
| `--markdown` | Markdown table | N/A |

See [`docs/integrations.md`](integrations.md) for CI and editor snippets that
consume the `--json` and `--sarif` outputs.
