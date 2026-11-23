# Roadmap

This document describes what is planned for soroban-guard, what is intentionally
out of scope, and how new checks are added. It is reviewed by maintainers and
updated at each release (see the checklist in [`docs/release.md`](docs/release.md)).

If you are unsure whether an idea fits, open a
[feature request](.github/ISSUE_TEMPLATE/feature_request.md) and reference this
roadmap.

## Now

Work actively in progress or landing in the next release.

- **Baseline support** — track and compare findings against a committed baseline
  so existing debt does not block adoption.
- **Manifest checks** — validate `Cargo.toml` / Soroban manifest configuration
  (e.g. missing or inconsistent contract metadata).
- **Documentation** — keep the check reference and comparison docs current.

## Next

Planned, designed, but not yet scheduled.

- **LSP integration** — surface diagnostics in editors via a language server.
- **Additional checks** — new lint rules following the criteria below.
- **Output formats** — richer machine-readable output for CI pipelines.

## Later

Aspirational; may change based on feedback.

- **Configuration ergonomics** — simpler per-project configuration and presets.
- **Performance** — faster analysis on large workspaces.

## Non-goals

These are intentionally out of scope. Requests for them will be closed with a
pointer to this section.

- **Type inference** — soroban-guard does not infer types; it analyzes source
  as written.
- **Dynamic analysis** — no execution, fuzzing, or runtime instrumentation.
- **Auto-fix of semantic bugs** — the tool may suggest fixes, but it will not
  automatically rewrite code to resolve semantic issues.

## Adding a new check

A new check is accepted when it meets all of the following:

1. **Precision target** — the check must have a low false-positive rate on real
   Soroban contracts; document the precision you measured.
2. **Fixtures** — include positive and negative test fixtures that exercise the
   check, wired into the test suite.
3. **Docs** — add an entry to the check reference describing what the check
   detects, why it matters, and how to resolve a finding.

Open a feature request describing the check, the precision you expect, and the
fixtures you plan to add before sending a pull request.
