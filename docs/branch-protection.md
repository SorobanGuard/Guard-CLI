# Branch protection

`main` should be protected so broken commits cannot land while CI is red.

Recommended GitHub branch rule for `main`:

- Require a pull request before merging.
- Require status checks to pass before merging.
- Require branches to be up to date before merging.
- Required status checks: every job below. GitHub matches required checks on the
  **check-run name**, which is the job's `name:` (or its id when it has none),
  followed by the matrix values in parentheses for a matrixed job. These are the
  names shown in a PR's checks list and in the rule's search box:

  | Required check | Workflow / job | What it gates |
  |---|---|---|
  | `ci (ubuntu-latest)` | `.github/workflows/ci.yml` → `ci`, `os: ubuntu-latest` | fmt, clippy `-D warnings`, `cargo test --workspace`, release build on Linux |
  | `ci (windows-latest)` | `.github/workflows/ci.yml` → `ci`, `os: windows-latest` | the same on Windows (path separators, line endings) |
  | `fixture-check` | `.github/workflows/ci.yml` → `fixture-check` | `cargo check` on every `test-contracts/*/Cargo.toml` and `examples/all-findings` |
  | `MSRV (1.74)` | `.github/workflows/ci.yml` → `msrv` | the crates still build on the minimum supported Rust version |
  | `Security Audit` | `.github/workflows/security.yml` → `security-audit` | `cargo audit` and `cargo deny` |

  A bare `CI / ci` never reports, because the matrix splits it into one check per
  OS. Requiring it would leave the rule waiting forever, or, if it's dropped as
  "not found", silently let Windows-only failures merge. The same goes for
  `fixture-check`: unless it is required, a broken fixture contract does not
  block a merge.
- Restrict force pushes and branch deletion.
- Require CODEOWNERS review for files covered by `.github/CODEOWNERS`.

**Keep this list in sync with the workflows.** Renaming a job, changing its `name:`,
or adding or removing a matrix entry changes its check-run name. Update the rule
(and this table) in the same PR, otherwise the old name stays required and never
reports, or the new job isn't required at all. To see the current names, open any
PR's **Checks** tab, or run:

```sh
gh api repos/SorobanGuard/Guard-CLI/commits/<sha>/check-runs --jq '.check_runs[].name'
```

The repository CI workflow uses the stable Rust toolchain so it can read the
current Cargo lockfile format and should be the required merge gate for changes
to `main`.
