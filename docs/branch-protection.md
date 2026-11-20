# Branch protection

`main` should be protected so broken commits cannot land while CI is red.

## Merge queue (recommended)

Enable GitHub's **merge queue** for `main`. With the merge queue, GitHub builds a
temporary branch containing the PR combined with the current tip of `main` (and
any other queued PRs) and re-runs CI against that combined tree before merging.
This catches failures that only appear after the merge — for example duplicate
definitions, conflicting edits, or lockfile drift — which a PR-head-only run
cannot detect.

The merge queue re-tests the combined tree via the `merge_group` trigger, so the
CI and security workflows must declare `merge_group:` in their `on:` block (see
`.github/workflows/ci.yml` and `.github/workflows/security.yml`). Without that
trigger the queue has no checks to wait on and will not gate merges.

## Alternative: require up-to-date branches

If the merge queue is not enabled, instead require **"Require branches to be up
to date before merging"** on `main`. This forces each PR to be rebased or merged
with the current `main` tip and re-tested before it can land, giving a similar
guarantee that the post-merge tree compiles.

## Recommended GitHub branch rule for `main`

- Require a pull request before merging.
- Require status checks to pass before merging.
- Require branches to be up to date before merging **or** use the merge queue.
- Required status checks:
  - `ci (ubuntu-latest)`
  - `ci (windows-latest)`
  - `msrv`
  - `fixture-check`
  - `Security / security-audit`
- Restrict force pushes and branch deletion.
- Require CODEOWNERS review for files covered by `.github/CODEOWNERS`.

The repository CI workflow uses the stable Rust toolchain so it can read the
current Cargo lockfile format and should be the required merge gate for changes
to `main`.