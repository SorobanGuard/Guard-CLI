# Make `missing-require-auth` branch-sensitive (#1049)

## Summary

`FuncBodyScan` set a single `env_require_auth` flag if an auth call appeared anywhere in a function body, so a conditional
auth suppressed the finding for writes on paths that never authenticate. Auth now has to dominate a write on every path.

## What changed

- **`crates/checks/src/auth.rs`** — replaced the flat `Visit` scanner with an ordered, path-aware `AuthState` walker:
  - auth in a condition applies to both branches;
  - `if`/`else` and `match` arms merge with **AND** for auth (must hold on every path) and **OR** for writes;
  - a missing `else` arm contributes an unauthenticated path;
  - auth inside loops and closures is discarded for code after them (they may never run).
- Nine unit tests cover non-exhaustive `if`, auth in both arms, single `match` arm, loop and closure cases, plus the
  existing unconditional-auth cases.

## Acceptance criteria addressed

- Auth in a non-exhaustive `if` no longer gates later writes.
- Auth in both `if`/`else` arms still gates.
- Unit tests for `if`, `if/else`, `match`, loop and closure paths.

## Validation

`cargo test -p soroban-guard-checks --lib auth::tests` → 9 passed. Three unrelated pre-existing failures in `admin::`
and `balance::` tests were present before this change.

closes #1049
