# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project follows semantic versioning once published.

## [Unreleased]

### Added

- Inline `// soroban-guard: allow(check-name)` suppression annotations.
- `examples/all-findings` demo contract that intentionally triggers every default check.
- crates.io publishing metadata and release process documentation.
- Documentation for the `forbidden-std-imports` check.

### Changed

- `soroban-guard.toml`: unknown keys anywhere in the file (a typo like
  `disable` instead of `disabled`, or a misplaced section like `[check]`
  instead of `[checks]`) are now a malformed-config error (exit `2`, naming
  the offending key) instead of being silently ignored.

### Fixed

- Storage-write detection: `update` and `try_update` on persistent, temporary and
  instance storage are now recognised as writes by every check
  (`missing-require-auth`, `auth-after-storage-write`, `reentrancy-risk`,
  `missing-event-emission`, `missing-ttl-extension`, `re-initialization-risk`,
  `missing-event-for-admin-change`, `unprotected-token-mint`, `missing-nonce`,
  `unsafe-storage-patterns`). All checks now share one predicate, so
  `missing-nonce` no longer counts `Vec::push`/`push_back` and
  `missing-event-emission` / `unprotected-token-mint` no longer count
  `extend_ttl`/`bump` as state changes (#1051).
- `missing-nonce`: no longer reports methods protected by `require_auth`, whose
  replay protection the host already provides. It now reports functions that
  verify signatures themselves (`ed25519_verify`, `secp256k1_recover`,
  `secp256r1_verify`) without a nonce, and public methods that act for an
  `Address` parameter without any auth (#1052).
- `large-loop`: loops bounded by a constant (`0..10`, `0..=MAX`, `.take(MAX)`,
  array/`BytesN` iteration, a `.len()` cap, `while i < 10`, `loop` with a counter
  `break`) are no longer reported as unbounded (#1053).
- `unsafe-storage-patterns`: a dynamic `Symbol::new` is only reported when it
  flows into a storage key (directly or through `let` bindings), not when it is an
  `invoke_contract` function name or an event topic (#1054).

- `unsafe-storage-patterns`: `Symbol::new` detection now matches the last two
  path segments, so the fully-qualified `soroban_sdk::Symbol::new(...)` form is
  caught, not just the two-segment `Symbol::new(...)`.
- `unsafe-storage-patterns`: the dynamic-key check for `Symbol::new`'s second
  argument now resolves whether a path actually refers to a `const`/`static`
  item instead of guessing from identifier casing, so a lowercase-named
  constant is no longer misflagged and an upper-cased caller-controlled
  parameter is no longer missed.
- `mutable-global-state`: now finds `static mut` at any nesting — inside
  blocks (including `unsafe {}`), free functions, and trait impls — via a
  full `syn::visit` walk, instead of only the shapes a hand-rolled recursion
  anticipated.
- `mutable-global-state`: dropped its own copy of the `#[cfg(test)]`
  detection helper (which only matched a bare `#[cfg(test)]`) in favor of the
  shared one in `util.rs`, now taught to also recognize `test` nested inside
  `all(...)`/`any(...)`, e.g. `#[cfg(all(test, not(target_arch = "wasm32")))]`.
