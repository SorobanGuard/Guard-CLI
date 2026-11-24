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

- `unsafe-storage-patterns`: the temporary-storage `get_unchecked` rule (soroban-sdk
  has no such method) is replaced by one for `temporary().get(..).unwrap()` /
  `.expect(..)` and for unwrapping the `Option` passed to a temporary
  `update` / `try_update` closure. `get_unchecked` is also dropped from the read
  predicates in `reentrancy-risk`, `panic-in-contract` and
  `uninitialized-storage-read` (#1055).
- `reentrancy-risk`: external calls now include `try_invoke_contract` and any
  method called on a contract client built with `<X>Client::new(..)`
  (`token::Client`, `TokenClient`, generated clients, `use … as` aliases) (#1056).
- `reentrancy-risk`: calls and storage reads in an `if` / `if let` condition are
  now seen (#1057).
- `unsafe-randomness`: removed the dead `visit_impl_item_fn` override; a test now
  asserts that no default check reports an empty `function_name` for a finding
  inside a method (#1058).
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
