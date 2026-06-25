# Checks reference

This document describes what each Soroban Guard Core check looks for and why it matters.

---

## `missing-require-auth` (High)

**Status:** Phase 1

**What it detects**

In an `impl` block marked with `#[contractimpl]` or `#[soroban_sdk::contractimpl]`, any function whose body:

1. Performs a storage mutation through `env.storage()` (heuristic: method calls `set`, `remove`, `extend_ttl`, `bump`, or `append` on a receiver chain that includes `.storage()`), and  
2. Never calls `env.require_auth()` (parameter name **`env`**: `env.require_auth()`).

**Why it matters**

Contract state updates should be gated. This rule recognizes both `env.require_auth()` and `env.require_auth_for_args(…)` as valid auth gates.

**Limitations**

- Only the `Env` binding named `env` counts.
- Static analysis cannot see auth hidden in helpers.

**Fixture:** `test-contracts/vulnerable/`, `test-contracts/safe/`

---

## `unchecked-arithmetic` (High / Medium / Low)

**Status:** Phase 2

**What it detects**

Inside `#[contractimpl]` methods:

- Binary `+`, `-`, `*` where **both** sides are not integer/string literals (so `1 + 2` is ignored, `a + b` is flagged).
- Compound `+=`, `-=`, `*=` (syn 2 represents these as `ExprBinary` with `AddAssign` / `SubAssign` / `MulAssign`).

**Severity heuristic (name-based)**

| Operand name contains | Severity |
|---|---|
| `amount`, `balance`, `fee`, `price`, `supply`, `reward`, `stake`, `fund`, `value`, `total` | **High** |
| `idx`, `index`, `count`, `len`, `offset`, `pos`, `step`, or single-char `i/j/k/n/x/y/z` | **Low** |
| anything else | **Medium** |

**Why it matters**

Wrapping arithmetic on `i128` / `u128` amounts can silently overflow. Prefer `checked_*` or `saturating_*` for token math.

**Limitations**

- Heuristic is purely name-based; review context before acting on Low findings.
- Does not analyze types; it is syntactic.

**Fixture:** `test-contracts/arithmetic-vulnerable/`, `test-contracts/arithmetic-safe/`

---

## `unprotected-admin` (High)

**Status:** Phase 2

**What it detects**

Public (`pub fn`) methods in `#[contractimpl]` whose name **exactly matches** a built-in list of sensitive entrypoints (e.g. `set_owner`, `pause`, `migrate`, `upgrade`, … — see `SENSITIVE_NAMES` in `crates/checks/src/admin.rs`), and whose body contains **no** call to `require_auth` or `require_auth_for_args` on any receiver.

**Why it matters**

Names like `set_owner` strongly suggest privilege; without any auth call the scanner treats the entrypoint as world-callable.

**Limitations**

- Name allowlist only; extend the list as your org sees fit.
- Any `require_auth` / `require_auth_for_args` anywhere in the body clears the finding (no dataflow).

**Fixture:** `test-contracts/admin-vulnerable/`, `test-contracts/admin-safe/`

---

## `unsafe-storage-patterns` (Medium)

**Status:** Phase 2

**What it detects**

1. **Temporary storage writes** — `env.storage().temporary()` in the receiver chain of a storage mutation (`set`, `remove`, `extend_ttl`, `bump`, `append`).
2. **Dynamic `Symbol::new` keys** — `Symbol::new(&env, …)` where the second argument is **not** a string literal (e.g. derived from a parameter). Literal second args like `Symbol::new(&env, "fixed")` are ignored.

**Why it matters**

- Temporary data expires with TTL; it is easy to misuse for long-lived balances or ownership.
- Caller-derived symbol strings are easier to enumerate or collide than fixed `symbol_short!` keys.

**Limitations**

- Does not analyze `symbol_short!(...)` macros beyond normal parsing.
- `Symbol::new` with a `const` or macro-expanded literal may still be flagged if it is not a `syn::Lit::Str`.

**Fixture:** `test-contracts/storage-vulnerable/`, `test-contracts/storage-safe/`

---

## `unsafe-cross-contract-input` (High)

**Status:** Phase 3

**What it detects**

In `#[contractimpl]` methods: a local binding assigned from `invoke_contract(…)` that flows directly into `env.storage().*.set(…, &binding)` without any intervening validation (no `if`, `match`, `unwrap_or*`, `ok_or*`, or `checked_*` expression between the binding and the storage write).

**Why it matters**

Cross-contract call return values are externally influenced. Writing them to persistent ledger storage without validation can corrupt contract state or enable injection attacks.

**Limitations**

- Binding-level taint only; multi-step transformations that preserve the raw value are not tracked.
- Validation done inside a helper function is not visible to this check.

**Fixture:** tests in `crates/checks/src/xc_input.rs`

---

## `missing-contract-annotation` (Low)

**Status:** Phase 3

**What it detects**

A file containing a `#[contractimpl]` (or `#[soroban_sdk::contractimpl]`) `impl` block but no `#[contract]` struct in the same file.

**Why it matters**

The Soroban SDK requires a `#[contract]` struct to be present alongside `#[contractimpl]`. A mismatch is almost always a copy-paste error and will produce a compile error or unexpected runtime behaviour.

**Limitations**

- File-scoped only; does not resolve cross-file references.
- Only `#[contract]` on a `struct` item is recognized.

**Fixture:** tests in `crates/checks/src/annotations.rs`
