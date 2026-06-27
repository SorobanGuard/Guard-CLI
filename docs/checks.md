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

---

## `delegate-call-risk` (High)

**Status:** Phase 3

**What it detects**

In `#[contractimpl]` methods: a call to `invoke_contract` or `try_call` where the contract address argument originates from `env.storage().*.get()` (i.e. a stored address), which indicates a dynamic delegate-like call pattern that can be exploited if the stored address is attacker-controlled.

**Why it matters**

Invoking contracts from a storage-derived address is effectively a delegate call — if an attacker can manipulate the stored address, they can execute arbitrary contract logic.

**Limitations**

- Only detects when the address comes from storage in the same function; cross-function dataflow is not tracked.
- Intentional use (e.g. proxy patterns) is still flagged — review and suppress as needed.

**Fixture:** `test-contracts/delegate-vulnerable/`, `test-contracts/delegate-safe/`

---

## `integer-division-truncation` (Medium)

**Status:** Phase 2

**What it detects**

Inside `#[contractimpl]` methods: integer division (`/`) and compound division-assignment (`/=`) where at least one side is not a literal.

**Why it matters**

Integer division truncates the fractional part, which can lead to precision loss in financial calculations (e.g. fee splitting, reward distribution).

**Limitations**

- Syntactic only — any non-literal divisor triggers the finding regardless of actual values.
- Does not detect `checked_div` misuse or rounding strategies.

**Fixture:** tests in `crates/checks/src/division.rs`

---

## `missing-event-emission` (Medium)

**Status:** Phase 3

**What it detects**

In `#[contractimpl]` methods: storage mutations (`set`, `remove`, `extend_ttl`, `bump`, `append`) that occur in a function body that contains no call to `env.events().publish()`.

**Why it matters**

On-chain state changes should be accompanied by events so that off-chain indexers and users can observe state transitions. Silent state changes reduce transparency.

**Limitations**

- Does not verify that the event payload matches the mutation.
- Events published in helper functions called by the method are not detected.

**Fixture:** `test-contracts/events-vulnerable/`, `test-contracts/events-safe/`

---

## `symbol-key-collision` (Medium)

**Status:** Phase 3

**What it detects**

Within a single `#[contractimpl]` impl block: duplicate `symbol_short!("…")` keys used in `env.storage().instance().get(…)`, `.set(…)`, or `.has(…)` calls.

**Why it matters**

Duplicate storage keys cause silent overwrites. Two contract functions writing different data under the same `Symbol` key will clobber each other, leading to data corruption.

**Limitations**

- Only compares keys that share the same `#[contractimpl]` block; cross-block duplicates are not detected.
- Only `symbol_short!` is analyzed; `Symbol::new` with the same string literal is not matched.

**Fixture:** `test-contracts/key-collision-vulnerable/`, `test-contracts/key-collision-safe/`

---

## `self-transfer` (Medium)

**Status:** Phase 3

**What it detects**

In `#[contractimpl]` methods: calls to token transfer functions (`transfer`, `transfer_from`, `xfer`, `send`, etc.) where there is no guard checking that `from != to` (e.g. `if from != to { … }` or `assert!(from != to, …)`).

**Why it matters**

Self-transfers waste ledger space, waste the caller's gas, and may indicate a logic bug or missing validation in the contract.

**Limitations**

- Guard detection is structural (presence of a comparison expression in the body); complex guard logic may not be recognized.
- Only functions with "transfer" or "send" in the name are inspected.

**Fixture:** `test-contracts/transfer-vulnerable/`, `test-contracts/transfer-safe/`

---

## `missing-zero-address-check` (Medium)

**Status:** Phase 3

**What it detects**

In `#[contractimpl]` methods whose name matches a sensitive set (e.g. `set_owner`, `set_admin`, `initialize`, `init`): function parameters of type `Address` that are not guarded by a zero-address check (`require_auth`, `assert`, or comparison against a default/zero address) before being used.

**Why it matters**

Setting an admin or owner to `Address::default()` (the zero address) can permanently lock privileged functions. The check ensures that sensitive address parameters are validated before use.

**Limitations**

- Guard detection is heuristic — only standard patterns are recognized.
- External validation in helper functions is not tracked.

**Fixture:** tests in `crates/checks/src/zero_address.rs`

---

## `re-initialization-risk` (High)

**What it detects**

Public functions inside `#[contractimpl]` whose name contains `init`, `initialize`, or `setup`, that write to storage via `.set()` without a guard such as `.has()`, `.is_some()`, `.is_none()`, `require!`, or `panic!`.

**Why it matters**

Without a one-time guard, an attacker can call `initialize` again to overwrite the owner or reset critical contract state.

**Limitations**

- Name-based heuristic; rename-based patterns (e.g. `bootstrap`) are not detected.
- Any `.has()` / `.is_some()` anywhere in the function body clears the finding regardless of control-flow.

**Fixture:** `test-contracts/reinit-vulnerable/`, `test-contracts/reinit-safe/`

---

## `unchecked-invoke-return` (Medium)

**What it detects**

Inside `#[contractimpl]` methods, any call to `env.invoke_contract(…)` that appears as a standalone expression statement (semicolon-terminated, not bound to a variable), meaning the return value is silently discarded.

**Why it matters**

Cross-contract calls may fail. Discarding the return value silently swallows errors and can leave the calling contract in an inconsistent state.

**Limitations**

- Only flags the syntactic pattern of a bare statement; does not track data flow.
- `let _ = env.invoke_contract(…);` suppresses the warning even though the value is technically dropped.

**Fixture:** `test-contracts/invoke-return-vulnerable/`, `test-contracts/invoke-return-safe/`

---

## `missing-balance-check` (High)

**What it detects**

Inside `#[contractimpl]` methods, any call to `transfer` or `transfer_from` where the same function body contains no call to `balance()` or `authorized()`.

**Why it matters**

Attempting a transfer without verifying the sender has sufficient funds can cause a runtime panic, disrupting multi-step atomic operations.

**Limitations**

- Purely syntactic: the `balance()` call may be on a different token client or unrelated receiver.
- Does not verify that the balance check precedes the transfer in control flow.

**Fixture:** `test-contracts/balance-vulnerable/`, `test-contracts/balance-safe/`

---

## `unbounded-vec-growth` (Medium)

**What it detects**

Inside `#[contractimpl]` methods, any pattern where a value is read from storage via `.get()`, `.push()` / `.push_back()` / `.append()` is called on it, the result is written back via `.set()`, and no `.len()` call appears in the same function body.

**Why it matters**

Soroban ledger entries have a fixed size limit. A Vec that grows unboundedly across calls will eventually cause the entry to exceed the limit, permanently bricking the contract.

**Limitations**

- Heuristic: any `.len()` call in the function clears the finding even if no cap is enforced.
- Does not detect growth via helper functions called from the flagged method.

**Fixture:** `test-contracts/vec-growth-vulnerable/`, `test-contracts/vec-growth-safe/`

---

## `unsafe-randomness` (High)

**What it detects**

A call chain `env.ledger().timestamp()` or `env.ledger().sequence()` inside a `#[contractimpl]` method, where the binding is used in arithmetic or a conditional that influences storage.

**Why it matters**

Ledger timestamp and sequence are publicly known before transaction finalization. Validators and MEV actors can manipulate or predict these values, making them unsuitable as a source of randomness for games, lotteries, or ID generation.

**Limitations**

- Detects method calls but does not verify downstream usage; `env.ledger().timestamp()` alone is flagged even if unused.
- Does not track taint to subsequent expressions.

**Fixture:** `test-contracts/unsafe-randomness-vulnerable/`, `test-contracts/unsafe-randomness-safe/`

---

## `unchecked-divisor` (High)

**What it detects**

Integer division (`/` or `/=`) inside `#[contractimpl]` methods where the divisor expression is not a literal and is not preceded by a guard that ensures it is non-zero.

**Why it matters**

Division by zero panics in Soroban, aborting the transaction and potentially leaving the contract in an inconsistent state if partial writes occurred before the panic.

**Limitations**

- Syntactic only; does not track guard conditions across control flow.
- Any literal divisor (e.g. `a / 2`) is ignored regardless of context.

**Fixture:** `test-contracts/unchecked-divisor-vulnerable/`, `test-contracts/unchecked-divisor-safe/`
