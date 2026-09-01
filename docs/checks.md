# Checks reference

This document describes what each Soroban Guard Core check looks for and why it matters.

---

## `missing-require-auth` (High)

**Status:** Phase 1

**What it detects**

In an `impl` block marked with `#[contractimpl]` or `#[soroban_sdk::contractimpl]`, any function whose body:

1. Performs a storage mutation through `env.storage()` (heuristic: method s `set`, `remove`, `extend_ttl`, `bump`, or `append` on a receiver chain that includes `.storage()`), and  
2. Never calls `env.require_auth()` (parameter name **`env`**: `env.require_auth()`).

**Why it matters**

Contract state updates should be gated. This rule recognizes both `env.require_auth()` and `env.require_auth_for_args(…)` as valid auth gates.

**Limitations**

- Only the `Env` binding named `env` counts.
- Static analysis cannot see auth hidden in helpers.

**Fixture:** `test-contracts/vulnerable/`, `test-contracts/safe/`

---

## `auth-after-storage-write` (High)

**Status:** Phase 1

**What it detects**

In a `#[contractimpl]` method, a storage mutation through `env.storage()` (`set`, `remove`, `extend_ttl`, `bump`, or `append`) occurs before any call to `env.require_auth()` or `env.require_auth_for_args()` on the same `Env` binding.

**Why it matters**

Authorization should happen before state mutation. If a contract writes to storage before requiring auth, an attacker may influence state changes without being authorized.

**Example**

```rust
#[contractimpl]
impl Contract {
	pub fn update(env: Env, value: u32) {
		env.storage().instance().set(&symbol_short!("value"), &value);
		env.require_auth(); // Finding: authorization follows the write.
	}

	pub fn update_safely(env: Env, value: u32) {
		env.require_auth();
		env.storage().instance().set(&symbol_short!("value"), &value);
	}
}
```

**Limitations**

- Only the `Env` binding named `env` or the explicit environment parameter name is recognized.
- Static analysis cannot see auth enforced inside helper functions or via dataflow beyond the method body.
- The check compares the first storage write with the first auth call in source order; complex branching may produce a finding even when every runtime path authorizes before writing.

**Fixture:** `test-contracts/auth-order-vulnerable/`, `test-contracts/auth-order-safe/`

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

**Relationship to `unprotected-upgrade`**

`SENSITIVE_NAMES` in `crates/checks/src/admin.rs` includes `migrate` and `upgrade`, which the dedicated [`unprotected-upgrade`](#unprotected-upgrade-high) check also covers. The overlap is **intentional**: `unprotected-admin` is the broad "privileged entrypoint" net keyed on an exact name match, while `unprotected-upgrade` is narrower and adds upgrade-specific reasoning — it matches on substring (e.g. `set_wasm_hash`, `replace_wasm_v2`) and verifies that the auth call precedes the WASM swap. An unprotected `pub fn upgrade(...)` or `pub fn migrate(...)` is therefore reported by both checks: same root cause, two angles. Adding a `require_auth` / `require_auth_for_args` call clears both findings at once.

**Limitations**

- Name allowlist only; extend the list as your org sees fit.
- Any `require_auth` / `require_auth_for_args` anywhere in the body clears the finding (no dataflow).
- `migrate` / `upgrade` findings are also reported by [`unprotected-upgrade`](#unprotected-upgrade-high) (see above).

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

## `forbidden-std-imports` (High)

**Status:** Phase 2

**What it detects**

Files that contain `#[contract]` or `#[contractimpl]` and also import from `std` with paths such as `use std::...` or `use ::std::...`.

**Why it matters**

Soroban contracts compile to WASM with `#![no_std]`. Importing from `std` causes a compile error for WASM targets and indicates that the contract cannot be deployed as-is.

**Limitations**

- This is a file-level check only.
- It does not detect transitive `std` usage through re-exported types.

**Fixture:** To be added; see issue #117.

---

## `hardcoded-address` (Medium)

**Status:** Phase 3

**What it detects**

A string literal anywhere in the file that matches the shape of a Stellar `StrKey` address — a 56-character base32 run starting with `G` (Ed25519 public key) or `C` (Soroban contract address), bounded by non-alphanumeric characters on both sides. Works on the raw source text rather than the parsed AST, so it catches addresses regardless of which expression they appear in.

**Why it matters**

Baking a fixed account or contract address into source code breaks the contract if that account is ever redeployed or rotated, and makes the contract harder to reuse across networks (e.g. testnet vs. mainnet) without a rebuild. Addresses should be passed in as parameters, read from storage, or supplied via configuration.

**Limitations**

- Purely textual pattern matching — it does not verify the candidate is a valid `StrKey` checksum, so it can flag any 56-char `G...` or `C...` run, including ones in comments or non-address strings that happen to match the shape.
- Does not track whether the literal is actually used to construct an `Address` (e.g. via `Address::from_str`) vs. just printed or compared.

**Fixture:** `test-contracts/hardcoded-address-vulnerable/`, `test-contracts/hardcoded-address-safe/`

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

## `reentrancy-risk` (High)

**What it detects**

Inside a single `#[contractimpl]` method: a storage write (`set`, `remove`, `extend_ttl`, `bump`, or `append` called on a `.storage()`-derived receiver) followed by a call to `invoke_contract` or `invoke_contract_check`, with no intervening storage read (`get`, `get_unchecked`, or `has`) between the write and the call.

**Why it matters**

`invoke_contract` hands control to an external, potentially untrusted contract. If that callee can call back into this contract before the caller's state has been finalized or re-validated, it may observe or act on stale/inconsistent state — the same class of bug as reentrancy in EVM contracts. Following checks-effects-interactions (perform external calls before writes, or re-read state after the call) avoids this.

**Limitations**

- Tracks a single, linear path through one method body; writes and calls reached through different branches of an `if`/`match`, or made from a helper function, are not correlated.
- A storage read anywhere after the write clears the finding, even if it doesn't actually re-validate the state used by the subsequent `invoke_contract` call.

**Fixture:** tests in `crates/checks/src/reentrancy.rs`

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

**Fixture:** Covered by inline `#[cfg(test)]` unit tests in `crates/checks/src/key_collision.rs`.

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

**Fixture:** `test-contracts/self-transfer-vulnerable/`, `test-contracts/self-transfer-safe/`

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

## `mutable-global-state` (High)

**Status:** Phase 3

**What it detects**

A `static mut` item anywhere at module scope (`syn::Item::Static` with `mutability: Mut`).

**Why it matters**

Soroban contract instances are stateless between invocations — each call may run in a fresh execution environment, so a `static mut` value is not guaranteed to persist on-chain and is unsafe to mutate outside of `unsafe` blocks. Using it for state that needs to survive between calls (counters, caches, flags) silently loses data or behaves inconsistently; on-chain state must go through `env.storage()`.

**Limitations**

- Flags the declaration itself, not individual reads/writes — a single `static mut` only produces one finding regardless of how many places mutate it.
- Does not distinguish genuinely persistent-looking usage (e.g. write-once init flags) from clearly incorrect uses; all `static mut` declarations are flagged the same way.

**Fixture:** `test-contracts/global-state-vulnerable/`, `test-contracts/global-state-safe/`

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

Inside `#[contractimpl]` methods, any call to `env.invoke_contract(…)` or `env.invoke_contract_check(…)` whose return value is silently discarded (standalone expression statement, bound to `_`, or bound to an unreferenced variable).

**Why it matters**

Cross-contract calls may fail. Discarding the return value silently swallows errors and can leave the calling contract in an inconsistent state.

**Limitations**

- Only flags discarded or unreferenced return value bindings; does not track complex data flow.

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

## `unprotected-token-mint` (High)

**Status:** Phase 3

**What it detects**

Public (`pub fn`) methods in `#[contractimpl]` whose name contains `mint`, `burn`, `issue`, `redeem`, or `create_tokens`, and whose body contains **no** call to `require_auth` or `require_auth_for_args` on any receiver.

**Why it matters**

Token supply operations are among the most sensitive entrypoints in a Soroban contract. Without an auth gate, any account on the Stellar network can call `mint` or `burn` directly, inflating or destroying token balances at will. This is an immediate economic exploit — comparable to a printable-money bug — and is essentially irreversible once the transaction hits the ledger.

**Limitations**

- Name-based heuristic only: functions that perform minting logic under a different name (e.g. `distribute`, `award`) are not detected.
- Any `require_auth` / `require_auth_for_args` call anywhere in the method body clears the finding, even if it is inside a branch that is never reached in practice.
- Does not verify that the caller being authenticated is actually a trusted admin; a contract that calls `require_auth()` on the wrong address still passes this check.

**Fixture:** `test-contracts/token-mint-vulnerable/`, `test-contracts/token-mint-safe/`

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

---

## `panic-in-contract` (Medium)

**What it detects**

Inside `#[contractimpl]` methods: explicit `panic!()` and `unreachable!()` macro invocations, and `.unwrap()` / `.expect(...)` method calls.

**Why it matters**

Panics abort the transaction with an unhelpful, generic error and can leave the contract in a partially-updated state if some storage writes already happened earlier in the call. Prefer `Result`-returning methods with typed errors, or `env.panic_with_error` for explicit, well-defined aborts.

**Relationship to `uninitialized-storage-read`**

`.unwrap()`/`.expect(...)` chained directly onto a storage `.get(...)`/`.get_unchecked(...)` call (e.g. `env.storage().persistent().get(&K).unwrap()`) is **not** flagged here — that exact pattern is reported once, as the more specific and more severe [`uninitialized-storage-read`](#uninitialized-storage-read-high) finding, instead of being double-reported by both checks.

**Limitations**

- Does not track `unwrap`/`expect` through re-exports or type aliases — only the literal method name is matched.
- Flags every occurrence regardless of whether the `Option`/`Result` being unwrapped is realistically `None`/`Err` (e.g. immediately after a guarded check).

**Fixture:** `test-contracts/panic-vulnerable/`, `test-contracts/panic-safe/`

---

## `missing-ttl-extension` (Low)

**What it detects**

In `#[contractimpl]` methods, writes to persistent storage (`env.storage().persistent().set(...)`, `remove(...)`, or `append(...)`) that are not followed by an `env.storage().persistent().extend_ttl(...)` call in the same function.

**Why it matters**

Persistent contract storage entries eventually expire. Without an explicit TTL extension, the ledger can archive the data and later reads may fail or behave unexpectedly.

**Limitations**

- Only checks for direct persistent writes and TTL extension calls in the same function body.
- Does not analyze helper functions or control-flow paths that extend TTL elsewhere.

**Fixture:** `test-contracts/ttl-vulnerable/`, `test-contracts/ttl-safe/`

---

## `missing-input-length-bound` (Medium)

**What it detects**

Public methods inside `#[contractimpl]` impl blocks that accept a `Bytes` or `Vec` parameter without a `.len()` or `.is_empty()` check for that parameter in the method body.

**Why it matters**

Unbounded caller-provided collections can make a contract perform excessive work or consume more resources than expected. Checking the input length and rejecting values above the contract's intended maximum helps keep execution and storage costs predictable.

**Example**

```rust
#[contractimpl]
impl Contract {
	pub fn process(env: Env, data: Bytes) {
		// Finding: data is used without a length check.
		env.storage().instance().set(&symbol_short!("data"), &data);
	}

	pub fn process_bounded(env: Env, data: Bytes) {
		if data.len() > 1024 {
			panic!("input too large");
		}
		env.storage().instance().set(&symbol_short!("data"), &data);
	}
}
```

**Limitations and known false positives**

- The check is syntactic: any `.len()` or `.is_empty()` call on the parameter clears the finding, even if it does not enforce a useful maximum or minimum.
- It does not infer collection types beyond the `Bytes`/`Vec` text matched by the detector, and type aliases may be missed or misclassified.
- Validation performed in a helper function is not visible to this check.

**Fixture:** tests in `crates/checks/src/missing_input_length_bound.rs`

---

## `large-loop` (Medium)

**What it detects**

Inside `#[contractimpl]` public methods: `loop { … }`, `while <cond> { … }`, or `for <pattern> in <expr> { … }` constructs. The check treats every loop expression as potentially large or unbounded.

**Why it matters**

Soroban contracts run under a fixed compute-budget cap. An unbounded loop can exhaust the budget in a single invocation, causing the transaction to abort. In adversarial scenarios a caller can craft inputs that trigger worst-case iteration counts, turning the contract into a denial-of-service vector against itself.

**Limitations**

- Does not distinguish loops with a provably finite iteration count (e.g. `while i < 10`) from genuinely unbounded ones — all `loop`, `while`, and `for` constructs are flagged.
- It does not estimate collection size or iteration count, so a bounded `for` loop may still be reported.
- Loops inside private helper functions called from a `#[contractimpl]` method are not detected.

**Fixture:** `test-contracts/large-loop-vulnerable/`, `test-contracts/large-loop-safe/`

---

## `missing-nonce` (Medium)

**What it detects**

Public methods in `#[contractimpl]` that:

1. Accept at least one `Address` parameter, and
2. Perform a storage write (`set`, `remove`, `append`, `push`, or `push_back`), and
3. Contain no reference to a nonce or replay-protection identifier — specifically, no identifier matching `nonce`, `sequence`, `seq_num`, or `replay` in the function body.

**Why it matters**

Off-chain-signed meta-transactions (e.g. permit-style flows, delegated actions) must include a nonce or sequence number to prevent replay attacks. Without one, an observer can re-submit a valid signed payload to repeat the state-mutating operation indefinitely on behalf of the signer.

**Example**

```rust
#[contractimpl]
impl Contract {
	pub fn set_balance(env: Env, user: Address, amount: i128) {
		// Finding: Address parameter + storage write, no nonce reference.
		user.require_auth();
		env.storage().persistent().set(&user, &amount);
	}

	pub fn set_balance_protected(env: Env, user: Address, amount: i128, nonce: u64) {
		user.require_auth();
		let key = (symbol_short!("nonce"), user.clone());
		let expected: u64 = env.storage().persistent().get(&key).unwrap_or(0);
		assert_eq!(nonce, expected, "bad nonce");
		env.storage().persistent().set(&key, &(nonce + 1));
		env.storage().persistent().set(&user, &amount);
	}
}
```

**Limitations**

- Detection is purely identifier-based; a nonce stored under a differently-named variable (e.g. `counter`, `ts`) will not clear the finding.
- Does not verify that the nonce value is actually checked or incremented — only that a recognised keyword appears in the function body.
- Validation done inside a helper function called from the flagged method is not visible to this check.

**Fixture:** `test-contracts/nonce-vulnerable/`, `test-contracts/nonce-safe/`

---

## `uninitialized-storage-read` (High)

**What it detects**

In `#[contractimpl]` methods: a storage read (`.storage().<tier>().get(...)` or `.get_unchecked(...)`) with `.unwrap()` or `.expect(...)` chained directly onto it, with no prior `has()` guard.

**Why it matters**

Reading uninitialized storage in Soroban returns `None`; calling `.unwrap()` or `.expect(...)` on it panics and aborts the contract invocation. This is a high-severity failure mode because it can brick a contract for legitimate callers or be triggered intentionally by an attacker to cause a denial of service.

**Relationship to `panic-in-contract`**

This check owns the `storage.get(...).unwrap()`/`.expect(...)` pattern exclusively: [`panic-in-contract`](#panic-in-contract-medium) explicitly skips `.unwrap()`/`.expect(...)` calls chained onto a storage read so the same line isn't reported twice under two different check names.

**Limitations**

- Only flags `.unwrap()`/`.expect(...)` chained directly onto the `.get(...)` call; a read stored in an intermediate variable before unwrapping is not tracked.
- Does not check whether a preceding `has()` guard exists earlier in the function body.

**Fixture:** tests in `crates/checks/src/uninitialized_storage_read.rs`

---

## `unprotected-upgrade` (High)

**What it detects**

In an `impl` block marked with `#[contractimpl]`, a `pub fn` whose name contains `upgrade`, `migrate`, `set_wasm`, or `replace_wasm`, and whose body contains no call to `require_auth` or `require_auth_for_args`.

**Why it matters**

Upgrade and migration entrypoints replace the contract's executable code. Without an authorization check, any caller could push arbitrary WASM, taking full control of the contract.

**Relationship to `unprotected-admin`**

[`unprotected-admin`](#unprotected-admin-high) also flags `upgrade` and `migrate` by exact name match against its `SENSITIVE_NAMES` list. This check is broader: it matches on substring (e.g. `set_wasm_hash`, `replace_wasm_v2`) rather than requiring an exact name, and it additionally checks that the auth call comes *before* the WASM swap. The double report on a plain `upgrade` / `migrate` entrypoint is **intentional** — two useful angles on the same bug — and a single fix (adding `require_auth`) clears both findings.

**Limitations**

- Name-based matching only; an upgrade entrypoint with an unrelated name is not detected.
- Any `require_auth` / `require_auth_for_args` call anywhere in the body clears the finding (no dataflow).

**Fixture:** `test-contracts/upgrade-vulnerable/`, `test-contracts/upgrade-safe/`

---

## `unprotected-contract-deployment` (High)

**What it detects**

In a `#[contractimpl]` method, a call to `.deployer()` (e.g. `env.deployer().upload_contract_wasm(...)` or `env.deployer().deploy(...)`) with no call to `require_auth` or `require_auth_for_args` anywhere in the same method body.

**Why it matters**

Deploying or uploading contract WASM is a privileged operation. Without an authorization check, any caller could deploy arbitrary contracts through the flagged entrypoint, including on behalf of the contract itself.

**Limitations**

- Only detects `.deployer()` calls made directly in the method body; deployment logic delegated to a helper function is not visible to this check.
- Any `require_auth` / `require_auth_for_args` call anywhere in the body clears the finding (no dataflow), even if it does not actually gate the deployer call.

**Fixture:** `test-contracts/contract-deployment-vulnerable/`, `test-contracts/contract-deployment-safe/`

---

## `missing-event-for-admin-change` (Medium)

**What it detects**

Public admin-mutating functions inside `#[contractimpl]` whose name matches a sensitive set (`set_owner`, `set_admin`, `transfer_ownership`, `set_operator`) that write to storage via `set`, `remove`, or `append` but contain no call to `env.events().publish()`.

**Why it matters**

Administrative changes — transferring ownership, rotating operators, changing administrators — are among the most security-critical state transitions in a contract. Without an emitted event, off-chain monitors, indexers, and governance tools have no reliable way to observe or audit these transitions. Silent privilege escalation is difficult to detect after the fact.

**Limitations**

- Detection is name-based; admin functions with non-standard names (e.g. `update_controller`) are not flagged.
- Any `publish` call anywhere in the method body clears the finding, even if it is for an unrelated event.
- Events emitted inside helper functions called by the flagged method are not tracked.

**Fixture:** tests in `crates/checks/src/missing_event_for_admin_change.rs`

---

## `unchecked-token-amount` (Medium)

**What it detects**

In `#[contractimpl]` methods: calls to token transfer or mint-style functions (`transfer`, `transfer_from`, `xfer`, `mint`) where the function body contains no guard that validates the amount is greater than zero (e.g. a comparison expression, `assert!`, or `require!` involving the amount).

**Why it matters**

Passing a zero or negative token amount to a transfer or mint call can result in no-op state changes that silently bypass expected accounting logic, or — depending on the token implementation — an unexpected revert that leaves the contract in an inconsistent state. Explicit amount validation is a baseline defence for any financial operation.

**Limitations**

- Guard detection is heuristic: the check looks for a binary comparison or `assert`/`require`-style macro that references a variable named `amount`. Differently-named parameters or complex guard logic may not be recognized.
- Does not verify that the guard precedes the transfer call in control flow, only that it appears somewhere in the function body.
- Validation performed inside a helper function called by the flagged method is not visible to this check.

**Fixture:** tests in `crates/checks/src/unchecked_token_amount.rs`
