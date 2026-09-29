# Checks reference

This document describes what each Soroban Guard Core check looks for and why it matters.

---

## `missing-require-auth` (High)

**Status:** Phase 1

**What it detects**

In an `impl` block marked with `#[contractimpl]` or `#[soroban_sdk::contractimpl]`, any function whose body:

1. Performs a storage mutation through `env.storage()` (heuristic: method `set`, `remove`, or `append` on a receiver chain that includes `.storage()`), and 
2. Never calls `env.require_auth()` (parameter name **`env`**: `env.require_auth()`).

**Why it matters**

Contract state updates should be gated. This rule recognizes both `env.require_auth()` and `env.require_auth_for_args(...)` as valid auth gates.

**Limitations**

- Only the `Env` binding named `env` counts.
- Static analysis cannot see auth hidden in helpers.
- `extend_ttl`/`bump` are not treated as storage mutations: extending a ledger entry's TTL does not change the stored value, cannot move funds, and cannot escalate privilege, so it is not a write this check cares about.

**Fixture:** `test-contracts/vulnerable/`, `test-contracts/safe/`

---

## `auth-after-storage-write` (High)

**Status:** Phase 1

**What it detects**

In a `#[contractimpl]` method, a storage mutation through `env.storage()` (`set`, `remove`, or `append`) occurs before any call to `env.require_auth()` or `env.require_auth_for_args()` on the same `Env` binding.

**Why it matters**

Authorization should happen before state mutation. If a contract writes to storage before requiring auth, an attacker may influence state changes without being authorized.

**Limitations**

- `extend_ttl`/`bump` are not treated as storage mutations for this check: extending a ledger entry's TTL is a deliberately permissionless operation in Soroban (anyone paying the rent may keep an entry alive) and does not change the stored value, so ordering it before `require_auth()` is not a finding.

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
| --- | --- |
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

Public (`pub fn`) methods in `#[contractimpl]` whose name **exactly** matches a known high-risk entrypoint name (e.g., `set_owner`, `set_admin`, `transfer_ownership`, `pause`, `unpause`, `migrate`, `upgrade`, `emergency_pause`, `emergency_stop`, `grant_role`, `revoke_role`, `withdraw_fees`, `set_fee`, `set_fees`, `renounce_ownership`, `destroy`, `kill`), or a prefix (e.g., `set_admin`, `pause_`, `emergency_`), and whose body never calls `env.require_auth()` or `env.require_auth_for_args()` (any receiver).

**Why it matters**

Privileged-style entrypoints without any `require_auth()` / `require_auth_for_args()` call are a security risk. Anyone may invoke these entrypoints.

**Limitations**

- Only the `Env` binding named `env` or the explicit environment parameter name is recognized.
- Static analysis cannot see auth enforced inside helper functions or via dataflow beyond the method body.
- The check compares the first storage write with the first auth call in source order; complex branching may produce a finding even when every runtime path authorizes before writing.

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

## `symbol-key-collision` (Medium)

**Status:** Phase 2

**What it detects**

Duplicate `symbol_short!("...")` literals in the same `impl` block.

**Why it matters**

Duplicate symbol keys may lead to accidental storage slot collisions.

**Limitations**

- Only detects duplicate `symbol_short!("...")` literals; `Symbol::new(..., "...")` calls are not checked.
- Does not analyze types; it is syntactic.

**Fixture:** `test-contracts/symbol-key-collision-vulnerable/`, `test-contracts/symbol-key-collision-safe/`