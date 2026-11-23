# Soroban Security Pitfalls

This guide explains *why* each class of Soroban vulnerability matters, with a short
vulnerable/safe snippet per class, and links to the check that detects it. For a
check-by-check reference see [`docs/checks.md`](./checks.md).

> Every registered check is referenced from at least one section below. This is
> enforced by `crates/checks/tests/registry_consistency.rs`.

## Authorization

Soroban auth is explicit: a contract must call `require_auth` (or
`require_auth_for_args`) for the addresses whose authority it relies on. Auth
trees let a call chain prove authorization, but only if every privileged path
actually requires it. Missing or overly broad auth lets anyone invoke a
privileged function.

```rust
// Vulnerable: no auth check before moving funds.
pub fn withdraw(env: Env, from: Address, amount: i128) {
    token::transfer(&env, &from, &amount);
}

// Safe: require auth for the exact address and arguments.
pub fn withdraw(env: Env, from: Address, amount: i128) {
    from.require_auth();
    token::transfer(&env, &from, &amount);
}
```

Detected by: [`missing-require-auth`](./checks.md#missing-require-auth),
[`unprotected-admin`](./checks.md#unprotected-admin),
[`require-auth-for-args`](./checks.md#require-auth-for-args).

## Arithmetic

Integer overflow/underflow and unchecked casts can silently corrupt balances.
Use checked arithmetic and validate inputs.

```rust
// Vulnerable: can overflow.
let total = a + b;

// Safe: checked arithmetic.
let total = a.checked_add(b).expect("overflow");
```

Detected by: [`unchecked-arithmetic`](./checks.md#unchecked-arithmetic),
[`unsafe-cast`](./checks.md#unsafe-cast).

## State & TTL / Archival

Soroban ledger entries expire. Persistent and instance storage must be extended
(`extend_ttl`) or data can be archived and reads fail. Temporary storage is not
suitable for long-lived state.

```rust
// Vulnerable: persistent entry may expire.
env.storage().persistent().set(&key, &value);

// Safe: extend TTL when writing long-lived state.
env.storage().persistent().set(&key, &value);
env.storage().persistent().extend_ttl(&key, min, max);
```

Detected by: [`missing-ttl-extension`](./checks.md#missing-ttl-extension),
[`temporary-storage-misuse`](./checks.md#temporary-storage-misuse).

## Cross-contract calls

Calling another contract trusts its return values and behavior. Validate
addresses, check return values, and avoid re-entrancy hazards.

```rust
// Vulnerable: trusts an arbitrary address and ignores the result.
let other = Address::from_string(&env, &addr);
other.invoke(&env, "transfer", &args);

// Safe: validate the callee and check the result.
let other = Address::from_string(&env, &addr);
let ok: bool = other.invoke(&env, "transfer", &args);
assert!(ok, "transfer failed");
```

Detected by: [`unchecked-cross-contract-call`](./checks.md#unchecked-cross-contract-call),
[`untrusted-callee`](./checks.md#untrusted-callee).

## Upgrade / Admin

Upgrade and admin entry points are the highest-value targets. They must be
guarded by auth and should not be callable by arbitrary addresses.

```rust
// Vulnerable: anyone can upgrade.
pub fn upgrade(env: Env, wasm: Bytes) {
    env.deployer().update_current_contract_wasm(wasm);
}

// Safe: require admin auth.
pub fn upgrade(env: Env, wasm: Bytes) {
    let admin: Address = env.storage().instance().get(&ADMIN).unwrap();
    admin.require_auth();
    env.deployer().update_current_contract_wasm(wasm);
}
```

Detected by: [`unprotected-admin`](./checks.md#unprotected-admin),
[`unprotected-upgrade`](./checks.md#unprotected-upgrade).

## DoS / Budget

`unwrap`/`expect` on user-controlled input, unbounded loops, and excessive
storage reads can panic or exhaust the budget, denying service.

```rust
// Vulnerable: panics on bad input.
let amount: i128 = env.storage().instance().get(&KEY).unwrap();

// Safe: handle the missing case.
let amount: i128 = env.storage().instance().get(&KEY).unwrap_or(0);
```

Detected by: [`unwrap-in-contract`](./checks.md#unwrap-in-contract),
[`unbounded-loop`](./checks.md#unbounded-loop),
[`excessive-storage-reads`](./checks.md#excessive-storage-reads).

## Randomness / Time

Ledger timestamps and pseudo-random values are observable and manipulable.
Do not use them for security-critical decisions.

```rust
// Vulnerable: predictable "randomness".
let r = env.ledger().timestamp() % 100;

// Safe: use a committed seed / oracle, not ledger time.
let r = prng_from_committed_seed(&env);
```

Detected by: [`weak-randomness`](./checks.md#weak-randomness),
[`timestamp-dependence`](./checks.md#timestamp-dependence).

## Deployment / Config

Constructor and initialization paths must be safe against re-initialization and
misconfiguration.

```rust
// Vulnerable: re-initializable.
pub fn init(env: Env, admin: Address) {
    env.storage().instance().set(&ADMIN, &admin);
}

// Safe: guard against re-init.
pub fn init(env: Env, admin: Address) {
    if env.storage().instance().has(&ADMIN) {
        panic!("already initialized");
    }
    env.storage().instance().set(&ADMIN, &admin);
}
```

Detected by: [`reinitialization`](./checks.md#reinitialization),
[`missing-constructor-guard`](./checks.md#missing-constructor-guard).

## Events

Events are how indexers observe contract activity. Missing events make off-chain
systems blind to state changes.

```rust
// Vulnerable: state change with no event.
env.storage().persistent().set(&key, &value);

// Safe: emit an event for indexers.
env.storage().persistent().set(&key, &value);
env.events().publish(("set", key), value);
```

Detected by: [`missing-event`](./checks.md#missing-event).
