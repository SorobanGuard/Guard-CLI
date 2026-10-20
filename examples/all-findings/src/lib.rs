#![no_std]

// Triggers `forbidden-std-imports`: Soroban contracts are `no_std`, so importing `std`
// is invalid.
use std::collections::HashMap;

use soroban_sdk::{contractimpl, symbol_short, Address, Bytes, Env, Symbol, Vec};

// Triggers `mutable-global-state`: mutable global state is unsafe in deterministic contracts.
static mut CALL_COUNT: u32 = 0;

// Triggers `missing-contract-annotation`: this struct intentionally omits `#[contract]`.
pub struct AllFindingsContract;

const DATA_KEY: Symbol = symbol_short!("data");

// Triggers `missing-contract-annotation`: `#[contractimpl]` exists but there is no
// sibling `#[contract]` struct.
#[contractimpl]
impl AllFindingsContract {
    // Triggers `missing-require-auth`: storage is mutated without `env.require_auth()`.
    // Also triggers `missing-event-emission`: state changes are not paired with an event.
    pub fn unauthenticated_write(env: Env, value: i128) {
        env.storage().instance().set(&DATA_KEY, &value);
    }

    // Triggers `unchecked-arithmetic`: asset-like operands are added with wrapping `+`.
    pub fn unchecked_amount_math(_env: Env, amount: i128, fee: i128) -> i128 {
        amount + fee
    }

    // Triggers `unprotected-admin`: sensitive admin-style entrypoint has no auth gate.
    pub fn set_owner(_env: Env, _new_owner: Address) {}

    // Triggers `auth-after-storage-write`: auth happens after a storage mutation.
    pub fn write_before_auth(env: Env, value: i128) {
        env.storage().persistent().set(&symbol_short!("val"), &value);
        env.require_auth();
    }

    // Triggers `unsafe-storage-patterns`: temporary storage is used for contract state.
    pub fn temporary_state(env: Env, value: i128) {
        env.require_auth();
        env.storage().temporary().set(&symbol_short!("tmp"), &value);
    }

    // Triggers `missing-ttl-extension`: persistent storage is written without `extend_ttl`.
    pub fn persistent_without_ttl(env: Env, value: i128) {
        env.require_auth();
        env.storage().persistent().set(&symbol_short!("ttl"), &value);
    }

    // Triggers `hardcoded-address`: a fixed Stellar address is embedded in source code.
    pub fn hardcoded_admin(env: Env) -> Address {
        Address::from_str(&env, "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF")
    }

    // Triggers `unsafe-cross-contract-input`: cross-contract return value is persisted directly.
    pub fn store_external_value(env: Env, callee: Address) {
        let result = env.invoke_contract::<i128>(&callee, &symbol_short!("get"), ());
        env.storage().persistent().set(&symbol_short!("xval"), &result);
    }

    // Triggers `delegate-call-risk`: callee address is read from storage before invocation.
    // Also triggers `uninitialized-storage-read`: the read is `.unwrap()`-ed with no guard.
    pub fn delegate_from_storage(env: Env) {
        let callee: Address = env
            .storage()
            .persistent()
            .get(&symbol_short!("callee"))
            .unwrap();
        env.invoke_contract::<()>(&callee, &symbol_short!("ping"), soroban_sdk::vec![&env]);
    }

    // Triggers `integer-division-truncation` and `unchecked-divisor`: runtime division
    // can truncate and panic on zero.
    pub fn divide_without_guard(_env: Env, total: i128, parts: i128) -> i128 {
        total / parts
    }

    // Triggers `symbol-key-collision`: duplicate `symbol_short!` keys appear in this impl block.
    pub fn duplicate_keys(_env: Env) {
        let _first = symbol_short!("dupe");
        let _second = symbol_short!("dupe");
    }

    // Triggers `self-transfer`: transfer-like method has no `from == to` guard.
    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        let token = soroban_sdk::token::Client::new(&env, &from);
        token.transfer(&from, &to, &amount);
    }

    // Triggers `missing-zero-address-check`: address is accepted and stored without a
    // zero/default check.
    pub fn set_recipient(env: Env, recipient: Address) {
        env.require_auth();
        env.storage()
            .instance()
            .set(&symbol_short!("recipient"), &recipient);
    }

    // Triggers `re-initialization-risk`: initializer writes state without an already-initialized guard.
    pub fn initialize(env: Env, owner: Address) {
        env.storage().instance().set(&symbol_short!("owner"), &owner);
    }

    // Triggers `unchecked-invoke-return`: cross-contract call return value is ignored.
    pub fn notify(env: Env, callee: Address) {
        env.invoke_contract::<()>(&callee, &symbol_short!("notify"), soroban_sdk::vec![&env]);
    }

    // Triggers `missing-balance-check`: token transfer occurs without a preceding
    // balance/authorized check.
    pub fn send_without_balance_check(
        env: Env,
        token: Address,
        from: Address,
        to: Address,
        amount: i128,
    ) {
        let token_client = soroban_sdk::token::Client::new(&env, &token);
        token_client.transfer(&from, &to, &amount);
    }

    // Triggers `unbounded-vec-growth`: Vec from storage is pushed and stored back without
    // a length cap.
    pub fn append_unbounded(env: Env, value: i128) {
        let key = symbol_short!("items");
        let mut items: Vec<i128> = env
            .storage()
            .persistent()
            .get(&key)
            .unwrap_or(soroban_sdk::vec![&env]);
        items.push_back(value);
        env.storage().persistent().set(&key, &items);
    }

    // Triggers `unsafe-randomness`: ledger timestamp is used as a random seed.
    pub fn random_from_ledger(env: Env) -> u64 {
        env.ledger().timestamp()
    }

    // Triggers `large-loop`: an unbounded loop appears inside a contract method.
    pub fn unbounded_loop(env: Env) {
        loop {
            env.storage().instance().set(&symbol_short!("loop"), &1u32);
        }
    }

    // Triggers `uninitialized-storage-read`: `.get(…)` is `.unwrap()`-ed with no `has()`
    // guard. This does *not* also trigger `panic-in-contract` — that check skips
    // `.unwrap()`/`.expect(…)` chained directly onto a storage read so the two checks don't
    // double-report the same line (see docs/checks.md).
    pub fn unwrap_storage(env: Env) -> i128 {
        env.storage()
            .instance()
            .get::<_, i128>(&symbol_short!("maybe"))
            .unwrap()
    }

    // Triggers `panic-in-contract`: `.unwrap()` on a plain `Option` (not a storage read)
    // aborts the invocation with an unhelpful error.
    pub fn fee_or_panic(_env: Env, fee: Option<u32>) -> u32 {
        fee.unwrap()
    }

    // Triggers `reentrancy-risk`: storage write is followed by an external contract call.
    pub fn write_then_call(env: Env, callee: Address, value: i128) {
        env.storage().persistent().set(&symbol_short!("rent"), &value);
        env.invoke_contract::<()>(&callee, &symbol_short!("call"), soroban_sdk::vec![&env]);
    }

    // Keeps the intentionally invalid `std` import visibly used in the source.
    pub fn std_marker(_env: Env) {
        let _ = HashMap::<u32, u32>::new();
    }

    // Triggers `unprotected-contract-deployment`: `env.deployer()` is used with no
    // `require_auth()` call. Also keeps publish metadata examples realistic by including
    // currently common Soroban parameter types.
    pub fn upload_without_auth(env: Env, wasm: Bytes) {
        env.deployer().upload_contract_wasm(&wasm);
    }

    // Exercises mutable global state in a contract method.
    pub fn increment_global(_env: Env) -> u32 {
        unsafe {
            CALL_COUNT += 1;
            CALL_COUNT
        }
    }

    // Triggers `missing-event-for-admin-change`: admin-style method mutates storage
    // without a paired `env.events().publish(…)` call.
    pub fn set_admin(env: Env, new_admin: Address) {
        env.require_auth();
        env.storage().instance().set(&symbol_short!("admin"), &new_admin);
    }

    // Triggers `unprotected-token-mint`: mint-style entrypoint has no auth gate.
    pub fn mint(_env: Env, _to: Address, _amount: i128) {}

    // Triggers `unprotected-upgrade`: upgrade-style entrypoint has no auth gate.
    pub fn set_wasm(_env: Env, _new_wasm_hash: soroban_sdk::BytesN<32>) {}

    // Triggers `unchecked-token-amount`: transfer amount is not validated before the call.
    pub fn send_tokens(env: Env, token: Address, to: Address, amount: i128) {
        let client = soroban_sdk::token::Client::new(&env, &token);
        client.transfer(&env.current_contract_address(), &to, &amount);
    }

    // Triggers `missing-nonce`: state-mutating method with an `Address` parameter lacks
    // replay protection.
    pub fn update_profile(env: Env, user: Address) {
        env.require_auth();
        env.storage().instance().set(&symbol_short!("profile"), &user);
    }

    // Triggers `missing-input-length-bound`: `Bytes` parameter is used without a length
    // check.
    pub fn store_payload(env: Env, payload: Bytes) {
        env.require_auth();
        env.storage().instance().set(&symbol_short!("payload"), &payload);
    }
}

// Triggers `duplicate-contracterror-code`: two variants share the same discriminant.
#[soroban_sdk::contracterror]
pub enum AllFindingsError {
    NotFound = 1,
    AlsoNotFound = 1,
}
