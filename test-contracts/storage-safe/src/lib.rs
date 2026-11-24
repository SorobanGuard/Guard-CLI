#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Address, Env, String, Symbol, Val, Vec};

#[contract]
pub struct StorageSafe;

const KEY: Symbol = symbol_short!("data");

/// `Env::require_auth` is not public SDK API (it's `pub(crate)` and takes an
/// `&Address`); forward the zero-arg call the checks expect to the real
/// public `Address::require_auth` on the contract's own address.
trait EnvRequireAuthExt {
    fn require_auth(&self);
}

impl EnvRequireAuthExt for Env {
    fn require_auth(&self) {
        self.current_contract_address().require_auth();
    }
}

#[contractimpl]
impl StorageSafe {
    /// Persistent storage + fixed `symbol_short!` key — should pass `unsafe-storage-patterns`.
    pub fn put(env: Env, v: u32) {
        env.require_auth();
        env.storage().persistent().set(&KEY, &v);
    }

    /// A dynamic `Symbol::new` that is a cross-contract function name, not a storage key.
    pub fn forward(env: Env, target: Address, fn_name: String) -> Val {
        env.require_auth();
        env.invoke_contract::<Val>(&target, &Symbol::new(&env, &fn_name), Vec::new(&env))
    }

    /// A dynamic `Symbol::new` that is an event topic, not a storage key.
    pub fn announce(env: Env, kind: String, v: u32) {
        env.require_auth();
        env.events().publish((Symbol::new(&env, &kind),), v);
    }
}
