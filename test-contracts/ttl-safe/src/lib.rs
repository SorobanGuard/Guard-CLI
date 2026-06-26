#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Env, Symbol};

#[contract]
pub struct TtlSafe;

const KEY: Symbol = symbol_short!("data");

#[contractimpl]
impl TtlSafe {
    /// Writes to persistent storage and extends the TTL — entry will not expire.
    pub fn store(env: Env, v: u32) {
        env.require_auth();
        env.storage().persistent().set(&KEY, &v);
        env.storage().persistent().extend_ttl(&KEY, 100, 1000);
    }
}
