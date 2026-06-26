#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Env, Symbol};

#[contract]
pub struct TtlVulnerable;

const KEY: Symbol = symbol_short!("data");

#[contractimpl]
impl TtlVulnerable {
    /// Writes to persistent storage but never calls extend_ttl — entry can expire.
    pub fn store(env: Env, v: u32) {
        env.require_auth();
        env.storage().persistent().set(&KEY, &v);
    }
}
