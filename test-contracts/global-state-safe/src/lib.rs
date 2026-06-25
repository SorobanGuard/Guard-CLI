#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Env};

/// ✅ State stored in contract storage — passes `mutable-global-state`.
#[contract]
pub struct GlobalStateSafe;

const KEY: soroban_sdk::Symbol = symbol_short!("count");

#[contractimpl]
impl GlobalStateSafe {
    pub fn increment(env: Env) -> u32 {
        let n: u32 = env.storage().instance().get(&KEY).unwrap_or(0);
        let next = n + 1;
        env.storage().instance().set(&KEY, &next);
        next
    }
}
