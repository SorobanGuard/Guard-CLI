#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Address, Env};

#[contract]
pub struct ReinitSafe;

#[contractimpl]
impl ReinitSafe {
    // ✅ Guards against re-initialization with .has() check
    pub fn initialize(env: Env, owner: Address) {
        let key = symbol_short!("owner");
        if env.storage().instance().has(&key) {
            panic!("already initialized");
        }
        env.storage().instance().set(&key, &owner);
    }
}
