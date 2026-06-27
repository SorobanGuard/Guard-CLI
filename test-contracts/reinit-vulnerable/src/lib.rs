#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Address, Env};

#[contract]
pub struct ReinitVulnerable;

#[contractimpl]
impl ReinitVulnerable {
    // ❌ No guard: anyone can call initialize again to overwrite owner
    pub fn initialize(env: Env, owner: Address) {
        env.storage()
            .instance()
            .set(&symbol_short!("owner"), &owner);
    }
}
