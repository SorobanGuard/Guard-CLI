#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Address, Env};

#[contract]
pub struct NonceVulnerable;

#[contractimpl]
impl NonceVulnerable {
    pub fn update(env: Env, user: Address, new_val: u32) {
        env.storage().instance().set(&symbol_short!("val"), &new_val);
    }
}
