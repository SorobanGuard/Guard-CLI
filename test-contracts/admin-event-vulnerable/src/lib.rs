#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Address, Env};

#[contract]
pub struct AdminEventVulnerable;

#[contractimpl]
impl AdminEventVulnerable {
    pub fn set_owner(env: Env, new_owner: Address) {
        env.storage().instance().set(&symbol_short!("owner"), &new_owner);
    }
}
