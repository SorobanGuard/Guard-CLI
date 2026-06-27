#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Address, Env};

#[contract]
pub struct AdminEventSafe;

#[contractimpl]
impl AdminEventSafe {
    pub fn set_owner(env: Env, new_owner: Address) {
        env.storage().instance().set(&symbol_short!("owner"), &new_owner);
        env.events().publish((symbol_short!("owner_changed"),), &new_owner);
    }
}
