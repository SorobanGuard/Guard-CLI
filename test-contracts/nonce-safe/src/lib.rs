#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Address, Env};

#[contract]
pub struct NonceSafe;

#[contractimpl]
impl NonceSafe {
    pub fn update(env: Env, user: Address, nonce: u64, new_val: u32) {
        let stored_nonce: u64 = env.storage().instance().get(&symbol_short!("nonce"))
            .unwrap_or(0);
        if nonce <= stored_nonce {
            return;
        }
        env.storage().instance().set(&symbol_short!("nonce"), &nonce);
        env.storage().instance().set(&symbol_short!("val"), &new_val);
    }
}
