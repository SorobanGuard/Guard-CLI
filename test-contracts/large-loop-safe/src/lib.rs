#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Env};

#[contract]
pub struct LargeLoopSafe;

#[contractimpl]
impl LargeLoopSafe {
    pub fn process(env: Env, count: u32) {
        for i in 0..count {
            env.storage().instance().set(&symbol_short!("x"), &i);
        }
    }
}
