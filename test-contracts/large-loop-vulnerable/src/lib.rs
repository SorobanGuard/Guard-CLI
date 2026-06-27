#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Env};

#[contract]
pub struct LargeLoopVulnerable;

#[contractimpl]
impl LargeLoopVulnerable {
    pub fn process(env: Env) {
        loop {
            env.storage().instance().set(&symbol_short!("x"), &1);
        }
    }

    pub fn iterate(env: Env) {
        while true {
            let x = 1u32;
        }
    }
}
