#![no_std]
use soroban_sdk::{contract, contractimpl, Env, Symbol};

#[contract]
pub struct ViewFunctionWritesStorage;

#[contractimpl]
impl ViewFunctionWritesStorage {
    pub fn get_counter(env: Env) -> u32 {
        let key = Symbol::new(&env, "counter");
        let current: u32 = env.storage().instance().get(&key).unwrap_or(0);
        let next = current + 1;
        env.storage().instance().set(&key, &next);
        next
    }

    pub fn total_supply(env: Env) -> u32 {
        let key = Symbol::new(&env, "supply");
        let current: u32 = env.storage().instance().get(&key).unwrap_or(0);
        let next = current + 1;
        env.storage().instance().set(&key, &next);
        next
    }
}