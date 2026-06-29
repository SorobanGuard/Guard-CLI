#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Env, Vec};

const MAX_ITEMS: u32 = 100;

#[contract]
pub struct VecGrowthSafe;

#[contractimpl]
impl VecGrowthSafe {
    // ✅ Length checked before pushing to prevent unbounded growth
    pub fn append_entry(env: Env, value: u32) {
        let key = symbol_short!("items");
        let mut items: Vec<u32> = env
            .storage()
            .persistent()
            .get(&key)
            .unwrap_or(soroban_sdk::vec![&env]);
        if items.len() >= MAX_ITEMS {
            panic!("capacity exceeded");
        }
        items.push_back(value);
        env.storage().persistent().set(&key, &items);
    }
}
