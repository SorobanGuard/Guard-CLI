#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Env, Vec};

#[contract]
pub struct VecGrowthVulnerable;

#[contractimpl]
impl VecGrowthVulnerable {
    // ❌ Vec read from storage, pushed to, and written back with no length cap
    pub fn append_entry(env: Env, value: u32) {
        let key = symbol_short!("items");
        let mut items: Vec<u32> = env
            .storage()
            .persistent()
            .get(&key)
            .unwrap_or(soroban_sdk::vec![&env]);
        items.push_back(value);
        env.storage().persistent().set(&key, &items);
    }
}
