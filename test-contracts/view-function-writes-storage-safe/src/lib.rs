#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Env};

#[contracttype]
pub enum DataKey {
    Value,
}

#[contract]
pub struct ViewFunctionWritesStorageSafe;

#[contractimpl]
impl ViewFunctionWritesStorageSafe {
    // Getter that only reads storage: safe.
    pub fn get_value(env: Env) -> u32 {
        env.storage().instance().get(&DataKey::Value).unwrap_or(0)
    }

    // Getter that only extends TTL: safe (TTL extension is an acceptable side effect).
    pub fn get_value_with_ttl(env: Env) -> u32 {
        env.storage().instance().extend_ttl(100, 200);
        env.storage().instance().get(&DataKey::Value).unwrap_or(0)
    }

    // Non-getter writer: safe (not a getter pattern).
    pub fn set_value(env: Env, value: u32) {
        env.storage().instance().set(&DataKey::Value, &value);
    }
}