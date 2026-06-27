#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Env};

#[contract]
pub struct AuthOrderVulnerable;

#[contractimpl]
impl AuthOrderVulnerable {
    /// Storage write happens before require_auth — should trigger `auth-after-storage-write` (High).
    pub fn set_value(env: Env, value: i128) {
        env.storage().persistent().set(&symbol_short!("val"), &value);
        env.require_auth();
    }
}
