#![no_std]
use soroban_sdk::{contract, contractimpl, Bytes, Env};

#[contract]
pub struct UpgradeVulnerable;

#[contractimpl]
impl UpgradeVulnerable {
    /// Unprotected upgrade — triggers unprotected-upgrade (High).
    pub fn upgrade(env: Env, new_code: Bytes) {
        env.invoke_wasm(&new_code);
    }

    /// Unprotected migrate — triggers unprotected-upgrade (High).
    pub fn migrate(env: Env, new_code: Bytes) {
        env.invoke_wasm(&new_code);
    }
}
