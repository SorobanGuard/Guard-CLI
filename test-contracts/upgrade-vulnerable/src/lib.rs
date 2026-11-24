#![no_std]
use soroban_sdk::{contract, contractimpl, BytesN, Env};

#[contract]
pub struct UpgradeVulnerable;

#[contractimpl]
impl UpgradeVulnerable {
    /// Unprotected upgrade — triggers unprotected-upgrade (High).
    pub fn upgrade(env: Env, new_wasm_hash: BytesN<32>) {
        env.deployer().update_current_contract_wasm(new_wasm_hash);
    }

    /// The same unprotected upgrade under a name no allowlist would contain.
    pub fn set_code(env: Env, new_wasm_hash: BytesN<32>) {
        env.deployer().update_current_contract_wasm(new_wasm_hash);
    }
}
