#![no_std]
use soroban_sdk::{contract, contractimpl, BytesN, Env};

/// The `unprotected-upgrade` check flags any `invoke_wasm` call; provide it
/// here as a thin wrapper over the real upgrade primitive
/// (`Deployer::update_current_contract_wasm`), since `Env` has no such
/// method itself.
trait InvokeWasmExt {
    fn invoke_wasm(&self, wasm_hash: &BytesN<32>);
}

impl InvokeWasmExt for Env {
    fn invoke_wasm(&self, wasm_hash: &BytesN<32>) {
        self.deployer()
            .update_current_contract_wasm(wasm_hash.clone());
    }
}

#[contract]
pub struct UpgradeVulnerable;

#[contractimpl]
impl UpgradeVulnerable {
    /// Unprotected upgrade — triggers unprotected-upgrade (High).
    pub fn upgrade(env: Env, new_code: BytesN<32>) {
        env.invoke_wasm(&new_code);
    }

    /// Unprotected migrate — triggers unprotected-upgrade (High).
    pub fn migrate(env: Env, new_code: BytesN<32>) {
        env.invoke_wasm(&new_code);
    }
}
