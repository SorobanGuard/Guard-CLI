#![no_std]
use soroban_sdk::{contract, contractimpl, Bytes, Env};

#[contract]
pub struct ContractDeploymentVulnerable;

#[contractimpl]
impl ContractDeploymentVulnerable {
    pub fn upload(env: Env, wasm: Bytes) {
        env.deployer().upload_contract_wasm(&wasm);
    }
}
