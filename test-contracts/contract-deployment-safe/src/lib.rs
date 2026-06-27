#![no_std]
use soroban_sdk::{contract, contractimpl, Bytes, Env};

#[contract]
pub struct ContractDeploymentSafe;

#[contractimpl]
impl ContractDeploymentSafe {
    pub fn upload(env: Env, wasm: Bytes) {
        env.require_auth();
        env.deployer().upload_contract_wasm(&wasm);
    }
}
