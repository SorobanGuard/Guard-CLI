#![no_std]
use soroban_sdk::{contract, contractimpl, Bytes, Env};

#[contract]
pub struct UpgradeSafe;

#[contractimpl]
impl UpgradeSafe {
    /// Protected upgrade with auth — safe.
    pub fn upgrade(env: Env, new_code: Bytes) {
        env.require_auth();
        env.invoke_wasm(&new_code);
    }
}
