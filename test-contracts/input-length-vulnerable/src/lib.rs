#![no_std]
use soroban_sdk::{contract, contractimpl, Bytes, Env};

#[contract]
pub struct InputLengthVulnerable;

#[contractimpl]
impl InputLengthVulnerable {
    pub fn process(env: Env, data: Bytes) {
        let x = data;
    }
}
