#![no_std]
use soroban_sdk::{contract, contractimpl, Bytes, Env};

#[contract]
pub struct InputLengthSafe;

#[contractimpl]
impl InputLengthSafe {
    pub fn process(env: Env, data: Bytes) {
        if data.len() > 1000 {
            return;
        }
    }
}
