#![no_std]
use soroban_sdk::{contract, contractimpl, Env};

#[contract]
pub struct NegationVulnerable;

#[contractimpl]
impl NegationVulnerable {
    pub fn negate(env: Env, amount: i128) -> i128 {
        let _ = env;
        -amount
    }

    pub fn absolute(env: Env, amount: i128) -> i128 {
        let _ = env;
        amount.abs()
    }
}