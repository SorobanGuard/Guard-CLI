#![no_std]
use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct BalanceVulnerable;

#[contractimpl]
impl BalanceVulnerable {
    // ❌ transfer called without checking sender balance first
    pub fn send(env: Env, token: Address, from: Address, to: Address, amount: i128) {
        let token_client = soroban_sdk::token::Client::new(&env, &token);
        token_client.transfer(&from, &to, &amount);
    }
}
