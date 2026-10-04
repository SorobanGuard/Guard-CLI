#![no_std]
use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct TokenAmountVulnerable;

#[contractimpl]
impl TokenAmountVulnerable {
    pub fn transfer_unsafe(env: Env, token: Address, from: Address, to: Address, amount: i128) {
        let client = soroban_sdk::token::Client::new(&env, &token);
        client.transfer(&from, &to, &amount);
    }
}
