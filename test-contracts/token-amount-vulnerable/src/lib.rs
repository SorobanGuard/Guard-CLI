#![no_std]
use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct TokenAmountVulnerable;

#[contractimpl]
impl TokenAmountVulnerable {
    pub fn transfer_unsafe(env: Env, to: Address, amount: u128) {
        let token = soroban_sdk::token::Client::new(&env, &Address::default());
        token.transfer(&to, &amount);
    }
}
