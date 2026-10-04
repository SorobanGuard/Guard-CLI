#![no_std]
use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct TokenAmountSafe;

#[contractimpl]
impl TokenAmountSafe {
    pub fn transfer_safe(env: Env, token: Address, from: Address, to: Address, amount: i128) {
        if amount > 0 {
            let client = soroban_sdk::token::Client::new(&env, &token);
            client.transfer(&from, &to, &amount);
        }
    }
}
