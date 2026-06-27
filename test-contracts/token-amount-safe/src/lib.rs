#![no_std]
use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct TokenAmountSafe;

#[contractimpl]
impl TokenAmountSafe {
    pub fn transfer_safe(env: Env, to: Address, amount: u128) {
        if amount > 0 {
            let token = soroban_sdk::token::Client::new(&env, &Address::default());
            token.transfer(&to, &amount);
        }
    }
}
