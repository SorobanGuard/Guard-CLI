#![no_std]
use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct BalanceSafe;

#[contractimpl]
impl BalanceSafe {
    // ✅ balance checked before transfer
    pub fn send(env: Env, token: Address, from: Address, to: Address, amount: i128) {
        let token_client = soroban_sdk::token::Client::new(&env, &token);
        let bal = token_client.balance(&from);
        if bal < amount {
            panic!("insufficient balance");
        }
        token_client.transfer(&from, &to, &amount);
    }
}
