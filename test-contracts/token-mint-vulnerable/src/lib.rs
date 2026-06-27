#![no_std]
use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct TokenMintVulnerable;

#[contractimpl]
impl TokenMintVulnerable {
    pub fn mint(env: Env, to: Address, amount: u128) {
        env.storage().instance().set(&soroban_sdk::symbol_short!("supply"), &amount);
    }
}
