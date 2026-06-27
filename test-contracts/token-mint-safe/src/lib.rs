#![no_std]
use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct TokenMintSafe;

#[contractimpl]
impl TokenMintSafe {
    pub fn mint(env: Env, to: Address, amount: u128) {
        env.require_auth();
        env.storage().instance().set(&soroban_sdk::symbol_short!("supply"), &amount);
    }
}
