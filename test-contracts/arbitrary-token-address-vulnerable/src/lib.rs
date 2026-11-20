#![no_std]
use soroban_sdk::{contract, contractimpl, token, Address, Env};
#[contract]
pub struct Fixture;
#[contractimpl]
impl Fixture {
    pub fn pay(env: Env, token: Address, to: Address, amount: i128) {
        let client = token::Client::new(&env, &token);
        client.transfer(&to, &amount);
    }
}
