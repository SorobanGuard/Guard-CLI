#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, token, Address, Env};
#[contract]
pub struct Fixture;
#[contractimpl]
impl Fixture {
    pub fn pay(env: Env, token: Address, to: Address, amount: i128) {
        let allowed: Address = env.storage().instance().get(&symbol_short!("token")).unwrap();
        if token != allowed { return; }
        let client = token::Client::new(&env, &token);
        client.transfer(&to, &amount);
    }
}
