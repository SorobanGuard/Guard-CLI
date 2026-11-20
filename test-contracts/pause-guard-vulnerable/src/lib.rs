#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Address, Env};
#[contract]
pub struct Fixture;
#[contractimpl]
impl Fixture {
    pub fn pause(env: Env) {
        env.storage().instance().set(&symbol_short!("paused"), &true);
    }
    pub fn withdraw(env: Env, to: Address, amount: i128) {
        let _ = (to, amount);
        env.storage().instance().set(&symbol_short!("bal"), &amount);
    }
}
