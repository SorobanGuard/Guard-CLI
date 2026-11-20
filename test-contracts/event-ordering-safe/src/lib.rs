#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Address, Env};
#[contract]
pub struct Fixture;
#[contractimpl]
impl Fixture {
    pub fn set(env: Env, v: u32) {
        env.storage().instance().set(&symbol_short!("v"), &v);
        env.events().publish((symbol_short!("Set"),), v);
    }
}
