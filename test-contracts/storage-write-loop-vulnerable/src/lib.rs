#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Address, Env, BytesN};
#[contract]
pub struct Fixture;
#[contractimpl]
impl Fixture {
    pub fn run(env: Env, user: Address) {
        for i in 0..user.to_string().len() { env.storage().persistent().set(&symbol_short!("k"), &i); }
    }
}
