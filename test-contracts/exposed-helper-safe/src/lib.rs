#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Address, Env, BytesN};
#[contract]
pub struct Fixture;
#[contractimpl]
impl Fixture {
    pub fn run(env: Env, user: Address) {
        let _ = (env, user);
    }
}
