#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Address, Env, BytesN};
#[contract]
pub struct Fixture;
#[contractimpl]
impl Fixture {
    pub fn run(env: Env, user: Address) {
        env.storage().instance().set(&symbol_short!("x"), &1u32);
                        env.storage().instance().extend_ttl(&symbol_short!("x"), 100, 200);
    }
}
