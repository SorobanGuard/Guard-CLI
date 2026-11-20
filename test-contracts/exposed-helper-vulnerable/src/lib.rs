#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Address, Env, BytesN};
#[contract]
pub struct Fixture;
#[contractimpl]
impl Fixture {
    pub fn internal_update(env: Env, user: Address) {
        env.storage().instance().set(&symbol_short!("u"), &user);
    }
}
