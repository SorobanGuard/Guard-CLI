#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Address, Env};
#[contract]
pub struct Fixture;
#[contractimpl]
impl Fixture {
    pub fn initialize(env: Env, admin: Address) {
        admin.require_auth();
        env.storage().instance().set(&symbol_short!("admin"), &admin);
    }
}
