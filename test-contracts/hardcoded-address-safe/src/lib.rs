#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Address, Env};

#[contract]
pub struct HardcodedAddressSafe;

#[contractimpl]
impl HardcodedAddressSafe {
    // ✅ Address passed as a parameter — no hardcoded key in source
    pub fn set_admin(env: Env, admin: Address) {
        env.storage().instance().set(&symbol_short!("admin"), &admin);
    }

    pub fn get_admin(env: Env) -> Address {
        env.storage().instance().get(&symbol_short!("admin")).unwrap()
    }
}
