#![no_std]
use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct HardcodedAddressVulnerable;

#[contractimpl]
impl HardcodedAddressVulnerable {
    // ❌ Stellar public key baked into source — triggers hardcoded-address
    pub fn get_admin(env: Env) -> Address {
        Address::from_str(&env, "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF")
    }
}
