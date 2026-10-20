#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Env};

#[contract]
pub struct DeprecatedApiSafe;

#[contractimpl]
impl DeprecatedApiSafe {
    pub fn extend(e: Env) {
        e.storage().instance().extend_ttl(100, 1000);
        let _sym = symbol_short!("SAFE");
    }
}
