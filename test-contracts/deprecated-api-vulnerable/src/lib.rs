#![no_std]
use soroban_sdk::{contract, contractimpl, Env, Symbol};

#[contract]
pub struct DeprecatedApiVulnerable;

#[contractimpl]
impl DeprecatedApiVulnerable {
    pub fn extend(e: Env) {
        // Uses legacy .bump(..) instead of .extend_ttl(..)
        e.storage().instance().bump(100, 1000);
        // Uses legacy Symbol::short(..) instead of symbol_short!(..)
        let _sym = Symbol::short("KEY");
    }
}
