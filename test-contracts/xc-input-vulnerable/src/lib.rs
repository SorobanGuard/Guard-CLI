#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Address, Env, Symbol};

#[contract]
pub struct XcInputVulnerable;

#[contractimpl]
impl XcInputVulnerable {
    // ❌ invoke_contract result stored directly — no validation
    pub fn relay(env: Env, callee: Address) {
        let result = env.invoke_contract::<i128>(&callee, &symbol_short!("get"), ());
        env.storage()
            .persistent()
            .set(&symbol_short!("val"), &result);
    }
}
