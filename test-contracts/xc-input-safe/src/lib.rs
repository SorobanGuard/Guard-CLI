#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Address, Env};

#[contract]
pub struct XcInputSafe;

#[contractimpl]
impl XcInputSafe {
    // ✅ invoke_contract result validated before storage write
    pub fn relay(env: Env, callee: Address) {
        let result = env.invoke_contract::<i128>(&callee, &symbol_short!("get"), ());
        let safe = if result > 0 { result } else { 0 };
        env.storage()
            .persistent()
            .set(&symbol_short!("val"), &safe);
    }
}
