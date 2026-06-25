#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Env};

#[contract]
pub struct PanicSafe;

#[contractimpl]
impl PanicSafe {
    /// Uses unwrap_or_default — should not trigger `panic-in-contract`.
    pub fn get_value(env: Env) -> u32 {
        env.storage()
            .instance()
            .get::<_, u32>(&symbol_short!("val"))
            .unwrap_or(0) // ✅ handles missing key gracefully
    }
}
