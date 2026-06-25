#![no_std]
use soroban_sdk::{contract, contractimpl, Env};

/// ❌ Mutable global state — should trigger `mutable-global-state` (High).
static mut CALL_COUNT: u32 = 0;

#[contract]
pub struct GlobalStateVulnerable;

#[contractimpl]
impl GlobalStateVulnerable {
    pub fn increment(_env: Env) -> u32 {
        unsafe {
            CALL_COUNT += 1;
            CALL_COUNT
        }
    }
}
