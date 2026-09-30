#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Env};

#[contract]
pub struct LargeLoopSafe;

#[contractimpl]
impl LargeLoopSafe {
    /// Safe pattern: single operation without explicit loops.
    /// This demonstrates code that handles iteration internally (e.g., through
    /// a library function or pre-computed value) rather than using an explicit
    /// loop expression that would trigger large-loop detection.
    pub fn process(env: Env, value: u32) {
        // Single operation without loop expression
        env.storage().instance().set(&symbol_short!("x"), &value);
    }

    /// Another safe pattern: bounded computation without explicit loops.
    pub fn compute_sum(env: Env, n: u32) -> u32 {
        // Use mathematical formula instead of loop
        let result = (n.wrapping_mul(n.wrapping_add(1))) / 2;
        env.storage().instance().set(&symbol_short!("sum"), &result);
        result
    }
}
