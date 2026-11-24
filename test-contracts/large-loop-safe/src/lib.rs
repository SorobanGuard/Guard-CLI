#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Env, Vec};

const MAX_ITEMS: u32 = 16;

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

    /// Loops with a constant bound: a literal range and `.take(CONST)`.
    pub fn bounded(env: Env, items: Vec<u32>) -> u32 {
        let mut total = 0u32;
        for i in 0..10u32 {
            total = total.wrapping_add(i);
        }
        for x in items.iter().take(MAX_ITEMS as usize) {
            total = total.wrapping_add(x);
        }
        env.storage().instance().set(&symbol_short!("total"), &total);
        total
    }

    /// A caller-supplied collection whose length is checked against a constant first.
    pub fn capped(env: Env, items: Vec<u32>) -> u32 {
        if items.len() > MAX_ITEMS {
            panic!("too many items");
        }
        let mut total = 0u32;
        for x in items.iter() {
            total = total.wrapping_add(x);
        }
        env.storage().instance().set(&symbol_short!("total"), &total);
        total
    }
}
