#![no_std]
use soroban_sdk::{contract, contractimpl, Env};

#[contract]
pub struct ArithmeticSafe;

#[contractimpl]
impl ArithmeticSafe {
    /// Uses `checked_add` — should not trigger `unchecked-arithmetic`.
    pub fn total(_env: Env, a: i128, b: i128) -> Option<i128> {
        a.checked_add(b)
    }
}
