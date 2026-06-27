#![no_std]
use soroban_sdk::{contract, contractimpl, Env};

#[contract]
pub struct UncheckedDivisorSafe;

#[contractimpl]
impl UncheckedDivisorSafe {
    /// Uses literal divisor — safe.
    pub fn halve(env: Env, amount: u128) -> u128 {
        amount / 2
    }

    /// Validates divisor before use — safe.
    pub fn divide_safe(env: Env, total: u128, divisor: u128) -> Option<u128> {
        if divisor == 0 {
            return None;
        }
        Some(total / divisor)
    }

    /// Uses checked_div — safe.
    pub fn divide_checked(_env: Env, a: u128, b: u128) -> Option<u128> {
        a.checked_div(b)
    }
}
