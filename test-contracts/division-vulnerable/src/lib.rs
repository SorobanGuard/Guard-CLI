#![no_std]
use soroban_sdk::{contract, contractimpl, Env};

#[contract]
pub struct DivisionVulnerable;

#[contractimpl]
impl DivisionVulnerable {
    /// Divisor is validated, so `unchecked-divisor` does not fire — but the
    /// division still silently truncates, which should trigger
    /// `integer-division-truncation` (Medium).
    pub fn share(_env: Env, total: i128, parts: i128) -> i128 {
        if parts == 0 {
            panic!("parts must not be zero");
        }
        total / parts // ❌ result truncated
    }
}
