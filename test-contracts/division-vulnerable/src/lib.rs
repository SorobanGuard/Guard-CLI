#![no_std]
use soroban_sdk::{contract, contractimpl, Env};

#[contract]
pub struct DivisionVulnerable;

#[contractimpl]
impl DivisionVulnerable {
    /// Integer division silently truncates — should trigger
    /// `integer-division-truncation` (Medium).
    pub fn share(_env: Env, total: i128, parts: i128) -> i128 {
        total / parts // ❌ result truncated
    }
}
