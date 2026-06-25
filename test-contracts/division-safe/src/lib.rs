#![no_std]
use soroban_sdk::{contract, contractimpl, Env};

#[contract]
pub struct DivisionSafe;

#[contractimpl]
impl DivisionSafe {
    /// Literal-only division and explicit rounding — should not trigger
    /// `integer-division-truncation`.
    pub fn half(_env: Env) -> i128 {
        6 / 2 // ✅ both operands are literals
    }

    /// Uses checked_div — safe for variable operands.
    pub fn safe_div(_env: Env, total: i128, parts: i128) -> Option<i128> {
        total.checked_div(parts) // ✅ returns None on divide-by-zero, no silent truncation concern
    }
}
