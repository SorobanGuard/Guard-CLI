#![no_std]

use soroban_sdk::{contract, contractimpl, Env};

#[contract]
pub struct DivideBeforeMultiplyVulnerable;

#[contractimpl]
impl DivideBeforeMultiplyVulnerable {
    /// Vulnerable: divides before multiplying, truncating the fractional part.
    pub fn fee(env: Env, amount: i128, total: i128, price: i128) -> i128 {
        let _ = env;
        amount / total * price
    }

    /// Vulnerable: parenthesised division operand.
    pub fn fee_parenthesised(env: Env, amount: i128, total: i128, price: i128) -> i128 {
        let _ = env;
        (amount / total) * price
    }

    /// Vulnerable: division bound to a local, then multiplied.
    pub fn fee_local(env: Env, amount: i128, total: i128, price: i128) -> i128 {
        let _ = env;
        let share = amount / total;
        share * price
    }
}