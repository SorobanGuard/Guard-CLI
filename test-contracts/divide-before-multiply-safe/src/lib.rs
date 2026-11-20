#![no_std]

use soroban_sdk::{contract, contractimpl, Env};

#[contract]
pub struct DivideBeforeMultiplySafe;

#[contractimpl]
impl DivideBeforeMultiplySafe {
    /// Correct order: multiply first, then divide.
    pub fn scaled_amount(_env: Env, amount: i128, price: i128, total: i128) -> i128 {
        amount * price / total
    }

    /// Power-of-two shift: dividing by 2 is fine.
    pub fn half(_env: Env, value: i128) -> i128 {
        value / 2
    }

    /// Multiplication by literal 1 is a no-op and should not be flagged.
    pub fn identity(_env: Env, amount: i128, total: i128) -> i128 {
        amount / total * 1
    }

    /// Parenthesised correct order.
    pub fn share(_env: Env, amount: i128, price: i128, total: i128) -> i128 {
        (amount * price) / total
    }
}