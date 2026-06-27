#![no_std]
use soroban_sdk::{contract, contractimpl, Env};

#[contract]
pub struct UncheckedDivisorVulnerable;

#[contractimpl]
impl UncheckedDivisorVulnerable {
    /// Divides without checking divisor — triggers unchecked-divisor (High).
    pub fn calculate_share(env: Env, total: u128, shares: u128) -> u128 {
        total / shares
    }

    /// Compound division assignment without check — triggers unchecked-divisor (High).
    pub fn reduce_amount(env: Env, mut amount: u128, divisor: u128) {
        amount /= divisor;
    }
}
