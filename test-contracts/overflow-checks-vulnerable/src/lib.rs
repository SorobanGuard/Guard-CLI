#![no_std]
use soroban_sdk::{contract, contractimpl};

#[contract]
pub struct OverflowChecksVulnerable;

#[contractimpl]
impl OverflowChecksVulnerable {
    pub fn add(a: i64, b: i64) -> i64 {
        a + b
    }
}
