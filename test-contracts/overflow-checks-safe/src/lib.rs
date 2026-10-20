#![no_std]
use soroban_sdk::{contract, contractimpl};

#[contract]
pub struct OverflowChecksSafe;

#[contractimpl]
impl OverflowChecksSafe {
    pub fn add(a: i64, b: i64) -> i64 {
        a.checked_add(b).unwrap_or(0)
    }
}
