#![no_std]
use soroban_sdk::{contract, contractimpl};

#[contract]
pub struct LongNameSafe;

#[contractimpl]
impl LongNameSafe {
    pub fn get_value() {}
}