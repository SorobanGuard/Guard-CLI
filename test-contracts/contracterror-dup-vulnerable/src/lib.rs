#![no_std]
use soroban_sdk::{contract, contractimpl, contracterror};

#[contracterror]
pub enum MyError {
    NotFound = 1,
    AlsoNotFound = 1, // duplicate discriminant
    Unauthorized = 2,
}

#[contract]
pub struct ContractErrorDupVulnerable;

#[contractimpl]
impl ContractErrorDupVulnerable {
    pub fn run() -> Result<(), MyError> {
        Ok(())
    }
}
