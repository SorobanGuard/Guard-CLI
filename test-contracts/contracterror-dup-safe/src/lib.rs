#![no_std]
use soroban_sdk::{contract, contractimpl, contracterror};

#[contracterror]
pub enum MyError {
    NotFound = 1,
    Unauthorized = 2,
    BadInput = 3,
}

#[contract]
pub struct ContractErrorDupSafe;

#[contractimpl]
impl ContractErrorDupSafe {
    pub fn run() -> Result<(), MyError> {
        Ok(())
    }
}
