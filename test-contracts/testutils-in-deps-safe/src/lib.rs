#![no_std]
use soroban_sdk::{contract, contractimpl, Env};

#[contract]
pub struct SafeContract;

#[contractimpl]
impl SafeContract {
    pub fn ping(_env: Env) -> u32 {
        1
    }
}