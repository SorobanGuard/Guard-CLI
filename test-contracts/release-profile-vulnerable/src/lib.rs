#![no_std]

use soroban_sdk::{contract, contractimpl, Env};

#[contract]
pub struct ReleaseProfileContract;

#[contractimpl]
impl ReleaseProfileContract {
    pub fn ping(_env: Env) {}
}
