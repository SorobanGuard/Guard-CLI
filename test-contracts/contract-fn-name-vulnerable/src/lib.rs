#![no_std]
use soroban_sdk::{contract, contractimpl};

#[contract]
pub struct LongNameVulnerable;

#[contractimpl]
impl LongNameVulnerable {
    pub fn this_contract_entrypoint_name_is_too_long() {}
}