#![no_std]
use soroban_sdk::{contract, contractimpl, Env, Vec};
#[contract]
pub struct Fixture;
#[contractimpl]
impl Fixture {
    pub fn pick(env: Env, v: Vec<u32>, idx: u32) -> u32 {
        v.get_unchecked(idx)
    }
}
