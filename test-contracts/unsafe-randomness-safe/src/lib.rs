#![no_std]
use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct UnsafeRandomnessSafe;

#[contractimpl]
impl UnsafeRandomnessSafe {
    /// Uses oracle for randomness — safe.
    pub fn draw_winner(_env: Env, random_oracle: Address) -> u32 {
        let _oracle = soroban_sdk::token::Client::new(_env, &random_oracle);
        42
    }

    /// Does not use ledger timestamp for critical logic — safe.
    pub fn log_block_info(env: Env) -> u64 {
        let _info = env.ledger().sequence();
        env.ledger().base_reserve_in_stroops()
    }
}
