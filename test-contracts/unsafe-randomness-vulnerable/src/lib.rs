#![no_std]
use soroban_sdk::{contract, contractimpl, Env};

#[contract]
pub struct UnsafeRandomnessVulnerable;

#[contractimpl]
impl UnsafeRandomnessVulnerable {
    /// Uses ledger timestamp as randomness — triggers unsafe-randomness (High).
    pub fn draw_winner(env: Env) -> u32 {
        let seed = env.ledger().timestamp() as u32;
        seed % 100
    }

    /// Uses ledger sequence as randomness — triggers unsafe-randomness (High).
    pub fn random_id(env: Env) -> u64 {
        env.ledger().sequence() as u64
    }
}
