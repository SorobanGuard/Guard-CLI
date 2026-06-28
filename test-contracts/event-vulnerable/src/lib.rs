#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Env};

#[contract]
pub struct EventVulnerable;

#[contractimpl]
impl EventVulnerable {
    /// ❌ Writes to storage but never calls env.events().publish().
    /// Off-chain indexers have no way to track this state change.
    /// Should trigger `missing-event-emission` (Medium).
    pub fn set_value(env: Env, value: i128) {
        env.storage()
            .persistent()
            .set(&symbol_short!("val"), &value);
    }
}
