#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Env};

#[contract]
pub struct EventSafe;

#[contractimpl]
impl EventSafe {
    /// ✅ Every storage write is paired with an event so off-chain indexers
    /// can track state changes. No `missing-event-emission` finding expected.
    pub fn set_value(env: Env, value: i128) {
        env.storage()
            .persistent()
            .set(&symbol_short!("val"), &value);
        env.events()
            .publish((symbol_short!("set_value"),), value);
    }
}
