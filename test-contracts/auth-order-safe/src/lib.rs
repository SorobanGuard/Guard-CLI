#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Env};

#[contract]
pub struct AuthOrderSafe;

#[contractimpl]
impl AuthOrderSafe {
    /// require_auth is called first — should pass `auth-after-storage-write`.
    pub fn set_value(env: Env, value: i128) {
        env.require_auth();
        env.storage().persistent().set(&symbol_short!("val"), &value);
    }
}
