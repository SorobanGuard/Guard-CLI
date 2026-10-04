#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Env, Symbol};

#[contract]
pub struct VulnerableContract;

const KEY: Symbol = symbol_short!("counter");

#[contractimpl]
impl VulnerableContract {
    /// Increments stored counter with no `env.require_auth()` — should trigger `missing-require-auth`.
    pub fn bump(env: Env) {
        let mut n: u32 = env.storage().instance().get(&KEY).unwrap_or(0);
        n += 1;
        env.storage().instance().set(&KEY, &n);
    }
}
