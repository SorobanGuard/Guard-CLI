#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, symbol_short, Env};

#[contract]
pub struct AllowanceExpirationVulnerable;

#[contracttype]
#[derive(Clone)]
pub struct Allowance {
    pub amount: i128,
    pub expiration_ledger: u32,
}

#[contractimpl]
impl AllowanceExpirationVulnerable {
    pub fn approve(env: Env, amount: i128, expiration_ledger: u32) {
        env.storage().persistent().set(
            &symbol_short!("allowance"),
            &Allowance {
                amount,
                expiration_ledger,
            },
        );
    }

    pub fn transfer_from(env: Env, amount: i128) {
        let allowance: Allowance = env
            .storage()
            .persistent()
            .get(&symbol_short!("allowance"))
            .unwrap();
        if allowance.amount < amount {
            panic!();
        }
    }
}