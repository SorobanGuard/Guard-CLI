//! Realistic-shaped SEP-41-style token contract used as a regression fixture.
//!
//! Modelled on the public Soroban token example, re-written for this test
//! suite. It is intentionally *safe*: the goal is to measure the analyzer's
//! false-positive rate on idiomatic code (helpers, nested blocks, storage
//! access patterns), not to demonstrate vulnerabilities.
#![no_std]

use soroban_sdk::{contract, contractimpl, contracttype, Address, Env, String};

#[contracttype]
#[derive(Clone)]
pub struct AllowanceKey {
    pub from: Address,
    pub spender: Address,
}

#[contracttype]
#[derive(Clone)]
pub struct AllowanceValue {
    pub amount: i128,
    pub expiration_ledger: u32,
}

#[contract]
pub struct TokenContract;

fn read_balance(env: &Env, id: &Address) -> i128 {
    env.storage().persistent().get(id).unwrap_or(0)
}

fn write_balance(env: &Env, id: &Address, amount: i128) {
    env.storage().persistent().set(id, &amount);
}

fn read_allowance(env: &Env, key: &AllowanceKey) -> AllowanceValue {
    env.storage()
        .temporary()
        .get(key)
        .unwrap_or(AllowanceValue {
            amount: 0,
            expiration_ledger: 0,
        })
}

fn spend_allowance(env: &Env, key: &AllowanceKey, amount: i128) {
    let current = read_allowance(env, key);
    if current.amount < amount {
        panic!("insufficient allowance");
    }
    let remaining = current.amount - amount;
    if remaining == 0 {
        env.storage().temporary().remove(key);
    } else {
        env.storage().temporary().set(
            key,
            &AllowanceValue {
                amount: remaining,
                expiration_ledger: current.expiration_ledger,
            },
        );
    }
}

#[contractimpl]
impl TokenContract {
    pub fn initialize(env: Env, admin: Address, decimal: u32, name: String, symbol: String) {
        if env.storage().instance().has(&"admin") {
            panic!("already initialized");
        }
        env.storage().instance().set(&"admin", &admin);
        env.storage().instance().set(&"decimal", &decimal);
        env.storage().instance().set(&"name", &name);
        env.storage().instance().set(&"symbol", &symbol);
    }

    pub fn mint(env: Env, to: Address, amount: i128) {
        let admin: Address = env.storage().instance().get(&"admin").unwrap();
        admin.require_auth();
        if amount < 0 {
            panic!("negative amount");
        }
        let balance = read_balance(&env, &to);
        write_balance(&env, &to, balance + amount);
    }

    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        from.require_auth();
        if amount < 0 {
            panic!("negative amount");
        }
        let from_balance = read_balance(&env, &from);
        if from_balance < amount {
            panic!("insufficient balance");
        }
        write_balance(&env, &from, from_balance - amount);
        let to_balance = read_balance(&env, &to);
        write_balance(&env, &to, to_balance + amount);
    }

    pub fn approve(
        env: Env,
        from: Address,
        spender: Address,
        amount: i128,
        expiration_ledger: u32,
    ) {
        from.require_auth();
        if amount < 0 {
            panic!("negative amount");
        }
        let key = AllowanceKey { from, spender };
        env.storage().temporary().set(
            &key,
            &AllowanceValue {
                amount,
                expiration_ledger,
            },
        );
    }

    pub fn transfer_from(env: Env, spender: Address, from: Address, to: Address, amount: i128) {
        spender.require_auth();
        if amount < 0 {
            panic!("negative amount");
        }
        let key = AllowanceKey {
            from: from.clone(),
            spender,
        };
        spend_allowance(&env, &key, amount);
        let from_balance = read_balance(&env, &from);
        if from_balance < amount {
            panic!("insufficient balance");
        }
        write_balance(&env, &from, from_balance - amount);
        let to_balance = read_balance(&env, &to);
        write_balance(&env, &to, to_balance + amount);
    }

    pub fn balance(env: Env, id: Address) -> i128 {
        read_balance(&env, &id)
    }

    pub fn allowance(env: Env, from: Address, spender: Address) -> i128 {
        read_allowance(&env, &AllowanceKey { from, spender }).amount
    }
}
