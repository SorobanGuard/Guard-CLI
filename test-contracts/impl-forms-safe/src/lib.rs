//! Safe counterpart to `impl-forms-vulnerable` — same 6 impl shapes but
//! each entrypoint calls `require_auth` before mutating storage.
#![no_std]
use soroban_sdk::{contract, contractimpl, Env};

#[contract]
pub struct PlainContract;

#[contractimpl]
impl PlainContract {
    pub fn set_value(env: Env, caller: soroban_sdk::Address, val: u64) {
        caller.require_auth();
        env.storage().persistent().set(&"key", &val);
    }
}

pub mod inner {
    use soroban_sdk::{contract, contractimpl, Env};

    #[contract]
    pub struct NestedContract;

    #[contractimpl]
    impl NestedContract {
        pub fn store(env: Env, caller: soroban_sdk::Address, val: u64) {
            caller.require_auth();
            env.storage().persistent().set(&"n", &val);
        }
    }
}

#[contract]
pub struct FqContract;

#[soroban_sdk::contractimpl]
impl FqContract {
    pub fn write(env: Env, caller: soroban_sdk::Address, v: u32) {
        caller.require_auth();
        env.storage().instance().set(&"k", &v);
    }
}

#[contract]
pub struct TraitContract;

pub trait TokenOps {
    fn mint(env: Env, caller: soroban_sdk::Address, amount: i128);
}

#[contractimpl]
impl TokenOps for TraitContract {
    fn mint(env: Env, caller: soroban_sdk::Address, amount: i128) {
        caller.require_auth();
        env.storage().persistent().set(&"bal", &amount);
    }
}

#[contract]
pub struct CrateVisContract;

#[contractimpl]
impl CrateVisContract {
    pub(crate) fn update(env: Env, caller: soroban_sdk::Address, v: i64) {
        caller.require_auth();
        env.storage().persistent().set(&"cv", &v);
    }
}

#[contract]
pub struct GenericContainer;

#[contractimpl]
impl GenericContainer {
    pub fn store_pair(env: Env, caller: soroban_sdk::Address, a: u32, b: u32) {
        caller.require_auth();
        env.storage().persistent().set(&"a", &a);
        env.storage().persistent().set(&"b", &b);
    }
}
