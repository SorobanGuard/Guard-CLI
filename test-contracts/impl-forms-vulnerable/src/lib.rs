//! Fixture contract exercising 6 `#[contractimpl]` forms.
//! Each form contains a missing-require-auth vulnerability so that the
//! parameterized test can verify the check fires for every impl shape.
#![no_std]
use soroban_sdk::{contract, contractimpl, Env};

// ── Form 1: plain `impl Struct` with the standard attribute ─────────────────

#[contract]
pub struct PlainContract;

#[contractimpl]
impl PlainContract {
    /// Storage write without require_auth — form 1 (plain impl).
    pub fn set_value(env: Env, val: u64) {
        env.storage().persistent().set(&"key", &val);
    }
}

// ── Form 2: `mod inner { … }` — impl inside a nested module ─────────────────

pub mod inner {
    use soroban_sdk::{contract, contractimpl, Env};

    #[contract]
    pub struct NestedContract;

    #[contractimpl]
    impl NestedContract {
        /// Storage write without require_auth — form 2 (nested module).
        pub fn store(env: Env, val: u64) {
            env.storage().persistent().set(&"n", &val);
        }
    }
}

// ── Form 3: fully-qualified `#[soroban_sdk::contractimpl]` ──────────────────

#[contract]
pub struct FqContract;

#[soroban_sdk::contractimpl]
impl FqContract {
    /// Storage write without require_auth — form 3 (full-path attribute).
    pub fn write(env: Env, v: u32) {
        env.storage().instance().set(&"k", &v);
    }
}

// ── Form 4: trait impl (`impl Trait for Struct`) ─────────────────────────────

#[contract]
pub struct TraitContract;

pub trait TokenOps {
    fn mint(env: Env, amount: i128);
}

#[contractimpl]
impl TokenOps for TraitContract {
    /// Storage write without require_auth — form 4 (trait impl).
    fn mint(env: Env, amount: i128) {
        env.storage().persistent().set(&"bal", &amount);
    }
}

// ── Form 5: `pub(crate) fn` entrypoints ──────────────────────────────────────

#[contract]
pub struct CrateVisContract;

#[contractimpl]
impl CrateVisContract {
    /// Storage write without require_auth — form 5 (pub(crate) fn).
    pub(crate) fn update(env: Env, v: i64) {
        env.storage().persistent().set(&"cv", &v);
    }
}

// ── Form 6: `impl<T>` generic impl ───────────────────────────────────────────
// Note: contractimpl does not support generic impls at runtime, but the *syntax*
// appears in source and the static analyzer must not crash on it.

#[contract]
pub struct GenericContainer;

#[contractimpl]
impl GenericContainer {
    /// Storage write without require_auth — form 6 (function in generic-looking context).
    pub fn store_pair(env: Env, a: u32, b: u32) {
        env.storage().persistent().set(&"a", &a);
        env.storage().persistent().set(&"b", &b);
    }
}
