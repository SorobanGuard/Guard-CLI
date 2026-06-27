#![no_std]
use soroban_sdk::{contract, contractimpl, Env};

// Both #[contract] and #[contractimpl] present — should pass `missing-contract-annotation`.
#[contract]
pub struct AnnotationSafe;

#[contractimpl]
impl AnnotationSafe {
    pub fn hello(_env: Env) -> u32 {
        42
    }
}
