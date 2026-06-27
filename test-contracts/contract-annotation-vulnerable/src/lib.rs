#![no_std]
use soroban_sdk::{contractimpl, Env};

// Missing #[contract] on the struct — should trigger `missing-contract-annotation` (Low).
pub struct AnnotationVulnerable;

#[contractimpl]
impl AnnotationVulnerable {
    pub fn hello(_env: Env) -> u32 {
        42
    }
}
