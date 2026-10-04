#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Address, Env};

#[contract]
pub struct DelegateSafe;

#[contractimpl]
impl DelegateSafe {
    /// ✅ The callee address comes from the caller, not from storage.
    /// No delegate-call-risk finding should be produced.
    pub fn forward(env: Env, callee: Address) {
        env.invoke_contract::<()>(
            &callee,
            &symbol_short!("ping"),
            soroban_sdk::vec![&env],
        );
    }
}
