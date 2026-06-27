#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Address, Env};

#[contract]
pub struct InvokeReturnVulnerable;

#[contractimpl]
impl InvokeReturnVulnerable {
    // ❌ Return value of invoke_contract is discarded — callee failure silently ignored
    pub fn notify(env: Env, callee: Address) {
        env.invoke_contract::<()>(
            &callee,
            &symbol_short!("ping"),
            soroban_sdk::vec![&env],
        );
    }
}
