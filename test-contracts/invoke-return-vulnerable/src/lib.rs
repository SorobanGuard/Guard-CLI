#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, token, Address, Env, InvokeError, Val};

#[contract]
pub struct InvokeReturnVulnerable;

#[contractimpl]
impl InvokeReturnVulnerable {
    // ❌ `try_invoke_contract` returns the callee's failure as a `Result`, and it is dropped.
    pub fn notify(env: Env, callee: Address) {
        let _ = env.try_invoke_contract::<Val, InvokeError>(
            &callee,
            &symbol_short!("ping"),
            soroban_sdk::vec![&env],
        );
    }

    // ❌ The token transfer may have failed, but the function carries on regardless.
    pub fn pay(env: Env, token: Address, to: Address, amount: i128) {
        let client = token::Client::new(&env, &token);
        let _ = client.try_transfer(&env.current_contract_address(), &to, &amount);
    }
}
