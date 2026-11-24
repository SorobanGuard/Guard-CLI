#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, token, Address, Env};

#[contract]
pub struct InvokeReturnSafe;

#[contractimpl]
impl InvokeReturnSafe {
    // ✅ `invoke_contract` traps the transaction if the callee fails, so a discarded
    // (unit) return value hides nothing.
    pub fn notify(env: Env, callee: Address) {
        env.invoke_contract::<()>(&callee, &symbol_short!("ping"), soroban_sdk::vec![&env]);
    }

    // ✅ The fallible call's `Result` is inspected.
    pub fn pay(env: Env, token: Address, to: Address, amount: i128) -> bool {
        let client = token::Client::new(&env, &token);
        client
            .try_transfer(&env.current_contract_address(), &to, &amount)
            .is_ok()
    }
}
