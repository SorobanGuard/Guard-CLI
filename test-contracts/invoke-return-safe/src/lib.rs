#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Address, Env};

#[contract]
pub struct InvokeReturnSafe;

#[contractimpl]
impl InvokeReturnSafe {
    // ✅ Return value is bound and used
    pub fn notify(env: Env, callee: Address) -> i128 {
        let result = env.invoke_contract::<i128>(
            &callee,
            &symbol_short!("get"),
            soroban_sdk::vec![&env],
        );
        result
    }
}
