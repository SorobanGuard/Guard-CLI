#![no_std]
use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};
#[contract]
pub struct Fixture;
#[contractimpl]
impl Fixture {
    pub fn relay(env: Env) {
        let addr = env.current_contract_address();
        env.invoke_contract::<()>(&addr, &Symbol::new(&env, "run"), soroban_sdk::vec![&env]);
    }
}
