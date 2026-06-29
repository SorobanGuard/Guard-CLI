#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Address, Env};

#[contract]
pub struct DelegateVulnerable;

#[contractimpl]
impl DelegateVulnerable {
    /// ❌ The callee address is read from persistent storage.
    /// If storage is poisoned (e.g., via a malicious upgrade or temp-storage
    /// race), this call can be redirected to an attacker-controlled contract.
    /// Should trigger `delegate-call-risk` (Medium).
    pub fn forward(env: Env) {
        let callee: Address = env
            .storage()
            .persistent()
            .get(&symbol_short!("callee"))
            .unwrap();
        env.invoke_contract::<()>(
            &callee,
            &symbol_short!("ping"),
            soroban_sdk::vec![&env],
        );
    }
}
