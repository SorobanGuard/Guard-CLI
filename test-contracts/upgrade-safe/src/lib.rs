#![no_std]
use soroban_sdk::{contract, contractimpl, BytesN, Env};

/// `Env::require_auth` is not public SDK API (it's `pub(crate)` and takes an
/// `&Address`); forward the zero-arg call the checks expect to the real
/// public `Address::require_auth` on the contract's own address.
trait EnvRequireAuthExt {
    fn require_auth(&self);
}

impl EnvRequireAuthExt for Env {
    fn require_auth(&self) {
        self.current_contract_address().require_auth();
    }
}

#[contract]
pub struct UpgradeSafe;

#[contractimpl]
impl UpgradeSafe {
    /// Protected upgrade: authorization happens before the WASM is replaced.
    pub fn upgrade(env: Env, new_wasm_hash: BytesN<32>) {
        env.require_auth();
        env.deployer().update_current_contract_wasm(new_wasm_hash);
    }
}
