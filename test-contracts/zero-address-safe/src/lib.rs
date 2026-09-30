#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Address, Env};

#[contract]
pub struct ZeroAddressSafe;

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

#[contractimpl]
impl ZeroAddressSafe {
    /// Rejects the contract's own address as the new owner — should not
    /// trigger `missing-zero-address-check`. `require_auth()` alone only
    /// proves who is *calling*; it says nothing about the *value* of
    /// `new_owner`, so the check additionally requires this comparison.
    pub fn set_owner(env: Env, new_owner: Address) {
        env.require_auth();
        assert!(
            new_owner != env.current_contract_address(),
            "invalid address"
        ); // ✅ real invalid-destination check
        env.storage()
            .instance()
            .set(&symbol_short!("owner"), &new_owner);
    }
}
