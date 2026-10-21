#![no_std]
use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct AuthOnWrongAddressVulnerable;

#[contractimpl]
impl AuthOnWrongAddressVulnerable {
    /// Vulnerable: authorises the recipient (`to`) instead of the debited
    /// party (`from`), so anyone can move another user's funds by naming
    /// themselves as `to`.
    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        to.require_auth();
        let from_balance: i128 = env.storage().persistent().get(&from).unwrap_or(0);
        let to_balance: i128 = env.storage().persistent().get(&to).unwrap_or(0);
        env.storage()
            .persistent()
            .set(&from, &(from_balance - amount));
        env.storage()
            .persistent()
            .set(&to, &(to_balance + amount));
    }
}