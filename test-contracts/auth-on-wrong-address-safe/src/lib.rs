#![no_std]
use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct AuthOnWrongAddressSafe;

#[contractimpl]
impl AuthOnWrongAddressSafe {
    /// Safe: the debited party (`from`) authorises the transfer.
    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        from.require_auth();
        let from_balance: i128 = env.storage().persistent().get(&from).unwrap_or(0);
        let to_balance: i128 = env.storage().persistent().get(&to).unwrap_or(0);
        env.storage()
            .persistent()
            .set(&from, &(from_balance - amount));
        env.storage().persistent().set(&to, &(to_balance + amount));
    }

    /// Safe: both parties authorise the transfer.
    pub fn transfer_both(env: Env, from: Address, to: Address, amount: i128) {
        from.require_auth();
        to.require_auth();
        let from_balance: i128 = env.storage().persistent().get(&from).unwrap_or(0);
        let to_balance: i128 = env.storage().persistent().get(&to).unwrap_or(0);
        env.storage()
            .persistent()
            .set(&from, &(from_balance - amount));
        env.storage().persistent().set(&to, &(to_balance + amount));
    }

    /// Safe: the owner authorises the debit.
    pub fn spend(env: Env, owner: Address, recipient: Address, amount: i128) {
        owner.require_auth();
        let owner_balance: i128 = env.storage().persistent().get(&owner).unwrap_or(0);
        let recipient_balance: i128 = env.storage().persistent().get(&recipient).unwrap_or(0);
        env.storage()
            .persistent()
            .set(&owner, &(owner_balance - amount));
        env.storage()
            .persistent()
            .set(&recipient, &(recipient_balance + amount));
    }
}