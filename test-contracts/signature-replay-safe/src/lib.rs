#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Address, BytesN, Env};
#[contract]
pub struct Fixture;
#[contractimpl]
impl Fixture {
    pub fn redeem(env: Env, signer: Address, nonce: u64, msg: BytesN<32>, sig: BytesN<64>) {
        let _ = signer;
        let stored: u64 = env.storage().instance().get(&symbol_short!("nonce")).unwrap_or(0);
        if nonce <= stored { return; }
        let pk = env.crypto().ed25519_public_key_from_bytes(&BytesN::from_array(&env, &[0u8; 32])).unwrap();
        env.crypto().ed25519_verify(&pk, &msg, &sig);
        env.storage().instance().set(&symbol_short!("nonce"), &nonce);
    }
}
