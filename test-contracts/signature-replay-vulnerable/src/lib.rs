#![no_std]
use soroban_sdk::{contract, contractimpl, Address, BytesN, Env};
#[contract]
pub struct Fixture;
#[contractimpl]
impl Fixture {
    pub fn redeem(env: Env, signer: Address, msg: BytesN<32>, sig: BytesN<64>) {
        let _ = signer;
        let pk = env.crypto().ed25519_public_key_from_bytes(&BytesN::from_array(&env, &[0u8; 32])).unwrap();
        env.crypto().ed25519_verify(&pk, &msg, &sig);
    }
}
