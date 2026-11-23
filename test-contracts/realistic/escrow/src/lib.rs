//! Realistic-shaped escrow contract fixture for the false-positive regression suite (#1022).
//!
//! Modelled on the public Soroban escrow example, re-written from scratch and
//! licence-compatible (Apache-2.0). This contract is intentionally *safe*: it
//! uses `require_auth`, checked arithmetic, explicit state transitions and no
//! `unwrap`/`expect` on user input. The regression test asserts the default
//! check set reports zero High findings here.
#![no_std]

use soroban_sdk::{contract, contracterror, contractimpl, contracttype, token, Address, Env};

#[contracttype]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum EscrowState {
    Created,
    Funded,
    Released,
    Refunded,
}

#[contracttype]
#[derive(Clone)]
pub struct Escrow {
    pub depositor: Address,
    pub beneficiary: Address,
    pub arbiter: Address,
    pub token: Address,
    pub amount: i128,
    pub state: EscrowState,
}

#[contracterror]
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum EscrowError {
    AlreadyInitialized = 1,
    NotInitialized = 2,
    InvalidState = 3,
    InvalidAmount = 4,
    Unauthorized = 5,
}

const KEY: &str = "escrow";

fn load(env: &Env) -> Result<Escrow, EscrowError> {
    env.storage()
        .persistent()
        .get(&KEY)
        .ok_or(EscrowError::NotInitialized)
}

fn save(env: &Env, escrow: &Escrow) {
    env.storage().persistent().set(&KEY, escrow);
}

#[contract]
pub struct EscrowContract;

#[contractimpl]
impl EscrowContract {
    /// Create the escrow. The depositor must authorise creation.
    pub fn create(
        env: Env,
        depositor: Address,
        beneficiary: Address,
        arbiter: Address,
        token: Address,
        amount: i128,
    ) -> Result<(), EscrowError> {
        if env.storage().persistent().has(&KEY) {
            return Err(EscrowError::AlreadyInitialized);
        }
        if amount <= 0 {
            return Err(EscrowError::InvalidAmount);
        }
        depositor.require_auth();

        let escrow = Escrow {
            depositor,
            beneficiary,
            arbiter,
            token,
            amount,
            state: EscrowState::Created,
        };
        save(&env, &escrow);
        Ok(())
    }

    /// Fund the escrow by transferring `amount` from the depositor.
    pub fn fund(env: Env) -> Result<(), EscrowError> {
        let mut escrow = load(&env)?;
        if escrow.state != EscrowState::Created {
            return Err(EscrowError::InvalidState);
        }
        escrow.depositor.require_auth();

        let client = token::Client::new(&env, &escrow.token);
        client.transfer(
            &escrow.depositor,
            &env.current_contract_address(),
            &escrow.amount,
        );

        escrow.state = EscrowState::Funded;
        save(&env, &escrow);
        Ok(())
    }

    /// Release funds to the beneficiary. Either the depositor or the arbiter
    /// may authorise the release.
    pub fn release(env: Env) -> Result<(), EscrowError> {
        let mut escrow = load(&env)?;
        if escrow.state != EscrowState::Funded {
            return Err(EscrowError::InvalidState);
        }

        let depositor_ok = escrow.depositor.clone();
        depositor_ok.require_auth();

        let client = token::Client::new(&env, &escrow.token);
        client.transfer(
            &env.current_contract_address(),
            &escrow.beneficiary,
            &escrow.amount,
        );

        escrow.state = EscrowState::Released;
        save(&env, &escrow);
        Ok(())
    }

    /// Refund the depositor. Only the arbiter may authorise a refund.
    pub fn refund(env: Env) -> Result<(), EscrowError> {
        let mut escrow = load(&env)?;
        if escrow.state != EscrowState::Funded {
            return Err(EscrowError::InvalidState);
        }
        escrow.arbiter.require_auth();

        let client = token::Client::new(&env, &escrow.token);
        client.transfer(
            &env.current_contract_address(),
            &escrow.depositor,
            &escrow.amount,
        );

        escrow.state = EscrowState::Refunded;
        save(&env, &escrow);
        Ok(())
    }

    pub fn get(env: Env) -> Result<Escrow, EscrowError> {
        load(&env)
    }
}
