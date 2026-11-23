//! Realistic-shaped constant-product AMM fixture for the false-positive
//! regression suite (issue #1022).
//!
//! Modelled on the public Soroban token/AMM examples but re-written from
//! scratch (Apache-2.0 compatible). It is intentionally *safe*: it exercises
//! helpers, nested blocks, storage accessors and idiomatic arithmetic so the
//! default check set should report zero High findings.
#![no_std]

use soroban_sdk::{contract, contractimpl, contracttype, token, Address, Env};

#[contracttype]
#[derive(Clone)]
pub struct PoolState {
    pub token_a: Address,
    pub token_b: Address,
    pub reserve_a: i128,
    pub reserve_b: i128,
    pub total_shares: i128,
}

#[contracttype]
#[derive(Clone)]
pub struct Position {
    pub shares: i128,
}

const MIN_LIQUIDITY: i128 = 1_000;

fn pool_key(env: &Env) -> soroban_sdk::Symbol {
    soroban_sdk::Symbol::new(env, "pool")
}

fn position_key(env: &Env, who: &Address) -> (soroban_sdk::Symbol, Address) {
    (soroban_sdk::Symbol::new(env, "pos"), who.clone())
}

fn load_pool(env: &Env) -> PoolState {
    env.storage()
        .persistent()
        .get(&pool_key(env))
        .expect("pool not initialised")
}

fn save_pool(env: &Env, pool: &PoolState) {
    env.storage().persistent().set(&pool_key(env), pool);
}

fn load_position(env: &Env, who: &Address) -> Position {
    env.storage()
        .persistent()
        .get(&position_key(env, who))
        .unwrap_or(Position { shares: 0 })
}

fn save_position(env: &Env, who: &Address, pos: &Position) {
    env.storage().persistent().set(&position_key(env, who), pos);
}

/// Integer square root via Newton's method; used for initial share pricing.
fn isqrt(n: i128) -> i128 {
    if n <= 0 {
        return 0;
    }
    let mut x = n;
    let mut y = (x + 1) / 2;
    while y < x {
        x = y;
        y = (x + n / x) / 2;
    }
    x
}

fn checked_mul_div(a: i128, b: i128, denom: i128) -> i128 {
    assert!(denom > 0, "division by zero");
    a.checked_mul(b).expect("overflow") / denom
}

#[contract]
pub struct AmmContract;

#[contractimpl]
impl AmmContract {
    pub fn initialize(env: Env, token_a: Address, token_b: Address) {
        if env.storage().persistent().has(&pool_key(&env)) {
            panic!("already initialised");
        }
        let pool = PoolState {
            token_a,
            token_b,
            reserve_a: 0,
            reserve_b: 0,
            total_shares: 0,
        };
        save_pool(&env, &pool);
    }

    pub fn add_liquidity(env: Env, provider: Address, amount_a: i128, amount_b: i128) -> i128 {
        provider.require_auth();
        assert!(amount_a > 0 && amount_b > 0, "amounts must be positive");

        let mut pool = load_pool(&env);
        let token_a = token::Client::new(&env, &pool.token_a);
        let token_b = token::Client::new(&env, &pool.token_b);

        token_a.transfer(&provider, &env.current_contract_address(), &amount_a);
        token_b.transfer(&provider, &env.current_contract_address(), &amount_b);

        let minted = if pool.total_shares == 0 {
            isqrt(amount_a.checked_mul(amount_b).expect("overflow"))
        } else {
            let share_a = checked_mul_div(amount_a, pool.total_shares, pool.reserve_a);
            let share_b = checked_mul_div(amount_b, pool.total_shares, pool.reserve_b);
            if share_a < share_b {
                share_a
            } else {
                share_b
            }
        };
        assert!(minted >= MIN_LIQUIDITY, "insufficient liquidity minted");

        pool.reserve_a += amount_a;
        pool.reserve_b += amount_b;
        pool.total_shares += minted;
        save_pool(&env, &pool);

        let mut pos = load_position(&env, &provider);
        pos.shares += minted;
        save_position(&env, &provider, &pos);

        minted
    }

    pub fn swap_a_for_b(env: Env, trader: Address, amount_in: i128, min_out: i128) -> i128 {
        trader.require_auth();
        assert!(amount_in > 0, "amount must be positive");

        let mut pool = load_pool(&env);
        assert!(pool.reserve_a > 0 && pool.reserve_b > 0, "empty pool");

        // Constant product with a 0.3% fee, kept in integer arithmetic.
        let amount_in_with_fee = amount_in * 997;
        let numerator = amount_in_with_fee * pool.reserve_b;
        let denominator = pool.reserve_a * 1000 + amount_in_with_fee;
        let amount_out = numerator / denominator;
        assert!(amount_out >= min_out, "slippage exceeded");
        assert!(amount_out < pool.reserve_b, "insufficient reserve");

        let token_a = token::Client::new(&env, &pool.token_a);
        let token_b = token::Client::new(&env, &pool.token_b);
        token_a.transfer(&trader, &env.current_contract_address(), &amount_in);
        token_b.transfer(&env.current_contract_address(), &trader, &amount_out);

        pool.reserve_a += amount_in;
        pool.reserve_b -= amount_out;
        save_pool(&env, &pool);

        amount_out
    }

    pub fn remove_liquidity(env: Env, provider: Address, shares: i128) -> (i128, i128) {
        provider.require_auth();
        assert!(shares > 0, "shares must be positive");

        let mut pool = load_pool(&env);
        let mut pos = load_position(&env, &provider);
        assert!(pos.shares >= shares, "insufficient shares");

        let out_a = checked_mul_div(shares, pool.reserve_a, pool.total_shares);
        let out_b = checked_mul_div(shares, pool.reserve_b, pool.total_shares);

        pos.shares -= shares;
        pool.total_shares -= shares;
        pool.reserve_a -= out_a;
        pool.reserve_b -= out_b;
        save_position(&env, &provider, &pos);
        save_pool(&env, &pool);

        let token_a = token::Client::new(&env, &pool.token_a);
        let token_b = token::Client::new(&env, &pool.token_b);
        token_a.transfer(&env.current_contract_address(), &provider, &out_a);
        token_b.transfer(&env.current_contract_address(), &provider, &out_b);

        (out_a, out_b)
    }

    pub fn get_reserves(env: Env) -> (i128, i128) {
        let pool = load_pool(&env);
        (pool.reserve_a, pool.reserve_b)
    }

    pub fn get_position(env: Env, who: Address) -> i128 {
        load_position(&env, &who).shares
    }
}
