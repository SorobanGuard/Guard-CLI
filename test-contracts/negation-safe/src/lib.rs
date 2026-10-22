#![no_std]
use soroban_sdk::{contract, contractimpl, Env};

#[contract]
pub struct NegationSafe;

#[contractimpl]
impl NegationSafe {
    /// Guarded negation: returns 0 when the amount is `i128::MIN`.
    pub fn negate_guarded(env: Env, amount: i128) -> i128 {
        let _ = env;
        if amount == i128::MIN {
            return 0;
        }
        -amount
    }

    /// Guarded abs: returns 0 when the amount is `i128::MIN`.
    pub fn abs_guarded(env: Env, amount: i128) -> i128 {
        let _ = env;
        if amount == i128::MIN {
            return 0;
        }
        amount.abs()
    }

    /// Uses `checked_neg` instead of unary negation.
    pub fn negate_checked(env: Env, amount: i128) -> i128 {
        let _ = env;
        amount.checked_neg().unwrap_or(0)
    }

    /// Uses `checked_abs` instead of `abs`.
    pub fn abs_checked(env: Env, amount: i128) -> i128 {
        let _ = env;
        amount.checked_abs().unwrap_or(0)
    }

    /// Uses `unsigned_abs`, which never overflows.
    pub fn abs_unsigned(env: Env, amount: i128) -> u128 {
        let _ = env;
        amount.unsigned_abs()
    }

    /// Uses `saturating_neg`, which saturates at `i128::MAX`.
    pub fn negate_saturating(env: Env, amount: i128) -> i128 {
        let _ = env;
        amount.saturating_neg()
    }

    /// Guarded against zero before negating (comparison against 0).
    pub fn negate_nonzero(env: Env, amount: i128) -> i128 {
        let _ = env;
        if amount == 0 {
            return 0;
        }
        -amount
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use soroban_sdk::Env;

    #[test]
    fn guarded_negation_handles_min() {
        let env = Env::default();
        let client = NegationSafeClient::new(&env, &env.register(NegationSafe, ()));
        assert_eq!(client.negate_guarded(&i128::MIN), 0);
        assert_eq!(client.negate_guarded(&5), -5);
    }

    #[test]
    fn checked_abs_handles_min() {
        let env = Env::default();
        let client = NegationSafeClient::new(&env, &env.register(NegationSafe, ()));
        assert_eq!(client.abs_checked(&i128::MIN), 0);
        assert_eq!(client.abs_checked(&-5), 5);
    }
}