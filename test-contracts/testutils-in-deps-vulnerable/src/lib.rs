#![no_std]

use soroban_sdk::{contract, contractimpl, Env};

#[contract]
pub struct TestutilsInDepsVulnerable;

#[contractimpl]
impl TestutilsInDepsVulnerable {
    pub fn hello(env: Env) -> u32 {
        let _ = env;
        42
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use soroban_sdk::Env;

    #[test]
    fn test_hello() {
        let env = Env::default();
        let contract_id = env.register(TestutilsInDepsVulnerable, ());
        let client = TestutilsInDepsVulnerableClient::new(&env, &contract_id);
        assert_eq!(client.hello(), 42);
    }
}