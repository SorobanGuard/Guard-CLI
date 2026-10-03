use soroban_sdk::{contractimpl, Symbol, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn set_owner(env: Env, new_owner: Symbol) {
        env.events().publish((symbol_short!("own_chg"),), &new_owner);
    }
}