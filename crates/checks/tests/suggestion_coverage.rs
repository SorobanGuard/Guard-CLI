//! Asserts that every check in `default_checks()` which can produce a `Finding`
//! always sets `suggestion` to `Some(_)` — never `None`.
//!
//! Each sub-test supplies a minimal Rust snippet that is known to trigger the
//! relevant check.  If a check does not produce a finding for the given snippet
//! the test reports a clear failure message rather than silently passing.

use soroban_guard_checks::{default_checks, Finding};
use syn::parse_file;

/// Run a single check (identified by name) against `src`, assert at least one
/// finding is produced, and assert every finding's `suggestion` is `Some`.
fn assert_check_has_suggestion(check_name: &str, src: &str) {
    let file = parse_file(src).expect("test snippet should parse as valid Rust");
    let checks = default_checks();
    let check = checks
        .iter()
        .find(|c| c.name() == check_name)
        .unwrap_or_else(|| panic!("check `{check_name}` not found in default_checks()"));

    let findings: Vec<Finding> = check.run(&file, src);
    assert!(
        !findings.is_empty(),
        "check `{check_name}` produced no findings — update the test snippet so it actually triggers the check"
    );
    for f in &findings {
        assert!(
            f.suggestion.is_some(),
            "check `{check_name}` emitted a Finding with suggestion=None:\n{f:#?}"
        );
    }
}

// ─── missing-require-auth ───────────────────────────────────────────────────

#[test]
fn missing_require_auth_has_suggestion() {
    assert_check_has_suggestion(
        "missing-require-auth",
        r#"
use soroban_sdk::{contractimpl, Env, Symbol};
pub struct C;
#[contractimpl]
impl C {
    pub fn set_val(env: Env, v: u32) {
        env.storage().persistent().set(&Symbol::new(&env, "k"), &v);
    }
}
"#,
    );
}

// ─── auth-after-storage-write ───────────────────────────────────────────────

#[test]
fn auth_after_storage_write_has_suggestion() {
    assert_check_has_suggestion(
        "auth-after-storage-write",
        r#"
use soroban_sdk::{contractimpl, Env, Symbol};
pub struct C;
#[contractimpl]
impl C {
    pub fn bad(env: Env, v: u32) {
        env.storage().persistent().set(&Symbol::new(&env, "k"), &v);
        env.require_auth();
    }
}
"#,
    );
}

// ─── unchecked-arithmetic ────────────────────────────────────────────────────

#[test]
fn unchecked_arithmetic_has_suggestion() {
    assert_check_has_suggestion(
        "unchecked-arithmetic",
        r#"
use soroban_sdk::{contractimpl, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn add(env: Env, a: i128, b: i128) -> i128 { let _ = env; a + b }
}
"#,
    );
}

// ─── unprotected-admin ───────────────────────────────────────────────────────

#[test]
fn unprotected_admin_has_suggestion() {
    assert_check_has_suggestion(
        "unprotected-admin",
        r#"
use soroban_sdk::{contractimpl, Address, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn set_owner(env: Env, owner: Address) { let _ = (env, owner); }
}
"#,
    );
}

// ─── unsafe-storage-patterns ─────────────────────────────────────────────────

#[test]
fn unsafe_storage_patterns_has_suggestion() {
    assert_check_has_suggestion(
        "unsafe-storage-patterns",
        r#"
use soroban_sdk::{contractimpl, symbol_short, Env};
pub struct C;
const K: soroban_sdk::Symbol = symbol_short!("k");
#[contractimpl]
impl C {
    pub fn stash(env: Env, v: u32) {
        env.require_auth();
        env.storage().temporary().set(&K, &v);
    }
}
"#,
    );
}

// ─── missing-ttl-extension ───────────────────────────────────────────────────

#[test]
fn missing_ttl_extension_has_suggestion() {
    assert_check_has_suggestion(
        "missing-ttl-extension",
        r#"
use soroban_sdk::{contractimpl, symbol_short, Env};
pub struct C;
const K: soroban_sdk::Symbol = symbol_short!("k");
#[contractimpl]
impl C {
    pub fn put(env: Env, v: u32) {
        env.require_auth();
        env.storage().persistent().set(&K, &v);
    }
}
"#,
    );
}

// ─── forbidden-std-imports ────────────────────────────────────────────────────

#[test]
fn forbidden_std_imports_has_suggestion() {
    assert_check_has_suggestion(
        "forbidden-std-imports",
        r#"
use std::collections::HashMap;
use soroban_sdk::{contractimpl, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn hello(env: Env) { let _ = env; }
}
"#,
    );
}

// ─── hardcoded-address ────────────────────────────────────────────────────────

#[test]
fn hardcoded_address_has_suggestion() {
    let key = format!("G{}", "A".repeat(55));
    let src = format!(
        r#"
use soroban_sdk::{{contractimpl, Address, Env}};
pub struct C;
#[contractimpl]
impl C {{
    pub fn hello(env: Env) {{
        let addr = Address::from_str(&env, "{key}");
        let _ = addr;
    }}
}}
"#
    );
    assert_check_has_suggestion("hardcoded-address", &src);
}

// ─── unsafe-cross-contract-input ─────────────────────────────────────────────

#[test]
fn unsafe_cross_contract_input_has_suggestion() {
    assert_check_has_suggestion(
        "unsafe-cross-contract-input",
        r#"
use soroban_sdk::{contractimpl, Env, Address, Symbol};
pub struct C;
#[contractimpl]
impl C {
    pub fn relay(env: Env, callee: Address) {
        let result = env.invoke_contract::<i128>(&callee, &Symbol::short("get"), ());
        env.storage().persistent().set(&Symbol::short("k"), &result);
    }
}
"#,
    );
}

// ─── missing-contract-annotation ─────────────────────────────────────────────

#[test]
fn missing_contract_annotation_has_suggestion() {
    assert_check_has_suggestion(
        "missing-contract-annotation",
        r#"
use soroban_sdk::{contractimpl, Env};
pub struct MyContract;
#[contractimpl]
impl MyContract {
    pub fn hello(_env: Env) {}
}
"#,
    );
}

// ─── delegate-call-risk ───────────────────────────────────────────────────────

#[test]
fn delegate_call_risk_has_suggestion() {
    assert_check_has_suggestion(
        "delegate-call-risk",
        r#"
use soroban_sdk::{contractimpl, Address, Env, Symbol};
pub struct C;
#[contractimpl]
impl C {
    pub fn call_external(env: Env) {
        let addr: Address = env.storage().instance().get(&0).unwrap();
        env.invoke_contract::<()>(&addr, &Symbol::new(&env, "do_thing"), ());
    }
}
"#,
    );
}

// ─── integer-division-truncation ──────────────────────────────────────────────

#[test]
fn integer_division_truncation_has_suggestion() {
    assert_check_has_suggestion(
        "integer-division-truncation",
        r#"
use soroban_sdk::{contractimpl, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn half(_env: Env, a: i128, b: i128) -> i128 { a / b }
}
"#,
    );
}

// ─── missing-event-emission ────────────────────────────────────────────────────

#[test]
fn missing_event_emission_has_suggestion() {
    assert_check_has_suggestion(
        "missing-event-emission",
        r#"
use soroban_sdk::{contractimpl, Symbol, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn set_balance(env: Env, amount: i128) {
        env.storage().instance().set(&Symbol::new(&env, "bal"), &amount);
    }
}
"#,
    );
}

// ─── symbol-key-collision ──────────────────────────────────────────────────────

#[test]
fn symbol_key_collision_has_suggestion() {
    assert_check_has_suggestion(
        "symbol-key-collision",
        r#"
use soroban_sdk::{contractimpl, symbol_short, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn foo(env: Env) {
        let _ = env;
        let k1 = symbol_short!("key");
    }
    pub fn bar(env: Env) {
        let _ = env;
        let k2 = symbol_short!("key");
    }
}
"#,
    );
}

// ─── self-transfer ─────────────────────────────────────────────────────────────

#[test]
fn self_transfer_has_suggestion() {
    assert_check_has_suggestion(
        "self-transfer",
        r#"
use soroban_sdk::{contractimpl, Address, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        from.require_auth();
        let _ = (env, to, amount);
    }
}
"#,
    );
}

// ─── missing-zero-address-check ───────────────────────────────────────────────

#[test]
fn missing_zero_address_check_has_suggestion() {
    assert_check_has_suggestion(
        "missing-zero-address-check",
        r#"
use soroban_sdk::{contractimpl, Env, Address};
pub struct C;
#[contractimpl]
impl C {
    pub fn set_owner(env: Env, new_owner: Address) {
        env.storage().instance().set(&"owner", &new_owner);
    }
}
"#,
    );
}

// ─── mutable-global-state ─────────────────────────────────────────────────────

#[test]
fn mutable_global_state_has_suggestion() {
    assert_check_has_suggestion(
        "mutable-global-state",
        r#"
static mut COUNTER: u32 = 0;
pub struct C;
"#,
    );
}

// ─── re-initialization-risk ───────────────────────────────────────────────────

#[test]
fn re_initialization_risk_has_suggestion() {
    assert_check_has_suggestion(
        "re-initialization-risk",
        r#"
use soroban_sdk::{contractimpl, Env, Symbol};
pub struct C;
#[contractimpl]
impl C {
    pub fn init(env: Env, v: u32) {
        env.storage().instance().set(&Symbol::new(&env, "k"), &v);
    }
}
"#,
    );
}

// ─── unchecked-invoke-return ──────────────────────────────────────────────────

#[test]
fn unchecked_invoke_return_has_suggestion() {
    assert_check_has_suggestion(
        "unchecked-invoke-return",
        r#"
use soroban_sdk::{contractimpl, Env, Symbol, Address};
pub struct C;
#[contractimpl]
impl C {
    pub fn f(env: Env, callee: Address) {
        env.invoke_contract::<()>(&callee, &Symbol::short("do"), ());
    }
}
"#,
    );
}

// ─── missing-balance-check ────────────────────────────────────────────────────

#[test]
fn missing_balance_check_has_suggestion() {
    assert_check_has_suggestion(
        "missing-balance-check",
        r#"
use soroban_sdk::{contractimpl, Env, Address};
#[contractimpl]
impl Token {
    pub fn pay(env: Env, id: Address, sender: Address, recipient: Address, amount: i128) {
        let token = token::Client::new(&env, &id);
        token.transfer(&sender, &recipient, &amount);
    }
}
"#,
    );
}

// ─── unbounded-vec-growth ─────────────────────────────────────────────────────

#[test]
fn unbounded_vec_growth_has_suggestion() {
    assert_check_has_suggestion(
        "unbounded-vec-growth",
        r#"
use soroban_sdk::{contractimpl, Env, Symbol};
pub struct C;
#[contractimpl]
impl C {
    pub fn append(env: Env, item: u32) {
        let mut v: Vec<u32> = env.storage().instance().get(&Symbol::new(&env, "list")).unwrap_or_default();
        v.push(item);
        env.storage().instance().set(&Symbol::new(&env, "list"), &v);
    }
}
"#,
    );
}

// ─── unsafe-randomness ────────────────────────────────────────────────────────

#[test]
fn unsafe_randomness_has_suggestion() {
    assert_check_has_suggestion(
        "unsafe-randomness",
        r#"
#[contractimpl]
impl C {
    pub fn draw(env: Env) {
        let seed = env.ledger().timestamp();
        let _ = seed;
    }
}
"#,
    );
}

// ─── unchecked-divisor ────────────────────────────────────────────────────────

#[test]
fn unchecked_divisor_has_suggestion() {
    assert_check_has_suggestion(
        "unchecked-divisor",
        r#"
#[contractimpl]
impl C {
    pub fn divide(a: u128, b: u128) -> u128 { a / b }
}
"#,
    );
}

// ─── panic-in-contract ────────────────────────────────────────────────────────

#[test]
fn panic_in_contract_has_suggestion() {
    assert_check_has_suggestion(
        "panic-in-contract",
        r#"
use soroban_sdk::{contractimpl, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn f(_env: Env) -> u32 { Some(1u32).unwrap() }
}
"#,
    );
}

// ─── unprotected-upgrade ──────────────────────────────────────────────────────

#[test]
fn unprotected_upgrade_has_suggestion() {
    assert_check_has_suggestion(
        "unprotected-upgrade",
        r#"
#[contractimpl]
impl C {
    pub fn upgrade(env: Env, new_code: Bytes) {
        env.invoke_wasm(&new_code);
    }
}
"#,
    );
}

// ─── unprotected-token-mint ───────────────────────────────────────────────────

#[test]
fn unprotected_token_mint_has_suggestion() {
    assert_check_has_suggestion(
        "unprotected-token-mint",
        r#"
use soroban_sdk::{contractimpl, symbol_short, Env, Address};
pub struct C;
#[contractimpl]
impl C {
    pub fn mint(env: Env, to: Address, amount: u128) {
        env.storage().instance().set(&symbol_short!("supply"), &amount);
        let _ = to;
    }
}
"#,
    );
}

// ─── unprotected-contract-deployment ─────────────────────────────────────────

#[test]
fn unprotected_contract_deployment_has_suggestion() {
    assert_check_has_suggestion(
        "unprotected-contract-deployment",
        r#"
#[contractimpl]
impl C {
    pub fn deploy(env: Env, wasm: Bytes) {
        env.deployer().upload_contract_wasm(&wasm);
    }
}
"#,
    );
}

// ─── large-loop ───────────────────────────────────────────────────────────────

#[test]
fn large_loop_has_suggestion() {
    assert_check_has_suggestion(
        "large-loop",
        r#"
use soroban_sdk::{contractimpl, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn process(env: Env) {
        let _ = env;
        loop { break; }
    }
}
"#,
    );
}

// ─── missing-nonce ────────────────────────────────────────────────────────────

#[test]
fn missing_nonce_has_suggestion() {
    assert_check_has_suggestion(
        "missing-nonce",
        r#"
#[contractimpl]
impl C {
    pub fn update(env: Env, user: Address, new_val: u32) {
        env.storage().instance().set(&symbol_short!("val"), &new_val);
        let _ = user;
    }
}
"#,
    );
}

// ─── uninitialized-storage-read ───────────────────────────────────────────────

#[test]
fn uninitialized_storage_read_has_suggestion() {
    assert_check_has_suggestion(
        "uninitialized-storage-read",
        r#"
use soroban_sdk::{contractimpl, symbol_short, Env};
pub struct C;
const K: soroban_sdk::Symbol = symbol_short!("k");
#[contractimpl]
impl C {
    pub fn get_val(env: Env) -> u32 {
        env.storage().persistent().get(&K).unwrap()
    }
}
"#,
    );
}

// ─── reentrancy-risk ──────────────────────────────────────────────────────────

#[test]
fn reentrancy_risk_has_suggestion() {
    assert_check_has_suggestion(
        "reentrancy-risk",
        r#"
use soroban_sdk::{contractimpl, Env, Address};
pub struct C;
#[contractimpl]
impl C {
    pub fn transfer(env: Env, to: Address, amount: i128) {
        env.storage().persistent().set(&to, &amount);
        env.invoke_contract::<()>(&to, &soroban_sdk::symbol_short!("cb"), soroban_sdk::vec![&env]);
    }
}
"#,
    );
}

// ─── missing-event-for-admin-change ──────────────────────────────────────────

#[test]
fn missing_event_for_admin_change_has_suggestion() {
    assert_check_has_suggestion(
        "missing-event-for-admin-change",
        r#"
use soroban_sdk::{contractimpl, symbol_short, Env, Address};
pub struct C;
#[contractimpl]
impl C {
    pub fn set_owner(env: Env, new_owner: Address) {
        env.storage().instance().set(&symbol_short!("owner"), &new_owner);
    }
}
"#,
    );
}

// ─── missing-input-length-bound ───────────────────────────────────────────────

#[test]
fn missing_input_length_bound_has_suggestion() {
    assert_check_has_suggestion(
        "missing-input-length-bound",
        r#"
use soroban_sdk::{contractimpl, Env, Bytes};
pub struct C;
#[contractimpl]
impl C {
    pub fn process(env: Env, data: Bytes) {
        let _ = (env, data);
    }
}
"#,
    );
}

// ─── view-function-writes-storage ────────────────────────────────────────────

#[test]
fn view_function_writes_storage_has_suggestion() {
    assert_check_has_suggestion(
        "view-function-writes-storage",
        r#"
use soroban_sdk::{contractimpl, symbol_short, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn get_balance(env: Env) -> u32 {
        let v: u32 = env.storage().instance().get(&symbol_short!("bal")).unwrap_or(0);
        env.storage().instance().set(&symbol_short!("bal"), &v);
        v
    }
}
"#,
    );
}

// ─── auth-on-wrong-address ───────────────────────────────────────────────────

#[test]
fn auth_on_wrong_address_has_suggestion() {
    assert_check_has_suggestion(
        "auth-on-wrong-address",
        r#"
use soroban_sdk::{contractimpl, Env, Address};
pub struct C;
#[contractimpl]
impl C {
    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        to.require_auth();
        let token = token::Client::new(&env, &env.current_contract_address());
        token.transfer(&from, &to, &amount);
    }
}
"#,
    );
}
