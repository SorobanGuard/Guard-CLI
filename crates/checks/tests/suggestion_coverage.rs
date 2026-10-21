//! Asserts that every check in `default_checks()` which can produce a `Finding`
//! always sets `suggestion` to `Some(_)` — never `None`.
//!
//! Each sub-test supplies a minimal Rust snippet that is known to trigger the
//! relevant check.  If a check does not produce a finding for the given snippet
//! the test reports a clear failure message rather than silently passing.
//!
//! Additionally, every finding's `suggestion` and `description` are validated
//! against the style guide documented in `CONTRIBUTING.md`:
//!   * single line (no newlines)
//!   * no leading/trailing whitespace
//!   * at most `MAX_MESSAGE_LEN` characters
//!   * starts with an uppercase letter (imperative mood)
//!   * no unresolved `{}` / `{name}` format placeholders
//!   * no trailing period

use soroban_guard_checks::{default_checks, Finding};
use syn::parse_file;

/// Maximum allowed length (in characters) for a `suggestion` or `description`.
const MAX_MESSAGE_LEN: usize = 200;

/// Validate a single user-facing message against the style guide.
///
/// `check_name` and `field` are used purely for a clear failure message.
fn assert_message_style(check_name: &str, field: &str, message: &str) {
    assert!(
        !message.contains('\n') && !message.contains('\r'),
        "check `{check_name}` {field} must be a single line, got:\n{message:?}"
    );
    assert!(
        message == message.trim(),
        "check `{check_name}` {field} must not have leading/trailing whitespace, got:\n{message:?}"
    );
    assert!(
        !message.is_empty(),
        "check `{check_name}` {field} must not be empty"
    );
    let len = message.chars().count();
    assert!(
        len <= MAX_MESSAGE_LEN,
        "check `{check_name}` {field} is {len} chars (max {MAX_MESSAGE_LEN}):\n{message:?}"
    );
    let first = message.chars().next().unwrap();
    assert!(
        first.is_uppercase(),
        "check `{check_name}` {field} must start with an uppercase letter (imperative mood), got:\n{message:?}"
    );
    assert!(
        !message.contains("{}") && !contains_named_placeholder(message),
        "check `{check_name}` {field} contains an unresolved format placeholder:\n{message:?}"
    );
    assert!(
        !message.ends_with('.'),
        "check `{check_name}` {field} must not end with a trailing period, got:\n{message:?}"
    );
}

/// Detect `{identifier}` style placeholders (e.g. `{name}`) without flagging
/// legitimate braces that are not format placeholders.
fn contains_named_placeholder(message: &str) -> bool {
    let bytes = message.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'{' {
            let mut j = i + 1;
            let start = j;
            while j < bytes.len() && (bytes[j].is_ascii_alphanumeric() || bytes[j] == b'_') {
                j += 1;
            }
            if j > start && j < bytes.len() && bytes[j] == b'}' {
                return true;
            }
        }
        i += 1;
    }
    false
}

/// Run a single check (identified by name) against `src`, assert at least one
/// finding is produced, and assert every finding's `suggestion` is `Some` and
/// that both `suggestion` and `description` conform to the style guide.
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
        let suggestion = f.suggestion.as_deref().unwrap_or_else(|| {
            panic!("check `{check_name}` emitted a Finding with suggestion=None:\n{f:#?}")
        });
        assert_message_style(check_name, "suggestion", suggestion);
        assert_message_style(check_name, "description", &f.description);
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
