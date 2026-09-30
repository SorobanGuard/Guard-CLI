//! Detect a `require_auth()` call - on the `Env` parameter or on an `Address`
//! parameter - made *after* a storage write in `#[contractimpl]` methods.

// =============================================================================
// Issue #700 — checks: auth_order.rs duplicates util.rs's env/address
// parameter helpers instead of reusing them
// https://github.com/SorobanGuard/Guard-CLI/issues/700
//
// ─── PROBLEM ─────────────────────────────────────────────────────────────────
//
// This file privately reimplements four functions that already exist as `pub`
// in `crates/checks/src/util.rs`. The private copies here are byte-for-byte
// identical to the public versions:
//
//   Private copy here (approx lines)   Public version in util.rs
//   ─────────────────────────────────  ──────────────────────────────────
//   fn env_param_name      (~L61-72)   pub fn env_param_name   (L332-343)
//   fn type_is_env         (~L74-82)   pub fn type_is_env      (L345-353)
//   fn type_is_address     (~L84-93)   pub fn type_is_address  (L355-364)
//   fn address_param_names (~L95-106)  pub fn address_param_names (L366-378)
//
// util.rs's stated convention (from its `pat_ident_name` doc comment):
//   "Lives here once so every check that needs [this] shares it, rather
//    than each keeping its own private copy."
//
// Having private copies creates the exact drift risk already seen elsewhere
// in this crate — the `is_storage_mutation_call` divergence between
// events.rs and util.rs. The two copies can silently diverge when one is
// updated and the other is not.
//
// ─── FIX ─────────────────────────────────────────────────────────────────────
//
// Step 1 — Extend the existing `use crate::util` import at the top of this
//           file to include the four shared helpers:
//
//   use crate::util::{
//       contractimpl_functions_excluding_test,
//       is_storage_mutation_call,
//       receiver_is_auth_gate,
//       env_param_name,        // ← add these four
//       type_is_env,
//       type_is_address,
//       address_param_names,
//   };
//
// Step 2 — Delete all four private function definitions from this file
//   (the four `fn` blocks that are currently private to this module).
//
// That's the complete change. All call sites in this file already use the
// unqualified names (e.g. `type_is_env(ty)`, `address_param_names(sig)`) so
// they will resolve to the util.rs versions automatically — no call-site edits.
//
// ─── WHY THIS IS SAFE ────────────────────────────────────────────────────────
//
// The four functions are byte-for-byte identical between this file and util.rs.
// Replacing the private copies with imports is a pure refactor — no behavior
// change whatsoever. `cargo test -p soroban-guard-checks` must pass with
// identical results before and after.
//
// ─── VERIFICATION STEPS ──────────────────────────────────────────────────────
//
//   # 1. Compiles cleanly
//   cargo check -p soroban-guard-checks
//
//   # 2. All tests still pass with identical behavior
//   cargo test  -p soroban-guard-checks
//
//   # 3. No private copies remain (must return zero matches)
//   Select-String -Path "crates\checks\src\auth_order.rs" `
//     -Pattern "^fn env_param_name|^fn type_is_env|^fn type_is_address|^fn address_param_names"
//
// ─── ACCEPTANCE CRITERIA ─────────────────────────────────────────────────────
//
//  ✅  auth_order.rs's private copies of the four functions removed
//  ✅  use crate::util import extended with all four function names
//  ✅  `cargo test -p soroban-guard-checks` passes with identical behavior
//  ✅  No other file's behavior changes
//
// ─── FILES TO CHANGE ─────────────────────────────────────────────────────────
//
//   crates/checks/src/auth_order.rs  ← (THIS FILE)
//     1. Add env_param_name, type_is_env, type_is_address, address_param_names
//        to the existing `use crate::util` block
//     2. Delete the four private fn definitions below
//   crates/checks/src/util.rs        ← no change needed (pub fns already exist)
//
// =============================================================================

use crate::util::{
    contractimpl_functions_excluding_test, is_storage_mutation_call, receiver_is_auth_gate,
};
use crate::{Check, Finding, Severity};
use std::collections::HashSet;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Block, ExprMethodCall, File, FnArg, Pat, Stmt, Type};

const CHECK_NAME: &str = "auth-after-storage-write";

/// Flags `#[contractimpl]` methods where `env.require_auth()` is called after a
/// storage write rather than before it.
pub struct AuthAfterStorageWriteCheck;

impl Check for AuthAfterStorageWriteCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions_excluding_test(file) {
            let env_param = env_param_name(&method.sig);
            let env_name = env_param.as_deref().unwrap_or("env");
            let address_params = address_param_names(&method.sig);
            let write_line = first_storage_write_line(&method.block);
            let auth_line = first_require_auth_line(&method.block, env_name, &address_params);
            if let (Some(write), Some(auth)) = (write_line, auth_line) {
                if write < auth {
                    let fn_name = method.sig.ident.to_string();
                    out.push(Finding {
                        check_name: CHECK_NAME.to_string(),
                        severity: Severity::High,
                        file_path: String::new(),
                        line: write,
                        function_name: fn_name.clone(),
                        description: format!(
                            "Method `{fn_name}` calls `require_auth()` on line {auth} \
                             but already wrote to storage on line {write}. State was mutated \
                             before the caller was authorized."
                        ),
                        rule_url: Some(
                            "https://github.com/SorobanGuard/Guard-CLI/blob/main/docs/checks.md#auth-after-storage-write-high"
                                .to_string(),
                        ),
                        suggestion: Some(format!(
                            "Move the `require_auth()` call to the very first line of `{fn_name}`."
                        )),
                    });
                }
            }
        }
        out
    }
}

fn env_param_name(sig: &syn::Signature) -> Option<String> {
    for arg in &sig.inputs {
        let FnArg::Typed(pat_type) = arg else {
            continue;
        };
        if !type_is_env(&pat_type.ty) {
            continue;
        }
        if let Pat::Ident(ident) = &*pat_type.pat {
            return Some(ident.ident.to_string());
        }
    }
    None
}

fn type_is_env(ty: &Type) -> bool {
    let Type::Path(tp) = ty else {
        return false;
    };
    tp.path.segments.last().is_some_and(|s| s.ident == "Env")
}

fn type_is_address(ty: &Type) -> bool {
    let Type::Path(tp) = ty else {
        return false;
    };
    tp.path.segments.last().is_some_and(|s| s.ident == "Address")
}

/// Names of every `Address`-typed parameter, so `<address>.require_auth()` is
/// recognized as a valid authorization call - the form `auth.rs` already handles
/// and the one `Address::require_auth` exists for.
fn address_param_names(sig: &syn::Signature) -> Vec<String> {
    let mut names = Vec::new();
    for arg in &sig.inputs {
        let FnArg::Typed(pat_type) = arg else {
            continue;
        };
        if type_is_address(&pat_type.ty) {
            if let Pat::Ident(ident) = &*pat_type.pat {
                names.push(ident.ident.to_string());
            }
        }
    }
    names
}

fn is_require_auth_call(
    m: &ExprMethodCall,
    env_name: &str,
    address_names: &[String],
    address_locals: &HashSet<String>,
) -> bool {
    if m.method != "require_auth" && m.method != "require_auth_for_args" {
        return false;
    }
    receiver_is_auth_gate(&m.receiver, env_name, address_names, address_locals)
}

/// Name bound by a `let` pattern whose (possibly annotated) type is `Address`.
fn address_local_binding(pat: &Pat) -> Option<String> {
    match pat {
        Pat::Type(pt) => {
            if type_is_address(&pt.ty) {
                address_local_binding(&pt.pat)
            } else {
                None
            }
        }
        Pat::Ident(pi) => Some(pi.ident.to_string()),
        _ => None,
    }
}

struct FirstStorageWrite {
    line: Option<usize>,
}

impl<'ast> Visit<'ast> for FirstStorageWrite {
    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        if self.line.is_none() && is_storage_mutation_call(i) {
            self.line = Some(i.span().start().line);
        }
        visit::visit_expr_method_call(self, i);
    }
}

fn first_storage_write_line(block: &Block) -> Option<usize> {
    let mut v = FirstStorageWrite { line: None };
    v.visit_block(block);
    v.line
}

struct FirstRequireAuth {
    line: Option<usize>,
    env_name: String,
    address_names: Vec<String>,
    address_locals: HashSet<String>,
}

impl<'ast> Visit<'ast> for FirstRequireAuth {
    fn visit_stmt(&mut self, stmt: &'ast Stmt) {
        if let Stmt::Local(local) = stmt {
            if let (Some(name), Some(_init)) = (address_local_binding(&local.pat), &local.init) {
                self.address_locals.insert(name);
            }
        }
        visit::visit_stmt(self, stmt);
    }

    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        if self.line.is_none()
            && is_require_auth_call(i, &self.env_name, &self.address_names, &self.address_locals)
        {
            self.line = Some(i.span().start().line);
        }
        visit::visit_expr_method_call(self, i);
    }
}

fn first_require_auth_line(
    block: &Block,
    env_name: &str,
    address_names: &[String],
) -> Option<usize> {
    let mut v = FirstRequireAuth {
        line: None,
        env_name: env_name.to_string(),
        address_names: address_names.to_vec(),
        address_locals: HashSet::new(),
    };
    v.visit_block(block);
    v.line
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_file;

    fn run(src: &str) -> Vec<Finding> {
        let file = parse_file(src).expect("parse");
        AuthAfterStorageWriteCheck.run(&file, src)
    }

    #[test]
    fn flags_address_require_auth_after_storage_write() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Address, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn transfer(env: Env, from: Address, amount: i128) {
        env.storage().persistent().set(&0, &amount);
        from.require_auth();
    }
}
"#);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].check_name, CHECK_NAME);
    }

    #[test]
    fn passes_when_address_require_auth_precedes_storage_write() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Address, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn transfer(env: Env, from: Address, amount: i128) {
        from.require_auth();
        env.storage().persistent().set(&0, &amount);
    }
}
"#);
        assert!(hits.is_empty());
    }

    #[test]
    fn still_flags_env_require_auth_after_storage_write() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn set_value(env: Env, value: i128) {
        env.storage().persistent().set(&0, &value);
        env.require_auth();
    }
}
"#);
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn flags_self_field_require_auth_after_storage_write() {
        // #514: `self.admin.require_auth()` has an `Expr::Field` receiver and must
        // be recognized as a valid auth gate, so a post-write call is still flagged.
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn set_value(env: Env, value: i128) {
        env.storage().persistent().set(&0, &value);
        self.admin.require_auth();
    }
}
"#);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].check_name, CHECK_NAME);
    }

    #[test]
    fn flags_cloned_address_require_auth_after_storage_write() {
        // #514: `admin.clone().require_auth()` has an `Expr::MethodCall` receiver.
        let hits = run(r#"
use soroban_sdk::{contractimpl, Address, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn set_value(env: Env, admin: Address, value: i128) {
        env.storage().persistent().set(&0, &value);
        admin.clone().require_auth();
    }
}
"#);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].check_name, CHECK_NAME);
    }

    #[test]
    fn passes_when_self_field_require_auth_precedes_storage_write() {
        // #514: a properly ordered `self.admin.require_auth()` must not be flagged.
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn set_value(env: Env, value: i128) {
        self.admin.require_auth();
        env.storage().persistent().set(&0, &value);
    }
}
"#);
        assert!(hits.is_empty());
    }

    #[test]
    fn passes_when_cloned_address_require_auth_precedes_storage_write() {
        // #514: a properly ordered `admin.clone().require_auth()` must not be flagged.
        let hits = run(r#"
use soroban_sdk::{contractimpl, Address, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn set_value(env: Env, admin: Address, value: i128) {
        admin.clone().require_auth();
        env.storage().persistent().set(&0, &value);
    }
}
"#);
        assert!(hits.is_empty());
    }

    #[test]
    fn passes_when_only_storage_call_is_extend_ttl() {
        // #401: a function whose only storage call is `extend_ttl` mutates nothing and must
        // not be flagged, regardless of when `require_auth` is (or isn't) called.
        let hits = run(r#"
use soroban_sdk::Env;
pub struct C;
#[contractimpl]
impl C {
    pub fn bump_balance(env: Env, key: u32) {
        env.storage().persistent().extend_ttl(&key, 100, 1000);
        env.current_contract_address().require_auth();
    }
}
"#);
        assert!(hits.is_empty());
    }
}
