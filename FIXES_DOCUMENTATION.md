# Batch-77 Check Fixes Documentation

This document outlines the four check fixes implemented in this batch:

## #653: unsafe-cross-contract-input - Clear taint on assert!/require! validation

**File**: `crates/checks/src/xc_input.rs`

**Issue**: The taint-tracking only clears taint via `let` reassignment of binding names, but guard assertions like `assert!(result > 0)` don't trigger taint clearing even though they validate the result.

**Fix**: Modify `visit_expr` to detect `assert!()` and `require!()` macro calls that reference tainted bindings and clear their taint. The pattern to match:
1. Detect Expr::Macro with macro name "assert" or "require"
2. Extract the referenced binding name from the macro's tokens
3. If the binding name is in the taint set, clear it

**Test**: Add regression test for:
```rust
let result = env.invoke_contract(...);
assert!(result > 0, "bad result");
storage.set(&k, &result);  // Should NOT fire unsafe-cross-contract-input
```

---

## #654: unsafe-randomness - Resolve Env parameter name instead of hardcoding

**File**: `crates/checks/src/unsafe_randomness.rs`

**Issue**: `is_env_receiver()` at line 80-90 hardcodes "env" literal. If Env parameter is named differently (e.g., `e: Env`), the check doesn't recognize it.

**Fix**: Use the pattern from `delegate.rs::env_param_name()` to resolve the actual Env-typed parameter name from function signature:
1. Iterate through function parameters
2. Find the one with type `Env`
3. Extract its actual identifier name
4. Use that name instead of hardcoded "env"

**Test**: Add regression test for:
```rust
pub fn draw(e: Env) {
    e.ledger().timestamp();  // Should still fire unsafe-randomness
}
```

---

## #655: unprotected-*-deployment/token-mint/upgrade - Use address_names parameter

**Files**:
- `crates/checks/src/unprotected_contract_deployment.rs:143`
- `crates/checks/src/unprotected_token_mint.rs:151`
- `crates/checks/src/unprotected_upgrade.rs:143`

**Issue**: `is_valid_auth_call()` receives `address_names` parameter but never uses it (underscore-prefixed). The pattern `caller.require_auth()` is a valid authorization but is flagged as false positive.

**Fix**: In `is_valid_auth_call()`, update to recognize `require_auth()` called on any parameter in `address_names`, not just hardcoded names like "admin"/"authority":
1. Check if macro is "require_auth"
2. Extract the receiver name (left side of dot)
3. Check if receiver is in `address_names`
4. If yes, return true (valid auth)

**Test**: Add regression test per check for:
```rust
pub fn upload(env: Env, caller: Address, wasm: Bytes) {
    caller.require_auth();  // Should NOT fire any finding
    env.deployer().upload_contract_wasm(&wasm);
}
```

---

## #656: missing-contract-annotation - Key by module path

**File**: `crates/checks/src/annotations.rs`

**Issue**: `collect_items()` flattens contract struct names into a single HashSet without tracking module path. Same-named structs in different modules cause false negatives when only one is annotated.

**Fix**: Change contract items collection to use a keyed structure:
1. Use `HashMap<String, HashSet<String>>` where key is module path
2. Modify `collect_items()` to build full module paths as it recurses
3. Update the check at lines 63-66 to verify against the correct module

**Test**: Add regression test for:
```rust
mod module_a {
    #[contract]
    #[contractimpl]
    struct Counter { }
}

mod module_b {
    // No #[contractimpl]
    struct Counter { }  // Should fire missing-contract-annotation
}
```

---

## Implementation Notes

All fixes maintain backward compatibility with existing tests. The changes are targeted to the specific false-positive patterns while preserving the checks' core detection logic.

Each fix addresses a real-world false positive/negative that developers encounter:
- #653: Valid defensive programming (assertions) wrongly flagged
- #654: Renamed Env parameters break the check
- #655: Idiomatic authorization pattern marked as unsafe
- #656: Same-named contracts in different modules cause confusion
