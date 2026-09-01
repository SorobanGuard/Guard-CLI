# Handling false positives

Soroban Guard uses heuristic, AST-based analysis. It has no dataflow or type analysis, so it
occasionally flags code that is correct. This page explains why that happens, lists the known
limitations per check, and describes how to work around false positives today and in the future.

---

## Why false positives happen

Every check in Soroban Guard works by pattern-matching the syntax tree produced by `syn`. There is
no type inference, no control-flow graph, and no inter-procedural dataflow. Checks reason entirely
about what appears in a single function body.

Common causes:

- **Auth in a helper** — `require_auth` called in a private function before the flagged public one.
- **Validation in a helper** — a guard (`if`, `assert`, `checked_*`) that lives in a called
  function rather than inline.
- **Intentional patterns** — proxy contracts that deliberately read a callee address from storage,
  or contracts that use temporary storage for short-lived values by design.
- **Naming coincidences** — a function named `init` that is not a one-time initializer, or a
  variable named `balance` that is unrelated to token math.
- **Storage handle bound to a local** — a `.storage()` / `.persistent()` / `.temporary()`
  handle stored in a local variable defeats every check that walks the receiver chain
  (see issue [#502](https://github.com/SorobanGuard/Guard-CLI/issues/502)).

---

## Per-check known limitations

| Check | Known false-positive sources | Full details |
|---|---|---|
| `missing-require-auth` | Auth delegated to a helper function; `Env` param named something other than `env`; storage handle bound to a local variable is not tracked | [checks.md#missing-require-auth](checks.md#missing-require-auth) |
| `unchecked-arithmetic` | Severity is name-based; a variable named `amount` in non-financial context gets High. A `checked_*`/`saturating_*` call on a pair of operands suppresses unchecked binary operations on the *same* operands anywhere in the function body, even if the unchecked operation is not actually guarded by that specific check. | [checks.md#unchecked-arithmetic](checks.md#unchecked-arithmetic) |
| `auth-after-storage-write` | Auth performed by a helper function is not tracked; storage handle bound to a local variable is not tracked | [checks.md#auth-after-storage-write](checks.md#auth-after-storage-write) |
| `unchecked-arithmetic` | Severity is name-based; a variable named `amount` in non-financial context gets High | [checks.md#unchecked-arithmetic](checks.md#unchecked-arithmetic) |
| `unprotected-admin` | Any `require_auth` anywhere in the body clears the finding; auth inside a helper is not seen | [checks.md#unprotected-admin](checks.md#unprotected-admin) |
| `unsafe-storage-patterns` | `Symbol::new` with a `const` or macro-expanded literal may be flagged as a dynamic key; storage handle bound to a local variable is not tracked | [checks.md#unsafe-storage-patterns](checks.md#unsafe-storage-patterns) |
| `missing-ttl-extension` | TTL extension performed by a helper function is not tracked; storage handle bound to a local variable is not tracked | — |
| `forbidden-std-imports` | None known yet | [checks.md#forbidden-std-imports](checks.md#forbidden-std-imports) |
| `hardcoded-address` | Only string literals beginning with `G` are recognized as Stellar public keys | [checks.md#hardcoded-address](checks.md#hardcoded-address) |
| `unsafe-cross-contract-input` | Validation in a helper called after the assignment is not tracked | [checks.md#unsafe-cross-contract-input](checks.md#unsafe-cross-contract-input) |
| `missing-contract-annotation` | Contract declarations split across files are not resolved | [checks.md#missing-contract-annotation](checks.md#missing-contract-annotation) |
| `delegate-call-risk` | Intentional proxy patterns that read a callee from storage are flagged by design | [checks.md#delegate-call-risk](checks.md#delegate-call-risk) |
| `integer-division-truncation` | Any division with a non-literal operand is flagged regardless of the rounding strategy | [checks.md#integer-division-truncation](checks.md#integer-division-truncation) |
| `missing-event-emission` | Events emitted inside a helper called from the flagged method are not detected; storage handle bound to a local variable is not tracked | [checks.md#missing-event-emission](checks.md#missing-event-emission) |
| `symbol-key-collision` | Only duplicate `symbol_short!` keys within the same impl block are detected | [checks.md#symbol-key-collision](checks.md#symbol-key-collision) |
| `self-transfer` | Complex or helper-based sender/recipient guards may not be recognized | [checks.md#self-transfer](checks.md#self-transfer) |
| `missing-zero-address-check` | Validation performed by a helper function is not tracked | [checks.md#missing-zero-address-check](checks.md#missing-zero-address-check) |
| `mutable-global-state` | None known yet | [checks.md#mutable-global-state](checks.md#mutable-global-state) |
| `re-initialization-risk` | Any `.has()` / `.is_some()` in the body clears the finding regardless of control-flow; storage handle bound to a local variable is not tracked | [checks.md#re-initialization-risk](checks.md#re-initialization-risk) |
| `unchecked-invoke-return` | Return values evaluated via complex helper methods may not be tracked | [checks.md#unchecked-invoke-return](checks.md#unchecked-invoke-return) |
| `missing-balance-check` | `balance()` on an unrelated client clears the finding | [checks.md#missing-balance-check](checks.md#missing-balance-check) |
| `unbounded-vec-growth` | Any `.len()` call in the function clears the finding even without a cap; storage handle bound to a local variable is not tracked | [checks.md#unbounded-vec-growth](checks.md#unbounded-vec-growth) |
| `unsafe-randomness` | `env.ledger().timestamp()` alone is flagged even if the value is never used in logic | [checks.md#unsafe-randomness](checks.md#unsafe-randomness) |
| `unchecked-divisor` | Any literal divisor is skipped; complex runtime guards are not tracked | [checks.md#unchecked-divisor](checks.md#unchecked-divisor) |
| `panic-in-contract` | Intentional panics and unwraps in unreachable paths are still flagged | [checks.md#panic-in-contract](checks.md#panic-in-contract) |
| `unprotected-upgrade` | Authorization performed by a helper function is not tracked | — |
| `unprotected-token-mint` | Authorization performed by a helper function is not tracked | — |
| `unprotected-contract-deployment` | Authorization performed by a helper function is not tracked | — |
| `unchecked-token-amount` | Validation performed by a helper function is not tracked | — |
| `large-loop` | None known yet | [checks.md#large-loop](checks.md#large-loop) |
| `missing-nonce` | Nonce validation performed by a helper function is not tracked | [checks.md#missing-nonce](checks.md#missing-nonce) |
| `uninitialized-storage-read` | Initialization checks performed by a helper function are not tracked | [checks.md#uninitialized-storage-read](checks.md#uninitialized-storage-read) |
| `reentrancy-risk` | Branch-sensitive control flow and helper calls are not tracked; storage handle bound to a local variable is not tracked | [checks.md#reentrancy-risk](checks.md#reentrancy-risk) |
| `missing-event-for-admin-change` | Events emitted by a helper function are not detected | — |
| `missing-input-length-bound` | Length validation performed by a helper function is not tracked | — |

---

## Intentional overlap between checks

Some findings are reported by more than one check by design. This is **not** a false positive — the
checks look at the same code from different angles, and fixing the underlying issue clears every
related finding at once.

| Code pattern | Checks that report it | Why the overlap is intentional |
|---|---|---|
| `pub fn upgrade` / `pub fn migrate` with no `require_auth` | [`unprotected-admin`](checks.md#unprotected-admin-high) + [`unprotected-upgrade`](checks.md#unprotected-upgrade-high) | `unprotected-admin` is the broad exact-name "privileged entrypoint" net; `unprotected-upgrade` is narrower, matches upgrade names by substring, and also checks that auth precedes the WASM swap. |

(By contrast, `storage.get(...).unwrap()` and the `panic-in-contract` / `uninitialized-storage-read`
pair are deliberately *de-duplicated* — that line is reported once, by the more specific check. See
the "Relationship to" notes in [checks.md](checks.md).)

If a single overlapping finding is genuinely noise for your contract, suppress the individual check
by name with an inline annotation (see below).

---

## Inline suppression annotations

Use an inline suppression comment when a finding is intentional and should be ignored locally:

```rust
// soroban-guard: allow(unchecked-arithmetic)
let result = a + b;
```

Rules:

- The comment attaches to the next line of real code. Blank lines, `//` / `///` / `//!`
  comments, and `#[...]` attribute lines between the annotation and its target are skipped,
  so this suppresses `set_fee` as expected:

  ```rust
  // soroban-guard: allow(missing-event-emission)
  /// Updates the fee schedule.
  #[allow(dead_code)]
  pub fn set_fee(env: Env, bps: u32) { /* ... */ }
  ```

- If the first line of real code below the annotation is a `#[contractimpl]` method, the
  suppression is function-scoped; otherwise it applies to that single line.
- The check name inside `allow(...)` must exactly match the check's `name()` value.
- Multiple checks can be suppressed with a comma-separated list:
  `// soroban-guard: allow(delegate-call-risk, missing-event-emission)`

Place the same annotation immediately above a function declaration to suppress that check for all findings reported in that function:

```rust
// soroban-guard: allow(missing-require-auth)
pub fn bootstrap(env: Env) {
    env.storage().instance().set(&KEY, &1u32);
}
```

Function-level suppressions are scoped to the specific `#[contractimpl]` block the annotation sits above — if two different contract types in the same file both define a same-named method (e.g. two `set_owner`), suppressing one does not suppress the other.

Use suppressions for reviewed false positives only. Prefer fixing the code when the finding identifies a real deployability or security problem.

---

## Other workarounds

### Disable a check for an entire scan

Use `--disable-check` (tracked in issue #93) to skip a check globally:

```bash
cargo run -p soroban-guard-cli -- scan ./my-contract --disable-check delegate-call-risk
```

Multiple checks can be disabled:

```bash
--disable-check missing-event-emission --disable-check unchecked-arithmetic
```

### Exclude files or directories

Use `--exclude` to skip a path pattern entirely:

```bash
cargo run -p soroban-guard-cli -- scan ./my-contract --exclude src/proxy.rs
```

### Include only specific files

Use `--include` to restrict the scan to files whose paths match a glob pattern. Only matching
files are analysed; everything else is skipped:

```bash
cargo run -p soroban-guard-cli -- scan ./my-contract --include 'src/token*.rs'
```

`--include` and `--exclude` can be combined — `--exclude` is applied after `--include`, so a
file must match an include pattern *and* not match any exclude pattern to be scanned:

```bash
cargo run -p soroban-guard-cli -- scan ./my-contract \
    --include 'src/*.rs' \
    --exclude 'src/generated.rs'
```

> **Known limitation (issue [#316](https://github.com/SorobanGuard/Guard-CLI/issues/316)):**
> `--include` currently accepts only a single pattern per invocation. If you need to match
> several disjoint patterns you must run the scanner once per pattern, or use a broader glob
> that covers all the files you want. Track the linked issue for updates.

---

## Reporting a false positive

If you believe a finding is a genuine false positive (not covered by a known limitation above),
please open a GitHub issue with:

1. **The check name** — e.g. `missing-require-auth`.
2. **A minimal reproducible snippet** — the smallest `#[contractimpl]` block that triggers the
   finding. Strip all unrelated code.
3. **Why it is incorrect** — a brief explanation of the contract's intent.

Use this template:

```
**Check:** missing-require-auth

**Snippet:**
\`\`\`rust
#[contractimpl]
impl MyContract {
    pub fn update(env: Env) {
        // auth is handled inside guard()
        guard(&env);
        env.storage().instance().set(&KEY, &1u32);
    }
}
\`\`\`

**Why it's a false positive:**
`require_auth` is called inside the `guard` helper function.
```

We use these reports to improve heuristics and prioritise dataflow improvements.
