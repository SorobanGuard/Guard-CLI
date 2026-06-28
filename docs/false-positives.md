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

---

## Per-check known limitations

| Check | Known false-positive sources | Full details |
|---|---|---|
| `missing-require-auth` | Auth delegated to a helper function; `Env` param named something other than `env` | [checks.md#missing-require-auth](checks.md#missing-require-auth) |
| `unchecked-arithmetic` | Severity is name-based; a variable named `amount` in non-financial context gets High | [checks.md#unchecked-arithmetic](checks.md#unchecked-arithmetic) |
| `unprotected-admin` | Any `require_auth` anywhere in the body clears the finding; auth inside a helper is not seen | [checks.md#unprotected-admin](checks.md#unprotected-admin) |
| `unsafe-storage-patterns` | `Symbol::new` with a `const` or macro-expanded literal may be flagged as a dynamic key | [checks.md#unsafe-storage-patterns](checks.md#unsafe-storage-patterns) |
| `unsafe-cross-contract-input` | Validation in a helper called after the assignment is not tracked | [checks.md#unsafe-cross-contract-input](checks.md#unsafe-cross-contract-input) |
| `delegate-call-risk` | Intentional proxy patterns that read a callee from storage are flagged by design | [checks.md#delegate-call-risk](checks.md#delegate-call-risk) |
| `missing-event-emission` | Events emitted inside a helper called from the flagged method are not detected | [checks.md#missing-event-emission](checks.md#missing-event-emission) |
| `re-initialization-risk` | Any `.has()` / `.is_some()` in the body clears the finding regardless of control-flow | [checks.md#re-initialization-risk](checks.md#re-initialization-risk) |
| `unchecked-invoke-return` | `let _ = env.invoke_contract(…)` suppresses the warning even though the value is dropped | [checks.md#unchecked-invoke-return](checks.md#unchecked-invoke-return) |
| `missing-balance-check` | `balance()` on an unrelated client clears the finding | [checks.md#missing-balance-check](checks.md#missing-balance-check) |
| `unbounded-vec-growth` | Any `.len()` call in the function clears the finding even without a cap | [checks.md#unbounded-vec-growth](checks.md#unbounded-vec-growth) |
| `unsafe-randomness` | `env.ledger().timestamp()` alone is flagged even if the value is never used in logic | [checks.md#unsafe-randomness](checks.md#unsafe-randomness) |
| `unchecked-divisor` | Any literal divisor is skipped; complex runtime guards are not tracked | [checks.md#unchecked-divisor](checks.md#unchecked-divisor) |

---

## Workarounds today

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

---

## Planned suppression annotation (issue #149)

A future release will support inline suppression comments so you can silence a specific finding
for a specific line without disabling the check globally:

```rust
// soroban-guard: allow(delegate-call-risk)
let callee: Address = env.storage().persistent().get(&CALLEE_KEY).unwrap();
```

Rules for the annotation (subject to change before release):

- The comment must appear on the line immediately before the flagged expression.
- The check name inside `allow(…)` must exactly match the check's `name()` value.
- Multiple checks can be suppressed with a comma-separated list:
  `// soroban-guard: allow(delegate-call-risk, missing-event-emission)`

Until this ships, use `--disable-check` or `--exclude` as described above.

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
