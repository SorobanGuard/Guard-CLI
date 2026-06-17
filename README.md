# Guard CLI

> Static analysis engine for [Soroban](https://soroban.stellar.org/) smart contracts — securing the Stellar blockchain, one contract at a time.

Guard CLI is a CLI-based static analyzer for Rust smart contracts deployed on the **Stellar network** via the Soroban smart contract platform. It detects vulnerabilities before your code ever touches the chain.

---

## Why Soroban Guard?

Soroban is Stellar's smart contract platform — a WebAssembly-based execution environment designed for speed, low cost, and predictability. But like any smart contract platform, **bugs in Soroban contracts can be exploited on-chain and are irreversible**.

Soroban Guard catches common vulnerability classes at the source level, before `stellar contract deploy` ever runs.

---

## Stellar / Soroban Context

Soroban contracts are Rust crates compiled to WASM and deployed to the Stellar network. Key security concerns this tool addresses:

| Concern | Stellar/Soroban Impact |
|---|---|
| Missing `require_auth` | Any caller can invoke privileged contract functions |
| Unchecked arithmetic | Integer overflow/underflow in token balances or ledger math |
| Unprotected admin | Admin keys can be overwritten without authorization |
| Unsafe storage patterns | Persistent/temporary ledger storage misuse |

---

## Requirements

- Rust 1.74+ (2021 edition)
- No Stellar SDK or network connection required — analysis is purely static

## Build

```bash
cargo build --release
```

The binary is `target/release/soroban-guard` (package `soroban-guard-cli`).

---

## Usage

Scan a Soroban contract crate before deploying to Stellar:

```bash
cargo run -p soroban-guard-cli -- scan ./path/to/contract-crate
```

Output as JSON (useful for CI pipelines or the web dashboard):

```bash
cargo run -p soroban-guard-cli -- scan ./path/to/contract-crate --json
```

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | No High severity findings — safe to proceed |
| `1` | At least one High finding — **do not deploy** |
| `2` | Scan error (I/O or parse failure) |

---

## Workspace Scaffold

```
Guard-CLI/
├── Cargo.toml                  # workspace root
├── crates/
│   ├── cli/                    # clap entrypoint & reporting
│   │   └── src/main.rs
│   ├── analyzer/               # walks .rs files, parses with syn, runs checks
│   │   └── src/lib.rs
│   └── checks/                 # Check trait + individual detectors
│       └── src/
│           ├── lib.rs          # trait definition, Finding, Severity, default_checks()
│           ├── auth.rs         # missing-require-auth
│           ├── overflow.rs     # unchecked-arithmetic
│           ├── admin.rs        # unprotected-admin
│           └── storage.rs      # unsafe-storage-patterns
└── test-contracts/             # standalone Soroban crates (excluded from workspace)
    ├── vulnerable/             # triggers missing-require-auth
    ├── safe/                   # passes missing-require-auth
    ├── arithmetic-vulnerable/
    ├── arithmetic-safe/
    ├── admin-vulnerable/
    ├── admin-safe/
    ├── storage-vulnerable/
    └── storage-safe/
```

---

## Code Snippets

### Vulnerable contract — triggers `missing-require-auth`

```rust
#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Env, Symbol};

#[contract]
pub struct VulnerableContract;

const KEY: Symbol = symbol_short!("counter");

#[contractimpl]
impl VulnerableContract {
    // ❌ No env.require_auth() — anyone on Stellar can call this
    pub fn bump(env: Env) {
        let mut n: u32 = env.storage().instance().get(&KEY).unwrap_or(0);
        n += 1;
        env.storage().instance().set(&KEY, &n);
    }
}
```

### Safe contract — passes `missing-require-auth`

```rust
#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Address, Env, Symbol};

#[contract]
pub struct SafeContract;

const KEY: Symbol = symbol_short!("owner");

#[contractimpl]
impl SafeContract {
    // ✅ Caller must be the authorized Address on Stellar
    pub fn set_owner(env: Env, new_owner: Address) {
        env.require_auth();
        env.storage().instance().set(&KEY, &new_owner);
    }
}
```

### Adding a custom check

Implement the `Check` trait in `crates/checks/src/` and register it in `default_checks()`:

```rust
use crate::{Check, Finding};
use syn::File;

pub struct MyCustomCheck;

impl Check for MyCustomCheck {
    fn name(&self) -> &str { "my-custom-check" }

    fn run(&self, file: &File, source: &str) -> Vec<Finding> {
        // inspect the syn AST and return any findings
        vec![]
    }
}
```

```rust
// crates/checks/src/lib.rs — register it here
pub fn default_checks() -> Vec<Box<dyn Check + Send + Sync>> {
    vec![
        Box::new(MissingRequireAuthCheck),
        Box::new(UncheckedArithmeticCheck),
        Box::new(UnprotectedAdminCheck),
        Box::new(UnsafeStoragePatternsCheck),
        Box::new(MyCustomCheck),   // 👈 add your check
    ]
}
```

---

## Stellar Integration

Guard CLI is designed to sit at the gate of your Stellar deployment pipeline. Soroban contracts are compiled to WASM and deployed to the Stellar network — Guard CLI catches vulnerabilities at the source level before any of that happens.

### How it fits in

```
[Source code] → Guard CLI scan → [WASM build] → [Stellar deploy]
```

- Runs purely on Rust source — no Stellar SDK, no network connection, no wallet required.
- Exit code `1` on High findings lets CI block a deploy automatically.
- `--json` output can be piped into any dashboard or audit log.

### Deployment workflow

```bash
# 1. Scan before building — fails fast on High findings (exit 1)
cargo run -p soroban-guard-cli -- scan ./my-contract --json > findings.json

# 2. Build the WASM artifact only if scan passed
cargo build --target wasm32-unknown-unknown --release

# 3. Deploy to Stellar Testnet
stellar contract deploy \
  --wasm target/wasm32-unknown-unknown/release/my_contract.wasm \
  --source <account-name> \
  --network testnet

# 4. Or deploy to Mainnet
stellar contract deploy \
  --wasm target/wasm32-unknown-unknown/release/my_contract.wasm \
  --source <account-name> \
  --network mainnet
```

### CI example (GitHub Actions)

```yaml
- name: Guard CLI scan
  run: cargo run -p soroban-guard-cli -- scan ./my-contract
  # exits 1 on High findings — blocks the workflow

- name: Build WASM
  run: cargo build --target wasm32-unknown-unknown --release
```

---

## Workspace layout

| Crate | Role |
|-------|------|
| `crates/cli` | `clap` entrypoint, reporting |
| `crates/analyzer` | Walk `.rs` files, parse with `syn`, run checks |
| `crates/checks` | `Check` trait + individual detectors |

See `docs/checks.md` for implemented rules and `CONTRIBUTING.md` to add a check.

---

## License

MIT OR Apache-2.0 (see workspace `Cargo.toml`).
