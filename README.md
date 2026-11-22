# Guard CLI

[![CI](https://img.shields.io/github/actions/workflow/status/SorobanGuard/Guard-CLI/ci.yml?branch=main&label=CI)](https://github.com/SorobanGuard/Guard-CLI/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](https://github.com/SorobanGuard/Guard-CLI)
[![Rust Edition 2021](https://img.shields.io/badge/edition-2021-orange.svg)](Cargo.toml)
<!-- crates.io badge: add once `soroban-guard-cli` is published —
[![crates.io](https://img.shields.io/crates/v/soroban-guard-cli.svg)](https://crates.io/crates/soroban-guard-cli) -->

> Static analysis engine for [Soroban](https://soroban.stellar.org/) smart contracts — securing the Stellar blockchain, one contract at a time.

Guard CLI is a CLI-based static analyzer for Rust smart contracts deployed on the **Stellar network** via the Soroban smart contract platform. It detects vulnerabilities before your code ever touches the chain.

---

## Why Soroban Guard?

Soroban is Stellar's smart contract platform — a WebAssembly-based execution environment designed for speed, low cost, and predictability. But like any smart contract platform, **bugs in Soroban contracts can be exploited on-chain and are irreversible**.

Soroban Guard catches common vulnerability classes at the source level, before `stellar contract deploy` ever runs.

---

## How does this compare to `clippy` and `cargo-audit`?

These tools solve different problems and are complementary — running all three gives broader coverage than any one alone.

| | `soroban-guard` | `clippy` | `cargo-audit` |
|---|---|---|---|
| **What it analyzes** | Soroban contract source (`#[contractimpl]` methods, storage calls, cross-contract invocations) | Any Rust source, general-purpose | `Cargo.lock` dependency versions |
| **What it looks for** | Soroban/Stellar-specific contract security bugs (missing `require_auth`, reentrancy, unprotected admin, hardcoded addresses, unsafe storage, etc.) | General Rust correctness, style, and performance lints | Known-vulnerable crate versions published in the [RustSec advisory database](https://rustsec.org/) |
| **Domain awareness** | Yes — understands Soroban SDK patterns (`env.storage()`, `invoke_contract`, `#[contract]`/`#[contractimpl]`) | No — has no concept of Soroban, contracts, or on-chain state | No — operates purely on dependency metadata, not source code |
| **Catches supply-chain CVEs** | No | No | Yes |
| **Catches contract-logic vulnerabilities** | Yes | No | No |
| **Catches general Rust bugs/style issues** | No | Yes | No |

In short: `cargo-audit` checks *what you depend on*, `clippy` checks *how you write Rust in general*, and `soroban-guard` checks *whether your contract logic is safe to deploy on Stellar*. None of them substitute for the others — a contract can pass `clippy` and `cargo-audit` cleanly while still having an exploitable reentrancy or missing-auth bug, which is the gap `soroban-guard` is built to close.

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

## Install

### Homebrew (macOS arm64/x86_64 and Linux)

```bash
brew install SorobanGuard/tap/soroban-guard
soroban-guard --version
```

The formula downloads the release tarball, verifies its checksum, and installs
shell completions for Bash, Zsh, and Fish. The tap is bumped automatically on
every release.

### cargo-binstall (prebuilt binaries, no compile)

If you have [`cargo-binstall`](https://github.com/cargo-bins/cargo-binstall)
installed, you can skip compiling `syn` and friends entirely — `cargo binstall`
fetches the prebuilt release binary for your platform:

```bash
cargo binstall soroban-guard-cli
soroban-guard --version
```

This resolves the release asset for your target (`.tar.gz` on Linux/macOS,
`.zip` on Windows) from the GitHub Releases page. To preview the resolved URL
without downloading, run:

```bash
cargo binstall --dry-run soroban-guard-cli
```

### Prebuilt binaries

Prebuilt binaries for each release are published on the
[Releases page](https://github.com/SorobanGuard/Guard-CLI/releases). Every release
ships supply-chain artifacts so you can verify a download before running it:

- `SHA256SUMS` — checksums for every release asset
- `soroban-guard.cdx.json` — CycloneDX SBOM of the build
- a build-provenance attestation verifiable with `gh attestation verify`

```bash
# 1. Download the binary and SHA256SUMS for your platform, then verify the checksum
sha256sum --check --ignore-missing SHA256SUMS

# 2. Verify the build provenance attestation against the tagged source
gh attestation verify soroban-guard-x86_64-unknown-linux-gnu.tar.gz \
  --repo SorobanGuard/Guard-CLI

# 3. Inspect the SBOM for the dependency inventory
cat soroban-guard.cdx.json
```

See [docs/release.md](docs/release.md) for the full verification walkthrough.

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

Write JSON to a file instead of stdout:

```bash
cargo run -p soroban-guard-cli -- scan ./path/to/contract-crate --json --output findings.json
```

Emit SARIF 2.1.0 for GitHub Code Scanning:

```bash
cargo run -p soroban-guard-cli -- scan ./path/to/contract-crate --sarif > findings.sarif
```

List the checks that run by default:

```bash
cargo run -p soroban-guard-cli -- list-checks
cargo run -p soroban-guard-cli -- list-checks --json
```

Emit a Markdown table (handy for PR comments or docs):

```bash
cargo run -p soroban-guard-cli -- scan ./path/to/contract-crate --markdown
```

For plain terminal output, disable ANSI colors with:

```bash
NO_COLOR=1 soroban-guard scan ./path/to/contract-crate
```

Only fail (exit 1) on Medium-or-higher findings, instead of the High-only default:

```bash
cargo run -p soroban-guard-cli -- scan ./path/to/contract-crate --fail-on medium
```

Skip specific checks (may be repeated), or scope the scan to matching files:

```bash
cargo run -p soroban-guard-cli -- scan ./path/to/contract-crate --disable-check unsafe-randomness --disable-check reentrancy
cargo run -p soroban-guard-cli -- scan ./path/to/contract-crate --include 'src/token*.rs' --exclude 'src/proxy.rs'
```

Suppress output entirely unless a finding meets the `--fail-on` threshold, print extra scan statistics, or cap the number of findings shown in the terminal output:

```bash
cargo run -p soroban-guard-cli -- scan ./path/to/contract-crate --quiet
cargo run -p soroban-guard-cli -- scan ./path/to/contract-crate --verbose
cargo run -p soroban-guard-cli -- scan ./path/to/contract-crate --max-findings 50
```

`--max-findings` caps how many findings the pretty formatter prints (the trailing summary still counts the full result set). Use `--max-findings 0` to show all findings — the default.

Re-run the scan whenever a `.rs` file changes. The terminal is cleared between runs when output goes to a TTY; pass `--no-clear` to keep previous results on screen:

```bash
cargo run -p soroban-guard-cli -- scan ./path/to/contract-crate --watch
cargo run -p soroban-guard-cli -- scan ./path/to/contract-crate --watch --no-clear
```

Print full documentation for a single check:

```bash
cargo run -p soroban-guard-cli -- explain missing-require-auth
```

Generate shell completions (Bash, Zsh, Fish, or PowerShell):

```bash
cargo run -p soroban-guard-cli -- completions zsh > _soroban-guard
```

Create a commented starter configuration file:

```bash
cargo run -p soroban-guard-cli -- init
```

> Run `cargo run -p soroban-guard-cli -- scan --help` for the full, always-up-to-date flag reference.

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | No High severity findings — safe to proce

/* … truncated 393 chars — edit only what you need near the top … */
