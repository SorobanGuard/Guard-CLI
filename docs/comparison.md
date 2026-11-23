# Guard vs. other Soroban analysis tools

This page explains what `soroban-guard` does, what it does not do, and how it fits alongside other tools you may already use. It is meant to help you decide *when* to reach for Guard — not to argue that Guard replaces anything. Most teams get the best coverage by combining several approaches.

> Claims about third-party tools below are based on their public documentation at the time of writing. Tool capabilities change; always verify against the current docs linked in each section.

## What Guard analyses

Guard is a **static analyzer for Soroban contract source code**. It:

- Walks the `.rs` files in a crate and parses them with [`syn`](https://docs.rs/syn).
- Runs a set of **syntactic heuristics** over the parsed source — pattern-matching on how contract code is written (e.g. `#[contractimpl]` methods, `env.storage()` calls, `invoke_contract` invocations, `require_auth` presence).
- Reports findings with a severity, a check ID, and a source location.

Because analysis is purely syntactic, Guard **does not use type information or the compiler's type checker**. It reasons about the shape of the code, not its resolved types. This keeps it fast and dependency-light (no network, no Stellar SDK, no build of the target crate required), but it also bounds what it can prove.

## What Guard does not do

Guard is not a type checker, a compiler, a fuzzer, or a formal verifier. In particular it does **not**:

- Resolve types or perform data-flow/points-to analysis across the whole program.
- Prove the absence of bugs — a clean Guard run means no *known heuristic patterns* matched, not that the contract is correct.
- Check dependency versions for known CVEs.
- Enforce general Rust style or correctness lints.
- Execute the contract or explore runtime states.

See the [limitations page](limitations.md) (tracked in #875) for the authoritative, up-to-date list of what Guard cannot detect.

## How Guard complements other tools

Guard is designed to sit *alongside* the rest of your toolchain. Each tool below answers a different question.

### Clippy

[Clippy](https://doc.rust-lang.org/clippy/) is the standard Rust linter. It checks general Rust correctness, style, and performance across any crate, but it has no concept of Soroban, contracts, or on-chain state.

- **Clippy asks:** "Is this idiomatic, correct Rust?"
- **Guard asks:** "Does this contract logic look unsafe to deploy on Stellar?"

A contract can pass Clippy cleanly and still have a missing `require_auth` or a reentrancy pattern — that is the gap Guard targets. Run both.

### cargo-audit

[`cargo-audit`](https://github.com/rustsec/rustsec/tree/main/cargo-audit) inspects `Cargo.lock` and flags dependency versions with known advisories from the [RustSec advisory database](https://rustsec.org/). It operates on dependency metadata, not on your source code.

- **cargo-audit asks:** "Am I depending on a crate version with a known CVE?"
- **Guard asks:** "Is my own contract code safe?"

These are orthogonal: `cargo-audit` covers supply-chain risk, Guard covers contract-logic risk. Use both.

### Fuzzing

Fuzzers (e.g. [`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz)) execute the contract against many generated inputs to find inputs that trigger panics or invariant violations at runtime.

- **Fuzzing asks:** "Can I find an input that breaks this at runtime?"
- **Guard asks:** "Does the source contain known-risky patterns?"

Fuzzing explores behavior; Guard inspects structure. Fuzzing can catch bugs Guard's heuristics miss, and Guard can flag risky patterns before you invest in a fuzzing harness. They are complementary.

### Formal verification

Formal verification tools prove properties about a specification or model of the contract. They offer the strongest guarantees but require a specification and significant effort.

- **Formal verification asks:** "Can I *prove* this property holds?"
- **Guard asks:** "Are there obvious red flags in the source?"

Guard is a fast, low-effort first pass; formal verification is a high-effort, high-assurance step for critical paths. Use Guard to triage, and formal methods where the stakes justify the cost.

## Output formats

Guard emits findings in several formats so it can slot into existing workflows:

- **Terminal** (default, human-readable; `NO_COLOR` respected)
- **JSON** (`--json`, optionally `--output <file>`) — for CI pipelines and dashboards
- **SARIF 2.1.0** (`--sarif`) — for GitHub Code Scanning
- **Markdown** (`--markdown`) — for PR comments and docs

## Decision table

| Question you're asking | Tool |
|---|---|
| Is my contract logic safe to deploy on Stellar? | **Guard** |
| Is this idiomatic / correct Rust in general? | Clippy |
| Do I depend on a crate with a known CVE? | cargo-audit |
| Can I find an input that breaks this at runtime? | Fuzzing |
| Can I *prove* a property holds? | Formal verification |

In short: `cargo-audit` checks *what you depend on*, `clippy` checks *how you write Rust in general*, fuzzing and formal verification check *runtime behavior and provable properties*, and `soroban-guard` checks *whether your contract logic is safe to deploy on Stellar*. None substitutes for the others.
