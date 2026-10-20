---
name: New check proposal
about: Propose a detector with vulnerable and safe fixtures and expected severity
title: 'checks: add '
labels: 'enhancement'
assignees: ''

---

## Proposed check name
<!-- Use a stable kebab-case name, for example: unchecked-token-amount. -->

## Severity and rationale
<!-- Choose High, Medium, or Low. Explain the impact and when it can occur. -->

## Vulnerable Rust snippet
<!-- Provide a minimal, compilable Soroban contract that should trigger the check.
This becomes test-contracts/<name>-vulnerable/src/lib.rs. -->

```rust
// Vulnerable contract here.
```

## Safe Rust snippet
<!-- Show the corresponding safe contract that should not trigger the check.
This becomes test-contracts/<name>-safe/src/lib.rs. -->

```rust
// Safe contract here.
```

## Known false-positive risks
<!-- Describe legitimate patterns that resemble the vulnerable snippet. -->

## References
<!-- Link supporting advisories, audit reports, or Soroban SDK documentation.
Do not disclose private vulnerabilities in Guard CLI here; see SECURITY.md. -->

## Implementation checklist
<!-- See CONTRIBUTING.md for the full new-check workflow. -->
- [ ] Implement the check and unit tests in `crates/checks/src/`.
- [ ] Export and register the check in `crates/checks/src/lib.rs`.
- [ ] Document severity, patterns, and false positives in `docs/checks.md`.
- [ ] Add `test-contracts/<name>-vulnerable` and `<name>-safe` fixture crates.
- [ ] Add a fixture-pair assertion in `crates/cli/tests/fixture_scans.rs`.
- [ ] Add a triggering example in `examples/all-findings/src/lib.rs`.
