---
name: New check proposal
about: Propose a new detector with the fixtures and severity it needs
title: "checks: add `<check-name>` — "
labels: ["enhancement", "checks"]
---

## Check name

<!-- Kebab-case, for example `predictable-deploy-salt`. -->

## Severity and rationale

<!-- High, Medium or Low, and why. -->

## Vulnerable snippet

<!-- A Rust snippet the check must flag. It becomes `test-contracts/<name>-vulnerable`. -->

```rust

```

## Safe snippet

<!-- A Rust snippet the check must not flag. It becomes `test-contracts/<name>-safe`. -->

```rust

```

## Known false-positive risks

<!-- Patterns that look like the issue but are fine, and how they should be handled. -->

## References

<!-- Links to an advisory, audit report or SDK documentation. -->

## Contributor checklist

- [ ] Implementation in `crates/checks`
- [ ] Registry entry (`crates/checks/src/lib.rs`)
- [ ] Section in `docs/checks.md`
- [ ] Fixture pair under `test-contracts/`
- [ ] Entry in the `fixture_scans.rs` test
- [ ] Follows the steps in [CONTRIBUTING.md](../../CONTRIBUTING.md)
