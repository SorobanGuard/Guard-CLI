# Release process

Use this checklist when publishing Soroban Guard crates to crates.io.

## Prerequisites

- Confirm the workspace builds and tests pass locally or in CI.
- Confirm `CHANGELOG.md` has an entry for the version being released.
- Confirm you are authenticated to crates.io with `cargo login`.

## Steps

1. Bump the version in the root workspace `Cargo.toml` under `[workspace.package]`.
2. Update `CHANGELOG.md`: rename `Unreleased` to the release version and date, then add a new empty `Unreleased` section.
3. Publish crates in dependency order:

   ```bash
   cargo publish -p soroban-guard-checks
   cargo publish -p soroban-guard-analyzer
   cargo publish -p soroban-guard-cli
   ```

4. Tag the release in git:

   ```bash
   git tag v<version>
   git push upstream v<version>
   ```

5. Create a GitHub release from the tag and include the changelog notes.

Publish order matters because `soroban-guard-analyzer` depends on `soroban-guard-checks`, and `soroban-guard-cli` depends on both library crates.

## Release supply-chain artifacts

The release workflow attaches the following assets to every GitHub release so
users can verify a downloaded binary was built from the tagged source by CI:

- `SHA256SUMS` — checksums covering every released artifact.
- `soroban-guard-<version>.cdx.json` — a CycloneDX SBOM of the dependency tree.
- Build-provenance attestations generated with `actions/attest-build-provenance`.

### Verifying a release

1. Verify the checksum of the downloaded binary:

   ```bash
   sha256sum --check SHA256SUMS --ignore-missing
   ```

2. Verify the build provenance attestation with the GitHub CLI:

   ```bash
   gh attestation verify soroban-guard-<target> --repo <owner>/soroban-guard
   ```

3. Inspect the SBOM to review the dependency inventory:

   ```bash
   cat soroban-guard-<version>.cdx.json
   ```
