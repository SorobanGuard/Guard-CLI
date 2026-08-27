# Version compatibility and migration

Guard-CLI uses API versions for the contract/frontend interface. These are
independent of the package release version and must be changed only when the
interface changes.

## Matrix

| Frontend API version | Contract API version | Result |
|----------------------|----------------------|--------|
| `1` | `2` | Compatible |

The matrix is maintained in `crates/cli/src/version.rs`. Unknown versions and
pairs not listed there are incompatible by design.

## Startup check

Configure both versions and run `check-version` before enabling the app:

```toml
[contract]
version = "2"

[frontend]
version = "1"
```

```bash
soroban-guard check-version --config-path . --json
```

An application should keep its normal startup path disabled until the command
returns exit code `0`. For a mismatch, display the returned versions and direct
the operator to this guide. A mismatch is a deployment/configuration error,
not a reason to silently select another contract or downgrade one.

## Migration procedure

1. Identify the deployed contract API version and the frontend API version.
2. Check the pair against the matrix.
3. If the pair is unsupported, deploy or select the frontend release that
   supports the deployed contract, or plan a coordinated contract migration.
4. Update `[frontend].version` or `[contract].version` only after the deployed
   interface has actually changed.
5. Run `check-version` in CI and at application startup before rollout.

Guard-CLI does not query a network, choose among contracts, support concurrent
contract versions, or downgrade contracts. A frontend that needs live
verification must obtain the contract version through its own deployment
metadata/RPC adapter and pass that value to the check.