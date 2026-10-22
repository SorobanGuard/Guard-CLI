# Configuration

`soroban-guard` can be configured through CLI flags, environment variables, or a
`soroban-guard.toml` file. When the same setting is provided in more than one
place, the following precedence applies (highest first):

| Setting     | CLI flag    | Environment variable     | Config file key | Default |
| ----------- | ----------- | ------------------------ | --------------- | ------- |
| Config path | `--config`  | `SOROBAN_GUARD_CONFIG`   | —               | `soroban-guard.toml` discovery |
| Fail on     | `--fail-on` | `SOROBAN_GUARD_FAIL_ON`  | `fail_on`       | `high`  |

Precedence, from highest to lowest:

1. CLI flag (`--config`, `--fail-on`)
2. Environment variable (`SOROBAN_GUARD_CONFIG`, `SOROBAN_GUARD_FAIL_ON`)
3. `soroban-guard.toml` (explicit path or discovered)
4. Built-in default

Unset or empty environment variables are treated as not set, so they fall
through to the next layer. Invalid values supplied via an environment variable
produce the same error as the equivalent flag.

## Example

```sh
# CI systems that can only inject environment variables
SOROBAN_GUARD_CONFIG=./ci/soroban-guard.toml \
SOROBAN_GUARD_FAIL_ON=medium \
  soroban-guard scan ./contracts
```
