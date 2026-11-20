# Writing your first check

This tutorial builds one small check from scratch. By the end you will have a
working `Check` implementation, unit tests, a safe/vulnerable fixture pair, a
fixture-scan registration, and a docs entry — the same set of steps listed in
the [CONTRIBUTING](../CONTRIBUTING.md) checklist, but walked through end to end.

> **Illustrative check.** The check we build here is called
> `ExampleStorageCallCheck` and lives in the `example_storage_call` module. It is
> **not** registered in the real registry — it exists only to demonstrate the
> mechanics. When you write a real check, pick a descriptive name and register
> it (see [Registering the check](#registering-the-check)).

## What we are building

We will flag any call to a storage accessor named `dangerous_get` inside a
`#[contractimpl]` block. This is deliberately simple, but it exercises the
parts you will touch in almost every check:

- walking a `syn::File` with a visitor,
- restricting to `#[contractimpl]` functions while skipping `#[cfg(test)]`,
- building a `Finding`,
- writing unit tests and fixtures.

## 1. The visitor skeleton

Every check implements the `Check` trait. The core method is `run`, which
receives a parsed `syn::File` and returns a `Vec<Finding>`.

```rust
use crate::{Check, Finding};
use syn::File;

pub struct ExampleStorageCallCheck;

impl Check for ExampleStorageCallCheck {
    fn name(&self) -> &'static str {
        "example_storage_call"
    }

    fn description(&self) -> &'static str {
        "Flags calls to the illustrative `dangerous_get` storage accessor."
    }

    fn run(&self, file: &File) -> Vec<Finding> {
        let mut findings = Vec::new();
        // We will fill this in below.
        let _ = file;
        findings
    }
}
```

The exact signatures of `name`, `description`, and `run` are defined by the
`Check` trait in `crates/checks/src/lib.rs`. If you are unsure, open that file
and copy the trait definition — the compiler will tell you if a method is
missing or has the wrong signature.

## 2. Walking the AST with `syn`

To find calls, we implement a `syn::visit::Visit` visitor. The visitor pattern
lets you override only the node types you care about; everything else is walked
for you.

```rust
use syn::visit::Visit;
use syn::{ExprCall, File};

struct CallVisitor {
    findings: Vec<Finding>,
}

impl<'ast> Visit<'ast> for CallVisitor {
    fn visit_expr_call(&mut self, node: &'ast ExprCall) {
        if let syn::Expr::Path(path) = &*node.func {
            if let Some(segment) = path.path.segments.last() {
                if segment.ident == "dangerous_get" {
                    self.findings.push(Finding {
                        check: "example_storage_call".to_string(),
                        message: "call to `dangerous_get` storage accessor".to_string(),
                        line: 0,
                        column: 0,
                    });
                }
            }
        }
        // Always recurse so nested calls are visited too.
        syn::visit::visit_expr_call(self, node);
    }
}
```

A few things to note:

- `visit_expr_call` is called for every function-call expression.
- We match on the last path segment so `storage::dangerous_get()` and
  `dangerous_get()` are both caught.
- We call `syn::visit::visit_expr_call(self, node)` at the end so the default
  traversal continues into arguments and nested calls.

## 3. Restricting to `#[contractimpl]` and skipping tests

Most Soroban checks only care about code inside `#[contractimpl]` blocks, and
must ignore `#[cfg(test)]` items. The helpers in
`crates/checks/src/util.rs` do exactly this:

- `is_contractimpl(attrs)` — true if the item carries `#[contractimpl]`.
- `contractimpl_functions_excluding_test(items)` — yields the functions inside a
  `#[contractimpl]` block, skipping any marked `#[cfg(test)]`.
- `contractimpl_functions_with_type_excluding_test(items)` — same, but also
  yields the impl type name (useful when you need to know which contract the
  function belongs to).
- `impl_type_name(item_impl)` — extracts the type name from an `impl` block.
- `is_cfg_test(attrs)` — true if the item carries `#[cfg(test)]`.

Here is how to use them to drive the visitor only over the functions we care
about:

```rust
use crate::util::{contractimpl_functions_excluding_test, is_contractimpl};
use syn::visit::Visit;
use syn::{File, Item};

fn run(&self, file: &File) -> Vec<Finding> {
    let mut findings = Vec::new();

    for item in &file.items {
        let Item::Impl(item_impl) = item else {
            continue;
        };
        if !is_contractimpl(&item_impl.attrs) {
            continue;
        }

        for func in contractimpl_functions_excluding_test(&item_impl.items) {
            let mut visitor = CallVisitor {
                findings: Vec::new(),
            };
            visitor.visit_block(&func.block);
            findings.extend(visitor.findings);
        }
    }

    findings
}
```

`contractimpl_functions_excluding_test` already filters out `#[cfg(test)]`
functions, so we do not need to call `is_cfg_test` ourselves here. If you are
iterating over items manually instead, call `is_cfg_test(&item.attrs)` and skip
when it returns `true`.

## 4. The `Finding` fields

Each `Finding` describes one problem. The fields are:

| Field     | Type      | Meaning                                              |
|-----------|-----------|------------------------------------------------------|
| `check`   | `String`  | The check name (matches `Check::name`).              |
| `message` | `String`  | Human-readable description of the problem.           |
| `line`    | `usize`   | 1-based line number, or `0` if unknown.              |
| `column`  | `usize`   | 1-based column number, or `0` if unknown.            |

`syn` does not carry span information by default, so many checks report `0`
for `line`/`column` and rely on the message to point at the offending code. If
your check needs precise locations, enable the `proc-macro2` span features and
read `span.start()`.

## 5. Unit tests

Unit tests live in a `#[cfg(test)]` module inside the check's source file. Parse
a snippet with `syn::parse_file` and assert on the findings. The helper returns
`Result<File, syn::Error>`, so tests return `Result<(), syn::Error>` and use `?`.

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn run_check(source: &str) -> Result<Vec<Finding>, syn::Error> {
        let file = syn::parse_file(source)?;
        Ok(ExampleStorageCallCheck.run(&file))
    }

    #[test]
    fn flags_dangerous_get() -> Result<(), syn::Error> {
        let source = r#"
            #[contractimpl]
            impl MyContract {
                pub fn read(env: Env) -> u32 {
                    dangerous_get(&env)
                }
            }
        "#;
        let findings = run_check(source)?;
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].check, "example_storage_call");
        Ok(())
    }

    #[test]
    fn ignores_cfg_test() -> Result<(), syn::Error> {
        let source = r#"
            #[contractimpl]
            impl MyContract {
                #[cfg(test)]
                pub fn read(env: Env) -> u32 {
                    dangerous_get(&env)
                }
            }
        "#;
        let findings = run_check(source)?;
        assert!(findings.is_empty());
        Ok(())
    }
}
```

Run them with:

```sh
cargo test -p checks example_storage_call
```

## 6. Fixtures

Fixtures are real (small) contracts under `test-contracts/`. Each check gets a
pair: one that should produce **no** findings (safe) and one that should
produce findings (vulnerable). Create two directories:

```
test-contracts/example_storage_call_safe/
test-contracts/example_storage_call_vulnerable/
```

Each directory needs a `Cargo.toml` and a `src/lib.rs`. The vulnerable one
contains the offending call:

```rust
// test-contracts/example_storage_call_vulnerable/src/lib.rs
#![no_std]
use soroban_sdk::{contract, contractimpl, Env};

#[contract]
pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn read(env: Env) -> u32 {
        dangerous_get(&env)
    }
}

fn dangerous_get(_env: &Env) -> u32 {
    0
}
```

The safe one uses a different accessor name so the check stays quiet. Keep
fixtures minimal — they exist to exercise the check, not to be realistic
contracts.

## 7. Registering the fixture pair in `fixture_scans.rs`

`crates/cli/tests/fixture_scans.rs` runs every check against its fixtures and
asserts the expected finding counts. Add an entry for your pair following the
existing pattern in that file (the exact macro/struct name depends on the
current version — copy the nearest existing entry and adjust the check name,
fixture paths, and expected counts).

The important invariant: the **safe** fixture must yield zero findings and the
**vulnerable** fixture must yield at least one. If the vulnerable fixture yields
zero, your check is not matching what you think it is.

## 8. Documenting the check in `docs/checks.md`

Add a section to `docs/checks.md` describing what the check flags, why it
matters, and a short before/after example. Keep it consistent with the
surrounding sections — same heading level, same tone.

## 9. The registry consistency test

`crates/checks/tests/registry_consistency.rs` verifies that every registered
check has a matching docs entry and that names line up. Once you register your
check (see below) and add its docs section, this test should pass. Run it with:

```sh
cargo test -p checks --test registry_consistency
```

If it fails, it will tell you which name is missing from the registry or the
docs.

## Registering the check

> The `ExampleStorageCallCheck` above is **not** registered. To register a real
> check, add it to the registry in `crates/checks/src/lib.rs` (look for the
> function that builds the list of checks) and make sure its `name()` matches
> the docs heading and the fixture-scan entry.

## Checklist recap

- [ ] `Check` impl with `name`, `description`, `run`.
- [ ] Visitor over the relevant `syn` nodes.
- [ ] Uses `util.rs` helpers to scope to `#[contractimpl]` and skip tests.
- [ ] `Finding` populated with `check`, `message`, `line`, `column`.
- [ ] `#[cfg(test)]` unit tests using `syn::parse_file` and `Result<(), syn::Error>`.
- [ ] Safe and vulnerable fixtures under `test-contracts/`.
- [ ] Entry in `crates/cli/tests/fixture_scans.rs`.
- [ ] Section in `docs/checks.md`.
- [ ] Registered in `crates/checks/src/lib.rs`; `registry_consistency` passes.

## See also

- [CONTRIBUTING](../CONTRIBUTING.md) — the checklist this tutorial expands on.
- [README](../README.md) — project overview.
- [`docs/checks.md`](checks.md) — the catalog of existing checks.
- `crates/checks/src/util.rs` — the shared AST helpers.
- `crates/checks/src/lib.rs` — the `Check` trait and `Finding` type.