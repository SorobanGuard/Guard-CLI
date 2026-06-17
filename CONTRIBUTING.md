# Contributing to Guard CLI

Thank you for helping improve the static analyzer. This guide covers **local setup**, a **short `syn` tutorial with examples**, **how to add a check** (using `auth.rs` as a template), and **how to write test contracts**.

## Local development setup

1. **Install Rust** (1.74 or newer recommended) using [rustup](https://rustup.rs/):

   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   source "$HOME/.cargo/env"
   rustc --version
   ```

2. **Clone this repository** and `cd` into the workspace root:

   ```bash
   git clone https://github.com/SorobanGuard/Guard-CLI.git
   cd Guard-CLI
   ```

3. **Build and run the full test suite:**

   ```bash
   cargo build --workspace
   cargo test --workspace
   ```

4. **Run the CLI** against bundled fixtures:

   ```bash
   cargo run -p soroban-guard-cli -- scan test-contracts/vulnerable
   cargo run -p soroban-guard-cli -- scan test-contracts/safe --json
   ```

5. **Standalone Soroban crates** — Paths under `test-contracts/` are listed in `[workspace.exclude]`. To type-check a fixture on its own:

   ```bash
   cd test-contracts/arithmetic-safe && cargo check
   ```

6. **Install the `soroban-guard` binary** (optional):

   ```bash
   cargo install --path crates/cli
   ```

### Commit hygiene

Prefer **small, focused commits** (one logical change per commit): a single check, a doc section, or a test fixture pair. This makes review and `git bisect` straightforward. Aim for **clear commit messages** in [Conventional Commits](https://www.conventionalcommits.org/) style (`feat(checks): …`, `fix(cli): …`, `docs: …`).

---

## Mini tutorial: `syn` and the AST (with code examples)

The workspace enables **`syn` with the `full` feature** (see root `Cargo.toml` → `[workspace.dependencies]`) so every `Item`, `Expr`, and `Stmt` variant is available for pattern matching and visitors. **`proc-macro2`** is configured with **`span-locations`** so `expr.span().start().line` maps to a 1-based source line when parsing whole files.

### Walk the crate root

`syn::parse_file` returns a `syn::File`. Its `items` slice holds top-level declarations (`use`, `struct`, `impl`, …):

```rust
use syn::{parse_file, Item};

fn list_struct_names(src: &str) -> Result<Vec<String>, syn::Error> {
    let file = parse_file(src)?;
    let mut names = Vec::new();
    for item in &file.items {
        if let Item::Struct(s) = item {
            names.push(s.ident.to_string());
        }
    }
    Ok(names)
}
```

### Visit expressions without listing every `Expr` variant

Implementing [`syn::visit::Visit`](https://docs.rs/syn/latest/syn/visit/trait.Visit.html) dispatches recursively. This mirrors how `auth.rs` and `overflow.rs` detect method calls and binary operators:

```rust
use syn::visit::{self, Visit};
use syn::{ExprBinary, ExprMethodCall, BinOp};

#[derive(Default)]
struct StorageCallCount {
    storage_methods: usize,
    unchecked_int_ops: usize,
}

impl<'ast> Visit<'ast> for StorageCallCount {
    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        if i.method == "storage" {
            self.storage_methods += 1;
        }
        visit::visit_expr_method_call(self, i);
    }

    fn visit_expr_binary(&mut self, i: &'ast ExprBinary) {
        if matches!(i.op, BinOp::Add(_) | BinOp::Sub(_) | BinOp::Mul(_)) {
            self.unchecked_int_ops += 1;
        }
        visit::visit_expr_binary(self, i);
    }
}
```

Drive the visitor with `visit::visit_file(&mut v, &file)` or `v.visit_block(&func.block)` for a single function body.

### Further reading

- [`syn` on docs.rs](https://docs.rs/syn/)
- Internal rule reference: [`docs/checks.md`](docs/checks.md)

---

## How to add a new check (copy `auth.rs` as a template)

Use [`crates/checks/src/auth.rs`](crates/checks/src/auth.rs) as the canonical layout: a `const CHECK_NAME`, a unit struct, `impl Check`, private helpers, and a `#[cfg(test)]` module using `syn::parse_file` with `Result`-returning tests.

### Step-by-step

1. **Copy the file** — `cp crates/checks/src/auth.rs crates/checks/src/my_rule.rs` and rename:
   - `CHECK_NAME` → your stable rule id (e.g. `"my-rule"`).
   - `MissingRequireAuthCheck` → `MyRuleCheck`.
   - Replace `run` with your AST logic; keep `Finding { file_path: String::new(), ... }` (the analyzer fills paths).

2. **Register the module** — In [`crates/checks/src/lib.rs`](crates/checks/src/lib.rs):
   - `pub mod my_rule;`
   - `pub use my_rule::MyRuleCheck;`
   - Push `Box::new(MyRuleCheck)` into `default_checks()`. Order only affects listing, not semantics.

3. **Keep checks isolated** — Do **not** use shared mutable static state. Pass data through function arguments or use `util.rs` for **pure** helpers. Each `Check::run` must behave the same regardless of which other checks ran first.

4. **Document the rule** — Add a section to [`docs/checks.md`](docs/checks.md) (severity, patterns, false positives).

5. **Unit tests** — In `my_rule.rs`, add `#[test] fn ...() -> Result<(), syn::Error>` and use `parse_file(src)?` so parse failures surface as test errors instead of panics.

6. **Fixture crates** — Add `test-contracts/<rule>-vulnerable/` and `test-contracts/<rule>-safe/` (see below).

---

## How to write test contracts

Fixture crates live under **`test-contracts/`** and are **excluded** from the root workspace so each remains a normal Soroban `cdylib` package.

1. **Layout**

   ```
   test-contracts/my-rule-vulnerable/
   ├── Cargo.toml
   └── src/lib.rs
   ```

2. **`Cargo.toml`** — Match existing samples: `soroban-sdk`, `edition = "2021"`, `[lib] crate-type = ["cdylib"]`, `publish = false`.

3. **`src/lib.rs`** — Use real Soroban patterns (`#![no_std]`, `#[contract]`, `#[contractimpl]`) so `cargo check` inside the directory validates the sample.

4. **Naming** — Use `*-vulnerable` / `*-safe` pairs for clarity in docs and CI.

5. **Scanning** — `soroban-guard scan test-contracts/my-rule-vulnerable` only reads `.rs` files; building first is optional.

---

## Architecture constraints (for contributors)

- **`syn` `full`** — New crates in this workspace should inherit workspace `syn` with `features = ["full", "visit"]` unless there is a strong reason not to.
- **No `todo!()`** — Land complete logic; placeholders block merge.
- **No panics in library / CLI paths** — Propagate or handle `Result` (the CLI uses exit code **2** for report serialization failures and scan errors).
- **Checks stay isolated** — Stateless `run` implementations; no reliance on execution order or global mutable state.

---

## Code style

- Prefer small visitors and helpers over monolithic passes.
- Keep `--json` output stable for scripting.
- When you change severity or rule IDs, update `docs/checks.md` in the same change.

Thank you for contributing.