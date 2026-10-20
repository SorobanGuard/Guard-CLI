# Writing Your First Check

This tutorial guides you through creating a new custom check for **Guard-CLI**. By the end of this guide, you will understand how to build a check from scratch, traverse the AST using `syn`, use helper utilities, write unit tests, set up code fixtures, and register the check.

---

## 1. Overview of a Check

A check in Guard-CLI typically consists of:
1. A **Visitor** implementing the `syn::visit::Visit` trait (or walking the AST manually).
2. A **Rule definition** describing the warning or error code, description, and severity.
3. **Unit tests** and **fixtures** (safe and vulnerable source files) to ensure correct detection.
4. **Registry** entry so Guard-CLI runs the check during analysis.

---

## 2. Step-by-Step Implementation

### Step 1: Create the Module
Create a new file under `src/checks/your_check.rs` (or within your library's check modules). Define your rule struct and the visitor skeleton:

```rust
use syn::visit::Visit;
use crate::diagnostic::{Finding, Severity};

pub struct UnsafeStorageVisitor {
    pub findings: Vec<Finding>,
}

impl<'ast> Visit<'ast> for UnsafeStorageVisitor {
    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        if node.method == "unwrapped_storage" {
            self.findings.push(Finding {
                rule_id: "G001".to_string(),
                message: "Avoid calling unwrapped_storage directly in production contracts.".to_string(),
                severity: Severity::Warning,
                span: node.span(),
            });
        }
        syn::visit::visit_expr_method_call(self, node);
    }
}
```

### Step 2: Add Unit Tests & Fixtures
Create safe and vulnerable fixture files under `tests/fixtures/unprocessed_storage/`:
- `vulnerable.rs`: Contains calls to `unwrapped_storage()`.
- `safe.rs`: Uses proper wrapped handling.

### Step 3: Register the Check
Add your check to the central registry in `src/checks/mod.rs` so that it is included in the standard analyzer pass.

---

## 3. Verification

Run cargo test to ensure all tests pass:
```bash
cargo test
```
