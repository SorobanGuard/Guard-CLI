//! `view-function-writes-storage` check.
//!
//! Flags `#[contractimpl]` methods whose name looks like a read-only getter
//! (`get_*`, `balance`, `total_supply`, `is_*`, `view_*`, `*_of`) but whose
//! body mutates contract storage. Pure TTL extension (`extend_ttl`/`bump`) is
//! an acceptable getter side effect and is not reported.

use crate::util;
use crate::{Check, CheckContext, Finding, Severity};
use syn::{ImplItem, Item};

/// Name of the check.
pub const NAME: &str = "view-function-writes-storage";

/// Default getter name patterns.
const DEFAULT_PATTERNS: &[&str] = &[
    "get_*",
    "balance",
    "total_supply",
    "is_*",
    "view_*",
    "*_of",
];

/// Check that flags getter-like functions which mutate contract storage.
pub struct ViewFunctionWritesStorageCheck {
    patterns: Vec<String>,
}

impl Default for ViewFunctionWritesStorageCheck {
    fn default() -> Self {
        Self::new()
    }
}

impl ViewFunctionWritesStorageCheck {
    /// Create a check with the default getter patterns.
    pub fn new() -> Self {
        Self {
            patterns: DEFAULT_PATTERNS.iter().map(|s| s.to_string()).collect(),
        }
    }

    /// Create a check with a custom set of getter patterns.
    ///
    /// Patterns support a single `*` wildcard, either as a prefix
    /// (`get_*`) or a suffix (`*_of`).
    pub fn with_patterns<I, S>(patterns: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            patterns: patterns.into_iter().map(Into::into).collect(),
        }
    }

    fn is_getter_name(&self, name: &str) -> bool {
        self.patterns.iter().any(|pat| matches_pattern(pat, name))
    }
}

/// Match `name` against a pattern containing at most one `*` wildcard.
fn matches_pattern(pattern: &str, name: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix('*') {
        name.starts_with(prefix)
    } else if let Some(suffix) = pattern.strip_prefix('*') {
        name.ends_with(suffix)
    } else {
        pattern == name
    }
}

/// Returns true if the call name is a pure TTL extension helper.
fn is_ttl_only_call(name: &str) -> bool {
    let last = name.rsplit("::").next().unwrap_or(name);
    last == "extend_ttl" || last == "bump"
}

impl Check for ViewFunctionWritesStorageCheck {
    fn name(&self) -> &str {
        NAME
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn description(&self) -> &str {
        "Getter-like function mutates contract storage"
    }

    fn check(&self, ctx: &CheckContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        for item in &ctx.ast.items {
            let Item::Impl(impl_block) = item else {
                continue;
            };
            if !util::has_contractimpl_attr(&impl_block.attrs) {
                continue;
            }

            for func in util::contractimpl_functions_excluding_test(impl_block) {
                let ImplItem::Fn(method) = func else {
                    continue;
                };
                let name = method.sig.ident.to_string();
                if !self.is_getter_name(&name) {
                    continue;
                }

                let mut has_mutation = false;
                let mut has_non_ttl_mutation = false;

                for call in util::collect_call_names(&method.block) {
                    if !util::is_storage_mutation_call(&call) {
                        continue;
                    }
                    has_mutation = true;
                    if !is_ttl_only_call(&call) {
                        has_non_ttl_mutation = true;
                        break;
                    }
                }

                if !has_mutation || !has_non_ttl_mutation {
                    continue;
                }

                let span = method.sig.ident.span();
                findings.push(Finding {
                    check: NAME.to_string(),
                    severity: Severity::Low,
                    message: format!(
                        "Getter-like function `{name}` mutates contract storage"
                    ),
                    description: "Getter-like functions are assumed to be side-effect \
                        free by clients and other contracts. A getter that writes \
                        storage can make read-only simulations diverge from real \
                        execution."
                        .to_string(),
                    suggestion: format!(
                        "Remove the storage mutation from `{name}`, or rename it to \
                        reflect that it mutates state."
                    ),
                    file: ctx.file.to_string(),
                    line: util::line_of(span),
                    column: util::column_of(span),
                    rule_url: Some(
                        "docs/checks.md#view-function-writes-storage-low".to_string(),
                    ),
                });
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::run_check;

    #[test]
    fn flags_getter_with_set() {
        let src = r#"
            #[contractimpl]
            impl Contract {
                pub fn get_balance(env: Env) -> i128 {
                    let v = env.storage().persistent().get(&DataKey::Balance).unwrap_or(0);
                    env.storage().persistent().set(&DataKey::Balance, &(v + 1));
                    v
                }
            }
        "#;
        let findings = run_check(&ViewFunctionWritesStorageCheck::new(), src);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("get_balance"));
    }

    #[test]
    fn does_not_flag_getter_with_only_extend_ttl() {
        let src = r#"
            #[contractimpl]
            impl Contract {
                pub fn get_balance(env: Env) -> i128 {
                    let key = DataKey::Balance;
                    let v = env.storage().persistent().get(&key).unwrap_or(0);
                    env.storage().persistent().extend_ttl(&key, 100, 200);
                    v
                }
            }
        "#;
        let findings = run_check(&ViewFunctionWritesStorageCheck::new(), src);
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_flag_non_getter_writer() {
        let src = r#"
            #[contractimpl]
            impl Contract {
                pub fn deposit(env: Env, amount: i128) {
                    env.storage().persistent().set(&DataKey::Balance, &amount);
                }
            }
        "#;
        let findings = run_check(&ViewFunctionWritesStorageCheck::new(), src);
        assert!(findings.is_empty());
    }
}