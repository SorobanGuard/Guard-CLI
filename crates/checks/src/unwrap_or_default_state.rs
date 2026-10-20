//! Storage reads of state-like keys that silently fall back to a default value.

use crate::util::contractimpl_functions_excluding_test;
use crate::{Check, Finding, Severity};
use quote::ToTokens;
use std::collections::HashSet;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, File};

const CHECK_NAME: &str = "unwrap-or-default-on-state-read";

/// Words that mark a storage key as holding state an uninitialised read would hide.
const STATE_WORDS: &[&str] = &["balance", "supply", "counter", "nonce", "fee", "total", "config", "admin", "count"];

/// Flags `storage().<tier>().get(&key).unwrap_or(<default>)` and `.unwrap_or_default()` when the
/// key looks like a balance, supply, counter or config value. A missing entry then becomes a
/// zero or default value without any error. A read gated by `.has(&key)` in the same function
/// is not flagged.
pub struct UnwrapOrDefaultStateReadCheck;

impl Check for UnwrapOrDefaultStateReadCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions_excluding_test(file) {
            let fn_name = method.sig.ident.to_string();
            let mut v = ReadVisitor {
                has_keys: HashSet::new(),
                reads: Vec::new(),
            };
            v.visit_block(&method.block);

            for (key, line) in v.reads {
                if v.has_keys.contains(&key) {
                    continue;
                }
                out.push(Finding {
                    check_name: CHECK_NAME.to_string(),
                    severity: Severity::Low,
                    file_path: String::new(),
                    line,
                    function_name: fn_name.clone(),
                    description: format!(
                        "Function `{fn_name}` reads a state key from storage with a default value. \
                         If the entry was never written, the default is used silently, and later \
                         arithmetic or comparisons run on a value that was never set."
                    ),
                    rule_url: Some(
                        "https://github.com/SorobanGuard/Guard-CLI/blob/main/docs/checks.md#unwrap-or-default-on-state-read-low"
                            .to_string(),
                    ),
                    suggestion: Some(
                        "Read with `.get(&key).ok_or(Error::NotInitialized)?`, or check `.has(&key)` first."
                            .to_string(),
                    ),
                });
            }
        }
        out
    }
}

fn is_storage_chain(m: &ExprMethodCall) -> bool {
    m.receiver.to_token_stream().to_string().contains("storage")
}

fn looks_like_state(key: &str) -> bool {
    let lower = key.to_lowercase();
    STATE_WORDS.iter().any(|word| lower.contains(word))
}

struct ReadVisitor {
    /// Key texts guarded by a `.has(..)` call in this function.
    has_keys: HashSet<String>,
    /// `(key text, line)` for defaulted reads of state-like keys.
    reads: Vec<(String, usize)>,
}

impl Visit<'_> for ReadVisitor {
    fn visit_expr_method_call(&mut self, i: &ExprMethodCall) {
        let name = i.method.to_string();

        if name == "has" && is_storage_chain(i) {
            if let Some(key) = i.args.first() {
                self.has_keys.insert(key.to_token_stream().to_string());
            }
        }

        let defaulted = matches!(name.as_str(), "unwrap_or" | "unwrap_or_default");
        if defaulted {
            if let Expr::MethodCall(get) = &*i.receiver {
                if get.method == "get" && is_storage_chain(get) {
                    if let Some(key) = get.args.first() {
                        let key_text = key.to_token_stream().to_string();
                        if looks_like_state(&key_text) {
                            self.reads.push((key_text, i.span().start().line));
                        }
                    }
                }
            }
        }

        visit::visit_expr_method_call(self, i);
    }
}
