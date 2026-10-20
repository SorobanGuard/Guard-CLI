//! Admin-gated functions that transfer the contract's entire token balance.

use crate::util::contractimpl_functions_excluding_test;
use crate::{Check, Finding, Severity};
use quote::ToTokens;
use std::collections::HashSet;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{ExprMethodCall, File, Local, Pat};

const CHECK_NAME: &str = "admin-unrestricted-withdraw";

/// Flags a function whose body mentions an admin and calls `transfer` with an amount read from
/// the contract's own balance (`balance(&env.current_contract_address())`), directly or through
/// one local. Such a function can sweep everything the contract holds. It is reported at Low
/// severity so a reviewer can decide whether a timelock or limit is needed.
pub struct AdminSweepCheck;

impl Check for AdminSweepCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions_excluding_test(file) {
            let fn_name = method.sig.ident.to_string();
            let body = method.block.to_token_stream().to_string().to_lowercase();
            if !body.contains("admin") {
                continue;
            }

            let mut v = SweepVisitor {
                balance_locals: HashSet::new(),
                sweep_line: None,
            };
            v.visit_block(&method.block);

            if let Some(line) = v.sweep_line {
                out.push(Finding {
                    check_name: CHECK_NAME.to_string(),
                    severity: Severity::Low,
                    file_path: String::new(),
                    line,
                    function_name: fn_name.clone(),
                    description: format!(
                        "Admin-gated function `{fn_name}` transfers the contract's entire token \
                         balance. A single privileged key can empty the contract."
                    ),
                    rule_url: Some(
                        "https://github.com/SorobanGuard/Guard-CLI/blob/main/docs/checks.md#admin-unrestricted-withdraw-low"
                            .to_string(),
                    ),
                    suggestion: Some(
                        "Cap the amount withdrawn per call, or add a timelock to large withdrawals."
                            .to_string(),
                    ),
                });
            }
        }
        out
    }
}

/// True when `word` appears in `text` as a whole identifier, not as part of a longer name.
fn mentions_word(text: &str, word: &str) -> bool {
    text.split(|c: char| !c.is_alphanumeric() && c != '_').any(|w| w == word)
}

/// True when the tokens mention the contract's own balance.
fn reads_own_balance(text: &str) -> bool {
    text.contains("balance") && text.contains("current_contract_address")
}

struct SweepVisitor {
    /// Locals whose initialiser reads the contract's own balance.
    balance_locals: HashSet<String>,
    sweep_line: Option<usize>,
}

impl Visit<'_> for SweepVisitor {
    fn visit_local(&mut self, local: &Local) {
        if let (Pat::Ident(pat), Some(init)) = (&local.pat, &local.init) {
            if reads_own_balance(&init.expr.to_token_stream().to_string()) {
                self.balance_locals.insert(pat.ident.to_string());
            }
        }
        visit::visit_local(self, local);
    }

    fn visit_expr_method_call(&mut self, i: &ExprMethodCall) {
        if i.method == "transfer" && self.sweep_line.is_none() {
            let sweeps = i.args.iter().any(|arg| {
                let text = arg.to_token_stream().to_string();
                reads_own_balance(&text) || self.balance_locals.iter().any(|name| mentions_word(&text, name))
            });
            if sweeps {
                self.sweep_line = Some(i.span().start().line);
            }
        }
        visit::visit_expr_method_call(self, i);
    }
}
