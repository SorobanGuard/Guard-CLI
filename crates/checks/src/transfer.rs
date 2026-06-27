//! Token transfer functions that do not guard against `from == to`.
//!
//! Fee-on-transfer and rebasing token designs can be exploited when a transfer sender and
//! recipient are the same address. This heuristic flags `#[contractimpl]` methods whose
//! name contains "transfer" and whose body lacks an explicit sender-recipient comparison.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{BinOp, Expr, ExprBinary, File};

const CHECK_NAME: &str = "self-transfer";

/// Methods named like `transfer`, `transfer_from`, `safe_transfer`, etc. whose body does
/// **not** compare sender-like and recipient-like parameters (e.g., `from != to`).
pub struct SelfTransferCheck;

impl Check for SelfTransferCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            if !fn_name.contains("transfer") {
                continue;
            }
            if body_has_sender_recipient_guard(&method.block) {
                continue;
            }
            let line = method.sig.fn_token.span().start().line;
            out.push(Finding {
                check_name: CHECK_NAME.to_string(),
                severity: Severity::Low,
                file_path: String::new(),
                line,
                function_name: fn_name.clone(),
                description: format!(
                    "Method `{fn_name}` is named like a token transfer but does not appear \
                     to guard against `from == to`. In fee-on-transfer or rebasing designs, \
                     self-transfers can artificially inflate volume or extract fees."
                ),
                rule_url: None,
                suggestion: None,
            });
        }
        out
    }
}

/// Returns true if the method body contains a comparison (`!=` or `==`) between identifiers
/// that look like a sender/from and a recipient/to.
fn body_has_sender_recipient_guard(block: &syn::Block) -> bool {
    let mut v = GuardScan::default();
    v.visit_block(block);
    v.found
}

#[derive(Default)]
struct GuardScan {
    found: bool,
}

fn collect_idents(expr: &Expr) -> Vec<String> {
    let mut out = Vec::new();
    collect_idents_rec(expr, &mut out);
    out
}

fn collect_idents_rec(expr: &Expr, acc: &mut Vec<String>) {
    match expr {
        Expr::Path(p) => {
            if let Some(ident) = p.path.get_ident() {
                acc.push(ident.to_string());
            }
        }
        Expr::MethodCall(m) => {
            collect_idents_rec(&m.receiver, acc);
            acc.push(m.method.to_string());
        }
        Expr::Field(f) => collect_idents_rec(&f.base, acc),
        Expr::Call(c) => collect_idents_rec(&c.func, acc),
        Expr::Paren(p) => collect_idents_rec(&p.expr, acc),
        Expr::Unary(u) => collect_idents_rec(&u.expr, acc),
        _ => {}
    }
}

impl<'ast> Visit<'ast> for GuardScan {
    fn visit_expr_binary(&mut self, i: &'ast ExprBinary) {
        if self.found {
            return;
        }
        if matches!(i.op, BinOp::Ne(_) | BinOp::Eq(_)) {
            let left_idents = collect_idents(&i.left);
            let right_idents = collect_idents(&i.right);

            let from_keys = ["from", "sender", "source", "spender"];
            let to_keys = ["to", "recipient", "dest", "destination"];

            let left_is_from = left_idents.iter().any(|id| from_keys.contains(&id.as_str()));
            let left_is_to = left_idents.iter().any(|id| to_keys.contains(&id.as_str()));
            let right_is_from = right_idents.iter().any(|id| from_keys.contains(&id.as_str()));
            let right_is_to = right_idents.iter().any(|id| to_keys.contains(&id.as_str()));

            if (left_is_from && right_is_to) || (left_is_to && right_is_from) {
                self.found = true;
                return;
            }
        }
        visit::visit_expr_binary(self, i);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Check;
    use syn::parse_file;

    #[test]
    fn flags_transfer_without_guard() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Address, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        from.require_auth();
        let _ = (env, amount);
    }
}
"#,
        )?;
        let hits = SelfTransferCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].function_name, "transfer");
        Ok(())
    }

    #[test]
    fn passes_transfer_with_from_ne_to() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Address, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        if from != to {
            from.require_auth();
            let _ = (env, amount);
        }
    }
}
"#,
        )?;
        let hits = SelfTransferCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn passes_transfer_with_from_eq_to_panic() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Address, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        if from == to {
            panic!("self-transfer");
        }
        from.require_auth();
        let _ = (env, amount);
    }
}
"#,
        )?;
        let hits = SelfTransferCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn ignores_non_transfer_fn() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn do_thing(env: Env) {
        let _ = env;
    }
}
"#,
        )?;
        let hits = SelfTransferCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn flags_transfer_from_without_guard() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Address, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn transfer_from(env: Env, spender: Address, from: Address, to: Address, amount: i128) {
        spender.require_auth();
        let _ = (env, from, to, amount);
    }
}
"#,
        )?;
        let hits = SelfTransferCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].function_name, "transfer_from");
        Ok(())
    }
}
