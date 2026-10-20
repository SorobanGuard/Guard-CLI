//! Token transfer functions that do not guard against `from == to`.
//!
//! Fee-on-transfer and rebasing token designs can be exploited when a transfer sender and
//! recipient are the same address. This heuristic flags `#[contractimpl]` methods whose
//! name contains "transfer" and whose body lacks an explicit sender-recipient comparison.

use crate::util::contractimpl_functions_excluding_test;
use crate::{Check, Finding, Severity};
use proc_macro2::TokenTree;
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
        for method in contractimpl_functions_excluding_test(file) {
            let fn_name = method.sig.ident.to_string();
            if !is_transfer_like_name(&fn_name) {
                continue;
            }
            if body_has_sender_recipient_guard(&method.block) {
                continue;
            }
            let line = method.sig.fn_token.span().start().line;
            out.push(Finding {
                check_name: CHECK_NAME.to_string(),
                severity: Severity::Medium,
                file_path: String::new(),
                line,
                function_name: fn_name.clone(),
                description: format!(
                    "Method `{fn_name}` is named like a token transfer but does not appear \
                     to guard against `from == to`. In fee-on-transfer or rebasing designs, \
                     self-transfers can artificially inflate volume or extract fees."
                ),
                rule_url: Some(
                    "https://github.com/SorobanGuard/Guard-CLI/blob/main/docs/checks.md#self-transfer-medium"
                        .to_string(),
                ),
                suggestion: Some(format!(
                    "Add a guard at the top of `{fn_name}`: \
                     `if from == to {{ return; }}` (or panic) to prevent self-transfers."
                )),
            column: None,
            end_line: None,
            end_column: None,
            });
        }
        out
    }
}

/// Ownership/admin handovers share the `transfer_` prefix but move no tokens and
/// have no `from`/`to` pair to compare.
const NON_TOKEN_TRANSFER_NAMES: &[&str] = &[
    "transfer_ownership",
    "transfer_admin",
    "transfer_admin_role",
    "transfer_authority",
    "transfer_role",
];

fn is_transfer_like_name(name: &str) -> bool {
    if NON_TOKEN_TRANSFER_NAMES.contains(&name) {
        return false;
    }
    name == "transfer"
        || name.starts_with("transfer_")
        || name.starts_with("safe_transfer")
        || name.ends_with("_transfer")
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
    /// True while visiting the condition of an `if`/`while` or an argument of
    /// `assert!`/`require!`/`panic!` — i.e. a position that can actually gate execution.
    guard_ctx: bool,
}

const FROM_KEYS: &[&str] = &["from", "sender", "source", "spender"];
const TO_KEYS: &[&str] = &["to", "recipient", "dest", "destination"];

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
        // Field access (`tx.from`, `self.to`, ...): the field name itself is what carries
        // sender/recipient meaning, so collect it as well as walking into the base.
        Expr::Field(f) => {
            if let syn::Member::Named(name) = &f.member {
                acc.push(name.to_string());
            }
            collect_idents_rec(&f.base, acc);
        }
        Expr::Call(c) => collect_idents_rec(&c.func, acc),
        Expr::Paren(p) => collect_idents_rec(&p.expr, acc),
        Expr::Unary(u) => collect_idents_rec(&u.expr, acc),
        Expr::Reference(r) => collect_idents_rec(&r.expr, acc),
        _ => {}
    }
}

/// True if any collected identifier matches one of `keys`, either exactly or as an
/// underscore-delimited word (so `from_addr`/`tx.from`/`to_addr` match `from`/`to` while
/// unrelated identifiers like `token` do not).
fn idents_match_any(idents: &[String], keys: &[&str]) -> bool {
    idents.iter().any(|id| {
        let lower = id.to_lowercase();
        lower.split('_').any(|word| keys.contains(&word))
    })
}

/// Does the pair of expressions read like a sender/recipient comparison (in either order)?
fn is_sender_recipient_pair(left: &Expr, right: &Expr) -> bool {
    let left_idents = collect_idents(left);
    let right_idents = collect_idents(right);

    let left_is_from = idents_match_any(&left_idents, FROM_KEYS);
    let left_is_to = idents_match_any(&left_idents, TO_KEYS);
    let right_is_from = idents_match_any(&right_idents, FROM_KEYS);
    let right_is_to = idents_match_any(&right_idents, TO_KEYS);

    (left_is_from && right_is_to) || (left_is_to && right_is_from)
}

impl<'ast> Visit<'ast> for GuardScan {
    fn visit_expr_if(&mut self, i: &'ast syn::ExprIf) {
        let prev = self.guard_ctx;
        self.guard_ctx = true;
        self.visit_expr(&i.cond);
        self.guard_ctx = prev;
        self.visit_block(&i.then_branch);
        if let Some((_, els)) = &i.else_branch {
            self.visit_expr(els);
        }
    }

    fn visit_expr_while(&mut self, i: &'ast syn::ExprWhile) {
        let prev = self.guard_ctx;
        self.guard_ctx = true;
        self.visit_expr(&i.cond);
        self.guard_ctx = prev;
        self.visit_block(&i.body);
    }

    fn visit_macro(&mut self, i: &'ast syn::Macro) {
        let name = i
            .path
            .segments
            .last()
            .map(|s| s.ident.to_string())
            .unwrap_or_default();
        if matches!(name.as_str(), "assert" | "require" | "panic") {
            if let Some(expr) = first_macro_arg(&i.tokens) {
                let prev = self.guard_ctx;
                self.guard_ctx = true;
                self.visit_expr(&expr);
                self.guard_ctx = prev;
            }
        }
        visit::visit_macro(self, i);
    }

    fn visit_expr_binary(&mut self, i: &'ast ExprBinary) {
        if self.found || !self.guard_ctx {
            return;
        }
        if matches!(i.op, BinOp::Ne(_) | BinOp::Eq(_))
            && is_sender_recipient_pair(&i.left, &i.right)
        {
            self.found = true;
            return;
        }
        visit::visit_expr_binary(self, i);
    }

    fn visit_expr_method_call(&mut self, i: &'ast syn::ExprMethodCall) {
        if self.found || !self.guard_ctx {
            return;
        }
        let method = i.method.to_string();
        if matches!(method.as_str(), "ne" | "eq") {
            if let Some(arg) = i.args.first() {
                if i.args.len() == 1 && is_sender_recipient_pair(&i.receiver, arg) {
                    self.found = true;
                    return;
                }
            }
        }
        visit::visit_expr_method_call(self, i);
    }
}

/// Extract the first argument of an `assert!`/`require!`/`panic!` macro (everything up to the
/// first top-level comma) as an expression so its embedded comparison can be inspected.
fn first_macro_arg(tokens: &proc_macro2::TokenStream) -> Option<syn::Expr> {
    // Unwrap a single enclosing group such as `( ... )`.
    let inner = if let Some(TokenTree::Group(g)) = tokens.clone().into_iter().next() {
        if tokens.clone().into_iter().count() == 1 {
            g.stream()
        } else {
            tokens.clone()
        }
    } else {
        tokens.clone()
    };
    let mut buf = proc_macro2::TokenStream::new();
    let mut depth = 0i32;
    for tt in inner {
        match &tt {
            TokenTree::Punct(p) if p.as_char() == ',' && depth == 0 => break,
            TokenTree::Group(_) => {
                depth += 1;
                buf.extend(std::iter::once(tt));
                depth -= 1;
            }
            _ => buf.extend(std::iter::once(tt)),
        }
    }
    syn::parse2::<syn::Expr>(buf).ok()
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
        assert_eq!(hits[0].severity, Severity::Medium);
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

    #[test]
    fn passes_transfer_with_from_addr_ne_to_addr() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Address, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn transfer(env: Env, from_addr: Address, to_addr: Address, amount: i128) {
        if from_addr != to_addr {
            from_addr.require_auth();
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
    fn passes_transfer_with_from_ne_method_call() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Address, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        if from.ne(&to) {
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
    fn passes_transfer_with_field_access_guard() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Address, Env};

pub struct Tx {
    from: Address,
    to: Address,
}

pub struct C;

#[contractimpl]
impl C {
    pub fn transfer(env: Env, tx: Tx, amount: i128) {
        if tx.from != tx.to {
            tx.from.require_auth();
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
    fn flags_noop_comparison_that_does_not_gate_transfer() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Address, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        from.require_auth();
        let _unused = from == to;
        do_actual_transfer(&env, &from, &to, amount);
    }
}
"#,
        )?;
        let hits = SelfTransferCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        Ok(())
    }

    #[test]
    fn ignores_transfer_ownership() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Address, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn transfer_ownership(env: Env, new_owner: Address) {
        let _ = (env, new_owner);
    }
}
"#,
        )?;
        let hits = SelfTransferCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn flags_transfer_without_guard_still() -> Result<(), syn::Error> {
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
}
