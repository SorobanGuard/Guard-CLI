//! Flags token `transfer`/`transfer_from` calls in `#[contractimpl]` methods that lack
//! a preceding `balance()` or `authorized()` check.
//!
//! Calls are qualified by receiver: only `transfer` / `balance` / `authorized` invoked on
//! a local binding initialised from `token::Client::new(...)` (or `TokenClient::new(...)`)
//! count. A same-named method on an unrelated type (`self.ownership.transfer(...)`,
//! `self.ledger.balance()`) is ignored, in either direction.

use crate::util::contractimpl_functions_excluding_test;
use crate::{Check, Finding, Severity};
use std::collections::HashSet;
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, File, Item, Pat, Stmt};

const CHECK_NAME: &str = "missing-balance-check";

pub struct MissingBalanceCheck;

impl Check for MissingBalanceCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        let token_client_aliases = collect_token_client_aliases(file);
        for method in contractimpl_functions_excluding_test(file) {
            let fn_name = method.sig.ident.to_string();
            let mut scan = BodyScan {
                token_client_aliases: token_client_aliases.clone(),
                ..Default::default()
            };
            scan.visit_block(&method.block);

            let mut transfers = scan.transfers;
            transfers.sort_unstable();
            let mut balances = scan.balances;
            balances.sort_unstable();

            // Evaluate each transfer call site independently: a finding is emitted for
            // every transfer that has no balance()/authorized() call between the previous
            // transfer (exclusive) and this one (exclusive). A single check at the function
            // top does not "cover" every subsequent transfer because each transfer changes
            // the balance. Positions are `(line, column)` so a balance and a transfer on the
            // same source line are still ordered correctly.
            let mut prev_transfer: (usize, usize) = (0, 0);
            for &transfer_pos in &transfers {
                let guarded = balances
                    .iter()
                    .any(|&bal| bal > prev_transfer && bal < transfer_pos);
                if !guarded {
                    out.push(Finding {
                        check_name: CHECK_NAME.to_string(),
                        severity: Severity::High,
                        file_path: String::new(),
                        line: transfer_pos.0,
                        function_name: fn_name.clone(),
                        description: format!(
                            "Function `{fn_name}` calls `transfer` or `transfer_from` without a \
                             preceding `balance()` or `authorized()` check. An invalid transfer may \
                             cause a runtime panic that disrupts multi-step atomic operations."
                        ),
                        rule_url: Some(
                            "https://github.com/SorobanGuard/Guard-CLI/blob/main/docs/checks.md#missing-balance-check-high"
                                .to_string(),
                        ),
                        suggestion: Some(
                            "Call `token_client.balance(&sender)` before transferring and verify \
                             the sender holds sufficient funds."
                                .to_string(),
                        ),
                    });
                }
                prev_transfer = transfer_pos;
            }
        }
        out
    }
}

/// Accumulates the `(line, column)` position of every token-client `transfer`/`transfer_from`
/// call and every token-client `balance`/`authorized` call in a function body. Per-call-site
/// evaluation is done in the caller after the walk finishes.
///
/// Scoping is handled with a stack of `HashSet<String>` frames — one frame per block nesting
/// level. When a nested block introduces a `let` that shadows an outer token-client binding
/// with a non-token-client value, only the innermost frame is affected. Once the block exits,
/// the outer frame (and its token-client binding) is restored automatically, matching Rust's
/// actual lexical scoping rules.
#[derive(Default)]
struct BodyScan {
    /// Scope stack: each entry holds the set of token-client binding names that are
    /// *newly introduced* at that nesting level. The outermost frame (index 0) corresponds
    /// to the function body block; nested blocks push additional frames. A name is
    /// considered a live token-client binding if it appears in *any* frame on the stack.
    scope_stack: Vec<HashSet<String>>,
    /// Alias idents (`Tok`) that map to `Client` / `TokenClient` via `use ... as`.
    token_client_aliases: HashSet<String>,
    transfers: Vec<(usize, usize)>,
    balances: Vec<(usize, usize)>,
}

impl BodyScan {
    /// Returns `true` if `name` is currently tracked as a token-client binding in any
    /// live scope frame.
    fn is_token_binding(&self, name: &str) -> bool {
        self.scope_stack.iter().any(|frame| frame.contains(name))
    }

    /// Records a `let` binding at the current (innermost) scope level. If `is_token` is
    /// `true`, inserts `name`; otherwise removes it from the current frame (shadowing).
    /// Bindings in outer frames are not affected, preserving them for when the inner
    /// block exits.
    fn record_binding(&mut self, name: String, is_token: bool) {
        let frame = self
            .scope_stack
            .last_mut()
            .expect("scope_stack must be non-empty during a visit");
        if is_token {
            frame.insert(name);
        } else {
            // Remove from the current frame only. An outer frame may still hold the name
            // if it was introduced there — that outer binding will become visible again
            // after this inner frame is popped.
            frame.remove(&name);
        }
    }
}

impl<'ast> Visit<'ast> for BodyScan {
    fn visit_block(&mut self, block: &'ast syn::Block) {
        // Push a fresh scope frame before descending into any block so that `let`
        // bindings (and shadows) inside are isolated from outer frames.
        self.scope_stack.push(HashSet::new());
        visit::visit_block(self, block);
        self.scope_stack.pop();
    }

    fn visit_stmt(&mut self, stmt: &'ast Stmt) {
        // Collect token-client bindings in source order so later calls resolve against
        // them. Re-binding the same name to something else removes it from the *current*
        // frame only, leaving outer frames (and their token-client entries) intact.
        if let Stmt::Local(local) = stmt {
            if let (Some(name), Some(init)) = (binding_ident(&local.pat), &local.init) {
                let is_token =
                    expr_is_token_client_ctor(&init.expr, &self.token_client_aliases);
                self.record_binding(name, is_token);
            }
        }
        visit::visit_stmt(self, stmt);
    }

    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        let method = i.method.to_string();
        let on_token_client = ident_of(&i.receiver)
            .map(|r| self.is_token_binding(&r))
            .unwrap_or(false);
        if on_token_client {
            let start = i.method.span().start();
            let pos = (start.line, start.column);
            match method.as_str() {
                "transfer" | "transfer_from" => self.transfers.push(pos),
                "balance" | "authorized" => self.balances.push(pos),
                _ => {}
            }
        }
        visit::visit_expr_method_call(self, i);
    }
}

/// Name bound by a `let` pattern, digging through an explicit type annotation.
fn binding_ident(pat: &Pat) -> Option<String> {
    match pat {
        Pat::Ident(pi) => Some(pi.ident.to_string()),
        Pat::Type(pt) => binding_ident(&pt.pat),
        _ => None,
    }
}

/// Identifier behind a plain path (`x`) or a reference to one (`&x`, `&mut x`).
fn ident_of(e: &Expr) -> Option<String> {
    match e {
        Expr::Reference(r) => ident_of(&r.expr),
        Expr::Path(p) => p.path.get_ident().map(|i| i.to_string()),
        _ => None,
    }
}

/// Collect every `use ...::Client as X` / `use ...::TokenClient as X` alias so a renamed
/// token-client type (`Tok::new(...)`) is still recognised as a token-client constructor.
fn collect_token_client_aliases(file: &File) -> HashSet<String> {
    let mut aliases = HashSet::new();
    for item in &file.items {
        if let Item::Use(use_item) = item {
            collect_aliases_from_use_tree(&use_item.tree, &mut aliases);
        }
    }
    aliases
}

/// `syn::UseTree` is an enum (`Path`/`Name`/`Rename`/`Glob`/`Group`), not a
/// struct with `rename`/`prefix`/`group` fields — those don't exist. A
/// renamed import (`use a::b::TokenClient as Tc;`) parses as nested `Path`
/// nodes (`a`, then `b`) wrapping a terminal `Rename` node holding the
/// original name (`ident`, here `TokenClient`) and the new one (`rename`,
/// `Tc`); a group (`use a::{X, Y as Z};`) parses as a `Group` of `UseTree`s,
/// each needing the same walk.
fn collect_aliases_from_use_tree(tree: &syn::UseTree, out: &mut HashSet<String>) {
    match tree {
        syn::UseTree::Rename(rename) => {
            if rename.ident == "Client" || rename.ident == "TokenClient" {
                out.insert(rename.rename.to_string());
            }
        }
        syn::UseTree::Path(path) => collect_aliases_from_use_tree(&path.tree, out),
        syn::UseTree::Group(group) => {
            for nested in &group.items {
                collect_aliases_from_use_tree(nested, out);
            }
        }
        syn::UseTree::Name(_) | syn::UseTree::Glob(_) => {}
    }
}

/// Is `expr` a call to `token::Client::new(...)`, `TokenClient::new(...)`, an aliased client
/// type (`Tok::new(...)` where `Tok` aliases `Client`/`TokenClient`), or any path ending in
/// `Client::new` / `TokenClient::new`? Also looks through a leading `&`.
fn expr_is_token_client_ctor(expr: &Expr, aliases: &HashSet<String>) -> bool {
    match expr {
        Expr::Reference(r) => expr_is_token_client_ctor(&r.expr, aliases),
        Expr::Call(call) => {
            let Expr::Path(p) = &*call.func else {
                return false;
            };
            let segs = &p.path.segments;
            let n = segs.len();
            if n < 2 || segs[n - 1].ident != "new" {
                return false;
            }
            let ty = &segs[n - 2].ident;
            ty == "Client" || ty == "TokenClient" || aliases.contains(&ty.to_string())
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_file;

    // Helper: run the check and collect the reported line numbers.
    fn finding_lines(src: &str) -> Vec<usize> {
        let file = parse_file(src).unwrap();
        let mut hits = MissingBalanceCheck.run(&file, "");
        hits.sort_by_key(|f| f.line);
        hits.into_iter().map(|f| f.line).collect()
    }

    #[test]
    fn no_finding_when_balance_check_precedes_transfer() {
        let src = r#"
#[contractimpl]
impl Token {
    pub fn send(env: Env) {
        let token = token::Client::new(&env, &id);
        let bal = token.balance(&sender);
        token.transfer(&sender, &recv, &amount);
    }
}
"#;
        assert!(finding_lines(src).is_empty());
    }

    #[test]
    fn finding_when_no_balance_check() {
        let src = r#"
#[contractimpl]
impl Token {
    pub fn send(env: Env) {
        let token = token::Client::new(&env, &id);
        token.transfer(&sender, &recv, &amount);
    }
}
"#;
        assert_eq!(finding_lines(src).len(), 1);
    }

    /// Regression test for #364: two transfers in one function, only the first
    /// is balance-guarded.  A finding must be emitted for the second transfer.
    #[test]
    fn second_unguarded_transfer_is_flagged_when_first_is_guarded() {
        let src = r#"
#[contractimpl]
impl Token {
    pub fn double_send(env: Env) {
        let token = token::Client::new(&env, &id);

        // First transfer: guarded — should NOT produce a finding.
        let bal = token.balance(&sender);
        token.transfer(&sender, &recv, &amount);

        // Second transfer: no balance check before it — MUST produce a finding.
        token.transfer(&sender, &recv2, &amount2);
    }
}
"#;
        let lines = finding_lines(src);
        assert_eq!(
            lines.len(),
            1,
            "only the second (unguarded) transfer should be flagged; got lines: {lines:?}"
        );
    }

    /// Both transfers unguarded → two findings.
    #[test]
    fn both_unguarded_transfers_flagged() {
        let src = r#"
#[contractimpl]
impl Token {
    pub fn double_send(env: Env) {
        let token = token::Client::new(&env, &id);
        token.transfer(&sender, &recv, &amount);
        token.transfer(&sender, &recv2, &amount2);
    }
}
"#;
        let lines = finding_lines(src);
        assert_eq!(
            lines.len(),
            2,
            "both unguarded transfers should be flagged; got lines: {lines:?}"
        );
    }

    /// #403 false positive: a non-token `transfer` method on an unrelated type.
    #[test]
    fn ignores_transfer_on_non_token_receiver() {
        let src = r#"
#[contractimpl]
impl C {
    pub fn transfer_ownership(env: Env, new_owner: Address) {
        self.ownership.transfer(&new_owner);
    }
}
"#;
        assert!(finding_lines(src).is_empty());
    }

    /// #403 false negative: an unrelated `.balance()` must not silence a real finding.
    #[test]
    fn unrelated_balance_does_not_suppress_finding() {
        let src = r#"
#[contractimpl]
impl C {
    pub fn payout(env: Env, to: Address, amount: i128) {
        let token = token::Client::new(&env, &id);
        let _ = self.ledger.balance();
        token.transfer(&from, &to, &amount);
    }
}
"#;
        assert_eq!(finding_lines(src).len(), 1);
    }

    /// #403 precision: a balance check and the transfer on the same source line.
    #[test]
    fn same_line_balance_check_counts_as_preceding() {
        let src = r#"
#[contractimpl]
impl C {
    pub fn send(env: Env) {
        let token = token::Client::new(&env, &id);
        if token.balance(&sender) >= amount { token.transfer(&sender, &recv, &amount); }
    }
}
"#;
        assert!(finding_lines(src).is_empty());
    }

    #[test]
    fn recognizes_aliased_token_client_import() {
        // #515: `use soroban_sdk::token::Client as Tok; Tok::new(...)` must be
        // recognised as a token-client constructor so transfers are balance-checked.
        let src = r#"
use soroban_sdk::token::Client as Tok;

#[contractimpl]
impl C {
    pub fn send(env: Env) {
        let token = Tok::new(&env, &id);
        token.transfer(&sender, &recv, &amount);
    }
}
"#;
        assert_eq!(finding_lines(src).len(), 1);
    }

    #[test]
    fn collects_a_direct_alias() -> Result<(), syn::Error> {
        let file = syn::parse_file("use soroban_sdk::token::TokenClient as Tc;")?;
        let aliases = collect_token_client_aliases(&file);
        assert_eq!(aliases, HashSet::from(["Tc".to_string()]));
        Ok(())
    }

    #[test]
    fn collects_a_grouped_alias() -> Result<(), syn::Error> {
        let file = syn::parse_file("use soroban_sdk::token::{Client as C, StellarAssetClient};")?;
        let aliases = collect_token_client_aliases(&file);
        // `Client as C` is aliased and collected; `StellarAssetClient` has no
        // rename at all, so it contributes nothing (it's a `Name`, not a
        // `Rename`) — the group must not be mistaken for one big rename.
        assert_eq!(aliases, HashSet::from(["C".to_string()]));
        Ok(())
    }

    #[test]
    fn a_non_client_rename_is_not_collected() -> Result<(), syn::Error> {
        let file = syn::parse_file("use soroban_sdk::Address as Addr;")?;
        assert!(collect_token_client_aliases(&file).is_empty());
        Ok(())
    }

    /// Regression test for #683: a nested-block shadow of a token-client binding to a
    /// non-token-client value must not permanently remove the outer binding from tracking.
    /// After the inner block exits, the outer `token` binding must still be live, so an
    /// unguarded `transfer` call on it after the block must still be flagged.
    #[test]
    fn nested_block_shadow_does_not_suppress_outer_token_binding() {
        let src = r#"
#[contractimpl]
impl Token {
    pub fn send(env: Env, cond: bool) {
        let token = token::Client::new(&env, &id);
        if cond {
            // Shadow `token` with a non-client type inside the block.
            let token = SomeOtherType::new();
            token.transfer(&x, &y);   // unrelated, should not be tracked
        }
        // After the block, the outer `token` (a real token::Client) is live again.
        // This transfer has no preceding balance() check — must be flagged.
        token.transfer(&sender, &recv, &amount);
    }
}
"#;
        let lines = finding_lines(src);
        assert_eq!(
            lines.len(),
            1,
            "the outer token.transfer after the nested block must be flagged; got lines: {lines:?}"
        );
    }
}
