//! `event-topic-too-many` — flag `publish` calls whose literal topics tuple
//! exceeds the Soroban host topic limit.
//!
//! The Soroban host allows at most 4 topics per contract event (see
//! <https://developers.stellar.org/docs/learn/soroban/events>). A literal tuple
//! with more than 4 elements passed as the first `publish` argument will fail
//! at runtime, and the arity is visible statically.

use crate::{Check, Finding, Severity};
use syn::{Expr, ExprCall, ExprMethodCall, ExprTuple, File};

/// Maximum number of topics the Soroban host accepts per event.
pub const MAX_EVENT_TOPICS: usize = 4;

/// Flags `env.events().publish((..), data)` when the literal topics tuple has
/// more than [`MAX_EVENT_TOPICS`] elements.
pub struct EventTopicTooManyCheck;

impl Check for EventTopicTooManyCheck {
    fn name(&self) -> &str {
        "event-topic-too-many"
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        walk_items(&file.items, &mut findings);
        findings
    }
}

fn walk_items(items: &[syn::Item], findings: &mut Vec<Finding>) {
    for item in items {
        match item {
            syn::Item::Fn(func) => walk_block(&func.block, &func.sig.ident.to_string(), findings),
            syn::Item::Impl(imp) => {
                for it in &imp.items {
                    if let syn::ImplItem::Fn(func) = it {
                        walk_block(&func.block, &func.sig.ident.to_string(), findings);
                    }
                }
            }
            syn::Item::Mod(m) => {
                if let Some((_, inner)) = &m.content {
                    walk_items(inner, findings);
                }
            }
            _ => {}
        }
    }
}

fn walk_block(block: &syn::Block, function_name: &str, findings: &mut Vec<Finding>) {
    for stmt in &block.stmts {
        walk_stmt(stmt, function_name, findings);
    }
}

fn walk_stmt(stmt: &syn::Stmt, function_name: &str, findings: &mut Vec<Finding>) {
    match stmt {
        syn::Stmt::Expr(expr, _) => walk_expr(expr, function_name, findings),
        syn::Stmt::Local(local) => {
            if let Some(init) = &local.init {
                walk_expr(&init.expr, function_name, findings);
            }
        }
        syn::Stmt::Item(item) => walk_items(std::slice::from_ref(item), findings),
        _ => {}
    }
}

fn walk_expr(expr: &Expr, function_name: &str, findings: &mut Vec<Finding>) {
    match expr {
        Expr::MethodCall(call) => {
            check_publish(call, function_name, findings);
            walk_expr(&call.receiver, function_name, findings);
            for arg in &call.args {
                walk_expr(arg, function_name, findings);
            }
        }
        Expr::Call(call) => {
            check_publish_call(call, function_name, findings);
            for arg in &call.args {
                walk_expr(arg, function_name, findings);
            }
        }
        Expr::Block(b) => walk_block(&b.block, function_name, findings),
        Expr::If(i) => {
            walk_block(&i.then_branch, function_name, findings);
            if let Some((_, else_expr)) = &i.else_branch {
                walk_expr(else_expr, function_name, findings);
            }
        }
        Expr::Match(m) => {
            for arm in &m.arms {
                walk_expr(&arm.body, function_name, findings);
            }
        }
        Expr::ForLoop(f) => walk_block(&f.body, function_name, findings),
        Expr::While(w) => walk_block(&w.body, function_name, findings),
        Expr::Loop(l) => walk_block(&l.body, function_name, findings),
        Expr::Unary(u) => walk_expr(&u.expr, function_name, findings),
        Expr::Binary(b) => {
            walk_expr(&b.left, function_name, findings);
            walk_expr(&b.right, function_name, findings);
        }
        Expr::Assign(a) => {
            walk_expr(&a.left, function_name, findings);
            walk_expr(&a.right, function_name, findings);
        }
        Expr::Return(r) => {
            if let Some(e) = &r.expr {
                walk_expr(e, function_name, findings);
            }
        }
        Expr::Paren(p) => walk_expr(&p.expr, function_name, findings),
        Expr::Try(t) => walk_expr(&t.expr, function_name, findings),
        Expr::Await(a) => walk_expr(&a.base, function_name, findings),
        _ => {}
    }
}

fn check_publish(call: &ExprMethodCall, function_name: &str, findings: &mut Vec<Finding>) {
    if call.method != "publish" {
        return;
    }
    if let Some(first) = call.args.first() {
        check_topics(first, call, function_name, findings);
    }
}

fn check_publish_call(call: &ExprCall, function_name: &str, findings: &mut Vec<Finding>) {
    let is_publish = match &*call.func {
        Expr::Path(p) => p
            .path
            .segments
            .last()
            .map(|s| s.ident == "publish")
            .unwrap_or(false),
        _ => false,
    };
    if !is_publish {
        return;
    }
    if let Some(first) = call.args.first() {
        check_topics(first, call, function_name, findings);
    }
}

fn check_topics(
    first: &Expr,
    call: &impl syn::spanned::Spanned,
    function_name: &str,
    findings: &mut Vec<Finding>,
) {
    let tuple: &ExprTuple = match first {
        Expr::Tuple(t) => t,
        _ => return,
    };
    let arity = tuple.elems.len();
    if arity > MAX_EVENT_TOPICS {
        let line = call.span().start().line;
        findings.push(Finding {
            check_name: "event-topic-too-many".to_string(),
            severity: Severity::Low,
            file_path: String::new(),
            line,
            function_name: function_name.to_string(),
            description: format!(
                "`publish` topics tuple has {arity} elements but the Soroban host allows at most {MAX_EVENT_TOPICS}"
            ),
            rule_url: Some(
                "https://github.com/soroban-guard/soroban-guard/blob/main/docs/checks.md#event-topic-too-many"
                    .to_string(),
            ),
            suggestion: Some(format!(
                "Reduce the topics tuple to at most {MAX_EVENT_TOPICS} elements"
            )),
        });
    }
}
