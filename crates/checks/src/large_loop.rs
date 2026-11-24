//! `large-loop`: loops whose iteration count is not bounded by a constant.
//!
//! Soroban runs every invocation under a fixed compute budget, so a loop whose length a
//! caller (or ever-growing storage) controls can make an entrypoint fail. Loops with a
//! provably constant bound are fine and are not reported:
//!
//! - `for` over a range whose end is a literal or `const` (`0..10`, `0..=MAX`, also with
//!   `.rev()` / `.step_by(..)`),
//! - `for` over `.take(<literal or const>)`,
//! - `for` over an array literal, a `[T; N]` / `BytesN<N>` binding, or `.iter()` of one,
//! - `for` over a collection whose `.len()` is compared with a literal or `const`
//!   somewhere in the function (an explicit length cap),
//! - `while` whose condition compares against a literal or `const` (`while i < 10`),
//! - `loop` containing an `if <comparison with literal/const> { break }` counter guard.
//!
//! Everything else — iterating a parameter or a storage-loaded `Vec`/`Map`, `while true`,
//! a `loop` with no counter — is reported.

use crate::util::{contractimpl_functions_excluding_test, pat_ident_name};
use crate::{Check, Finding, Severity};
use std::collections::HashSet;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{BinOp, Expr, FnArg, Type};

const CHECK_NAME: &str = "large-loop";

pub struct LargeLoopCheck;

impl Check for LargeLoopCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &syn::File, _source: &str) -> Vec<Finding> {
        let consts = collect_const_names(file);
        let mut findings = Vec::new();
        for method in contractimpl_functions_excluding_test(file) {
            if !matches!(method.vis, syn::Visibility::Public(_)) {
                continue;
            }
            let ctx = FnContext::new(method, &consts);
            let mut loop_visitor = LoopFinder {
                ctx: &ctx,
                loops: Vec::new(),
            };
            visit::visit_block(&mut loop_visitor, &method.block);

            for (line, loop_type) in loop_visitor.loops {
                findings.push(Finding {
                    check_name: CHECK_NAME.to_string(),
                    severity: Severity::Medium,
                    file_path: String::new(),
                    line,
                    function_name: method.sig.ident.to_string(),
                    description: format!(
                        "Unbounded {loop_type} loop can exhaust compute budget: its iteration \
                         count is not bounded by a constant"
                    ),
                    rule_url: Some(
                        "https://github.com/SorobanGuard/Guard-CLI/blob/main/docs/checks.md#large-loop-medium"
                            .to_string(),
                    ),
                    suggestion: Some(
                        "Bound the iteration with a constant (`0..MAX`, `.take(MAX)`), or reject \
                         inputs whose `.len()` exceeds a constant before looping"
                            .to_string(),
                    ),
                });
            }
        }
        findings
    }
}

/// Facts about one function that decide whether a loop is bounded.
struct FnContext<'a> {
    consts: &'a HashSet<String>,
    /// Bindings typed as a fixed-size array or `BytesN<N>`.
    fixed_size: HashSet<String>,
    /// Bindings whose `.len()` is compared against a literal or const somewhere.
    len_capped: HashSet<String>,
}

impl<'a> FnContext<'a> {
    fn new(method: &syn::ImplItemFn, consts: &'a HashSet<String>) -> Self {
        let mut fixed_size = HashSet::new();
        for input in &method.sig.inputs {
            if let FnArg::Typed(pt) = input {
                if type_is_fixed_size(&pt.ty) {
                    if let Some(name) = pat_ident_name(&pt.pat) {
                        fixed_size.insert(name);
                    }
                }
            }
        }
        let mut scan = BodyFacts {
            consts,
            fixed_size: &mut fixed_size,
            len_capped: HashSet::new(),
        };
        scan.visit_block(&method.block);
        let len_capped = scan.len_capped;
        FnContext {
            consts,
            fixed_size,
            len_capped,
        }
    }

    fn is_const_expr(&self, expr: &Expr) -> bool {
        match expr {
            Expr::Lit(l) => matches!(l.lit, syn::Lit::Int(_)),
            Expr::Path(p) => p
                .path
                .segments
                .last()
                .is_some_and(|s| self.consts.contains(&s.ident.to_string())),
            Expr::Paren(p) => self.is_const_expr(&p.expr),
            Expr::Cast(c) => self.is_const_expr(&c.expr),
            Expr::Binary(b) => self.is_const_expr(&b.left) && self.is_const_expr(&b.right),
            _ => false,
        }
    }

    /// Is iterating `expr` with `for` bounded by a constant?
    fn iter_is_bounded(&self, expr: &Expr) -> bool {
        match expr {
            Expr::Range(r) => r.end.as_deref().is_some_and(|end| self.is_const_expr(end)),
            Expr::Array(_) | Expr::Repeat(_) => true,
            Expr::Paren(p) => self.iter_is_bounded(&p.expr),
            Expr::Reference(r) => self.iter_is_bounded(&r.expr),
            Expr::Path(p) => p.path.get_ident().is_some_and(|i| {
                let name = i.to_string();
                self.fixed_size.contains(&name) || self.len_capped.contains(&name)
            }),
            Expr::MethodCall(m) => {
                let method = m.method.to_string();
                if method == "take" {
                    return m.args.first().is_some_and(|a| self.is_const_expr(a))
                        || self.iter_is_bounded(&m.receiver);
                }
                // Adapters that never add elements keep the receiver's bound.
                matches!(
                    method.as_str(),
                    "iter"
                        | "into_iter"
                        | "iter_mut"
                        | "rev"
                        | "step_by"
                        | "enumerate"
                        | "skip"
                        | "filter"
                        | "map"
                        | "copied"
                        | "cloned"
                        | "zip"
                        | "keys"
                        | "values"
                        | "clone"
                ) && self.iter_is_bounded(&m.receiver)
            }
            _ => false,
        }
    }

    /// Is `cond` a comparison where one side is a literal or const?
    fn is_bounded_comparison(&self, cond: &Expr) -> bool {
        match cond {
            Expr::Binary(b) => match b.op {
                BinOp::Lt(_)
                | BinOp::Le(_)
                | BinOp::Gt(_)
                | BinOp::Ge(_)
                | BinOp::Eq(_)
                | BinOp::Ne(_) => self.is_const_expr(&b.left) || self.is_const_expr(&b.right),
                BinOp::And(_) | BinOp::Or(_) => {
                    self.is_bounded_comparison(&b.left) || self.is_bounded_comparison(&b.right)
                }
                _ => false,
            },
            Expr::Paren(p) => self.is_bounded_comparison(&p.expr),
            _ => false,
        }
    }
}

/// `[T; N]`, `&[T; N]`, or `BytesN<N>`.
fn type_is_fixed_size(ty: &Type) -> bool {
    match ty {
        Type::Array(_) => true,
        Type::Reference(r) => type_is_fixed_size(&r.elem),
        Type::Path(p) => p.path.segments.last().is_some_and(|s| s.ident == "BytesN"),
        _ => false,
    }
}

/// Collects typed fixed-size `let` bindings and `.len()` caps in one function body.
struct BodyFacts<'a, 'b> {
    consts: &'a HashSet<String>,
    fixed_size: &'b mut HashSet<String>,
    len_capped: HashSet<String>,
}

impl BodyFacts<'_, '_> {
    fn is_const_side(&self, expr: &Expr) -> bool {
        match expr {
            Expr::Lit(l) => matches!(l.lit, syn::Lit::Int(_)),
            Expr::Path(p) => p
                .path
                .segments
                .last()
                .is_some_and(|s| self.consts.contains(&s.ident.to_string())),
            Expr::Paren(p) => self.is_const_side(&p.expr),
            Expr::Cast(c) => self.is_const_side(&c.expr),
            _ => false,
        }
    }
}

/// `x.len()` (possibly cast) → `x`.
fn len_receiver(expr: &Expr) -> Option<String> {
    match expr {
        Expr::MethodCall(m) if m.method == "len" => match &*m.receiver {
            Expr::Path(p) => p.path.get_ident().map(|i| i.to_string()),
            _ => None,
        },
        Expr::Cast(c) => len_receiver(&c.expr),
        Expr::Paren(p) => len_receiver(&p.expr),
        _ => None,
    }
}

impl<'ast> Visit<'ast> for BodyFacts<'_, '_> {
    fn visit_local(&mut self, i: &'ast syn::Local) {
        if let syn::Pat::Type(pt) = &i.pat {
            if type_is_fixed_size(&pt.ty) {
                if let Some(name) = pat_ident_name(&pt.pat) {
                    self.fixed_size.insert(name);
                }
            }
        }
        visit::visit_local(self, i);
    }

    fn visit_expr_binary(&mut self, b: &'ast syn::ExprBinary) {
        if matches!(
            b.op,
            BinOp::Lt(_) | BinOp::Le(_) | BinOp::Gt(_) | BinOp::Ge(_)
        ) {
            if let Some(name) = len_receiver(&b.left).filter(|_| self.is_const_side(&b.right)) {
                self.len_capped.insert(name);
            } else if let Some(name) =
                len_receiver(&b.right).filter(|_| self.is_const_side(&b.left))
            {
                self.len_capped.insert(name);
            }
        }
        visit::visit_expr_binary(self, b);
    }
}

/// Does `block` contain `if <bounded comparison> { … break … }`?
fn has_counter_break(block: &syn::Block, ctx: &FnContext<'_>) -> bool {
    struct Finder<'a, 'b> {
        ctx: &'a FnContext<'b>,
        found: bool,
    }
    impl<'ast> Visit<'ast> for Finder<'_, '_> {
        fn visit_expr_if(&mut self, i: &'ast syn::ExprIf) {
            if self.ctx.is_bounded_comparison(&i.cond) && contains_break(&i.then_branch) {
                self.found = true;
            }
            visit::visit_expr_if(self, i);
        }
        // A nested loop's break does not exit this loop.
        fn visit_expr_loop(&mut self, _: &'ast syn::ExprLoop) {}
        fn visit_expr_while(&mut self, _: &'ast syn::ExprWhile) {}
        fn visit_expr_for_loop(&mut self, _: &'ast syn::ExprForLoop) {}
    }
    let mut finder = Finder { ctx, found: false };
    finder.visit_block(block);
    finder.found
}

fn contains_break(block: &syn::Block) -> bool {
    struct Finder(bool);
    impl<'ast> Visit<'ast> for Finder {
        fn visit_expr_break(&mut self, _: &'ast syn::ExprBreak) {
            self.0 = true;
        }
        fn visit_expr_return(&mut self, _: &'ast syn::ExprReturn) {
            self.0 = true;
        }
    }
    let mut finder = Finder(false);
    finder.visit_block(block);
    finder.0
}

/// Names of every `const`/`static` item in the file.
fn collect_const_names(file: &syn::File) -> HashSet<String> {
    struct ConstVisitor(HashSet<String>);
    impl Visit<'_> for ConstVisitor {
        fn visit_item_const(&mut self, i: &syn::ItemConst) {
            self.0.insert(i.ident.to_string());
            visit::visit_item_const(self, i);
        }
        fn visit_item_static(&mut self, i: &syn::ItemStatic) {
            self.0.insert(i.ident.to_string());
            visit::visit_item_static(self, i);
        }
        fn visit_impl_item_const(&mut self, i: &syn::ImplItemConst) {
            self.0.insert(i.ident.to_string());
            visit::visit_impl_item_const(self, i);
        }
    }
    let mut v = ConstVisitor(HashSet::new());
    v.visit_file(file);
    v.0
}

struct LoopFinder<'a, 'b> {
    ctx: &'a FnContext<'b>,
    loops: Vec<(usize, String)>,
}

impl<'ast> Visit<'ast> for LoopFinder<'_, '_> {
    fn visit_expr(&mut self, node: &'ast Expr) {
        match node {
            Expr::Loop(l) if !has_counter_break(&l.body, self.ctx) => {
                self.loops
                    .push((node.span().start().line, "loop".to_string()));
            }
            Expr::While(w) if !self.ctx.is_bounded_comparison(&w.cond) => {
                self.loops
                    .push((node.span().start().line, "while".to_string()));
            }
            Expr::ForLoop(f) if !self.ctx.iter_is_bounded(&f.expr) => {
                self.loops
                    .push((node.span().start().line, "for".to_string()));
            }
            _ => {}
        }
        visit::visit_expr(self, node);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_file;

    #[test]
    fn flags_loop() -> Result<(), syn::Error> {
        let src = r#"
#[contractimpl]
impl C {
    pub fn process(env: Env) {
        loop {
            env.storage().instance().set(&symbol_short!("x"), &1);
        }
    }
}
        "#;
        let file = parse_file(src)?;
        let check = LargeLoopCheck;
        let findings = check.run(&file, src);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].check_name, "large-loop");
        assert_eq!(findings[0].function_name, "process");
        assert_eq!(findings[0].line, 5);
        Ok(())
    }

    #[test]
    fn flags_while() -> Result<(), syn::Error> {
        let src = r#"
#[contractimpl]
impl C {
    pub fn process(env: Env) {
        while true {
            let x = 1;
        }
    }
}
        "#;
        let file = parse_file(src)?;
        let check = LargeLoopCheck;
        let findings = check.run(&file, src);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].function_name, "process");
        assert_eq!(findings[0].line, 5);
        Ok(())
    }

    #[test]
    fn ignores_loops_inside_cfg_test() -> Result<(), syn::Error> {
        let src = r#"
#[contractimpl]
impl C {
    pub fn process(env: Env) {
        let _ = env;
    }
}

#[cfg(test)]
mod tests {
    use soroban_sdk::{contractimpl, Env};

    #[contractimpl]
    impl C {
        pub fn process(env: Env) {
            loop {
                env.storage().instance().set(&symbol_short!("x"), &1);
            }
        }
    }
}
        "#;
        let file = parse_file(src)?;
        let check = LargeLoopCheck;
        let findings = check.run(&file, src);
        assert_eq!(findings.len(), 0);
        Ok(())
    }

    fn run(src: &str) -> Vec<Finding> {
        let file = parse_file(src).expect("parse");
        LargeLoopCheck.run(&file, src)
    }

    /// #1053: constant-bounded shapes are not reported.
    #[test]
    fn ignores_constant_bounded_loops() {
        let hits = run(r#"
const MAX: u32 = 20;
#[contractimpl]
impl C {
    pub fn bounded(env: Env, items: Vec<u32>, hash: BytesN<32>, n: u32) {
        for i in 0..10 { let _ = i; }
        for i in 0..=MAX { let _ = i; }
        for i in (0..MAX).rev() { let _ = i; }
        for x in items.iter().take(MAX as usize) { let _ = x; }
        for x in [1u32, 2, 3] { let _ = x; }
        for b in hash.iter() { let _ = b; }
        let fixed: [u32; 4] = [0; 4];
        for x in fixed.iter() { let _ = x; }
        let mut i = 0;
        while i < 10 { i += 1; }
        let mut j = 0;
        loop {
            j += 1;
            if j >= MAX { break; }
        }
    }

    pub fn capped(env: Env, items: Vec<u32>) {
        if items.len() > MAX { panic!("too many"); }
        for x in items.iter() { let _ = x; }
    }
}
"#);
        assert!(hits.is_empty(), "{hits:?}");
    }

    /// #1053: caller- or storage-controlled lengths are still reported.
    #[test]
    fn flags_unbounded_loops() {
        let hits = run(r#"
#[contractimpl]
impl C {
    pub fn unbounded(env: Env, items: Vec<u32>, n: u32) {
        for x in items.iter() { let _ = x; }
        let stored: Vec<u32> = env.storage().persistent().get(&0).unwrap();
        for x in stored.iter() { let _ = x; }
        for i in 0..n { let _ = i; }
        for x in items.iter().take(n as usize) { let _ = x; }
        let mut i = 0;
        while i < n { i += 1; }
        loop {
            if items.is_empty() { break; }
        }
    }
}
"#);
        assert_eq!(hits.len(), 6, "{hits:?}");
        assert!(hits.iter().all(|h| h.function_name == "unbounded"));
    }
}
