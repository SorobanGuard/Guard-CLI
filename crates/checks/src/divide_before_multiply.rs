//! `divide-before-multiply` check.
//!
//! Flags `a / b * c` patterns where integer division truncates before the
//! result is scaled by a multiplication, silently discarding precision.

use crate::util::{self, CheckFinding, Severity};
use crate::Check;
use syn::{BinOp, Expr, ExprBinary, ExprLit, Lit, Stmt};

/// Check for `divide-before-multiply`.
pub struct DivideBeforeMultiplyCheck;

const NAME: &str = "divide-before-multiply";
const RULE_URL: &str = "docs/checks.md#divide-before-multiply-medium";
const SUGGESTION: &str =
    "Reorder the arithmetic so the multiplication happens before the division \
     (e.g. `a * c / b`) to avoid truncating the quotient before scaling.";

impl Check for DivideBeforeMultiplyCheck {
    fn name(&self) -> &str {
        NAME
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn check(&self, file: &syn::File, source: &str) -> Vec<CheckFinding> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for func in util::contractimpl_functions_excluding_test(file) {
            let mut visitor = MulVisitor {
                findings: &mut findings,
                lines: &lines,
            };
            visitor.visit_block(&func.block);
        }

        findings
    }
}

struct MulVisitor<'a> {
    findings: &'a mut Vec<CheckFinding>,
    lines: &'a [&'a str],
}

impl<'a> MulVisitor<'a> {
    fn visit_block(&mut self, block: &syn::Block) {
        for stmt in &block.stmts {
            self.visit_stmt(stmt);
        }
    }

    fn visit_stmt(&mut self, stmt: &Stmt) {
        match stmt {
            Stmt::Local(local) => {
                if let Some(init) = &local.init {
                    self.visit_expr(&init.expr);
                }
            }
            Stmt::Expr(expr, _) => self.visit_expr(expr),
            Stmt::Item(_) | Stmt::Macro(_) => {}
        }
    }

    fn visit_expr(&mut self, expr: &Expr) {
        match expr {
            Expr::Binary(binary) => {
                self.check_binary(binary);
                self.visit_expr(&binary.left);
                self.visit_expr(&binary.right);
            }
            Expr::Paren(paren) => self.visit_expr(&paren.expr),
            Expr::Group(group) => self.visit_expr(&group.expr),
            Expr::Unary(unary) => self.visit_expr(&unary.expr),
            Expr::Call(call) => {
                self.visit_expr(&call.func);
                for arg in &call.args {
                    self.visit_expr(arg);
                }
            }
            Expr::MethodCall(mc) => {
                self.visit_expr(&mc.receiver);
                for arg in &mc.args {
                    self.visit_expr(arg);
                }
            }
            Expr::Block(block) => self.visit_block(&block.block),
            Expr::If(if_expr) => {
                self.visit_expr(&if_expr.cond);
                self.visit_block(&if_expr.then_branch);
                if let Some((_, else_expr)) = &if_expr.else_branch {
                    self.visit_expr(else_expr);
                }
            }
            Expr::Match(match_expr) => {
                self.visit_expr(&match_expr.expr);
                for arm in &match_expr.arms {
                    self.visit_expr(&arm.body);
                }
            }
            Expr::Let(let_expr) => self.visit_expr(&let_expr.expr),
            Expr::Assign(assign) => {
                self.visit_expr(&assign.left);
                self.visit_expr(&assign.right);
            }
            Expr::Return(ret) => {
                if let Some(inner) = &ret.expr {
                    self.visit_expr(inner);
                }
            }
            Expr::Loop(l) => self.visit_block(&l.body),
            Expr::While(w) => {
                self.visit_expr(&w.cond);
                self.visit_block(&w.body);
            }
            Expr::ForLoop(f) => {
                self.visit_expr(&f.expr);
                self.visit_block(&f.body);
            }
            Expr::Reference(r) => self.visit_expr(&r.expr),
            Expr::Cast(c) => self.visit_expr(&c.expr),
            Expr::Field(f) => self.visit_expr(&f.base),
            Expr::Index(i) => {
                self.visit_expr(&i.expr);
                self.visit_expr(&i.index);
            }
            Expr::Tuple(t) => {
                for elem in &t.elems {
                    self.visit_expr(elem);
                }
            }
            Expr::Array(a) => {
                for elem in &a.elems {
                    self.visit_expr(elem);
                }
            }
            _ => {}
        }
    }

    fn check_binary(&mut self, binary: &ExprBinary) {
        if !matches!(binary.op, BinOp::Mul(_)) {
            return;
        }

        // Skip multiplication by literal `1`.
        if is_literal_one(&binary.right) || is_literal_one(&binary.left) {
            return;
        }

        // Look for a division on either operand (directly or via parens).
        let div = find_div(&binary.left).or_else(|| find_div(&binary.right));
        let Some(div) = div else {
            return;
        };

        // Skip divisors that are literal powers of two (shift-like).
        if is_power_of_two_literal(&div.right) {
            return;
        }

        let line = div.left.span().start().line;
        if self.is_suppressed(line) {
            return;
        }

        let lhs = expr_to_string(&div.left);
        let rhs = expr_to_string(&div.right);
        let mul = expr_to_string(&binary.right);

        self.findings.push(CheckFinding {
            check: NAME.to_string(),
            severity: Severity::Medium,
            message: format!(
                "`{lhs} / {rhs}` is truncated before being multiplied by `{mul}`; \
                 reorder to multiply first to avoid precision loss"
            ),
            line,
            column: div.left.span().start().column,
            rule_url: RULE_URL.to_string(),
            suggestion: SUGGESTION.to_string(),
        });
    }

    fn is_suppressed(&self, line: usize) -> bool {
        // Check the line itself and the preceding line for an allow comment.
        let idx = line.saturating_sub(1);
        let candidates = [idx.checked_sub(1), Some(idx)];
        for cand in candidates.into_iter().flatten() {
            if let Some(text) = self.lines.get(cand) {
                if is_allow_comment(text) {
                    return true;
                }
            }
        }
        false
    }
}

fn is_allow_comment(text: &str) -> bool {
    let trimmed = text.trim_start();
    if !trimmed.starts_with("//") {
        return false;
    }
    let lower = trimmed.to_ascii_lowercase();
    if !lower.contains("soroban-guard:") || !lower.contains("allow") {
        return false;
    }
    lower.contains(NAME)
}

fn find_div(expr: &Expr) -> Option<&ExprBinary> {
    match expr {
        Expr::Binary(b) if matches!(b.op, BinOp::Div(_)) => Some(b),
        Expr::Paren(p) => find_div(&p.expr),
        Expr::Group(g) => find_div(&g.expr),
        _ => None,
    }
}

fn is_literal_one(expr: &Expr) -> bool {
    match expr {
        Expr::Lit(ExprLit {
            lit: Lit::Int(int), ..
        }) => int.base10_parse::<u64>().map(|v| v == 1).unwrap_or(false),
        Expr::Paren(p) => is_literal_one(&p.expr),
        Expr::Group(g) => is_literal_one(&g.expr),
        _ => false,
    }
}

fn is_power_of_two_literal(expr: &Expr) -> bool {
    match expr {
        Expr::Lit(ExprLit {
            lit: Lit::Int(int), ..
        }) => int
            .base10_parse::<u64>()
            .map(|v| v > 0 && v.is_power_of_two())
            .unwrap_or(false),
        Expr::Paren(p) => is_power_of_two_literal(&p.expr),
        Expr::Group(g) => is_power_of_two_literal(&g.expr),
        _ => false,
    }
}

fn expr_to_string(expr: &Expr) -> String {
    use quote::ToTokens;
    expr.to_token_stream().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(src: &str) -> Vec<CheckFinding> {
        let file = syn::parse_file(src).expect("parse");
        DivideBeforeMultiplyCheck.check(&file, src)
    }

    #[test]
    fn positive_div_then_mul() {
        let src = r#"
#[contractimpl]
impl C {
    pub fn f(amount: i128, total: i128, price: i128) -> i128 {
        amount / total * price
    }
}
"#;
        let findings = run(src);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].check, "divide-before-multiply");
        assert_eq!(findings[0].severity, Severity::Medium);
        assert!(findings[0].message.contains("amount"));
        assert!(findings[0].message.contains("total"));
        assert!(!findings[0].rule_url.is_empty());
        assert!(!findings[0].suggestion.is_empty());
    }

    #[test]
    fn negative_mul_then_div() {
        let src = r#"
#[contractimpl]
impl C {
    pub fn f(amount: i128, total: i128, price: i128) -> i128 {
        amount * price / total
    }
}
"#;
        assert!(run(src).is_empty());
    }

    #[test]
    fn cfg_test_excluded() {
        let src = r#"
#[contractimpl]
impl C {
    pub fn f(amount: i128, total: i128, price: i128) -> i128 {
        amount * price / total
    }
}

#[cfg(test)]
mod tests {
    fn helper(amount: i128, total: i128, price: i128) -> i128 {
        amount / total * price
    }
}
"#;
        assert!(run(src).is_empty());
    }

    #[test]
    fn allow_comment_suppresses() {
        let src = r#"
#[contractimpl]
impl C {
    pub fn f(amount: i128, total: i128, price: i128) -> i128 {
        // soroban-guard: allow(divide-before-multiply)
        amount / total * price
    }
}
"#;
        assert!(run(src).is_empty());
    }

    #[test]
    fn false_positive_power_of_two_and_one() {
        let src = r#"
#[contractimpl]
impl C {
    pub fn f(x: i128) -> i128 {
        let a = x / 2 * 3;
        let b = x / 4 * 5;
        let c = x / 3 * 1;
        a + b + c
    }
}
"#;
        assert!(run(src).is_empty());
    }

    #[test]
    fn parenthesised_div_detected() {
        let src = r#"
#[contractimpl]
impl C {
    pub fn f(amount: i128, total: i128, price: i128) -> i128 {
        (amount / total) * price
    }
}
"#;
        assert_eq!(run(src).len(), 1);
    }
}