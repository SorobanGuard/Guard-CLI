//! Unchecked `+`, `-`, `*`, and compound assignments in contract methods.

use crate::util::contractimpl_functions_excluding_test;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{BinOp, Expr, ExprBinary, ExprMethodCall, File};

const CHECK_NAME: &str = "unchecked-arithmetic";

/// Variable-name fragments that suggest index/counter math → downgrade to Low.
const INDEX_NAMES: &[&str] = &["idx", "index", "count", "len", "offset", "pos", "step"];
/// Single-char index variables (exact match).
const INDEX_CHARS: &[&str] = &["i", "j", "k", "n", "x", "y", "z"];
/// Variable-name fragments that suggest financial math → upgrade to High.
const FINANCIAL_NAMES: &[&str] = &[
    "amount", "balance", "fee", "price", "supply", "reward", "stake", "fund", "value", "total",
];

fn severity_for_operand_name(name: &str) -> Option<Severity> {
    let lower = name.to_lowercase();
    for &fin in FINANCIAL_NAMES {
        if lower.contains(fin) {
            return Some(Severity::High);
        }
    }
    for &idx in INDEX_NAMES {
        if lower.contains(idx) {
            return Some(Severity::Low);
        }
    }
    if INDEX_CHARS.contains(&lower.as_str()) {
        return Some(Severity::Low);
    }
    None
}

fn expr_ident(e: &Expr) -> Option<String> {
    match e {
        Expr::Path(p) => p.path.get_ident().map(|i| i.to_string()),
        _ => None,
    }
}

fn infer_severity(e: &ExprBinary) -> Severity {
    for operand in [&*e.left, &*e.right] {
        if let Some(name) = expr_ident(operand) {
            if let Some(sev) = severity_for_operand_name(&name) {
                return sev;
            }
        }
    }
    Severity::Medium
}

/// Returns true if `block` contains any `checked_*` or `saturating_*` method call,
/// indicating the function already uses safe arithmetic and should not be flagged.
fn uses_safe_arithmetic(block: &syn::Block, binary_expr: &ExprBinary) -> bool {
    let mut v = SafeArithScan {
        binary_expr,
        found: false,
    };
    v.visit_block(block);
    v.found
}

struct SafeArithScan<'a> {
    binary_expr: &'a ExprBinary,
    found: bool,
}

impl<'ast> Visit<'ast> for SafeArithScan<'_> {
    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        if !self.found {
            let name = i.method.to_string();
            if name.starts_with("checked_") || name.starts_with("saturating_") {
                if let Some(arg) = i.args.first() {
                    let left = &*self.binary_expr.left;
                    let right = &*self.binary_expr.right;
                    let recv = &*i.receiver;
                    let operands_match =
                        (left == recv && right == arg) || (right == recv && left == arg);
                    // Only suppress when the `checked_*` call guards *this* expression, i.e.
                    // it sits at the same source location. An operand-equal `checked_*` on
                    // another line (e.g. an earlier discarded computation) is unrelated and
                    // must not silence a genuinely unchecked `a + b`.
                    let same_site = i.span().start().line == self.binary_expr.span().start().line;
                    if operands_match && same_site {
                        self.found = true;
                    }
                }
            }
        }
        visit::visit_expr_method_call(self, i);
    }
}

/// Flags wrapping integer arithmetic that is not expressed via checked/saturating APIs.
///
/// Heuristic: in `#[contractimpl]` methods, binary `+`, `-`, `*` (and `+=`, `-=`, `*=`) where
/// both operands are not compile-time literals. Functions inside `#[cfg(test)]` or `mod tests`
/// are excluded.
///
/// `/` and `%` are intentionally excluded from this check: division cannot overflow (except
/// `i*/i*::MIN / -1` which panics rather than wraps), and truncation/remainder concerns are
/// covered by the dedicated `integer-division-truncation` check instead.
pub struct UncheckedArithmeticCheck;

impl Check for UncheckedArithmeticCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions_excluding_test(file) {
            let fn_name = method.sig.ident.to_string();
            let mut v = ArithVisitor {
                fn_name: fn_name.clone(),
                block: &method.block,
                out: &mut out,
            };
            v.visit_block(&method.block);
        }
        out
    }
}

fn is_literal_expr(expr: &Expr) -> bool {
    matches!(expr, Expr::Lit(_))
}

/// In syn 2, `a += b` is `ExprBinary` with `BinOp::AddAssign`, not a separate assign-op node.
fn is_unchecked_binary(e: &ExprBinary) -> bool {
    match &e.op {
        BinOp::Add(_) | BinOp::Sub(_) | BinOp::Mul(_) => {
            !(is_literal_expr(&e.left) && is_literal_expr(&e.right))
        }
        BinOp::AddAssign(_) | BinOp::SubAssign(_) | BinOp::MulAssign(_) => {
            !is_literal_expr(&e.right)
        }
        _ => false,
    }
}

struct ArithVisitor<'a> {
    fn_name: String,
    block: &'a syn::Block,
    out: &'a mut Vec<Finding>,
}

impl Visit<'_> for ArithVisitor<'_> {
    fn visit_expr_binary(&mut self, i: &ExprBinary) {
        if is_unchecked_binary(i) && !uses_safe_arithmetic(self.block, i) {
            let op = match &i.op {
                BinOp::Add(_) => "+",
                BinOp::Sub(_) => "-",
                BinOp::Mul(_) => "*",
                BinOp::AddAssign(_) => "+=",
                BinOp::SubAssign(_) => "-=",
                BinOp::MulAssign(_) => "*=",
                _ => "?",
            };
            let severity = infer_severity(i);
            self.out.push(Finding {
                check_name: CHECK_NAME.to_string(),
                severity,
                file_path: String::new(),
                line: i.span().start().line,
                function_name: self.fn_name.clone(),
                description: format!(
                    "Expression uses wrapping integer arithmetic (`{op}`) in `{}`. \
                     For asset amounts and balances prefer `checked_add`, `checked_sub`, \
                     `checked_mul`, or `saturating_*` to avoid silent overflow.",
                    self.fn_name
                ),
                rule_url: Some(
                    "https://github.com/SorobanGuard/Guard-CLI/blob/main/docs/checks.md#unchecked-arithmetic-high--medium--low"
                        .to_string(),
                ),
                suggestion: Some(format!(
                    "Replace `{op}` with `checked_add`/`checked_sub`/`checked_mul` and \
                     handle overflow explicitly, or use `saturating_add`/`saturating_sub` \
                     if saturating semantics are acceptable."
                )),
            });
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
    fn flags_add_of_parameters() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn sum(env: Env, a: i128, b: i128) -> i128 {
        let _ = env;
        a + b
    }
}
"#,
        )?;
        let hits = UncheckedArithmeticCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Medium);
        Ok(())
    }

    #[test]
    fn ignores_literal_plus_literal() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn f(env: Env) -> i128 {
        let _ = env;
        1 + 2
    }
}
"#,
        )?;
        let hits = UncheckedArithmeticCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn passes_with_checked_add() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn sum(env: Env, a: i128, b: i128) -> Option<i128> {
        let _ = env;
        a.checked_add(b)
    }
}
"#,
        )?;
        let hits = UncheckedArithmeticCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn flags_add_assign() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn acc(env: Env, mut x: i128, y: i128) {
        let _ = env;
        x += y;
    }
}
"#,
        )?;
        let hits = UncheckedArithmeticCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        Ok(())
    }

    #[test]
    fn ignores_add_assign_of_literal() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn acc(env: Env, mut x: i128) {
        let _ = env;
        x += 1;
    }
}
"#,
        )?;
        let hits = UncheckedArithmeticCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn flags_add_assign_of_non_literal() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn acc(env: Env, mut x: i128, y: i128) {
        let _ = env;
        x += y;
    }
}
"#,
        )?;
        let hits = UncheckedArithmeticCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        Ok(())
    }

    #[test]
    fn ignores_non_contractimpl() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::Env;

pub struct C;

impl C {
    pub fn sum(env: Env, a: i128, b: i128) -> i128 {
        let _ = env;
        a + b
    }
}
"#,
        )?;
        let hits = UncheckedArithmeticCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn financial_name_gets_high_severity() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn transfer(env: Env, amount: i128, fee: i128) -> i128 {
        let _ = env;
        amount - fee
    }
}
"#,
        )?;
        let hits = UncheckedArithmeticCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::High);
        Ok(())
    }

    #[test]
    fn index_name_gets_low_severity() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn next(env: Env, i: u32) -> u32 {
        let _ = env;
        i + 1
    }
}
"#,
        )?;
        let hits = UncheckedArithmeticCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Low);
        Ok(())
    }

    #[test]
    fn discarded_checked_add_does_not_suppress_later_unchecked_add() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn f(env: Env, a: i128, b: i128) -> i128 {
        let _ = env;
        let _preview = a.checked_add(b);
        a + b
    }
}
"#,
        )?;
        let hits = UncheckedArithmeticCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        Ok(())
    }

    #[test]
    fn flags_unguarded_arithmetic_despite_guarded_arithmetic_in_same_function() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn f(env: Env, a: i128, b: i128) -> i128 {
        let _ = env;
        let _ = a.checked_add(1);
        b + a
    }
}
"#,
        )?;
        let hits = UncheckedArithmeticCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Medium);
        Ok(())
    }
}
