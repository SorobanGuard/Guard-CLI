//! Unchecked `+`, `-`, `*`, and compound assignments in contract methods.

use crate::util::contractimpl_functions_excluding_test;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{BinOp, Expr, ExprBinary, File};

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

/// Flags wrapping integer arithmetic that is not expressed via checked/saturating APIs.
///
/// Heuristic: in `#[contractimpl]` methods, binary `+`, `-`, `*` (and `+=`, `-=`, `*=`) where
/// both operands are not compile-time literals. Functions inside `#[cfg(test)]` or `mod tests`
/// are excluded.
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
        BinOp::AddAssign(_) | BinOp::SubAssign(_) | BinOp::MulAssign(_) => true,
        _ => false,
    }
}

struct ArithVisitor<'a> {
    fn_name: String,
    out: &'a mut Vec<Finding>,
}

impl Visit<'_> for ArithVisitor<'_> {
    fn visit_expr_binary(&mut self, i: &ExprBinary) {
        if is_unchecked_binary(i) {
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
            let url_fragment = match severity {
                Severity::High => "unchecked-arithmetic-high",
                Severity::Low => "unchecked-arithmetic-low",
                _ => "unchecked-arithmetic-medium",
            };
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
                rule_url: Some(format!(
                    "https://github.com/SorobanGuard/Guard-CLI/blob/main/docs/checks.md#{url_fragment}"
                )),
                suggestion: None,
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
}
