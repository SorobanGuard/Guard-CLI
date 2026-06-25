//! Unchecked `+`, `-`, `*`, and compound assignments in contract methods.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{BinOp, Expr, ExprBinary, File};

const CHECK_NAME: &str = "unchecked-arithmetic";

/// Flags wrapping integer arithmetic that is not expressed via checked/saturating APIs.
///
/// Heuristic: in `#[contractimpl]` methods, binary `+`, `-`, `*` (and `+=`, `-=`, `*=`) where
/// both operands are not compile-time literals. This may include benign index math; treat as a
/// review signal for token balances and amounts (`i128`, `u128`, etc.).
pub struct UncheckedArithmeticCheck;

impl Check for UncheckedArithmeticCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
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
            self.out.push(Finding {
                check_name: CHECK_NAME.to_string(),
                severity: Severity::Medium,
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
                    "https://github.com/SorobanGuard/Guard-CLI/blob/main/docs/checks.md#unchecked-arithmetic-medium"
                        .to_string(),
                ),
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
}
