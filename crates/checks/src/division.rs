//! Integer-division-truncation: `/` and `/=` on non-literal operands.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{BinOp, Expr, ExprBinary, File};

const CHECK_NAME: &str = "integer-division-truncation";

/// Flags `/` and `/=` on non-literal operands inside `#[contractimpl]` methods.
/// Literal-only divisions (e.g. `6 / 2`) are ignored.
pub struct IntegerDivisionTruncationCheck;

impl Check for IntegerDivisionTruncationCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            let mut v = DivVisitor {
                fn_name: fn_name.clone(),
                out: &mut out,
            };
            v.visit_block(&method.block);
        }
        out
    }
}

fn is_literal(expr: &Expr) -> bool {
    matches!(expr, Expr::Lit(_))
}

struct DivVisitor<'a> {
    fn_name: String,
    out: &'a mut Vec<Finding>,
}

impl Visit<'_> for DivVisitor<'_> {
    fn visit_expr_binary(&mut self, i: &ExprBinary) {
        let flagged = match &i.op {
            BinOp::Div(_) => !(is_literal(&i.left) && is_literal(&i.right)),
            BinOp::DivAssign(_) => true,
            _ => false,
        };
        if flagged {
            let op = match &i.op {
                BinOp::Div(_) => "/",
                _ => "/=",
            };
            self.out.push(Finding {
                check_name: CHECK_NAME.to_string(),
                severity: Severity::Medium,
                file_path: String::new(),
                line: i.span().start().line,
                function_name: self.fn_name.clone(),
                description: format!(
                    "Integer division (`{op}`) in `{}` silently truncates the result. \
                     In token math this can drain value; consider whether rounding is intentional \
                     and use checked_div or explicit rounding where appropriate.",
                    self.fn_name
                ),
                rule_url: Some(
                    "https://github.com/SorobanGuard/Guard-CLI/blob/main/docs/checks.md#integer-division-truncation-medium"
                        .to_string(),
                ),
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

    fn run(src: &str) -> Vec<Finding> {
        let file = parse_file(src).expect("parse");
        IntegerDivisionTruncationCheck.run(&file, src)
    }

    #[test]
    fn flags_div_of_params() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn half(_env: Env, a: i128, b: i128) -> i128 { a / b }
}
"#);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Medium);
    }

    #[test]
    fn flags_div_assign() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn f(_env: Env, mut x: i128, y: i128) { x /= y; }
}
"#);
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn ignores_literal_div_literal() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn f(_env: Env) -> i128 { 6 / 2 }
}
"#);
        assert!(hits.is_empty());
    }

    #[test]
    fn ignores_non_contractimpl() {
        let hits = run(r#"
pub struct C;
impl C {
    pub fn half(a: i128, b: i128) -> i128 { a / b }
}
"#);
        assert!(hits.is_empty());
    }
}
