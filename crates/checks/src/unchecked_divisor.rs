use crate::util::contractimpl_functions_excluding_test;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{BinOp, Block, Expr, ExprBinary, ExprIf, File, Ident};

const CHECK_NAME: &str = "unchecked-divisor";

pub struct UncheckedDivisorCheck;

impl Check for UncheckedDivisorCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        for method in contractimpl_functions_excluding_test(file) {
            let mut expr_visitor = DivisorExprVisitor {
                findings: Vec::new(),
                current_function_name: method.sig.ident.to_string(),
                block: &method.block,
            };
            visit::visit_block(&mut expr_visitor, &method.block);
            findings.extend(expr_visitor.findings);
        }
        findings
    }
}

struct DivisorExprVisitor<'a> {
    findings: Vec<Finding>,
    current_function_name: String,
    /// The enclosing function block, used to check for preceding guards.
    block: &'a Block,
}

impl<'ast> Visit<'ast> for DivisorExprVisitor<'ast> {
    fn visit_expr_binary(&mut self, node: &'ast ExprBinary) {
        if matches!(node.op, BinOp::Div(_) | BinOp::DivAssign(_)) && !is_literal(&node.right) {
            // Collect the divisor name (if it's a simple identifier).
            let divisor_ident = expr_ident(&node.right);

            // Only report if there is no zero-check guard for this divisor in
            // the enclosing function block.
            if !block_has_zero_guard(self.block, divisor_ident.as_deref()) {
                let description =
                    "Divisor is not validated to be non-zero; division by zero will panic"
                        .to_string();
                self.findings.push(Finding {
                    check_name: CHECK_NAME.to_string(),
                    severity: Severity::High,
                    file_path: String::new(),
                    line: node.span().start().line,
                    function_name: self.current_function_name.clone(),
                    description,
                    rule_url: Some(
                        "https://github.com/SorobanGuard/Guard-CLI/blob/main/docs/checks.md#unchecked-divisor-high"
                            .to_string(),
                    ),
                    suggestion: Some(
                        "Use checked_div or validate divisor > 0 before division".to_string(),
                    ),
                });
            }
        }
        visit::visit_expr_binary(self, node);
    }
}

/// Extract a simple identifier name from an expression, if possible.
fn expr_ident(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Path(p) => p.path.get_ident().map(Ident::to_string),
        Expr::Reference(r) => expr_ident(&r.expr),
        _ => None,
    }
}

fn is_literal(expr: &Expr) -> bool {
    matches!(expr, Expr::Lit(_))
}

/// Returns `true` if the block contains an `if <divisor> == 0 { … }` or
/// `if 0 == <divisor> { … }` guard that returns/panics, OR a `checked_div`
/// call for the same divisor, OR any comparison of the divisor against zero
/// (e.g. `assert!(divisor != 0)`, `require!(divisor > 0)`).
///
/// When `divisor_name` is `None` (the divisor is a complex expression rather
/// than a plain variable), we conservatively treat the function as unguarded.
fn block_has_zero_guard(block: &Block, divisor_name: Option<&str>) -> bool {
    let name = match divisor_name {
        Some(n) => n,
        None => return false,
    };
    let mut v = ZeroGuardVisitor {
        divisor_name: name,
        found: false,
    };
    v.visit_block(block);
    v.found
}

struct ZeroGuardVisitor<'a> {
    divisor_name: &'a str,
    found: bool,
}

impl<'ast> Visit<'ast> for ZeroGuardVisitor<'ast> {
    fn visit_expr_if(&mut self, node: &'ast ExprIf) {
        if self.found {
            return;
        }
        // Check whether the condition is `<divisor> == 0` or `0 == <divisor>`
        // or any comparison of the divisor to a zero literal.
        if condition_checks_divisor_zero(&node.cond, self.divisor_name) {
            self.found = true;
            return;
        }
        visit::visit_expr_if(self, node);
    }

    fn visit_expr_binary(&mut self, node: &'ast ExprBinary) {
        if self.found {
            return;
        }
        // Catch assert!(divisor != 0) / require!(divisor > 0) style guards
        // expressed as raw binary comparisons (outside an if).
        if is_comparison_op(&node.op)
            && expr_references_name(&node.left, self.divisor_name)
            && is_zero_literal(&node.right)
        {
            self.found = true;
            return;
        }
        if is_comparison_op(&node.op)
            && is_zero_literal(&node.left)
            && expr_references_name(&node.right, self.divisor_name)
        {
            self.found = true;
            return;
        }
        visit::visit_expr_binary(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        if self.found {
            return;
        }
        // Treat `divisor.checked_div(…)` or `x.checked_div(divisor)` as a guard.
        if node.method == "checked_div" {
            if expr_references_name(&node.receiver, self.divisor_name) {
                self.found = true;
                return;
            }
            for arg in &node.args {
                if expr_references_name(arg, self.divisor_name) {
                    self.found = true;
                    return;
                }
            }
        }
        visit::visit_expr_method_call(self, node);
    }
}

fn condition_checks_divisor_zero(cond: &Expr, name: &str) -> bool {
    match cond {
        Expr::Binary(b) => {
            // `divisor == 0`
            if matches!(b.op, BinOp::Eq(_)) {
                if (expr_references_name(&b.left, name) && is_zero_literal(&b.right))
                    || (is_zero_literal(&b.left) && expr_references_name(&b.right, name))
                {
                    return true;
                }
            }
            // `divisor != 0`, `divisor > 0`, `divisor >= 1`, etc. — any
            // comparison of the divisor to a numeric literal counts.
            if is_comparison_op(&b.op) {
                if (expr_references_name(&b.left, name) && is_numeric_literal(&b.right))
                    || (is_numeric_literal(&b.left) && expr_references_name(&b.right, name))
                {
                    return true;
                }
            }
            false
        }
        // `if !(divisor == 0)` — negation wrapper
        Expr::Unary(u) => condition_checks_divisor_zero(&u.expr, name),
        _ => false,
    }
}

fn is_comparison_op(op: &BinOp) -> bool {
    matches!(
        op,
        BinOp::Eq(_)
            | BinOp::Ne(_)
            | BinOp::Lt(_)
            | BinOp::Le(_)
            | BinOp::Gt(_)
            | BinOp::Ge(_)
    )
}

fn expr_references_name(expr: &Expr, name: &str) -> bool {
    match expr {
        Expr::Path(p) => p.path.get_ident().map(|i| i == name).unwrap_or(false),
        Expr::Reference(r) => expr_references_name(&r.expr, name),
        _ => false,
    }
}

fn is_zero_literal(expr: &Expr) -> bool {
    if let Expr::Lit(l) = expr {
        if let syn::Lit::Int(i) = &l.lit {
            return i.base10_digits() == "0";
        }
    }
    false
}

fn is_numeric_literal(expr: &Expr) -> bool {
    matches!(expr, Expr::Lit(l) if matches!(l.lit, syn::Lit::Int(_)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_file;

    #[test]
    fn flags_non_literal_divisor() -> Result<(), syn::Error> {
        let src = r#"
#[contractimpl]
impl C {
    pub fn divide(a: u128, b: u128) -> u128 {
        a / b
    }
}
        "#;
        let file = parse_file(src)?;
        let check = UncheckedDivisorCheck;
        let findings = check.run(&file, src);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].check_name, "unchecked-divisor");
        assert!(findings[0]
            .description
            .contains("not validated to be non-zero"));
        Ok(())
    }

    #[test]
    fn flags_divide_assign() -> Result<(), syn::Error> {
        let src = r#"
#[contractimpl]
impl C {
    pub fn divide_assign(mut a: u128, b: u128) {
        a /= b;
    }
}
        "#;
        let file = parse_file(src)?;
        let check = UncheckedDivisorCheck;
        let findings = check.run(&file, src);
        assert_eq!(findings.len(), 1);
        Ok(())
    }

    #[test]
    fn ignores_literal_divisor() -> Result<(), syn::Error> {
        let src = r#"
#[contractimpl]
impl C {
    pub fn divide(a: u128) -> u128 {
        a / 2
    }
}
        "#;
        let file = parse_file(src)?;
        let check = UncheckedDivisorCheck;
        let findings = check.run(&file, src);
        assert_eq!(findings.len(), 0);
        Ok(())
    }

    #[test]
    fn ignores_non_contractimpl_impl() -> Result<(), syn::Error> {
        let src = r#"
impl C {
    pub fn divide(a: u128, b: u128) -> u128 {
        a / b
    }
}

impl std::fmt::Display for C {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.a / self.b)
    }
}
        "#;
        let file = parse_file(src)?;
        let check = UncheckedDivisorCheck;
        let findings = check.run(&file, src);
        assert_eq!(findings.len(), 0);
        Ok(())
    }

    #[test]
    fn ignores_cfg_test_module() -> Result<(), syn::Error> {
        let src = r#"
#[cfg(test)]
mod tests {
    use super::*;

    #[contractimpl]
    impl C {
        pub fn divide(a: u128, b: u128) -> u128 {
            a / b
        }
    }
}
        "#;
        let file = parse_file(src)?;
        let check = UncheckedDivisorCheck;
        let findings = check.run(&file, src);
        assert_eq!(findings.len(), 0);
        Ok(())
    }

    #[test]
    fn ignores_guarded_divisor_eq_zero_early_return() -> Result<(), syn::Error> {
        // Mirrors unchecked-divisor-safe: if divisor == 0 { return None; }
        let src = r#"
#[contractimpl]
impl C {
    pub fn divide_safe(_env: Env, total: u128, divisor: u128) -> Option<u128> {
        if divisor == 0 {
            return None;
        }
        Some(total / divisor)
    }
}
        "#;
        let file = parse_file(src)?;
        let check = UncheckedDivisorCheck;
        let findings = check.run(&file, src);
        assert_eq!(findings.len(), 0, "guarded division should not be flagged");
        Ok(())
    }

    #[test]
    fn ignores_checked_div() -> Result<(), syn::Error> {
        let src = r#"
#[contractimpl]
impl C {
    pub fn divide_checked(_env: Env, a: u128, b: u128) -> Option<u128> {
        a.checked_div(b)
    }
}
        "#;
        let file = parse_file(src)?;
        let check = UncheckedDivisorCheck;
        let findings = check.run(&file, src);
        assert_eq!(findings.len(), 0, "checked_div should not be flagged");
        Ok(())
    }
}
