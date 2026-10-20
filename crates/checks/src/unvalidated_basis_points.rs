//! Detect fee/rate/bps parameters stored or used without an upper-bound check.
//!
//! Admin setters such as `set_fee(env, fee_bps: u32)` frequently store the value
//! without ensuring it is `<= 10_000`. A value above 100% makes
//! `amount * fee_bps / 10_000` exceed `amount`, which can underflow later
//! subtraction or let fees drain principal.

use crate::util::contractimpl_functions_excluding_test;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, File, FnArg, Pat, Type};

const CHECK_NAME: &str = "unvalidated-basis-points";

/// Parameter-name fragments that suggest a fee / rate / basis-points value.
const SENSITIVE_PARAM_NAMES: &[&str] = &[
    "fee", "bps", "rate", "percent", "commission", "ratio",
];

pub struct UnvalidatedBasisPointsCheck;

impl Check for UnvalidatedBasisPointsCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();

        for method in contractimpl_functions_excluding_test(file) {
            // Collect integer parameter names that match our sensitive list.
            let sensitive_params: Vec<String> = method
                .sig
                .inputs
                .iter()
                .filter_map(|arg| {
                    if let FnArg::Typed(pat_type) = arg {
                        // Only integer parameters (u32, u64, u128, i32, i64, i128).
                        if !is_integer_type(&pat_type.ty) {
                            return None;
                        }
                        if let Pat::Ident(ident) = pat_type.pat.as_ref() {
                            let name = ident.ident.to_string().to_lowercase();
                            if SENSITIVE_PARAM_NAMES.iter().any(|&s| name.contains(s)) {
                                return Some(ident.ident.to_string());
                            }
                        }
                    }
                    None
                })
                .collect();

            if sensitive_params.is_empty() {
                continue;
            }

            // For each sensitive parameter, check whether there is an upper-bound
            // guard: a comparison (`< 10_000`, `<= MAX_BPS`, etc.), an `assert!`/
            // `require!`, or a `min`/`clamp` call mentioning that identifier.
            for param in &sensitive_params {
                let mut scanner = BpsScanner {
                    param: param.clone(),
                    guarded: false,
                    findings: Vec::new(),
                    fn_name: method.sig.ident.to_string(),
                };
                scanner.visit_block(&method.block);

                if !scanner.guarded {
                    let line = method.sig.ident.span().start().line;
                    out.push(Finding {
                        check_name: CHECK_NAME.to_string(),
                        severity: Severity::Medium,
                        file_path: String::new(),
                        line,
                        function_name: method.sig.ident.to_string(),
                        description: format!(
                            "Parameter `{param}` appears to be a fee/rate/bps value but is stored \
                             or used without an upper-bound check (`<= 10_000`, `assert!`, `min`, \
                             or `clamp`). A value above 100% can drain principal."
                        ),
                        rule_url: Some(
                            "https://github.com/SorobanGuard/Guard-CLI/blob/main/docs/checks.md#unvalidated-basis-points-medium"
                                .to_string(),
                        ),
                        suggestion: Some(format!(
                            "Add `assert!({param} <= 10_000, \"fee exceeds 100%\");` before storing or using `{param}`."
                        )),
                        column: None,
                        end_line: None,
                        end_column: None,
                    });
                }
            }
        }

        out
    }
}

fn is_integer_type(ty: &Type) -> bool {
    if let Type::Path(type_path) = ty {
        if let Some(seg) = type_path.path.segments.last() {
            let name = seg.ident.to_string();
            return matches!(
                name.as_str(),
                "u8" | "u16" | "u32" | "u64" | "u128" | "usize"
                    | "i8" | "i16" | "i32" | "i64" | "i128" | "isize"
            );
        }
    }
    false
}

struct BpsScanner {
    param: String,
    guarded: bool,
    findings: Vec<Finding>,
    fn_name: String,
}

impl<'ast> Visit<'ast> for BpsScanner {
    fn visit_expr(&mut self, node: &'ast Expr) {
        if self.guarded {
            return;
        }
        match node {
            // Binary comparison: `param <= 10_000`, `param < MAX`, etc.
            Expr::Binary(binary) => {
                use syn::BinOp;
                match binary.op {
                    BinOp::Le(_) | BinOp::Lt(_) | BinOp::Ge(_) | BinOp::Gt(_) => {
                        if expr_mentions_ident(&binary.left, &self.param)
                            || expr_mentions_ident(&binary.right, &self.param)
                        {
                            self.guarded = true;
                            return;
                        }
                    }
                    _ => {}
                }
            }
            // Method calls: `param.min(...)`, `param.clamp(...)`, etc.
            Expr::MethodCall(call) => {
                let method = call.method.to_string();
                if matches!(method.as_str(), "min" | "max" | "clamp") {
                    if expr_mentions_ident(&call.receiver, &self.param) {
                        self.guarded = true;
                        return;
                    }
                }
            }
            // Macro calls: `assert!(param <= ...)`, `require!(...)`.
            Expr::Macro(mac) => {
                let name = mac
                    .mac
                    .path
                    .segments
                    .last()
                    .map(|s| s.ident.to_string())
                    .unwrap_or_default();
                if matches!(name.as_str(), "assert" | "require" | "panic") {
                    let tokens = mac.mac.tokens.to_string();
                    if tokens.contains(&self.param) {
                        self.guarded = true;
                        return;
                    }
                }
            }
            _ => {}
        }

        visit::visit_expr(self, node);
    }
}

fn expr_mentions_ident(expr: &Expr, ident: &str) -> bool {
    if let Expr::Path(path) = expr {
        if path.path.is_ident(ident) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_file;

    fn findings_for(src: &str) -> Vec<Finding> {
        let file = parse_file(src).expect("parse");
        UnvalidatedBasisPointsCheck.run(&file, src)
    }

    #[test]
    fn unguarded_fee_bps_is_flagged() {
        let src = r#"
#[contractimpl]
impl C {
    pub fn set_fee(env: Env, fee_bps: u32) {
        env.storage().instance().set(&"fee", &fee_bps);
    }
}
"#;
        let findings = findings_for(src);
        assert!(!findings.is_empty(), "expected a finding");
        assert_eq!(findings[0].check_name, CHECK_NAME);
    }

    #[test]
    fn guarded_fee_bps_is_not_flagged() {
        let src = r#"
#[contractimpl]
impl C {
    pub fn set_fee(env: Env, fee_bps: u32) {
        assert!(fee_bps <= 10_000, "fee exceeds 100%");
        env.storage().instance().set(&"fee", &fee_bps);
    }
}
"#;
        assert!(findings_for(src).is_empty(), "expected no findings");
    }

    #[test]
    fn min_clamp_guards_are_accepted() {
        let src = r#"
#[contractimpl]
impl C {
    pub fn set_rate(env: Env, rate: u32) {
        let safe = rate.min(10_000u32);
        env.storage().instance().set(&"rate", &safe);
    }
}
"#;
        assert!(findings_for(src).is_empty(), "min() should satisfy guard");
    }

    #[test]
    fn comparison_guard_is_accepted() {
        let src = r#"
#[contractimpl]
impl C {
    pub fn set_commission(env: Env, commission: u64) {
        if commission > 10_000 {
            panic!("too high");
        }
        env.storage().instance().set(&"comm", &commission);
    }
}
"#;
        // The `>` comparison should count as a guard.
        assert!(findings_for(src).is_empty());
    }

    #[test]
    fn unrelated_params_are_not_flagged() {
        let src = r#"
#[contractimpl]
impl C {
    pub fn transfer(env: Env, amount: u128) {
        env.storage().instance().set(&"a", &amount);
    }
}
"#;
        assert!(findings_for(src).is_empty());
    }
}
