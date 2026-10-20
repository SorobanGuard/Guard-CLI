use crate::util::contractimpl_functions_excluding_test;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::Expr;

const CHECK_NAME: &str = "large-loop";

pub struct LargeLoopCheck;

impl Check for LargeLoopCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &syn::File, _source: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        for method in contractimpl_functions_excluding_test(file) {
            if matches!(method.vis, syn::Visibility::Public(_)) {
                let mut loop_visitor = LoopFinder::default();
                visit::visit_block(&mut loop_visitor, &method.block);

                for (line, loop_type) in loop_visitor.loops {
                    findings.push(Finding {
                        check_name: CHECK_NAME.to_string(),
                        severity: Severity::Medium,
                        file_path: String::new(),
                        line,
                        function_name: method.sig.ident.to_string(),
                        description: format!("Unbounded {} loop can exhaust compute budget", loop_type),
                        rule_url: Some(
                            "https://github.com/SorobanGuard/Guard-CLI/blob/main/docs/checks.md#large-loop-medium"
                                .to_string(),
                        ),
                        suggestion: Some(
                            "Use bounded iteration or add explicit break conditions".to_string(),
                        ),
                    });
                }
            }
        }
        findings
    }
}

#[derive(Default)]
struct LoopFinder {
    loops: Vec<(usize, String)>,
}

impl<'ast> Visit<'ast> for LoopFinder {
    fn visit_expr(&mut self, node: &'ast Expr) {
        match node {
            Expr::Loop(_) => {
                self.loops.push((node.span().start().line, "loop".to_string()));
            }
            Expr::While(_) => {
                self.loops.push((node.span().start().line, "while".to_string()));
            }
            Expr::ForLoop(for_loop) => {
                if !is_literal_bounded_range(&for_loop.expr) {
                    self.loops.push((node.span().start().line, "for".to_string()));
                }
            }
            _ => {}
        }
        visit::visit_expr(self, node);
    }
}

/// A `for` loop over a range whose both ends are integer literals (`0..10`, `1..=8`) has a
/// compile-time iteration count and cannot be driven by caller input.
fn is_literal_bounded_range(expr: &Expr) -> bool {
    match expr {
        Expr::Paren(p) => is_literal_bounded_range(&p.expr),
        Expr::Range(range) => {
            let is_int_lit = |e: &Option<Box<Expr>>| {
                matches!(
                    e.as_deref(),
                    Some(Expr::Lit(syn::ExprLit { lit: syn::Lit::Int(_), .. }))
                )
            };
            is_int_lit(&range.start) && is_int_lit(&range.end)
        }
        _ => false,
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

    #[test]
    fn flags_for_over_caller_controlled_range() -> Result<(), syn::Error> {
        let src = r#"
#[contractimpl]
impl C {
    pub fn process(env: Env, count: u32) {
        for i in 0..count {
            env.storage().instance().set(&symbol_short!("x"), &i);
        }
    }
}
        "#;
        let file = parse_file(src)?;
        let findings = LargeLoopCheck.run(&file, src);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].line, 5);
        Ok(())
    }

    #[test]
    fn ignores_for_over_literal_bounded_range() -> Result<(), syn::Error> {
        let src = r#"
#[contractimpl]
impl C {
    pub fn process(env: Env) {
        for i in 0..10u32 {
            env.storage().instance().set(&symbol_short!("x"), &i);
        }
        for j in 1..=4 {
            let _ = j;
        }
    }
}
        "#;
        let file = parse_file(src)?;
        assert!(LargeLoopCheck.run(&file, src).is_empty());
        Ok(())
    }
}
