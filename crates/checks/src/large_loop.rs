use crate::util::contractimpl_functions_excluding_test;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::Expr;

const CHECK_NAME: &str = "large-loop";
const CROSS_CONTRACT_CHECK_NAME: &str = "cross-contract-call-in-loop";

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

                let mut cross_visitor = CrossContractCallFinder::default();
                visit::visit_block(&mut cross_visitor, &method.block);

                for (line, call) in cross_visitor.calls {
                    findings.push(Finding {
                        check_name: CROSS_CONTRACT_CHECK_NAME.to_string(),
                        severity: Severity::Medium,
                        file_path: String::new(),
                        line,
                        function_name: method.sig.ident.to_string(),
                        description: format!(
                            "Cross-contract call `{}` inside a loop can exhaust compute budget",
                            call
                        ),
                        rule_url: Some(
                            "https://github.com/SorobanGuard/Guard-CLI/blob/main/docs/checks.md#cross-contract-call-in-loop-medium"
                                .to_string(),
                        ),
                        suggestion: Some(
                            "Move the cross-contract call outside the loop or bound the iteration count"
                                .to_string(),
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
            Expr::ForLoop(_) => {
                self.loops.push((node.span().start().line, "for".to_string()));
            }
            _ => {}
        }
        visit::visit_expr(self, node);
    }
}

#[derive(Default)]
struct CrossContractCallFinder {
    calls: Vec<(usize, String)>,
    loop_depth: usize,
    skip_depth: usize,
}

impl CrossContractCallFinder {
    fn is_cross_contract_call(node: &Expr) -> Option<String> {
        let Expr::MethodCall(method) = node else {
            return None;
        };
        let name = method.method.to_string();
        if name == "invoke_contract" || name == "try_invoke_contract" {
            return Some(name);
        }
        if name == "transfer" {
            if let Expr::Path(path) = &*method.receiver {
                if let Some(segment) = path.path.segments.last() {
                    if segment.ident == "Client" {
                        return Some(format!("Client::{}", name));
                    }
                }
            }
        }
        None
    }

    fn is_small_literal_range(node: &Expr) -> bool {
        let Expr::ForLoop(for_loop) = node else {
            return false;
        };
        let Expr::Range(range) = &*for_loop.expr else {
            return false;
        };
        let (Some(start), Some(end)) = (&range.start, &range.end) else {
            return false;
        };
        let (Expr::Lit(start_lit), Expr::Lit(end_lit)) = (&**start, &**end) else {
            return false;
        };
        let (syn::Lit::Int(start_int), syn::Lit::Int(end_int)) = (&start_lit.lit, &end_lit.lit)
        else {
            return false;
        };
        let (Ok(start_val), Ok(end_val)) = (
            start_int.base10_parse::<i64>(),
            end_int.base10_parse::<i64>(),
        ) else {
            return false;
        };
        end_val.saturating_sub(start_val) <= 3
    }
}

impl<'ast> Visit<'ast> for CrossContractCallFinder {
    fn visit_expr(&mut self, node: &'ast Expr) {
        let is_loop = matches!(node, Expr::Loop(_) | Expr::While(_) | Expr::ForLoop(_));
        if is_loop {
            if Self::is_small_literal_range(node) {
                self.skip_depth += 1;
                visit::visit_expr(self, node);
                self.skip_depth -= 1;
                return;
            }
            self.loop_depth += 1;
            visit::visit_expr(self, node);
            self.loop_depth -= 1;
            return;
        }

        if self.loop_depth > 0 && self.skip_depth == 0 {
            if let Some(call) = Self::is_cross_contract_call(node) {
                self.calls.push((node.span().start().line, call));
            }
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

    #[test]
    fn flags_invoke_contract_in_loop() -> Result<(), syn::Error> {
        let src = r#"
#[contractimpl]
impl C {
    pub fn process(env: Env, ids: Vec<Address>) {
        for id in ids.iter() {
            env.invoke_contract(&id, &symbol_short!("x"), Vec::new(&env));
        }
    }
}
        "#;
        let file = parse_file(src)?;
        let check = LargeLoopCheck;
        let findings = check.run(&file, src);
        let cross: Vec<_> = findings
            .iter()
            .filter(|f| f.check_name == "cross-contract-call-in-loop")
            .collect();
        assert_eq!(cross.len(), 1);
        assert_eq!(cross[0].function_name, "process");
        assert_eq!(cross[0].line, 5);
        Ok(())
    }

    #[test]
    fn flags_token_client_transfer_in_loop() -> Result<(), syn::Error> {
        let src = r#"
#[contractimpl]
impl C {
    pub fn process(env: Env, token: Address, to: Address) {
        let client = token::Client::new(&env, &token);
        while true {
            client.transfer(&env.current_contract_address(), &to, &1);
        }
    }
}
        "#;
        let file = parse_file(src)?;
        let check = LargeLoopCheck;
        let findings = check.run(&file, src);
        let cross: Vec<_> = findings
            .iter()
            .filter(|f| f.check_name == "cross-contract-call-in-loop")
            .collect();
        assert_eq!(cross.len(), 1);
        assert_eq!(cross[0].line, 6);
        Ok(())
    }

    #[test]
    fn ignores_cross_contract_call_outside_loop() -> Result<(), syn::Error> {
        let src = r#"
#[contractimpl]
impl C {
    pub fn process(env: Env, id: Address) {
        env.invoke_contract(&id, &symbol_short!("x"), Vec::new(&env));
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
    fn ignores_small_literal_range_loop() -> Result<(), syn::Error> {
        let src = r#"
#[contractimpl]
impl C {
    pub fn process(env: Env, id: Address) {
        for _ in 0..3 {
            env.invoke_contract(&id, &symbol_short!("x"), Vec::new(&env));
        }
    }
}
        "#;
        let file = parse_file(src)?;
        let check = LargeLoopCheck;
        let findings = check.run(&file, src);
        let cross: Vec<_> = findings
            .iter()
            .filter(|f| f.check_name == "cross-contract-call-in-loop")
            .collect();
        assert_eq!(cross.len(), 0);
        Ok(())
    }

    #[test]
    fn flags_renamed_env_in_loop() -> Result<(), syn::Error> {
        let src = r#"
#[contractimpl]
impl C {
    pub fn process(e: Env, ids: Vec<Address>) {
        for id in ids.iter() {
            e.try_invoke_contract(&id, &symbol_short!("x"), Vec::new(&e));
        }
    }
}
        "#;
        let file = parse_file(src)?;
        let check = LargeLoopCheck;
        let findings = check.run(&file, src);
        let cross: Vec<_> = findings
            .iter()
            .filter(|f| f.check_name == "cross-contract-call-in-loop")
            .collect();
        assert_eq!(cross.len(), 1);
        assert_eq!(cross[0].line, 5);
        Ok(())
    }
}
