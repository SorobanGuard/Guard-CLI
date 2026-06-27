use crate::{Check, Finding, Severity};
use syn::visit::{self, Visit};
use syn::{ExprMethodCall, File};

const CHECK_NAME: &str = "unsafe-randomness";

pub struct UnsafeRandomnessCheck;

impl Check for UnsafeRandomnessCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut visitor = RandomnessVisitor::default();
        visit::visit_file(&mut visitor, file);
        visitor.findings
    }
}

#[derive(Default)]
struct RandomnessVisitor {
    findings: Vec<Finding>,
}

impl<'ast> Visit<'ast> for RandomnessVisitor {
    fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
        let method_name = node.method.to_string();
        if method_name == "timestamp" || method_name == "sequence" {
            if is_ledger_receiver(&node.receiver) {
                self.findings.push(Finding {
                    check_name: CHECK_NAME.to_string(),
                    severity: Severity::High,
                    file_path: String::new(),
                    line: node.span().start().line,
                    function_name: String::new(),
                    description: format!(
                        "env.ledger().{}() should not be used as randomness source",
                        method_name
                    ),
                    rule_url: None,
                    fix_hint: Some(
                        "Use oracle services or cryptographic randomness instead".to_string(),
                    ),
                });
            }
        }
        visit::visit_expr_method_call(self, node);
    }
}

fn is_ledger_receiver(expr: &syn::Expr) -> bool {
    if let syn::Expr::MethodCall(method_call) = expr {
        if method_call.method == "ledger" {
            return is_env_receiver(&method_call.receiver);
        }
    }
    false
}

fn is_env_receiver(expr: &syn::Expr) -> bool {
    if let syn::Expr::Path(path) = expr {
        path.path
            .segments
            .last()
            .map(|seg| seg.ident == "env")
            .unwrap_or(false)
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_file;

    #[test]
    fn flags_ledger_timestamp() -> Result<(), syn::Error> {
        let src = r#"
#[contractimpl]
impl C {
    pub fn draw(env: Env) {
        let seed = env.ledger().timestamp();
    }
}
        "#;
        let file = parse_file(src)?;
        let check = UnsafeRandomnessCheck;
        let findings = check.run(&file, src);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].check_name, "unsafe-randomness");
        assert!(findings[0].description.contains("timestamp"));
        Ok(())
    }

    #[test]
    fn flags_ledger_sequence() -> Result<(), syn::Error> {
        let src = r#"
#[contractimpl]
impl C {
    pub fn draw(env: Env) {
        let seed = env.ledger().sequence();
    }
}
        "#;
        let file = parse_file(src)?;
        let check = UnsafeRandomnessCheck;
        let findings = check.run(&file, src);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].check_name, "unsafe-randomness");
        assert!(findings[0].description.contains("sequence"));
        Ok(())
    }

    #[test]
    fn ignores_other_methods() -> Result<(), syn::Error> {
        let src = r#"
#[contractimpl]
impl C {
    pub fn safe(env: Env) {
        let base_fee = env.ledger().base_reserve_in_stroops();
    }
}
        "#;
        let file = parse_file(src)?;
        let check = UnsafeRandomnessCheck;
        let findings = check.run(&file, src);
        assert_eq!(findings.len(), 0);
        Ok(())
    }
}
