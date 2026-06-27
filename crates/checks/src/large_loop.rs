use crate::{Check, Finding, Severity};
use syn::visit::{self, Visit};
use syn::{Expr, ImplItem, ItemImpl};

const CHECK_NAME: &str = "large-loop";

pub struct LargeLoopCheck;

impl Check for LargeLoopCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &syn::File, _source: &str) -> Vec<Finding> {
        let mut visitor = LoopVisitor::default();
        visit::visit_file(&mut visitor, file);
        visitor.findings
    }
}

#[derive(Default)]
struct LoopVisitor {
    findings: Vec<Finding>,
    in_contractimpl: bool,
}

impl<'ast> Visit<'ast> for LoopVisitor {
    fn visit_item_impl(&mut self, node: &'ast ItemImpl) {
        let was_in_contractimpl = self.in_contractimpl;
        self.in_contractimpl = has_contractimpl_attr(&node.attrs);

        for item in &node.items {
            if let ImplItem::Fn(method) = item {
                if self.in_contractimpl && method.sig.vis.is_pub() {
                    let mut loop_visitor = LoopFinder::default();
                    visit::visit_block(&mut loop_visitor, &method.block);

                    for (line, loop_type) in loop_visitor.loops {
                        self.findings.push(Finding {
                            check_name: CHECK_NAME.to_string(),
                            severity: Severity::Medium,
                            file_path: String::new(),
                            line,
                            function_name: method.sig.ident.to_string(),
                            description: format!(
                                "Unbounded {} loop can exhaust compute budget",
                                loop_type
                            ),
                            rule_url: None,
                            suggestion: Some(
                                "Use bounded iteration or add explicit break conditions"
                                    .to_string(),
                            ),
                        });
                    }
                }
            }
        }

        self.in_contractimpl = was_in_contractimpl;
        visit::visit_item_impl(self, node);
    }
}

fn has_contractimpl_attr(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        if let syn::Meta::Path(path) = &attr.meta {
            path.segments
                .last()
                .map(|seg| seg.ident == "contractimpl")
                .unwrap_or(false)
        } else {
            false
        }
    })
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
            _ => {}
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
        Ok(())
    }
}
