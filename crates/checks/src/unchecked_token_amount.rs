use crate::{Check, Finding, Severity};
use syn::visit::{self, Visit};
use quote::ToTokens;
use syn::{ExprMethodCall, Block};


const CHECK_NAME: &str = "unchecked-token-amount";
const TRANSFER_METHODS: &[&str] = &["transfer", "transfer_from", "xfer", "mint"];

pub struct UncheckedTokenAmountCheck;

impl Check for UncheckedTokenAmountCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &syn::File, _source: &str) -> Vec<Finding> {
        let mut visitor = TokenAmountVisitor::default();
        visit::visit_file(&mut visitor, file);
        visitor.findings
    }
}

#[derive(Default)]
struct TokenAmountVisitor {
    findings: Vec<Finding>,
    current_block: Option<Box<Block>>,
    current_function: String,
}

impl<'ast> Visit<'ast> for TokenAmountVisitor {
    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        let prev = std::mem::replace(&mut self.current_function, node.sig.ident.to_string());
        let prev_block = std::mem::replace(&mut self.current_block, Some(Box::new(node.block.clone())));
        visit::visit_impl_item_fn(self, node);
        self.current_block = prev_block;
        self.current_function = prev;
    }

    fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
        let method_name = node.method.to_string();
        if TRANSFER_METHODS.iter().any(|&m| method_name.contains(m)) {
            if let Some(ref _block) = self.current_block {
                if !has_amount_guard(_block) {
                    self.findings.push(Finding {
                        check_name: CHECK_NAME.to_string(),
                        severity: Severity::Medium,
                        file_path: String::new(),
                        line: node.method.span().start().line,
                        function_name: self.current_function.clone(),
                        description:
                            "Token transfer amount is not validated to be greater than zero"
                                .to_string(),
                        rule_url: Some(
                            "https://github.com/SorobanGuard/Guard-CLI/blob/main/docs/checks.md#unchecked-token-amount-medium"
                                .to_string(),
                        ),
                        suggestion: Some(
                            "Validate amount > 0 before transfer call".to_string(),
                        ),
                    });
                }
            }
        }
        visit::visit_expr_method_call(self, node);
    }
}

fn has_amount_guard(block: &Block) -> bool {
    let mut visitor = AmountGuardVisitor::default();
    visit::visit_block(&mut visitor, block);
    visitor.found_guard
}

#[derive(Default)]
struct AmountGuardVisitor {
    found_guard: bool,
}

impl<'ast> Visit<'ast> for AmountGuardVisitor {
    fn visit_expr_binary(&mut self, node: &'ast syn::ExprBinary) {
        if let syn::Expr::Path(left) = &*node.left {
            if let Some(ident) = left.path.get_ident() {
                if ident == "amount" {
                    if matches!(
                        node.op,
                        syn::BinOp::Gt(_) | syn::BinOp::Ge(_) | syn::BinOp::Lt(_) | syn::BinOp::Le(_)
                    ) {
                        self.found_guard = true;
                    }
                }
            }
        }
        visit::visit_expr_binary(self, node);
    }

    fn visit_expr_if(&mut self, node: &'ast syn::ExprIf) {
        let cond_text = format!("{:?}", node.cond);
        if cond_text.contains("amount") {
            self.found_guard = true;
        }
        visit::visit_expr_if(self, node);
    }

    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        let macro_text = node.to_token_stream().to_string();
        if macro_text.contains("amount") {
            self.found_guard = true;
        }
        visit::visit_macro(self, node);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_file;

    #[test]
    fn flags_unchecked_transfer() -> Result<(), syn::Error> {
        let src = r#"
#[contractimpl]
impl C {
    pub fn send_tokens(token: Address, to: Address, amount: u128) {
        let client = token::Client::new(&env, &token);
        client.transfer(&to, &amount);
    }
}
        "#;
        let file = parse_file(src)?;
        let check = UncheckedTokenAmountCheck;
        let findings = check.run(&file, src);
        assert_eq!(findings.len(), 1);
        Ok(())
    }

    #[test]
    fn does_not_flag_guarded_transfer() -> Result<(), syn::Error> {
        let src = r#"
#[contractimpl]
impl C {
    pub fn send_tokens(token: Address, to: Address, amount: u128) {
        if amount > 0 {
            let client = token::Client::new(&env, &token);
            client.transfer(&to, &amount);
        }
    }
}
        "#;
        let file = parse_file(src)?;
        let check = UncheckedTokenAmountCheck;
        let findings = check.run(&file, src);
        assert!(findings.is_empty());
        Ok(())
    }
}
