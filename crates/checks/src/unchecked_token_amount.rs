use crate::util::contractimpl_functions_excluding_test;
use crate::{Check, Finding, Severity};
use quote::ToTokens;
use syn::visit::{self, Visit};
use syn::Block;

const CHECK_NAME: &str = "unchecked-token-amount";
const TRANSFER_METHODS: &[&str] = &["transfer", "transfer_from", "xfer", "mint"];

pub struct UncheckedTokenAmountCheck;

impl Check for UncheckedTokenAmountCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &syn::File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();

        for method in contractimpl_functions_excluding_test(file) {
            // Only inspect public contract methods (private helpers are not
            // callable from the outside and should not be flagged).
            if !matches!(method.vis, syn::Visibility::Public(_)) {
                continue;
            }

            let function_name = method.sig.ident.to_string();

            // Walk all method calls inside this function body looking for
            // transfer-like calls that lack an amount guard.
            let mut visitor = TransferCallVisitor {
                function_name: function_name.clone(),
                block: &method.block,
                findings: Vec::new(),
            };
            visit::visit_block(&mut visitor, &method.block);
            out.extend(visitor.findings);
        }

        out
    }
}

/// Walks a single function body looking for transfer-like method calls that
/// are not protected by an amount guard.
struct TransferCallVisitor<'a> {
    function_name: String,
    block: &'a Block,
    findings: Vec<Finding>,
}

impl<'ast> Visit<'ast> for TransferCallVisitor<'_> {
    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        let method_name = node.method.to_string();
        if TRANSFER_METHODS.iter().any(|&m| method_name.contains(m)) {
            if !has_amount_guard(self.block) {
                self.findings.push(Finding {
                    check_name: CHECK_NAME.to_string(),
                    severity: Severity::Medium,
                    file_path: String::new(),
                    line: node.method.span().start().line,
                    function_name: self.function_name.clone(),
                    description: "Token transfer amount is not validated to be greater than zero"
                        .to_string(),
                    rule_url: Some(
                        "https://github.com/SorobanGuard/Guard-CLI/blob/main/docs/checks.md#unchecked-token-amount-medium"
                            .to_string(),
                    ),
                    suggestion: Some("Validate amount > 0 before transfer call".to_string()),
                });
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
                if ident == "amount"
                    && matches!(
                        node.op,
                        syn::BinOp::Gt(_)
                            | syn::BinOp::Ge(_)
                            | syn::BinOp::Lt(_)
                            | syn::BinOp::Le(_)
                    )
                {
                    self.found_guard = true;
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

    // --- regression tests for issue #708 ---

    /// A plain `impl` block (no `#[contractimpl]`) must never produce a
    /// finding, even when it contains transfer-like calls without amount
    /// guards.  Before the fix the whole-file visitor would walk it and flag
    /// its methods as if they were contract entry points.
    #[test]
    fn does_not_flag_plain_impl_without_contractimpl() -> Result<(), syn::Error> {
        let src = r#"
impl Helper {
    pub fn pay(token: Address, to: Address, amount: u128) {
        let client = token::Client::new(&env, &token);
        client.transfer(&to, &amount);
    }
}
        "#;
        let file = parse_file(src)?;
        let check = UncheckedTokenAmountCheck;
        let findings = check.run(&file, src);
        assert!(
            findings.is_empty(),
            "plain impl block should not be flagged, got: {:?}",
            findings
        );
        Ok(())
    }

    /// A `#[contractimpl]` impl nested inside a `#[cfg(test)]` module is
    /// test-only scaffolding and must not produce findings.  Before the fix
    /// the whole-file visitor would descend into it and flag its methods.
    #[test]
    fn does_not_flag_contractimpl_inside_cfg_test() -> Result<(), syn::Error> {
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

#[cfg(test)]
mod tests {
    use soroban_sdk::{contractimpl, Address};

    #[contractimpl]
    impl C {
        pub fn send_tokens(token: Address, to: Address, amount: u128) {
            // test mock — no amount guard intentionally
            let client = token::Client::new(&env, &token);
            client.transfer(&to, &amount);
        }
    }
}
        "#;
        let file = parse_file(src)?;
        let check = UncheckedTokenAmountCheck;
        let findings = check.run(&file, src);
        // Only the production impl (which IS guarded) should be visited → 0 findings.
        assert_eq!(
            findings.len(),
            0,
            "cfg(test) impl should not be flagged, got: {:?}",
            findings
        );
        Ok(())
    }
}
