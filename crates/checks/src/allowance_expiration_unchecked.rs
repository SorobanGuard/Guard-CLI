use crate::util::{
    contractimpl_functions_excluding_test, is_cfg_test, is_storage_mutation_call,
    receiver_chain_contains_storage,
};
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{BinOp, Expr, ExprMethodCall, FnArg, ImplItemFn, Pat};

const CHECK_NAME: &str = "allowance-expiration-unchecked";

pub struct AllowanceExpirationUncheckedCheck;

impl Check for AllowanceExpirationUncheckedCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &syn::File, _source: &str) -> Vec<Finding> {
        contractimpl_functions_excluding_test(file)
            .into_iter()
            .filter(|method| !is_cfg_test(&method.attrs))
            .filter(|method| matches!(&method.vis, syn::Visibility::Public(_)))
            .filter_map(|method| {
                let function_name = method.sig.ident.to_string();
                let approve = function_name.starts_with("approve")
                    || function_name.starts_with("increase_allowance");
                let transfer_from = function_name.starts_with("transfer_from");
                let expiration_params = expiration_parameters(method);

                let vulnerable = if approve && !expiration_params.is_empty() {
                    let mut visitor = StorageAccessVisitor::default();
                    visitor.visit_block(&method.block);
                    visitor.writes && !has_expiration_comparison(&method.block, &expiration_params)
                } else if transfer_from {
                    let mut visitor = StorageAccessVisitor::default();
                    visitor.visit_block(&method.block);
                    visitor.reads && !has_expiration_comparison(&method.block, &[])
                } else {
                    false
                };

                vulnerable.then(|| Finding {
                    check_name: CHECK_NAME.to_string(),
                    severity: Severity::Medium,
                    file_path: String::new(),
                    line: method.sig.ident.span().start().line,
                    function_name: function_name.clone(),
                    description: format!(
                        "Allowance method `{function_name}` accesses stored allowance state without checking its expiration against the current ledger."
                    ),
                    rule_url: Some(
                        "https://github.com/SorobanGuard/Guard-CLI/blob/main/docs/checks.md#allowance-expiration-unchecked-medium"
                            .to_string(),
                    ),
                    suggestion: Some(
                        "Reject expired allowances using the current ledger sequence or timestamp; allow zero-amount approvals to clear an allowance."
                            .to_string(),
                    ),
                })
            })
            .collect()
    }
}

fn expiration_parameters(method: &ImplItemFn) -> Vec<String> {
    method
        .sig
        .inputs
        .iter()
        .filter_map(|argument| {
            let FnArg::Typed(argument) = argument else {
                return None;
            };
            let Pat::Ident(pattern) = &*argument.pat else {
                return None;
            };
            let name = pattern.ident.to_string();
            is_expiration_name(&name).then_some(name)
        })
        .collect()
}

fn is_expiration_name(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    name.contains("expiration") || name.contains("expires_at") || name.contains("expiry")
}

fn has_expiration_comparison(block: &syn::Block, parameter_names: &[String]) -> bool {
    let mut visitor = ExpirationComparisonVisitor {
        parameter_names,
        found: false,
    };
    visitor.visit_block(block);
    visitor.found
}

#[derive(Default)]
struct StorageAccessVisitor {
    reads: bool,
    writes: bool,
}

impl<'ast> Visit<'ast> for StorageAccessVisitor {
    fn visit_expr_method_call(&mut self, call: &'ast ExprMethodCall) {
        if receiver_chain_contains_storage(&call.receiver) && call.method == "get" {
            self.reads = true;
        }
        if is_storage_mutation_call(call) {
            self.writes = true;
        }
        visit::visit_expr_method_call(self, call);
    }
}

struct ExpirationComparisonVisitor<'a> {
    parameter_names: &'a [String],
    found: bool,
}

impl<'ast> Visit<'ast> for ExpirationComparisonVisitor<'_> {
    fn visit_expr_binary(&mut self, binary: &'ast syn::ExprBinary) {
        if is_comparison(&binary.op) {
            let left_expiration = references_expiration(&binary.left, self.parameter_names);
            let right_expiration = references_expiration(&binary.right, self.parameter_names);
            let left_ledger = uses_ledger_time(&binary.left);
            let right_ledger = uses_ledger_time(&binary.right);
            if (left_expiration && right_ledger) || (right_expiration && left_ledger) {
                self.found = true;
            }
        }
        visit::visit_expr_binary(self, binary);
    }
}

fn is_comparison(operator: &BinOp) -> bool {
    matches!(
        operator,
        BinOp::Eq(_) | BinOp::Ne(_) | BinOp::Lt(_) | BinOp::Le(_) | BinOp::Gt(_) | BinOp::Ge(_)
    )
}

fn references_expiration(expression: &Expr, parameter_names: &[String]) -> bool {
    let mut visitor = ExpirationNameVisitor {
        parameter_names,
        found: false,
    };
    visitor.visit_expr(expression);
    visitor.found
}

struct ExpirationNameVisitor<'a> {
    parameter_names: &'a [String],
    found: bool,
}

impl<'ast> Visit<'ast> for ExpirationNameVisitor<'_> {
    fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
        if let Some(ident) = path.path.get_ident() {
            let name = ident.to_string();
            self.found |= self.parameter_names.iter().any(|parameter| parameter == &name)
                || (self.parameter_names.is_empty() && is_expiration_name(&name));
        }
        visit::visit_expr_path(self, path);
    }

    fn visit_expr_field(&mut self, field: &'ast syn::ExprField) {
        if let syn::Member::Named(name) = &field.member {
            let name = name.to_string();
            self.found |= self.parameter_names.iter().any(|parameter| parameter == &name)
                || (self.parameter_names.is_empty() && is_expiration_name(&name));
        }
        visit::visit_expr_field(self, field);
    }
}

fn uses_ledger_time(expression: &Expr) -> bool {
    let mut visitor = LedgerTimeVisitor::default();
    visitor.visit_expr(expression);
    visitor.found
}

#[derive(Default)]
struct LedgerTimeVisitor {
    found: bool,
}

impl<'ast> Visit<'ast> for LedgerTimeVisitor {
    fn visit_expr_method_call(&mut self, call: &'ast ExprMethodCall) {
        if matches!(call.method.to_string().as_str(), "sequence" | "timestamp")
            && receiver_chain_contains_ledger(&call.receiver)
        {
            self.found = true;
        }
        visit::visit_expr_method_call(self, call);
    }
}

fn receiver_chain_contains_ledger(expression: &Expr) -> bool {
    match expression {
        Expr::MethodCall(call) => {
            call.method == "ledger" || receiver_chain_contains_ledger(&call.receiver)
        }
        Expr::Field(field) => receiver_chain_contains_ledger(&field.base),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_file;

    #[test]
    fn flags_approve_that_stores_unchecked_expiration() -> Result<(), syn::Error> {
        let source = r#"
#[contractimpl]
impl Token {
    pub fn approve(env: Env, amount: i128, expiration_ledger: u32) {
        env.storage().persistent().set(&symbol_short!("allow"), &expiration_ledger);
    }
}
"#;
        let findings = AllowanceExpirationUncheckedCheck.run(&parse_file(source)?, source);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
        Ok(())
    }

    #[test]
    fn accepts_approve_with_expiry_guard_and_zero_amount_exemption() -> Result<(), syn::Error> {
        let source = r#"
#[contractimpl]
impl Token {
    pub fn approve(env: Env, amount: i128, expires_at: u64) {
        if amount == 0 {
            env.storage().persistent().remove(&symbol_short!("allow"));
        } else {
            if expires_at < env.ledger().timestamp() { panic!(); }
            env.storage().persistent().set(&symbol_short!("allow"), &expires_at);
        }
    }
}
"#;
        let findings = AllowanceExpirationUncheckedCheck.run(&parse_file(source)?, source);
        assert!(findings.is_empty());
        Ok(())
    }

    #[test]
    fn flags_transfer_from_that_reads_unchecked_allowance_expiry() -> Result<(), syn::Error> {
        let source = r#"
#[contractimpl]
impl Token {
    pub fn transfer_from(env: Env, amount: i128) {
        let allowance = env.storage().persistent().get(&symbol_short!("allow"));
        if allowance.amount >= amount { }
    }
}
"#;
        let findings = AllowanceExpirationUncheckedCheck.run(&parse_file(source)?, source);
        assert_eq!(findings.len(), 1);
        Ok(())
    }

    #[test]
    fn accepts_transfer_from_that_compares_allowance_expiry() -> Result<(), syn::Error> {
        let source = r#"
#[contractimpl]
impl Token {
    pub fn transfer_from(env: Env, amount: i128) {
        let allowance = env.storage().persistent().get(&symbol_short!("allow"));
        if allowance.expiration_ledger >= env.ledger().sequence() && allowance.amount >= amount { }
    }
}
"#;
        let findings = AllowanceExpirationUncheckedCheck.run(&parse_file(source)?, source);
        assert!(findings.is_empty());
        Ok(())
    }
}