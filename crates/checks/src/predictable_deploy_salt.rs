//! Contract deployments whose salt is a literal or constant value.

use crate::util::contractimpl_functions_excluding_test;
use crate::{Check, Finding, Severity};
use quote::ToTokens;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, File};

const CHECK_NAME: &str = "predictable-deploy-salt";

/// Flags `deployer().with_current_contract(salt)` and `deployer().with_address(addr, salt)`
/// when the salt is a literal array, a repeated literal (`[0; 32]`), or a `from_array` built
/// from one. The deployed address is derived from the salt, so a constant salt makes the
/// address predictable, and a factory reusing it can deploy only once.
pub struct PredictableDeploySaltCheck;

impl Check for PredictableDeploySaltCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions_excluding_test(file) {
            let fn_name = method.sig.ident.to_string();
            let mut v = SaltVisitor { hits: Vec::new() };
            v.visit_block(&method.block);

            for line in v.hits {
                out.push(Finding {
                    check_name: CHECK_NAME.to_string(),
                    severity: Severity::Medium,
                    file_path: String::new(),
                    line,
                    function_name: fn_name.clone(),
                    description: format!(
                        "Function `{fn_name}` deploys a contract with a literal salt. The deployed \
                         address is derived from the salt, so anyone can precompute it, and a second \
                         deployment with the same salt traps."
                    ),
                    rule_url: Some(
                        "https://github.com/SorobanGuard/Guard-CLI/blob/main/docs/checks.md#predictable-deploy-salt-medium"
                            .to_string(),
                    ),
                    suggestion: Some(
                        "Derive the salt from caller input, a counter, or `env.prng()` instead of a literal."
                            .to_string(),
                    ),
                });
            }
        }
        out
    }
}

struct SaltVisitor {
    hits: Vec<usize>,
}

impl Visit<'_> for SaltVisitor {
    fn visit_expr_method_call(&mut self, i: &ExprMethodCall) {
        let receiver = i.receiver.to_token_stream().to_string();
        if receiver.contains("deployer") {
            // `with_current_contract(salt)` takes the salt first; `with_address(addr, salt)` second.
            let salt = match i.method.to_string().as_str() {
                "with_current_contract" => i.args.first(),
                "with_address" => i.args.iter().nth(1),
                _ => None,
            };
            if salt.is_some_and(is_literal_salt) {
                self.hits.push(i.span().start().line);
            }
        }
        visit::visit_expr_method_call(self, i);
    }
}

/// `[1, 2, ...]`, `[0; 32]`, `&[..]`, or `BytesN::from_array(&env, &[..])` built only from literals.
fn is_literal_salt(expr: &Expr) -> bool {
    match expr {
        Expr::Array(a) => a.elems.iter().all(|e| matches!(e, Expr::Lit(_))),
        Expr::Repeat(r) => matches!(&*r.expr, Expr::Lit(_)),
        Expr::Reference(r) => is_literal_salt(&r.expr),
        Expr::Call(c) => c.args.last().is_some_and(is_literal_salt),
        _ => false,
    }
}
