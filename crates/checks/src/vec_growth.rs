//! Flags `#[contractimpl]` methods that read a Vec from storage, push to it, and write it
//! back without any length cap, which can brick the contract once the ledger entry size
//! limit is exceeded.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, File};

const CHECK_NAME: &str = "unbounded-vec-growth";

pub struct UnboundedVecGrowthCheck;

impl Check for UnboundedVecGrowthCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            let mut scan = BodyScan::default();
            scan.visit_block(&method.block);
            if scan.has_storage_get
                && scan.has_push_or_append
                && scan.has_storage_set
                && !scan.has_len_check
            {
                let line = scan
                    .push_line
                    .unwrap_or_else(|| method.sig.ident.span().start().line);
                out.push(Finding {
                    check_name: CHECK_NAME.to_string(),
                    severity: Severity::Medium,
                    file_path: String::new(),
                    line,
                    function_name: fn_name.clone(),
                    description: format!(
                        "Function `{fn_name}` reads a Vec from storage, appends to it, and writes \
                         it back without a length cap. The ledger entry will eventually exceed \
                         Soroban's size limit, bricking the contract."
                    ),
                    rule_url: Some(
                        "https://github.com/SorobanGuard/Guard-CLI/blob/main/docs/checks.md#unbounded-vec-growth-medium"
                            .to_string(),
                    ),
                    suggestion: Some(
                        "Enforce a maximum length before pushing, e.g. \
                         `require!(vec.len() < MAX_SIZE, \"capacity exceeded\");`."
                            .to_string(),
                    ),
                });
            }
        }
        out
    }
}

fn receiver_chain_contains_storage(expr: &Expr) -> bool {
    match expr {
        Expr::MethodCall(m) => {
            if m.method == "storage" {
                return true;
            }
            receiver_chain_contains_storage(&m.receiver)
        }
        Expr::Field(f) => receiver_chain_contains_storage(&f.base),
        _ => false,
    }
}

#[derive(Default)]
struct BodyScan {
    has_storage_get: bool,
    has_push_or_append: bool,
    has_storage_set: bool,
    has_len_check: bool,
    push_line: Option<usize>,
}

impl<'ast> Visit<'ast> for BodyScan {
    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        let method = i.method.to_string();
        if method == "get" && receiver_chain_contains_storage(&i.receiver) {
            self.has_storage_get = true;
        }
        if method == "set" && receiver_chain_contains_storage(&i.receiver) {
            self.has_storage_set = true;
        }
        if matches!(method.as_str(), "push" | "push_back" | "append") {
            self.has_push_or_append = true;
            if self.push_line.is_none() {
                self.push_line = Some(i.method.span().start().line);
            }
        }
        if method == "len" {
            self.has_len_check = true;
        }
        visit::visit_expr_method_call(self, i);
    }
}
