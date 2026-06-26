//! Reentrancy-risk: `invoke_contract` after a storage write without a re-read.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, File};

const CHECK_NAME: &str = "reentrancy-risk";

/// Flags `#[contractimpl]` methods that call `invoke_contract` or
/// `invoke_contract_check` after a storage write (`set`, `remove`, `extend_ttl`,
/// `bump`, `append`) without reading state again first.
pub struct ReentrancyRiskCheck;

impl Check for ReentrancyRiskCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            let mut v = ReentrancyVisitor::default();
            v.visit_block(&method.block);
            if let Some(line) = v.invoke_after_write_line {
                out.push(Finding {
                    check_name: CHECK_NAME.to_string(),
                    severity: Severity::High,
                    file_path: String::new(),
                    line,
                    function_name: fn_name.clone(),
                    description: format!(
                        "Method `{fn_name}` calls `invoke_contract` after a storage write. \
                         The callee is an untrusted contract that may re-enter this contract \
                         before state is finalised. Perform all external calls before writing \
                         storage (checks-effects-interactions) or re-read state after the call."
                    ),
                    rule_url: Some(
                        "https://github.com/SorobanGuard/Guard-CLI/blob/main/docs/checks.md#reentrancy-risk-high"
                            .to_string(),
                    ),
                    suggestion: None,
                });
            }
        }
        out
    }
}

fn is_storage_write(m: &ExprMethodCall) -> bool {
    let name = m.method.to_string();
    if !matches!(
        name.as_str(),
        "set" | "remove" | "extend_ttl" | "bump" | "append"
    ) {
        return false;
    }
    receiver_has_storage(&m.receiver)
}

fn receiver_has_storage(expr: &Expr) -> bool {
    match expr {
        Expr::MethodCall(m) => m.method == "storage" || receiver_has_storage(&m.receiver),
        Expr::Field(f) => receiver_has_storage(&f.base),
        _ => false,
    }
}

fn is_storage_read(m: &ExprMethodCall) -> bool {
    let name = m.method.to_string();
    if !matches!(name.as_str(), "get" | "get_unchecked" | "has") {
        return false;
    }
    receiver_has_storage(&m.receiver)
}

fn is_invoke_contract(m: &ExprMethodCall) -> bool {
    matches!(
        m.method.to_string().as_str(),
        "invoke_contract" | "invoke_contract_check"
    )
}

#[derive(Default)]
struct ReentrancyVisitor {
    wrote: bool,
    re_read_after_write: bool,
    invoke_after_write_line: Option<usize>,
}

impl<'ast> Visit<'ast> for ReentrancyVisitor {
    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        if is_storage_write(i) {
            self.wrote = true;
            self.re_read_after_write = false;
        } else if self.wrote && is_storage_read(i) {
            self.re_read_after_write = true;
        } else if self.wrote && !self.re_read_after_write && is_invoke_contract(i) {
            if self.invoke_after_write_line.is_none() {
                self.invoke_after_write_line = Some(i.span().start().line);
            }
        }
        visit::visit_expr_method_call(self, i);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Check;
    use syn::parse_file;

    fn run(src: &str) -> Vec<Finding> {
        let file = parse_file(src).expect("parse");
        ReentrancyRiskCheck.run(&file, src)
    }

    #[test]
    fn flags_invoke_after_write() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env, Address};

pub struct C;

#[contractimpl]
impl C {
    pub fn transfer(env: Env, to: Address, amount: i128) {
        env.storage().persistent().set(&to, &amount);
        env.invoke_contract::<()>(&to, &soroban_sdk::symbol_short!("cb"), soroban_sdk::vec![&env]);
    }
}
"#);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::High);
    }

    #[test]
    fn passes_invoke_before_write() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env, Address};

pub struct C;

#[contractimpl]
impl C {
    pub fn transfer(env: Env, to: Address, amount: i128) {
        env.invoke_contract::<()>(&to, &soroban_sdk::symbol_short!("cb"), soroban_sdk::vec![&env]);
        env.storage().persistent().set(&to, &amount);
    }
}
"#);
        assert!(hits.is_empty());
    }

    #[test]
    fn passes_re_read_before_invoke() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env, Address};

pub struct C;

#[contractimpl]
impl C {
    pub fn transfer(env: Env, to: Address) {
        env.storage().persistent().set(&to, &42i128);
        let _v: i128 = env.storage().persistent().get(&to).unwrap();
        env.invoke_contract::<()>(&to, &soroban_sdk::symbol_short!("cb"), soroban_sdk::vec![&env]);
    }
}
"#);
        assert!(hits.is_empty());
    }

    #[test]
    fn ignores_non_contractimpl() {
        let hits = run(r#"
use soroban_sdk::{Env, Address};

pub struct C;

impl C {
    pub fn transfer(env: Env, to: Address, amount: i128) {
        env.storage().persistent().set(&to, &amount);
        env.invoke_contract::<()>(&to, &soroban_sdk::symbol_short!("cb"), soroban_sdk::vec![&env]);
    }
}
"#);
        assert!(hits.is_empty());
    }
}
