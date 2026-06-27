//! Detect `env.require_auth()` called *after* a storage write in `#[contractimpl]` methods.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Block, Expr, ExprMethodCall, File, FnArg, Pat, Type};

const CHECK_NAME: &str = "auth-after-storage-write";

/// Flags `#[contractimpl]` methods where `env.require_auth()` is called after a
/// storage write rather than before it.
pub struct AuthAfterStorageWriteCheck;

impl Check for AuthAfterStorageWriteCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let env_param = env_param_name(&method.sig);
            let env_name = env_param.as_deref().unwrap_or("env");
            let write_line = first_storage_write_line(&method.block);
            let auth_line = first_require_auth_line(&method.block, env_name);
            if let (Some(write), Some(auth)) = (write_line, auth_line) {
                if write < auth {
                    let fn_name = method.sig.ident.to_string();
                    out.push(Finding {
                        check_name: CHECK_NAME.to_string(),
                        severity: Severity::High,
                        file_path: String::new(),
                        line: write,
                        function_name: fn_name.clone(),
                        description: format!(
                            "Method `{fn_name}` calls `{env_name}.require_auth()` on line {auth} \
                             but already wrote to storage on line {write}. State was mutated \
                             before the caller was authorized."
                        ),
                        rule_url: Some(
                            "https://github.com/SorobanGuard/Guard-CLI/blob/main/docs/checks.md#auth-after-storage-write-high"
                                .to_string(),
                        ),
                        suggestion: Some(format!(
                            "Move `{env_name}.require_auth()` to the very first line of `{fn_name}`."
                        )),
                    });
                }
            }
        }
        out
    }
}

fn env_param_name(sig: &syn::Signature) -> Option<String> {
    for arg in &sig.inputs {
        let FnArg::Typed(pat_type) = arg else {
            continue;
        };
        if !type_is_env(&pat_type.ty) {
            continue;
        }
        if let Pat::Ident(ident) = &*pat_type.pat {
            return Some(ident.ident.to_string());
        }
    }
    None
}

fn type_is_env(ty: &Type) -> bool {
    let Type::Path(tp) = ty else {
        return false;
    };
    tp.path.segments.last().is_some_and(|s| s.ident == "Env")
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

fn is_storage_mutation_call(m: &ExprMethodCall) -> bool {
    let name = m.method.to_string();
    if !matches!(name.as_str(), "set" | "remove" | "extend_ttl" | "bump" | "append") {
        return false;
    }
    receiver_chain_contains_storage(&m.receiver)
}

fn is_env_require_auth(m: &ExprMethodCall, env_name: &str) -> bool {
    if m.method != "require_auth" && m.method != "require_auth_for_args" {
        return false;
    }
    match &*m.receiver {
        Expr::Path(p) => p.path.is_ident(env_name),
        _ => false,
    }
}

struct FirstStorageWrite {
    line: Option<usize>,
}

impl<'ast> Visit<'ast> for FirstStorageWrite {
    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        if self.line.is_none() && is_storage_mutation_call(i) {
            self.line = Some(i.span().start().line);
        }
        visit::visit_expr_method_call(self, i);
    }
}

fn first_storage_write_line(block: &Block) -> Option<usize> {
    let mut v = FirstStorageWrite { line: None };
    v.visit_block(block);
    v.line
}

struct FirstRequireAuth {
    line: Option<usize>,
    env_name: String,
}

impl<'ast> Visit<'ast> for FirstRequireAuth {
    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        if self.line.is_none() && is_env_require_auth(i, &self.env_name) {
            self.line = Some(i.span().start().line);
        }
        visit::visit_expr_method_call(self, i);
    }
}

fn first_require_auth_line(block: &Block, env_name: &str) -> Option<usize> {
    let mut v = FirstRequireAuth {
        line: None,
        env_name: env_name.to_string(),
    };
    v.visit_block(block);
    v.line
}
