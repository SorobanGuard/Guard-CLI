//! Detect `require_auth_for_args` calls that do not bind all value-affecting
//! parameters, allowing a relayer to redirect or tamper with the transaction
//! (closes #978).

use crate::{Check, Finding, Severity};
use std::collections::HashSet;
use syn::spanned::Spanned;
use syn::{
    visit::{self, Visit},
    Expr, ExprMethodCall, File, FnArg, ImplItemFn, Item, Pat, PatType,
};

const CHECK_NAME: &str = "require-auth-for-args-partial-binding";

pub struct RequireAuthForArgsPartialBindingCheck;

impl Check for RequireAuthForArgsPartialBindingCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        for item in &file.items {
            if let Item::Impl(imp) = item {
                if !has_contractimpl_attr(&imp.attrs) {
                    continue;
                }
                for impl_item in &imp.items {
                    if let syn::ImplItem::Fn(m) = impl_item {
                        check_method(m, &mut findings);
                    }
                }
            }
        }

        findings
    }
}

fn has_contractimpl_attr(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|a| {
        a.path()
            .segments
            .last()
            .map(|s| s.ident == "contractimpl")
            .unwrap_or(false)
    })
}

/// Names of parameters that are NOT `Env` and whose bindings are worth checking.
fn value_params(m: &ImplItemFn) -> Vec<String> {
    m.sig
        .inputs
        .iter()
        .filter_map(|arg| {
            if let FnArg::Typed(PatType { pat, ty, .. }) = arg {
                // Skip `env: Env`-shaped parameters.
                let type_str = quote_type(ty);
                if type_str.ends_with("Env") {
                    return None;
                }
                if let Pat::Ident(pi) = pat.as_ref() {
                    // skip `self`-looking idents
                    if pi.ident == "self" {
                        return None;
                    }
                    return Some(pi.ident.to_string());
                }
            }
            None
        })
        .collect()
}

fn quote_type(ty: &syn::Type) -> String {
    match ty {
        syn::Type::Path(tp) => tp
            .path
            .segments
            .last()
            .map(|s| s.ident.to_string())
            .unwrap_or_default(),
        _ => String::new(),
    }
}

struct ArgsVisitor {
    /// Identifiers found inside `require_auth_for_args(...)` call arguments.
    bound_params: HashSet<String>,
    /// Source line of the `require_auth_for_args` call.
    call_line: Option<usize>,
}

impl<'ast> Visit<'ast> for ArgsVisitor {
    fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
        if node.method == "require_auth_for_args" {
            self.call_line = Some(node.span().start().line);
            // Collect identifier names used anywhere inside the call arguments.
            for arg in &node.args {
                collect_idents(arg, &mut self.bound_params);
            }
        }
        visit::visit_expr_method_call(self, node);
    }
}

fn collect_idents(expr: &Expr, out: &mut HashSet<String>) {
    match expr {
        Expr::Path(p) => {
            if let Some(seg) = p.path.segments.last() {
                out.insert(seg.ident.to_string());
            }
        }
        Expr::Tuple(t) => {
            for e in &t.elems {
                collect_idents(e, out);
            }
        }
        Expr::Call(c) => {
            for a in &c.args {
                collect_idents(a, out);
            }
        }
        Expr::MethodCall(mc) => {
            collect_idents(&mc.receiver, out);
            for a in &mc.args {
                collect_idents(a, out);
            }
        }
        Expr::Reference(r) => collect_idents(&r.expr, out),
        _ => {}
    }
}

fn check_method(m: &ImplItemFn, findings: &mut Vec<Finding>) {
    let params = value_params(m);
    if params.is_empty() {
        return;
    }

    let mut visitor = ArgsVisitor {
        bound_params: HashSet::new(),
        call_line: None,
    };
    visitor.visit_impl_item_fn(m);

    // If there is no `require_auth_for_args` call, this check is not applicable
    // (a different check covers missing `require_auth`).
    let call_line = match visitor.call_line {
        Some(l) => l,
        None => return,
    };

    let unbound: Vec<&str> = params
        .iter()
        .filter(|p| !visitor.bound_params.contains(p.as_str()))
        .map(String::as_str)
        .collect();

    if unbound.is_empty() {
        return;
    }

    findings.push(Finding {
        check_name: CHECK_NAME.to_string(),
        severity: Severity::High,
        file_path: String::new(),
        line: call_line,
        function_name: m.sig.ident.to_string(),
        description: format!(
            "`require_auth_for_args` in `{}` does not bind parameter(s): {}. \
            A relayer can substitute those values, potentially redirecting funds \
            or bypassing authorization.",
            m.sig.ident,
            unbound.join(", ")
        ),
        rule_url: Some(
            "https://github.com/SorobanGuard/Guard-CLI/blob/main/docs/checks.md\
            #require-auth-for-args-partial-binding-high"
                .to_string(),
        ),
        suggestion: Some(format!(
            "Include {} in the `require_auth_for_args` arguments tuple, or \
            switch to `require_auth` to authorize all parameters implicitly.",
            unbound.join(", ")
        )),
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_file;

    fn run(src: &str) -> Vec<Finding> {
        let file = parse_file(src).expect("parse");
        RequireAuthForArgsPartialBindingCheck.run(&file, src)
    }

    #[test]
    fn flags_when_destination_not_bound() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env, Address};
pub struct Token;
#[contractimpl]
impl Token {
    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        from.require_auth_for_args((amount,).into_val(&env));
    }
}
"#);
        assert!(!hits.is_empty(), "should flag unbound `to`");
        assert_eq!(hits[0].check_name, CHECK_NAME);
        assert_eq!(hits[0].severity, Severity::High);
        assert!(hits[0].description.contains("to"), "description must mention unbound param");
    }

    #[test]
    fn passes_when_all_params_bound() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env, Address};
pub struct Token;
#[contractimpl]
impl Token {
    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        from.require_auth_for_args((to.clone(), amount).into_val(&env));
    }
}
"#);
        assert!(hits.is_empty(), "all params bound → no finding");
    }

    #[test]
    fn passes_when_no_require_auth_for_args_call() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env, Address};
pub struct Token;
#[contractimpl]
impl Token {
    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        from.require_auth();
    }
}
"#);
        assert!(hits.is_empty());
    }

    #[test]
    fn passes_outside_contractimpl() {
        let hits = run(r#"
use soroban_sdk::{Env, Address};
fn helper(env: Env, from: Address, to: Address, amount: i128) {
    from.require_auth_for_args((amount,).into_val(&env));
}
"#);
        assert!(hits.is_empty(), "only contractimpl methods should be checked");
    }
}
