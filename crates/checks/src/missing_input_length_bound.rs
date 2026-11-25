use crate::util::contractimpl_functions_excluding_test;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{FnArg, Pat};

const CHECK_NAME: &str = "missing-input-length-bound";

pub struct MissingInputLengthBoundCheck;

impl Check for MissingInputLengthBoundCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &syn::File, _source: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        for method in contractimpl_functions_excluding_test(file) {
            if matches!(method.vis, syn::Visibility::Public(_)) {
                let bytes_vec_params = find_bytes_vec_params(&method.sig.inputs);
                for (param_name, _) in bytes_vec_params {
                    if !has_length_check(&method.block, &param_name) {
                        findings.push(Finding {
                            check_name: CHECK_NAME.to_string(),
                            severity: Severity::Medium,
                            file_path: String::new(),
                            line: method.sig.fn_token.span().start().line,
                            function_name: method.sig.ident.to_string(),
                            description: format!(
                                "Parameter `{}` (Bytes/Vec) lacks length validation",
                                param_name
                            ),
                            rule_url: Some(
                                "https://github.com/SorobanGuard/Guard-CLI/blob/main/docs/checks.md#missing-input-length-bound-medium"
                                    .to_string(),
                            ),
                            suggestion: Some(
                                "Add an upper-bound check: assert!(data.len() <= MAX) or if data.len() > MAX { panic!(…) }"
                                    .to_string(),
                            ),
                        });
                    }
                }
            }
        }
        findings
    }
}

fn find_bytes_vec_params(
    inputs: &syn::punctuated::Punctuated<FnArg, syn::token::Comma>,
) -> Vec<(String, String)> {
    let mut params = Vec::new();
    for arg in inputs {
        if let FnArg::Typed(pat_type) = arg {
            if let Some(ty_name) = unbounded_collection_type_name(&pat_type.ty) {
                if let Pat::Ident(pat_ident) = &*pat_type.pat {
                    params.push((pat_ident.ident.to_string(), ty_name.to_string()));
                }
            }
        }
    }
    params
}

/// Peels `&`/`&mut` references and parens off a type so `&Bytes` matches like `Bytes`.
fn unwrap_type(ty: &syn::Type) -> &syn::Type {
    match ty {
        syn::Type::Reference(r) => unwrap_type(&r.elem),
        syn::Type::Paren(p) => unwrap_type(&p.elem),
        syn::Type::Group(g) => unwrap_type(&g.elem),
        _ => ty,
    }
}

/// Returns `"Bytes"` / `"Vec"` when `ty`'s last path segment is one of those
/// unbounded, runtime-length collection types.  Fixed-length types such as
/// `BytesN<32>` are intentionally excluded.
fn unbounded_collection_type_name(ty: &syn::Type) -> Option<&'static str> {
    let syn::Type::Path(type_path) = unwrap_type(ty) else {
        return None;
    };
    match type_path.path.segments.last()?.ident.to_string().as_str() {
        "Bytes" => Some("Bytes"),
        "Vec" => Some("Vec"),
        _ => None,
    }
}

// ── Length-check predicate ────────────────────────────────────────────────────

/// Return `true` when `expr` is `<param_name>.len()` with no arguments.
fn is_param_len_call(expr: &syn::Expr, param_name: &str) -> bool {
    if let syn::Expr::MethodCall(mc) = expr {
        if mc.method == "len" && mc.args.is_empty() {
            if let syn::Expr::Path(p) = &*mc.receiver {
                if let Some(id) = p.path.get_ident() {
                    return id == param_name;
                }
            }
        }
    }
    false
}

/// Return `true` when `expr` is a bound comparison (`<`, `<=`, `>`, `>=`) where
/// one operand is `<param_name>.len()`.
fn is_bound_comparison(expr: &syn::Expr, param_name: &str) -> bool {
    if let syn::Expr::Binary(bin) = expr {
        if matches!(
            bin.op,
            syn::BinOp::Lt(_) | syn::BinOp::Le(_) | syn::BinOp::Gt(_) | syn::BinOp::Ge(_)
        ) {
            return is_param_len_call(&bin.left, param_name)
                || is_param_len_call(&bin.right, param_name);
        }
    }
    false
}

/// Return `true` when any sub-expression within `expr` is a bound comparison on
/// `param_name` (recurses into `&&` / `||` and parentheses).
fn contains_bound_comparison(expr: &syn::Expr, param_name: &str) -> bool {
    if is_bound_comparison(expr, param_name) {
        return true;
    }
    if let syn::Expr::Binary(bin) = expr {
        if matches!(bin.op, syn::BinOp::And(_) | syn::BinOp::Or(_)) {
            return contains_bound_comparison(&bin.left, param_name)
                || contains_bound_comparison(&bin.right, param_name);
        }
    }
    if let syn::Expr::Paren(p) = expr {
        return contains_bound_comparison(&p.expr, param_name);
    }
    false
}

/// Return `true` when a bound comparison on `param_name` appears anywhere inside
/// the comma-separated token stream of a guard macro (e.g. `assert!(data.len() <= MAX)`).
fn macro_tokens_contain_bound_comparison(
    tokens: proc_macro2::TokenStream,
    param_name: &str,
) -> bool {
    if let Ok(exprs) = syn::parse2::<ExprListWrapper>(tokens) {
        return exprs
            .0
            .iter()
            .any(|e| contains_bound_comparison(e, param_name));
    }
    false
}

/// Thin newtype so we can implement `syn::parse::Parse` for a comma-separated
/// expression list without a foreign-trait conflict.
struct ExprListWrapper(syn::punctuated::Punctuated<syn::Expr, syn::Token![,]>);

impl syn::parse::Parse for ExprListWrapper {
    fn parse(input: syn::parse::ParseStream<'_>) -> syn::Result<Self> {
        Ok(ExprListWrapper(
            syn::punctuated::Punctuated::parse_terminated(input)?,
        ))
    }
}

/// Walk the block's AST and return `true` when a genuine upper-bound length guard
/// on `param_name` is found.
///
/// **Accepted** — `param_name.len()` used in an ordering comparison (`<`, `<=`,
/// `>`, `>=`) inside:
/// - an `if` / `else if` condition, or
/// - an `assert!`, `assert_eq!`, `assert_ne!`, `require!`, or `panic_with_error!`
///   macro argument list.
///
/// **Not accepted:**
/// - bare `param_name.len()` used only as a value (loop bound, log argument, etc.)
/// - `param_name.is_empty()` — only signals zero length, not an upper bound
fn has_length_check(block: &syn::Block, param_name: &str) -> bool {
    let mut visitor = LengthCheckVisitor {
        param_name,
        found: false,
    };
    visit::visit_block(&mut visitor, block);
    visitor.found
}

struct LengthCheckVisitor<'a> {
    param_name: &'a str,
    found: bool,
}

impl<'ast, 'a> Visit<'ast> for LengthCheckVisitor<'a> {
    fn visit_expr_if(&mut self, node: &'ast syn::ExprIf) {
        if self.found {
            return;
        }
        // Accept any `if` whose condition contains a bound comparison on the param.
        if contains_bound_comparison(&node.cond, self.param_name) {
            self.found = true;
            return;
        }
        visit::visit_expr_if(self, node);
    }

    fn visit_expr_macro(&mut self, node: &'ast syn::ExprMacro) {
        if self.found {
            return;
        }
        let mac = &node.mac;
        let last_seg = mac.path.segments.last().map(|s| s.ident.to_string());
        let is_guard = last_seg.as_deref().map_or(false, |s| {
            matches!(
                s,
                "assert" | "assert_eq" | "assert_ne" | "require" | "panic_with_error"
            )
        });
        if is_guard
            && macro_tokens_contain_bound_comparison(mac.tokens.clone(), self.param_name)
        {
            self.found = true;
            return;
        }
        visit::visit_expr_macro(self, node);
    }

    fn visit_stmt_macro(&mut self, node: &'ast syn::StmtMacro) {
        if self.found {
            return;
        }
        let mac = &node.mac;
        let last_seg = mac.path.segments.last().map(|s| s.ident.to_string());
        let is_guard = last_seg.as_deref().map_or(false, |s| {
            matches!(
                s,
                "assert" | "assert_eq" | "assert_ne" | "require" | "panic_with_error"
            )
        });
        if is_guard
            && macro_tokens_contain_bound_comparison(mac.tokens.clone(), self.param_name)
        {
            self.found = true;
            return;
        }
        visit::visit_stmt_macro(self, node);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_file;

    fn run(src: &str) -> Vec<Finding> {
        let file = parse_file(src).expect("parse error");
        MissingInputLengthBoundCheck.run(&file, src)
    }

    // ── original passing tests (kept) ────────────────────────────────────────

    #[test]
    fn flags_unbounded_bytes() {
        let src = r#"
#[contractimpl]
impl C {
    pub fn process(env: Env, data: Bytes) {
        let x = data;
    }
}
        "#;
        assert_eq!(run(src).len(), 1);
    }

    #[test]
    fn does_not_flag_when_length_checked_in_if() {
        let src = r#"
#[contractimpl]
impl C {
    pub fn process(env: Env, data: Bytes) {
        if data.len() > 1000 {
            panic!("input too long");
        }
        let x = data;
    }
}
        "#;
        assert!(run(src).is_empty());
    }

    #[test]
    fn ignores_fixed_size_bytes_n() {
        let src = r#"
#[contractimpl]
impl C {
    pub fn process(env: Env, data: BytesN<32>) {
        let x = data;
    }
}
        "#;
        assert_eq!(run(src).len(), 0);
    }

    #[test]
    fn reports_fn_line_not_doc_comment_line() -> Result<(), syn::Error> {
        let src = r#"
#[contractimpl]
impl C {
    /// Process some data.
    #[some_attr]
    pub fn process(env: Env, data: Bytes) {
        let x = data;
    }
}
        "#;
        let findings = run(src);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].line, 6);
        Ok(())
    }

    /// Regression test for #665: an unrelated receiver whose name ends with the
    /// param name must not be mistaken for a length check on that param.
    #[test]
    fn does_not_flag_false_negative_from_unrelated_receiver() {
        // `matrix.len()` must NOT count as a length check for the `x` parameter.
        let src = r#"
#[contractimpl]
impl C {
    pub fn process(env: Env, x: Bytes, matrix: Vec<u32>) {
        let _ = matrix.len();
    }
}
        "#;
        let findings = run(src);
        assert!(
            findings.iter().any(|f| f.description.contains("`x`")),
            "x should be flagged as unchecked"
        );
    }

    // ── new tests for issue #1069 ─────────────────────────────────────────────

    /// A bare `data.len()` used only as a value (loop counter, log arg, etc.)
    /// must NOT suppress the finding — it provides no upper bound.
    #[test]
    fn bare_len_call_does_not_suppress() {
        let src = r#"
#[contractimpl]
impl C {
    pub fn process(env: Env, data: Bytes) {
        let n = data.len();
        for i in 0..n { }
    }
}
        "#;
        assert_eq!(
            run(src).len(),
            1,
            "bare data.len() used only as a value must still flag"
        );
    }

    /// `data.len()` passed to log!/a function call must NOT suppress.
    #[test]
    fn len_in_log_call_does_not_suppress() {
        let src = r#"
#[contractimpl]
impl C {
    pub fn process(env: Env, data: Bytes) {
        log!("length: {}", data.len());
        env.storage().instance().set(&K, &data);
    }
}
        "#;
        assert_eq!(
            run(src).len(),
            1,
            "data.len() inside a log! must still flag"
        );
    }

    /// `data.is_empty()` alone does NOT provide an upper bound — must still flag.
    #[test]
    fn is_empty_alone_does_not_suppress() {
        let src = r#"
#[contractimpl]
impl C {
    pub fn process(env: Env, data: Bytes) {
        if data.is_empty() {
            return;
        }
        env.storage().instance().set(&K, &data);
    }
}
        "#;
        assert_eq!(
            run(src).len(),
            1,
            "is_empty() alone must not suppress: it only checks for zero length"
        );
    }

    /// `assert!(data.len() <= MAX)` is the canonical upper-bound guard — must suppress.
    #[test]
    fn assert_with_len_le_suppresses() {
        let src = r#"
#[contractimpl]
impl C {
    pub fn process(env: Env, data: Bytes) {
        assert!(data.len() <= 1024);
        env.storage().instance().set(&K, &data);
    }
}
        "#;
        assert!(
            run(src).is_empty(),
            "assert!(data.len() <= MAX) must suppress the finding"
        );
    }

    /// `assert!(data.len() < MAX)` — strict upper bound, must suppress.
    #[test]
    fn assert_with_len_lt_suppresses() {
        let src = r#"
#[contractimpl]
impl C {
    pub fn process(env: Env, data: Bytes) {
        assert!(data.len() < 1024);
    }
}
        "#;
        assert!(run(src).is_empty());
    }

    /// `if data.len() <= MAX { } else { panic!() }` — bound in if condition.
    #[test]
    fn if_with_len_le_suppresses() {
        let src = r#"
#[contractimpl]
impl C {
    pub fn process(env: Env, data: Bytes) {
        if data.len() <= 512 {
            env.storage().instance().set(&K, &data);
        } else {
            panic!("too large");
        }
    }
}
        "#;
        assert!(
            run(src).is_empty(),
            "if data.len() <= MAX must suppress the finding"
        );
    }

    /// `require!(data.len() <= MAX, "too long")` — Soroban guard macro.
    #[test]
    fn require_macro_with_len_bound_suppresses() {
        let src = r#"
#[contractimpl]
impl C {
    pub fn process(env: Env, data: Bytes) {
        require!(data.len() <= 256, "input too long");
    }
}
        "#;
        assert!(
            run(src).is_empty(),
            "require!(data.len() <= MAX, …) must suppress the finding"
        );
    }

    /// cfg(test) impl blocks must still be ignored even with the new predicate.
    #[test]
    fn ignores_cfg_test_blocks() {
        let src = r#"
#[contractimpl]
impl C {
    pub fn process(env: Env, data: Bytes) {
        if data.len() > 1024 { panic!(); }
    }
}

#[cfg(test)]
mod tests {
    #[contractimpl]
    impl C {
        pub fn process(env: Env, data: Bytes) {
            let x = data;
        }
    }
}
        "#;
        // The production impl has a bound check; the cfg(test) one is ignored.
        assert!(run(src).is_empty());
    }
}
