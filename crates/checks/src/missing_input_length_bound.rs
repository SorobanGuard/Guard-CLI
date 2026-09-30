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
                                "Validate parameter length with .len() or .is_empty()".to_string(),
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

/// Returns `"Bytes"`/`"Vec"` when `ty`'s last path segment is one of those unbounded,
/// runtime-length collection types. Fixed-length types such as `BytesN<32>` are
/// intentionally excluded: their length is a compile-time constant, so there is nothing
/// for a length check to validate.
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

/// Walk the block's AST and look for `<param_name>.len()` or `<param_name>.is_empty()`
/// where the immediate receiver is exactly `param_name` — not a longer identifier that
/// merely ends with the same characters (e.g. `matrix` vs `x`, `prefix` vs `fix`).
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
    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        let method = node.method.to_string();
        if matches!(method.as_str(), "len" | "is_empty") && node.args.is_empty() {
            // The receiver must be exactly the parameter identifier — not a field
            // access, index, or a longer name that happens to end with the same chars.
            if let syn::Expr::Path(path_expr) = &*node.receiver {
                if let Some(ident) = path_expr.path.get_ident() {
                    if ident == self.param_name {
                        self.found = true;
                        return;
                    }
                }
            }
        }
        visit::visit_expr_method_call(self, node);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_file;

    #[test]
    fn flags_unbounded_bytes() -> Result<(), syn::Error> {
        let src = r#"
#[contractimpl]
impl C {
    pub fn process(env: Env, data: Bytes) {
        let x = data;
    }
}
        "#;
        let file = parse_file(src)?;
        let check = MissingInputLengthBoundCheck;
        let findings = check.run(&file, src);
        assert_eq!(findings.len(), 1);
        Ok(())
    }

    #[test]
    fn does_not_flag_when_length_checked() -> Result<(), syn::Error> {
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
        let file = parse_file(src)?;
        let check = MissingInputLengthBoundCheck;
        let findings = check.run(&file, src);
        assert!(findings.is_empty());
        Ok(())
    }

    #[test]
    fn ignores_fixed_size_bytes_n() -> Result<(), syn::Error> {
        let src = r#"
#[contractimpl]
impl C {
    pub fn process(env: Env, data: BytesN<32>) {
        let x = data;
    }
}
        "#;
        let file = parse_file(src)?;
        let check = MissingInputLengthBoundCheck;
        let findings = check.run(&file, src);
        assert_eq!(findings.len(), 0);
        Ok(())
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
        let file = parse_file(src)?;
        let check = MissingInputLengthBoundCheck;
        let findings = check.run(&file, src);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].line, 6);
        Ok(())
    }

    /// Regression test for #665: an unrelated receiver whose name ends with the
    /// param name must not be mistaken for a length check on that param.
    #[test]
    fn does_not_flag_false_negative_from_unrelated_receiver() -> Result<(), syn::Error> {
        // `matrix.len()` must NOT count as a length check for the `x` parameter.
        let src = r#"
#[contractimpl]
impl C {
    pub fn process(env: Env, x: Bytes, matrix: Vec<u32>) {
        let _ = matrix.len();
    }
}
        "#;
        let file = parse_file(src)?;
        let check = MissingInputLengthBoundCheck;
        let findings = check.run(&file, src);
        // Both x and matrix lack their own length checks in the context relevant to them.
        // x has no length check at all; matrix.len() checks matrix, not x.
        let names: Vec<&str> = findings.iter().map(|f| f.description.as_str()).collect();
        assert!(
            findings.iter().any(|f| f.description.contains("`x`")),
            "x should be flagged as unchecked, got: {:?}", names
        );
        Ok(())
    }

    #[test]
    fn ignores_missing_length_bound_inside_cfg_test() -> Result<(), syn::Error> {
        let src = r#"
#[contractimpl]
impl C {
    pub fn process(env: Env, data: Bytes) {
        data.len();
    }
}

#[cfg(test)]
mod tests {
    use soroban_sdk::{contractimpl, Env, Bytes};

    #[contractimpl]
    impl C {
        pub fn process(env: Env, data: Bytes) {
            let x = data;
        }
    }
}
        "#;
        let file = parse_file(src)?;
        let check = MissingInputLengthBoundCheck;
        let findings = check.run(&file, src);
        assert_eq!(findings.len(), 0);
        Ok(())
    }
}
