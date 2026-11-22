//! Detection of `Symbol::new` / `symbol_short!` / `Symbol::try_from_val` literals
//! that are too long or contain invalid characters.
//!
//! Soroban `Symbol` values only accept `[a-zA-Z0-9_]`, with a maximum of 32
//! characters for `Symbol::new` / `Symbol::try_from_val` and 9 for `symbol_short!`.
//! A bad `Symbol::new` literal compiles and then panics at runtime; `symbol_short!`
//! fails at compile time, but this check surfaces a clearer message earlier.

use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprCall, File, Lit, LitStr, Macro};

const CHECK_NAME: &str = "symbol-literal-too-long";
const MAX_NEW: usize = 32;
const MAX_SHORT: usize = 9;
const VALID_CHARS: fn(char) -> bool = |c: char| c.is_ascii_alphanumeric() || c == '_';

fn is_symbol_new_path(path: &syn::Path) -> bool {
    let segs: Vec<String> = path.segments.iter().map(|s| s.ident.to_string()).collect();
    let n = segs.len();
    n >= 2
        && segs[n - 2] == "Symbol"
        && (segs[n - 1] == "new" || segs[n - 1] == "try_from_val")
}

fn is_symbol_short_macro(mac: &Macro) -> bool {
    let segs: Vec<_> = mac
        .path
        .segments
        .iter()
        .map(|s| s.ident.to_string())
        .collect();
    matches!(segs.last().map(String::as_str), Some("symbol_short"))
}

fn report(
    lit: &LitStr,
    max: usize,
    context: &str,
    fn_name: &str,
) -> Option<Finding> {
    let val = lit.value();
    let too_long = val.len() > max;
    let bad_chars: String = val.chars().filter(|c| !VALID_CHARS(*c)).collect();
    if !too_long && bad_chars.is_empty() {
        return None;
    }
    let line = lit.span().start().line;
    let description = if too_long && !bad_chars.is_empty() {
        format!(
            "`{}` passed to {context} is {} characters (max {max}) and contains \
             invalid characters `{bad_chars}` — only [a-zA-Z0-9_] are allowed.",
            val,
            val.len()
        )
    } else if too_long {
        format!(
            "`{}` passed to {context} is {} characters; maximum is {max}.",
            val,
            val.len()
        )
    } else {
        format!(
            "`{}` passed to {context} contains invalid characters `{bad_chars}` \
             — only [a-zA-Z0-9_] are allowed.",
            val
        )
    };
    Some(Finding {
        check_name: CHECK_NAME.to_string(),
        severity: Severity::High,
        file_path: String::new(),
        line,
        function_name: fn_name.to_string(),
        description,
        rule_url: Some(
            "https://github.com/SorobanGuard/Guard-CLI/blob/main/docs/checks.md#symbol-literal-too-long-high"
                .to_string(),
        ),
        suggestion: Some(format!(
            "Use only [a-zA-Z0-9_] with at most {max} characters."
        )),
    })
}

fn enclosing_fn<'a>(spans: &'a [(usize, usize, String)], line: usize) -> &'a str {
    spans
        .iter()
        .find(|(start, end, _)| line >= *start && line <= *end)
        .map(|(_, _, name)| name.as_str())
        .unwrap_or("")
}

struct SymbolLiteralVisitor<'a> {
    findings: &'a mut Vec<Finding>,
    fn_spans: &'a [(usize, usize, String)],
}

impl<'ast> Visit<'ast> for SymbolLiteralVisitor<'_> {
    fn visit_expr_call(&mut self, node: &'ast ExprCall) {
        if let Expr::Path(ref path_expr) = *node.func {
            if is_symbol_new_path(&path_expr.path) {
                // Symbol::new(&env, "literal") — second argument is the string.
                // Symbol::try_from_val(&env, &"literal") — second argument.
                if let Some(arg) = node.args.iter().nth(1) {
                    if let Some(lit_str) = extract_str_lit(arg) {
                        let line = lit_str.span().start().line;
                        let fn_name = enclosing_fn(self.fn_spans, line).to_string();
                        let ctx = if path_expr
                            .path
                            .segments
                            .last()
                            .map(|s| s.ident == "try_from_val")
                            .unwrap_or(false)
                        {
                            "Symbol::try_from_val"
                        } else {
                            "Symbol::new"
                        };
                        if let Some(f) = report(&lit_str, MAX_NEW, ctx, &fn_name) {
                            self.findings.push(f);
                        }
                    }
                }
            }
        }
        visit::visit_expr_call(self, node);
    }

    fn visit_macro(&mut self, node: &'ast Macro) {
        if is_symbol_short_macro(node) {
            if let Ok(lit) = node.parse_body::<Lit>() {
                if let Lit::Str(lit_str) = lit {
                    let line = lit_str.span().start().line;
                    let fn_name = enclosing_fn(self.fn_spans, line).to_string();
                    if let Some(f) = report(&lit_str, MAX_SHORT, "symbol_short!", &fn_name) {
                        self.findings.push(f);
                    }
                }
            }
        }
        visit::visit_macro(self, node);
    }
}

/// Extract a `LitStr` from an expression, unwrapping one level of `&` reference.
fn extract_str_lit(expr: &Expr) -> Option<LitStr> {
    match expr {
        Expr::Lit(expr_lit) => {
            if let Lit::Str(ref s) = expr_lit.lit {
                return Some(s.clone());
            }
        }
        Expr::Reference(r) => {
            if let Expr::Lit(ref expr_lit) = *r.expr {
                if let Lit::Str(ref s) = expr_lit.lit {
                    return Some(s.clone());
                }
            }
        }
        _ => {}
    }
    None
}

pub struct SymbolLiteralTooLongCheck;

fn build_fn_spans(file: &File) -> Vec<(usize, usize, String)> {
    crate::util::contractimpl_functions_excluding_test(file)
        .into_iter()
        .map(|m| {
            let start = m.span().start().line;
            let end = m.span().end().line;
            (start, end, m.sig.ident.to_string())
        })
        .collect()
}

impl Check for SymbolLiteralTooLongCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let fn_spans = build_fn_spans(file);

        let mut findings = Vec::new();
        let mut visitor = SymbolLiteralVisitor {
            findings: &mut findings,
            fn_spans: &fn_spans,
        };
        visitor.visit_file(file);
        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(src: &str) -> Vec<Finding> {
        let file = syn::parse_file(src).unwrap();
        SymbolLiteralTooLongCheck.run(&file, src)
    }

    #[test]
    fn valid_symbol_new_is_not_flagged() {
        let src = r#"
#[contractimpl]
impl C {
    pub fn f(env: Env) {
        let _ = Symbol::new(&env, "valid_key");
    }
}
"#;
        assert!(check(src).is_empty());
    }

    #[test]
    fn symbol_new_over_32_chars_is_flagged() {
        let key = "a".repeat(33);
        let src = format!(
            r#"
#[contractimpl]
impl C {{
    pub fn f(env: Env) {{
        let _ = Symbol::new(&env, "{key}");
    }}
}}
"#
        );
        let findings = check(&src);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].check_name, CHECK_NAME);
    }

    #[test]
    fn symbol_new_invalid_chars_is_flagged() {
        let src = r#"
#[contractimpl]
impl C {
    pub fn f(env: Env) {
        let _ = Symbol::new(&env, "bad-key!");
    }
}
"#;
        let findings = check(src);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn symbol_short_over_9_chars_is_flagged() {
        let src = r#"
#[contractimpl]
impl C {
    pub fn f(env: Env) {
        let _ = symbol_short!("toolongkey");
    }
}
"#;
        let findings = check(src);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn valid_symbol_short_is_not_flagged() {
        let src = r#"
#[contractimpl]
impl C {
    pub fn f(env: Env) {
        let _ = symbol_short!("short");
    }
}
"#;
        assert!(check(src).is_empty());
    }
}
