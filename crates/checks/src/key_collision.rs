
//! Detection of duplicate symbol keys (symbol_short!("...")) within the same impl block.

use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{File, Lit, Macro};

const CHECK_NAME: &str = "symbol-key-collision";

/// Detect duplicate `symbol_short!` literals in the same `impl` block.
pub struct SymbolKeyCollisionCheck;

impl Check for SymbolKeyCollisionCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut symbol_keys = std::collections::HashMap::new();
        let mut visitor = SymbolKeyVisitor {
            symbol_keys: &mut symbol_keys,
            current_function: String::new(),
        };
        visitor.visit_file(file);

        for (key, positions) in symbol_keys {
            if positions.len() > 1 {
                for (pos, line, fn_name) in positions.iter().skip(1) {
                    let loc = if fn_name.is_empty() {
                        "module level".to_string()
                    } else {
                        fn_name.clone()
                    };
                    findings.push(Finding {
                        check_name: CHECK_NAME.to_string(),
                        severity: Severity::Medium,
                        file_path: String::new(),
                        line: *line,
                        function_name: loc,
                        description: format!(
                            "Duplicate symbol key `{}` found at position {}",
                            key, pos
                        ),
                        rule_url: Some(
                            "https://github.com/SorobanGuard/Guard-CLI/blob/main/docs/checks.md#symbol-key-collision-medium"
                                .to_string(),
                        ),
                        suggestion: Some(format!(
                            "Rename one of the duplicate `symbol_short!(\"{key}\")` / \
                             `Symbol::new(…, \"{key}\")` usages to a unique key to avoid \
                             accidental storage slot collisions."
                        )),
                    });
                }
            }
        }

        findings
    }
}

struct SymbolKeyVisitor<'a> {
    symbol_keys: &'a mut std::collections::HashMap<String, Vec<(usize, usize, String)>>,
    current_function: String,
}

impl<'ast, 'a> Visit<'ast> for SymbolKeyVisitor<'a> {
    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        let prev = std::mem::replace(&mut self.current_function, node.sig.ident.to_string());
        visit::visit_impl_item_fn(self, node);
        self.current_function = prev;
    }

    fn visit_item_const(&mut self, node: &'ast syn::ItemConst) {
        let prev = std::mem::replace(&mut self.current_function, format!("const {}", node.ident));
        visit::visit_item_const(self, node);
        self.current_function = prev;
    }

    fn visit_macro(&mut self, m: &'ast Macro) {
        if let Some(last_segment) = m.path.segments.last() {
            if last_segment.ident == "symbol_short" {
                let tokens = m.tokens.clone();
                if let Ok(Lit::Str(s)) = syn::parse2::<Lit>(tokens) {
                    let key = s.value();
                    let span = m.span().start();
                    let pos = span.column;
                    let line = span.line;
                    self.symbol_keys
                        .entry(key)
                        .or_default()
                        .push((pos, line, self.current_function.clone()));
                }
            }
        }
        visit::visit_macro(self, m);
    }

    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if let syn::Expr::Path(p) = &*node.func {
            let segments: Vec<_> = p.path.segments.iter().collect();
            if segments.len() >= 2 {
                let last = segments[segments.len() - 1].ident.to_string();
                let prev = segments[segments.len() - 2].ident.to_string();
                if last == "new" && prev == "Symbol" {
                    if let Some(syn::Expr::Lit(expr_lit)) = node.args.iter().nth(1) {
                        if let Lit::Str(s) = &expr_lit.lit {
                            let key = s.value();
                            let span = node.span().start();
                            self.symbol_keys
                                .entry(key)
                                .or_default()
                                .push((span.column, span.line, self.current_function.clone()));
                        }
                    }
                }
            }
        }
        visit::visit_expr_call(self, node);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Check;
    use syn::parse_file;

    #[test]
    fn detects_duplicate_symbol_keys() {
        let src = r#"
use soroban_sdk::{contractimpl, symbol_short, Symbol, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn foo(env: Env) {
        let k1 = symbol_short!("key");
        let k2 = symbol_short!("key");
    }
}
"#;
        let file = parse_file(src).unwrap();
        let findings = SymbolKeyCollisionCheck.run(&file, src);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn ignores_unique_symbol_keys() {
        let src = r#"
use soroban_sdk::{contractimpl, symbol_short, Symbol, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn foo(env: Env) {
        let k1 = symbol_short!("key1");
        let k2 = symbol_short!("key2");
    }
}
"#;
        let file = parse_file(src).unwrap();
        let findings = SymbolKeyCollisionCheck.run(&file, src);
        assert!(findings.is_empty());
    }

    #[test]
    fn detects_module_level_const_collisions() {
        let src = r#"
use soroban_sdk::{symbol_short, Symbol, Env};

const BALANCE_KEY: Symbol = symbol_short!("bal");
const OLD_ADMIN_KEY: Symbol = Symbol::new(&env, "bal");
"#;
        let file = parse_file(src).unwrap();
        let findings = SymbolKeyCollisionCheck.run(&file, src);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
        assert_eq!(findings[0].function_name, "const OLD_ADMIN_KEY");
    }
}
