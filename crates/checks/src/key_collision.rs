
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

        for item in &file.items {
            if let syn::Item::Impl(impl_block) = item {
                let mut symbol_keys = std::collections::HashMap::new();
                let mut visitor = SymbolKeyVisitor {
                    symbol_keys: &mut symbol_keys,
                };
                visitor.visit_item_impl(impl_block);

                for (key, positions) in symbol_keys {
                    if positions.len() > 1 {
                        for (pos, line) in positions.iter().skip(1) {
                            findings.push(Finding {
                                check_name: CHECK_NAME.to_string(),
                                severity: Severity::Medium,
                                file_path: String::new(),
                                line: *line,
                                function_name: String::new(),
                                description: format!(
                                    "Duplicate symbol key `{}` found at position {}",
                                    key, pos
                                ),
                            });
                        }
                    }
                }
            }
        }

        findings
    }
}

struct SymbolKeyVisitor<'a> {
    symbol_keys: &'a mut std::collections::HashMap<String, Vec<(usize, usize)>>,
}

impl<'ast, 'a> Visit<'ast> for SymbolKeyVisitor<'a> {
    fn visit_macro(&mut self, m: &'ast Macro) {
        if let Some(last_segment) = m.path.segments.last() {
            if last_segment.ident == "symbol_short" {
                let tokens = m.tokens.clone();
                if let Ok(lit) = syn::parse2::<Lit>(tokens) {
                    if let Lit::Str(s) = lit {
                        let key = s.value();
                        let span = m.span().start();
                        let pos = span.column;
                        let line = span.line;
                        self.symbol_keys
                            .entry(key)
                            .or_default()
                            .push((pos, line));
                    }
                }
            }
        }
        visit::visit_macro(self, m);
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
}
