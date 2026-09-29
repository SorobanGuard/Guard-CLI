//! Detection of duplicate symbol keys (symbol_short!("...")) within the same impl block.

use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{File, Lit, Macro};

const CHECK_NAME: &str = "symbol-key-collision";

/// Detect duplicate `symbol_short!("...")` literals in the same `impl` block.
pub struct SymbolKeyCollisionCheck;

impl Check for SymbolKeyCollisionCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut symbol_keys = std::collections::HashMap::new();
        let mut str_consts = std::collections::HashMap::new();
        collect_str_consts(&file.items, &mut str_consts);
        let mut visitor = SymbolKeyVisitor {
            symbol_keys: &mut symbol_keys,
            str_consts: &str_consts,
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
                            "Rename one of the duplicate `symbol_short!("{key}")` / \n             `Symbol::new(..., "{key}")` usages to a unique key to avoid \n             accidental storage slot collisions."
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
    /// `const NAME: &str = "..."` declarations, so `Symbol::new(env, NAME)` can be
    /// resolved to its literal key and compared against `symbol_short!("...")` literals.
    str_consts: &'a std::collections::HashMap<String, String>,
    current_function: String,
}

/// Extract the value of a string-literal expression (`"foo"`).
fn str_lit_value(expr: &syn::Expr) -> Option<String> {
    if let syn::Expr::Lit(lit) = expr {
        if let Lit::Str(s) = &lit.lit {
            return Some(s.value());
        }
    }
    None
}

/// Collect `const NAME: &str = "..."` declarations (module level and nested modules).
fn collect_str_consts(items: &[syn::Item], out: &mut std::collections::HashMap<String, String>) {
    for item in items {
        match item {
            syn::Item::Const(c) => {
                if let Some(v) = str_lit_value(&c.expr) {
                    out.insert(c.ident.to_string(), v);
                }
            }
            syn::Item::Mod(m) => {
                if let Some((_, nested)) = &m.content {
                    collect_str_consts(nested, out);
                }
            }
            _ => {},
        }
    }
}

impl<'ast, 'a> Visit<'ast> for SymbolKeyVisitor<'a> {
    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        let prev = std::mem::replace(&mut self.current_function, node.sig.ident.to_string());
        visit::visit_impl_item_fn(self, node);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_quote;

    #[test]
    fn test_symbol_key_collision() {
        let code = r#"
            #[contractimpl]
            impl Contract {
                pub fn test() {
                    symbol_short!("OLD_ADMIN_KEY");
                    symbol_short!("OLD_ADMIN_KEY");
                }
            }
        "#;
        let mut file = parse_file(code);
        let check = SymbolKeyCollisionCheck;
        let findings = check.run(&file, "");
        assert_eq!(1, findings.len());
        assert_eq!(
            "Duplicate symbol key `OLD_ADMIN_KEY` found at position 1",
            findings[0].description
        );
    }
}