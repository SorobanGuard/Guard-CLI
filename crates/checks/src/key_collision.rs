//! Detection of duplicate symbol keys (symbol_short!("...")) within the same impl block.
//!
//! Two unrelated `#[contractimpl]` blocks in the same file that happen to reuse
//! the same key name are **not** flagged — each impl block is checked in
//! isolation because different contracts have separate storage namespaces.

use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{File, Lit, Macro};

const CHECK_NAME: &str = "symbol-key-collision";

/// Detect duplicate `symbol_short!` / `Symbol::new` literals within the same
/// `impl` block.  Two independent `#[contractimpl]` blocks (different
/// contracts, different storage namespaces) reusing the same key name are **not**
/// flagged.
pub struct SymbolKeyCollisionCheck;

impl Check for SymbolKeyCollisionCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut str_consts = std::collections::HashMap::new();
        collect_str_consts(&file.items, &mut str_consts);

        // Visit each top-level impl block independently so that two unrelated
        // `#[contractimpl]` blocks (different contracts, different storage
        // namespaces) reusing the same key name do not produce a false positive.
        // Module-level `const` declarations (outside any impl) are still
        // checked as a single group.
        let mut module_level_keys: std::collections::HashMap<
            String,
            Vec<(usize, usize, String)>,
        > = std::collections::HashMap::new();

        for item in &file.items {
            match item {
                syn::Item::Impl(impl_block) => {
                    // Each impl block gets its own key map.
                    let mut impl_keys: std::collections::HashMap<
                        String,
                        Vec<(usize, usize, String)>,
                    > = std::collections::HashMap::new();
                    let mut visitor = SymbolKeyVisitor {
                        symbol_keys: &mut impl_keys,
                        str_consts: &str_consts,
                        current_function: String::new(),
                    };
                    visitor.visit_item_impl(impl_block);
                    emit_findings(&impl_keys, &mut findings);
                }
                // Collect module-level symbol keys (const initialisers, free functions, etc.)
                other => {
                    let mut visitor = SymbolKeyVisitor {
                        symbol_keys: &mut module_level_keys,
                        str_consts: &str_consts,
                        current_function: String::new(),
                    };
                    visitor.visit_item(other);
                }
            }
        }
        emit_findings(&module_level_keys, &mut findings);

        findings
    }
}

fn emit_findings(
    symbol_keys: &std::collections::HashMap<String, Vec<(usize, usize, String)>>,
    findings: &mut Vec<Finding>,
) {
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
}

struct SymbolKeyVisitor<'a> {
    symbol_keys: &'a mut std::collections::HashMap<String, Vec<(usize, usize, String)>>,
    /// `const NAME: &str = "..."` declarations, so `Symbol::new(env, NAME)` can be
    /// resolved to its literal key and compared against `symbol_short!` literals.
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
            _ => {}
        }
    }
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
                    self.symbol_keys.entry(key).or_default().push((
                        pos,
                        line,
                        self.current_function.clone(),
                    ));
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
                    let key = match node.args.iter().nth(1) {
                        Some(syn::Expr::Lit(expr_lit)) => match &expr_lit.lit {
                            Lit::Str(s) => Some(s.value()),
                            _ => None,
                        },
                        // A named `const` key — the idiomatic way to declare keys.
                        Some(syn::Expr::Path(p)) => p
                            .path
                            .get_ident()
                            .and_then(|id| self.str_consts.get(&id.to_string()).cloned()),
                        _ => None,
                    };
                    if let Some(key) = key {
                        let span = node.span().start();
                        self.symbol_keys.entry(key).or_default().push((
                            span.column,
                            span.line,
                            self.current_function.clone(),
                        ));
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
    fn detects_const_key_colliding_with_symbol_short_literal() {
        let src = r#"
use soroban_sdk::{contractimpl, symbol_short, Symbol, Env};

const BAL: &str = "bal";

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn foo(env: Env) {
        let a = symbol_short!("bal");
        let b = Symbol::new(&env, BAL);
    }
}
"#;
        let file = parse_file(src).unwrap();
        let findings = SymbolKeyCollisionCheck.run(&file, src);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn detects_module_level_const_collisions() {
        // Compilable, idiomatic module-level `Symbol` constants using `symbol_short!` —
        // `Symbol::new(&env, "...")` cannot appear in a `const` initializer since `env` does
        // not exist at module scope, so this fixture no longer references an undefined `env`.
        let src = r#"
use soroban_sdk::{symbol_short, Symbol};

const BALANCE_KEY: Symbol = symbol_short!("bal");
const OLD_ADMIN_KEY: Symbol = symbol_short!("bal");
"#;
        let file = parse_file(src).unwrap();
        let findings = SymbolKeyCollisionCheck.run(&file, src);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
        assert_eq!(findings[0].function_name, "const OLD_ADMIN_KEY");
    }

    /// Regression coverage for the non-literal-second-argument gap: `Symbol::new(&env, CONST)`
    /// inside a method, where `CONST` is a `&str` constant rather than an inline string
    /// literal. `visit_expr_call` only recognizes `Symbol::new`'s second argument when it is a
    /// `Lit::Str` directly, so a collision expressed through a shared `&str` constant is
    /// currently **not** detected. This test documents that gap; it should start failing (i.e.
    /// findings.len() should become 1) once the check is taught to resolve constant references.
    #[test]
    fn does_not_detect_in_method_symbol_new_collision_via_shared_const() {
        let src = r#"
use soroban_sdk::{contractimpl, Symbol, Env};

const OLD_ADMIN_KEY: &str = "bal";

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn foo(env: Env) {
        let k1 = Symbol::new(&env, OLD_ADMIN_KEY);
        let k2 = Symbol::new(&env, OLD_ADMIN_KEY);
        let _ = (k1, k2);
    }
}
"#;
        let file = parse_file(src).unwrap();
        let findings = SymbolKeyCollisionCheck.run(&file, src);
        assert!(
            findings.is_empty(),
            "known gap: Symbol::new(&env, CONST) with a non-literal second argument is not \
             yet resolved to its constant value, so no collision is detected here"
        );
    }

    /// Regression test for issue #695: two *unrelated* `#[contractimpl]` blocks in the same
    /// file that each independently use `symbol_short!("bal")` for their own contract's
    /// storage namespace should produce **no** finding — different contracts have different
    /// storage namespaces, so the same key name is not a collision.
    #[test]
    fn no_false_positive_for_unrelated_impl_blocks_sharing_key_name() {
        let src = r#"
use soroban_sdk::{contractimpl, symbol_short, Env};

pub struct ContractA;
pub struct ContractB;

#[contractimpl]
impl ContractA {
    pub fn get_balance(env: Env) -> i128 {
        env.storage().instance().get(&symbol_short!("bal")).unwrap_or(0)
    }
}

#[contractimpl]
impl ContractB {
    pub fn get_balance(env: Env) -> i128 {
        env.storage().instance().get(&symbol_short!("bal")).unwrap_or(0)
    }
}
"#;
        let file = parse_file(src).unwrap();
        let findings = SymbolKeyCollisionCheck.run(&file, src);
        assert!(
            findings.is_empty(),
            "two unrelated #[contractimpl] blocks reusing the same key name in separate \
             storage namespaces should not be flagged as a collision; got: {findings:#?}"
        );
    }

    /// Confirm that a *true* collision within a single impl block is still detected
    /// after the per-impl scoping change.
    #[test]
    fn still_detects_collision_within_single_impl_block() {
        let src = r#"
use soroban_sdk::{contractimpl, symbol_short, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn foo(env: Env) {
        let _ = env.storage().instance().get::<_, i128>(&symbol_short!("bal")).unwrap_or(0);
    }
    pub fn bar(env: Env) {
        let _ = env.storage().instance().get::<_, i128>(&symbol_short!("bal")).unwrap_or(0);
    }
}
"#;
        let file = parse_file(src).unwrap();
        let findings = SymbolKeyCollisionCheck.run(&file, src);
        assert_eq!(
            findings.len(),
            1,
            "duplicate key within the same impl block should still be flagged; got: {findings:#?}"
        );
    }
}
