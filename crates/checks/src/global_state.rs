//! Detects `static mut` items in Soroban contracts (mutable global state).

use crate::util::is_cfg_test;
use crate::{Check, Finding, Severity};
use syn::visit::{self, Visit};
use syn::{File, ItemMod, ItemStatic};

const CHECK_NAME: &str = "mutable-global-state";

pub struct MutableGlobalStateCheck;

impl Check for MutableGlobalStateCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut visitor = StaticVisitor { out: Vec::new() };
        visitor.visit_file(file);

        visitor
            .out
            .into_iter()
            .filter_map(|ItemStatic { mutability, ident, .. }| {
                if matches!(mutability, syn::StaticMutability::Mut(_)) {
                    return Some(Finding {
                        check_name: CHECK_NAME.to_string(),
                        severity: Severity::High,
                        file_path: String::new(),
                        line: ident.span().start().line,
                        function_name: String::new(),
                        description: format!(
                            "`static mut {ident}` introduces mutable global state. \
                             In Soroban, contract instances are stateless between \
                             invocations — `static mut` is unsafe and its value is \
                             not persisted on-chain."
                        ),
                        rule_url: Some(
                            "https://github.com/SorobanGuard/Guard-CLI/blob/main/docs/checks.md#mutable-global-state-high"
                                .to_string(),
                        ),
                        suggestion: Some(
                            "Replace `static mut` with `env.storage().persistent()` or `env.storage().instance()` for on-chain state."
                                .to_string(),
                        ),
                    });
                }
                None
            })
            .collect()
    }
}

/// Collects every `ItemStatic` reachable in the file via a full `syn::visit`
/// walk, so it finds one nested arbitrarily deep — inside a block (even an
/// `unsafe {}` one), a free function, a trait impl, or a `#[contractimpl]`
/// method — rather than only the shapes a hand-rolled recursion anticipated.
/// `#[cfg(test)]`-gated modules (in the [`is_cfg_test`] sense, so
/// `#[cfg(all(test, ...))]` too) and modules named `tests`/`test` are pruned
/// from the walk entirely, so nothing inside them is visited.
struct StaticVisitor<'a> {
    out: Vec<&'a ItemStatic>,
}

impl<'a> Visit<'a> for StaticVisitor<'a> {
    fn visit_item_static(&mut self, i: &'a ItemStatic) {
        self.out.push(i);
        visit::visit_item_static(self, i);
    }

    fn visit_item_mod(&mut self, i: &'a ItemMod) {
        if is_cfg_test(&i.attrs) || i.ident == "tests" || i.ident == "test" {
            return; // prune: don't recurse into test modules at all.
        }
        visit::visit_item_mod(self, i);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_file;

    #[test]
    fn flags_static_mut() {
        let file = parse_file("static mut COUNT: u32 = 0;").unwrap();
        let hits = MutableGlobalStateCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::High);
        assert!(hits[0].description.contains("COUNT"));
    }

    #[test]
    fn ignores_immutable_static() {
        let file = parse_file("static COUNT: u32 = 0;").unwrap();
        let hits = MutableGlobalStateCheck.run(&file, "");
        assert!(hits.is_empty());
    }

    #[test]
    fn flags_static_mut_inside_contractimpl_method() {
        let src = r#"
#[contractimpl]
impl MyContract {
    pub fn risky(_env: Env) {
        static mut COUNTER: u32 = 0;
        unsafe { COUNTER += 1; }
    }
}
"#;
        let file = parse_file(src).unwrap();
        let hits = MutableGlobalStateCheck.run(&file, "");
        assert_eq!(
            hits.len(),
            1,
            "should flag local static mut inside impl method"
        );
        assert!(hits[0].description.contains("COUNTER"));
        assert_eq!(hits[0].severity, Severity::High);
    }

    #[test]
    fn ignores_static_mut_inside_cfg_test_module() {
        let src = r#"
#[cfg(test)]
mod tests {
    static mut COUNTER: u32 = 0;
}
"#;
        let file = parse_file(src).unwrap();
        let hits = MutableGlobalStateCheck.run(&file, "");
        assert!(
            hits.is_empty(),
            "should not flag static mut inside #[cfg(test)] module"
        );
    }

    #[test]
    fn ignores_static_mut_inside_module_named_tests() {
        let src = r#"
mod tests {
    static mut COUNTER: u32 = 0;
}
"#;
        let file = parse_file(src).unwrap();
        let hits = MutableGlobalStateCheck.run(&file, "");
        assert!(
            hits.is_empty(),
            "should not flag static mut inside module named `tests`"
        );
    }

    #[test]
    fn flags_static_mut_nested_inside_an_unsafe_block() {
        let src = r#"
pub fn tick(_env: Env) {
    unsafe {
        static mut N: u32 = 0;
        N += 1;
    }
}
"#;
        let file = parse_file(src).unwrap();
        let hits = MutableGlobalStateCheck.run(&file, "");
        assert_eq!(
            hits.len(),
            1,
            "should flag static mut nested inside an unsafe block"
        );
        assert!(hits[0].description.contains('N'));
    }

    #[test]
    fn flags_static_mut_inside_a_module_level_free_function() {
        let src = r#"
fn helper() {
    static mut CACHE: u64 = 0;
}
"#;
        let file = parse_file(src).unwrap();
        let hits = MutableGlobalStateCheck.run(&file, "");
        assert_eq!(
            hits.len(),
            1,
            "should flag static mut inside a module-level free function"
        );
        assert!(hits[0].description.contains("CACHE"));
    }

    #[test]
    fn ignores_static_mut_inside_cfg_all_test_not_wasm32_module() {
        let src = r#"
#[cfg(all(test, not(target_arch = "wasm32")))]
mod native {
    static mut COUNTER: u32 = 0;
}
"#;
        let file = parse_file(src).unwrap();
        let hits = MutableGlobalStateCheck.run(&file, "");
        assert!(
            hits.is_empty(),
            "should not flag static mut inside a #[cfg(all(test, ...))] module"
        );
    }
}
