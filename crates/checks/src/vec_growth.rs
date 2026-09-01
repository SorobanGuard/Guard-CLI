//! Flags `#[contractimpl]` methods that read a Vec from storage, push to it, and write it
//! back without any length cap, which can brick the contract once the ledger entry size
//! limit is exceeded.
//!
//! Detection is binding-scoped: the storage `get`, the `push`/`append`, and the storage
//! `set` must all name the *same* local binding. Three unrelated operations on three
//! unrelated values (a config read, a scratch vector, a balance write) do not fire.

use crate::util::{contractimpl_functions_excluding_test, receiver_chain_contains_storage};
use crate::{Check, Finding, Severity};
use std::collections::{HashMap, HashSet};
use syn::punctuated::Punctuated;
use syn::visit::{self, Visit};
use syn::{Expr, ExprIf, ExprMatch, ExprMethodCall, ExprWhile, File, Macro, Pat, Stmt, Token};

const CHECK_NAME: &str = "unbounded-vec-growth";

pub struct UnboundedVecGrowthCheck;

impl Check for UnboundedVecGrowthCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions_excluding_test(file) {
            let fn_name = method.sig.ident.to_string();
            let mut scan = BodyScan::default();
            scan.visit_block(&method.block);

            // A binding is unbounded-growing only when the same name flows through all
            // three operations and no `.len()` guards it.
            let mut offenders: Vec<&String> = scan
                .get_bindings
                .iter()
                .filter(|b| {
                    scan.grown.contains(*b)
                        && scan.written_back.contains(*b)
                        && !scan.len_checked.contains(*b)
                })
                .collect();
            offenders.sort();

            for binding in offenders {
                let line = scan
                    .grow_line
                    .get(binding)
                    .copied()
                    .unwrap_or_else(|| method.sig.ident.span().start().line);
                out.push(Finding {
                    check_name: CHECK_NAME.to_string(),
                    severity: Severity::Medium,
                    file_path: String::new(),
                    line,
                    function_name: fn_name.clone(),
                    description: format!(
                        "Function `{fn_name}` reads a Vec from storage, appends to it, and writes \
                         it back without a length cap. The ledger entry will eventually exceed \
                         Soroban's size limit, bricking the contract."
                    ),
                    rule_url: Some(
                        "https://github.com/SorobanGuard/Guard-CLI/blob/main/docs/checks.md#unbounded-vec-growth-medium"
                            .to_string(),
                    ),
                    suggestion: Some(
                        "Enforce a maximum length before pushing, e.g. \
                         `require!(vec.len() < MAX_SIZE, \"capacity exceeded\");`."
                            .to_string(),
                    ),
                });
            }
        }
        out
    }
}

#[derive(Default)]
struct BodyScan {
    /// Local bindings whose initializer reads a value from storage via `.get()`.
    get_bindings: HashSet<String>,
    /// Bindings that are the receiver of a `push` / `push_back` / `append` call.
    grown: HashSet<String>,
    /// Bindings passed by value or by reference into a storage `.set(...)`.
    written_back: HashSet<String>,
    /// Bindings whose `.len()` appears in a guard position (`if` / `while` / `match`
    /// condition, or a `require!` / `assert!` argument) — an actual length cap.
    len_checked: HashSet<String>,
    /// First line at which each binding is grown, for finding placement.
    grow_line: HashMap<String, usize>,
    /// Nesting depth of guard conditions currently being visited.
    guard_depth: usize,
}

impl<'ast> Visit<'ast> for BodyScan {
    fn visit_stmt(&mut self, stmt: &'ast Stmt) {
        // Collect `let <ident> = <expr reading storage>` bindings in source order, so a
        // later push/set sees them. Re-binding the same name to a non-storage value
        // clears the taint (the variable has been replaced).
        if let Stmt::Local(local) = stmt {
            if let (Some(name), Some(init)) = (binding_ident(&local.pat), &local.init) {
                if expr_reads_storage_get(&init.expr) {
                    self.get_bindings.insert(name);
                } else {
                    self.get_bindings.remove(&name);
                }
            }
        }
        visit::visit_stmt(self, stmt);
    }

    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        let method = i.method.to_string();

        if matches!(method.as_str(), "push" | "push_back" | "append") {
            if let Some(recv) = ident_of(&i.receiver).filter(|r| self.get_bindings.contains(r)) {
                self.grow_line
                    .entry(recv.clone())
                    .or_insert_with(|| i.method.span().start().line);
                self.grown.insert(recv);
            }
        } else if method == "len" && self.guard_depth > 0 {
            if let Some(recv) = ident_of(&i.receiver) {
                self.len_checked.insert(recv);
            }
        } else if method == "set" && receiver_chain_contains_storage(&i.receiver) {
            for arg in &i.args {
                if let Some(name) = ident_of(arg).filter(|n| self.get_bindings.contains(n)) {
                    self.written_back.insert(name);
                }
            }
        }

        visit::visit_expr_method_call(self, i);
    }

    fn visit_expr_if(&mut self, i: &'ast ExprIf) {
        self.guard_depth += 1;
        self.visit_expr(&i.cond);
        self.guard_depth -= 1;
        self.visit_block(&i.then_branch);
        if let Some((_, else_branch)) = &i.else_branch {
            self.visit_expr(else_branch);
        }
    }

    fn visit_expr_while(&mut self, i: &'ast ExprWhile) {
        self.guard_depth += 1;
        self.visit_expr(&i.cond);
        self.guard_depth -= 1;
        self.visit_block(&i.body);
    }

    fn visit_expr_match(&mut self, i: &'ast ExprMatch) {
        self.guard_depth += 1;
        self.visit_expr(&i.expr);
        self.guard_depth -= 1;
        for arm in &i.arms {
            self.visit_arm(arm);
        }
    }

    fn visit_macro(&mut self, m: &'ast Macro) {
        let macro_name = m.path.segments.last().map(|s| s.ident.to_string());
        let is_guard_macro = matches!(
            macro_name.as_deref(),
            Some("require" | "assert" | "assert_eq" | "assert_ne" | "debug_assert")
        );
        if is_guard_macro {
            if let Ok(args) = m.parse_body_with(Punctuated::<Expr, Token![,]>::parse_terminated) {
                self.guard_depth += 1;
                for arg in &args {
                    self.visit_expr(arg);
                }
                self.guard_depth -= 1;
            }
        }
        visit::visit_macro(self, m);
    }
}

/// Name bound by a `let` pattern, digging through an explicit type annotation
/// (`let x: T = ...`).
fn binding_ident(pat: &Pat) -> Option<String> {
    match pat {
        Pat::Ident(pi) => Some(pi.ident.to_string()),
        Pat::Type(pt) => binding_ident(&pt.pat),
        _ => None,
    }
}

/// Identifier behind a plain path (`x`) or a reference to one (`&x`, `&mut x`).
fn ident_of(e: &Expr) -> Option<String> {
    match e {
        Expr::Reference(r) => ident_of(&r.expr),
        Expr::Path(p) => p.path.get_ident().map(|i| i.to_string()),
        _ => None,
    }
}

/// Does `expr` contain a `.get()` call whose receiver chain reaches `.storage()`?
/// Covers wrappers such as `...get(&k).unwrap_or(default)`.
fn expr_reads_storage_get(expr: &Expr) -> bool {
    struct Finder {
        found: bool,
    }
    impl<'ast> Visit<'ast> for Finder {
        fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
            if i.method == "get" && receiver_chain_contains_storage(&i.receiver) {
                self.found = true;
            }
            visit::visit_expr_method_call(self, i);
        }
    }
    let mut f = Finder { found: false };
    f.visit_expr(expr);
    f.found
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Check;
    use syn::parse_file;

    fn run(src: &str) -> Vec<Finding> {
        let file = parse_file(src).expect("parse");
        UnboundedVecGrowthCheck.run(&file, src)
    }

    #[test]
    fn flags_unbounded_push_despite_unrelated_len_call() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env, Vec};
pub struct C;
#[contractimpl]
impl C {
    pub fn add(env: Env, other: Vec<u32>) {
        let mut entries: Vec<u32> = env.storage().instance().get(&0).unwrap().unwrap();
        entries.push(1u32);
        let _ = other.len();
        env.storage().instance().set(&0, &entries);
    }
}
"#);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].check_name, CHECK_NAME);
    }

    #[test]
    fn passes_when_len_check_targets_pushed_receiver() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env, Vec};
pub struct C;
#[contractimpl]
impl C {
    pub fn add(env: Env, max: u32) {
        let mut entries: Vec<u32> = env.storage().instance().get(&0).unwrap().unwrap();
        entries.push(1u32);
        if entries.len() >= max {
            panic!("capacity exceeded");
        }
        env.storage().instance().set(&0, &entries);
    }
}
"#);
        assert!(hits.is_empty());
    }

    #[test]
    fn flags_when_len_only_used_for_logging_after_write_back() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env, Vec};
pub struct C;
#[contractimpl]
impl C {
    pub fn add(env: Env, x: u32) {
        let mut items: Vec<u32> = env.storage().persistent().get(&0).unwrap_or(soroban_sdk::vec![&env]);
        items.push_back(x);
        env.storage().persistent().set(&0, &items);
        log(&env, items.len());
    }
}
"#);
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn passes_when_len_capped_via_require_macro() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env, Vec};
pub struct C;
#[contractimpl]
impl C {
    pub fn add(env: Env, x: u32) {
        let mut items: Vec<u32> = env.storage().persistent().get(&0).unwrap_or(soroban_sdk::vec![&env]);
        require!(items.len() < 100, "capacity exceeded");
        items.push_back(x);
        env.storage().persistent().set(&0, &items);
    }
}
"#);
        assert!(hits.is_empty(), "{hits:#?}");
    }

    #[test]
    fn flags_when_no_length_check_at_all() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env, Vec};
pub struct C;
#[contractimpl]
impl C {
    pub fn add(env: Env) {
        let mut entries: Vec<u32> = env.storage().instance().get(&0).unwrap().unwrap();
        entries.push(1u32);
        env.storage().instance().set(&0, &entries);
    }
}
"#);
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn does_not_flag_unrelated_get_local_push_and_set() {
        // Three unrelated operations on three unrelated values: a config read, a scratch
        // vector push, and a balance write. None share a binding, so no finding.
        let hits = run(r#"
use soroban_sdk::{contractimpl, Address, Env, Vec};
pub struct C;
#[contractimpl]
impl C {
    pub fn record(env: Env, user: Address, amount: i128) {
        let cfg: u32 = env.storage().instance().get(&0).unwrap().unwrap();
        let mut local = Vec::new(&env);
        local.push_back(amount);
        env.storage().persistent().set(&user, &amount);
        let _ = cfg;
    }
}
"#);
        assert!(hits.is_empty(), "unrelated ops must not fire: {hits:#?}");
    }

    #[test]
    fn flags_when_same_binding_flows_get_push_set() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env, Vec};
pub struct C;
#[contractimpl]
impl C {
    pub fn append_entry(env: Env, value: u32) {
        let mut items: Vec<u32> = env.storage().persistent().get(&0).unwrap_or(soroban_sdk::vec![&env]);
        items.push_back(value);
        env.storage().persistent().set(&0, &items);
    }
}
"#);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Medium);
        assert_eq!(hits[0].function_name, "append_entry");
    }
}
