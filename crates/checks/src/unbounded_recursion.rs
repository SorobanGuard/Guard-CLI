//! Detect directly or mutually recursive functions reachable from public
//! `#[contractimpl]` entry points (stack/budget exhaustion, closes #977).

use crate::{Check, Finding, Severity};
use std::collections::{HashMap, HashSet, VecDeque};
use syn::spanned::Spanned;
use syn::{
    visit::{self, Visit},
    Expr, ExprCall, ExprMethodCall, File, Item, ItemFn, ItemImpl,
};

const CHECK_NAME: &str = "unbounded-recursion";

pub struct UnboundedRecursionCheck;

impl Check for UnboundedRecursionCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let graph = build_call_graph(file);
        let entry_points = collect_contractimpl_pub_fns(file);

        let mut findings = Vec::new();
        let mut reported: HashSet<String> = HashSet::new();

        for (entry_name, entry_line) in &entry_points {
            // BFS from this entry point; detect any node in a cycle.
            if let Some(cycle) = find_cycle_reachable_from(&graph, entry_name) {
                let key = cycle.join("->");
                if reported.contains(&key) {
                    continue;
                }
                reported.insert(key.clone());
                findings.push(Finding {
                    check_name: CHECK_NAME.to_string(),
                    severity: Severity::Medium,
                    file_path: String::new(),
                    line: *entry_line,
                    function_name: entry_name.clone(),
                    description: format!(
                        "Recursive call cycle detected reachable from `{entry_name}`: \
                        {cycle_str}. Unbounded recursion exhausts the Soroban CPU/memory \
                        budget and the WASM stack.",
                        cycle_str = cycle.join(" → ")
                    ),
                    rule_url: Some(
                        "https://github.com/SorobanGuard/Guard-CLI/blob/main/docs/checks.md#unbounded-recursion-medium"
                            .to_string(),
                    ),
                    suggestion: Some(
                        "Rewrite using an explicit stack (e.g. `VecDeque`) or add a depth \
                        guard parameter with a small literal maximum (≤ 16)."
                            .to_string(),
                    ),
                });
            }
        }

        findings
    }
}

/// Build a call graph: `fn_name → set of called fn_names` for free functions
/// and `impl` methods within the file.
fn build_call_graph(file: &File) -> HashMap<String, HashSet<String>> {
    let mut graph: HashMap<String, HashSet<String>> = HashMap::new();

    for item in &file.items {
        match item {
            Item::Fn(f) => {
                let name = f.sig.ident.to_string();
                let calls = calls_in_fn(f);
                graph.entry(name).or_default().extend(calls);
            }
            Item::Impl(imp) => {
                for item in &imp.items {
                    if let syn::ImplItem::Fn(m) = item {
                        let name = m.sig.ident.to_string();
                        let calls = calls_in_method(m);
                        graph.entry(name).or_default().extend(calls);
                    }
                }
            }
            _ => {}
        }
    }

    graph
}

struct CallVisitor {
    calls: HashSet<String>,
}

impl<'ast> Visit<'ast> for CallVisitor {
    fn visit_expr_call(&mut self, node: &'ast ExprCall) {
        if let Expr::Path(p) = node.func.as_ref() {
            if let Some(seg) = p.path.segments.last() {
                self.calls.insert(seg.ident.to_string());
            }
        }
        visit::visit_expr_call(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
        self.calls.insert(node.method.to_string());
        visit::visit_expr_method_call(self, node);
    }
}

fn calls_in_fn(f: &ItemFn) -> HashSet<String> {
    let mut v = CallVisitor {
        calls: HashSet::new(),
    };
    v.visit_item_fn(f);
    v.calls
}

fn calls_in_method(m: &syn::ImplItemFn) -> HashSet<String> {
    let mut v = CallVisitor {
        calls: HashSet::new(),
    };
    v.visit_impl_item_fn(m);
    v.calls
}

/// Collect `(fn_name, line)` for every `pub` method in every `#[contractimpl]` block.
fn collect_contractimpl_pub_fns(file: &File) -> Vec<(String, usize)> {
    let mut result = Vec::new();
    for item in &file.items {
        if let Item::Impl(imp) = item {
            if !has_contractimpl_attr(&imp.attrs) {
                continue;
            }
            for impl_item in &imp.items {
                if let syn::ImplItem::Fn(m) = impl_item {
                    if matches!(m.vis, syn::Visibility::Public(_)) {
                        result.push((m.sig.ident.to_string(), m.span().start().line));
                    }
                }
            }
        }
    }
    result
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

/// BFS from `start`; returns the first cycle (as an ordered list of node names)
/// reachable from `start`, or `None` if there is none.
fn find_cycle_reachable_from(
    graph: &HashMap<String, HashSet<String>>,
    start: &str,
) -> Option<Vec<String>> {
    // We track the path that led to each node so we can reconstruct the cycle.
    // `parent[node] = from` means we reached `node` via `from`.
    let mut visited: HashSet<String> = HashSet::new();
    let mut queue: VecDeque<String> = VecDeque::new();
    let mut parent: HashMap<String, String> = HashMap::new();

    queue.push_back(start.to_string());
    visited.insert(start.to_string());

    while let Some(node) = queue.pop_front() {
        if let Some(callees) = graph.get(node.as_str()) {
            for callee in callees {
                if callee == start || parent.contains_key(callee.as_str()) {
                    // Found a cycle; reconstruct it.
                    let mut cycle = vec![callee.clone()];
                    let mut cur = node.clone();
                    while cur != *callee {
                        cycle.push(cur.clone());
                        if let Some(p) = parent.get(&cur) {
                            cur = p.clone();
                        } else {
                            cycle.push(start.to_string());
                            break;
                        }
                    }
                    cycle.push(callee.clone());
                    cycle.reverse();
                    return Some(cycle);
                }
                if !visited.contains(callee.as_str()) {
                    visited.insert(callee.clone());
                    parent.insert(callee.clone(), node.clone());
                    queue.push_back(callee.clone());
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_file;

    fn run(src: &str) -> Vec<Finding> {
        let file = parse_file(src).expect("parse");
        UnboundedRecursionCheck.run(&file, src)
    }

    #[test]
    fn flags_direct_recursion_in_contractimpl() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn count(env: Env, n: u32) -> u32 {
        if n == 0 { return 0; }
        C::count(env, n - 1) + 1
    }
}
"#);
        assert!(!hits.is_empty(), "should flag self-recursion");
        assert_eq!(hits[0].check_name, CHECK_NAME);
    }

    #[test]
    fn passes_when_no_recursion() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn add(_env: Env, a: u32, b: u32) -> u32 { a + b }
}
"#);
        assert!(hits.is_empty());
    }

    #[test]
    fn passes_without_contractimpl() {
        let hits = run(r#"
fn factorial(n: u64) -> u64 {
    if n == 0 { 1 } else { n * factorial(n - 1) }
}
"#);
        assert!(hits.is_empty(), "plain fn recursion should not be flagged");
    }
}
