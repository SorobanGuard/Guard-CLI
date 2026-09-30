/// Criterion benchmarks for analyzer performance.
///
/// Tracks whole-tree scan performance and per-check cost to detect
/// regressions and identify performance bottlenecks.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use soroban_guard_analyzer::analyze_source;
use std::fs;

fn load_fixture(name: &str) -> String {
    let path = format!("fixtures/{}.rs", name);
    fs::read_to_string(&path).unwrap_or_else(|_| {
        // Fallback: create a realistic contract stub if fixture doesn't exist
        r#"
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env, Symbol, symbol_short};

#[contract]
pub struct Counter;

#[contractimpl]
impl Counter {
    pub fn increment(env: Env, user: Address) -> u32 {
        user.require_auth();
        let mut count: u32 = env.storage().instance().get(&symbol_short!("count")).unwrap_or(0);
        count += 1;
        env.storage().instance().set(&symbol_short!("count"), &count);
        count
    }

    pub fn admin_transfer(env: Env, admin: Address, to: Address, amount: i128) {
        admin.require_auth();
        if to == Address::default() {
            panic!("Cannot transfer to zero address");
        }
        // Transfer logic here
    }

    pub fn unsafe_invoke(env: Env, contract: Address, func: Symbol) {
        // Unsafe contract invocation
        let _result: u32 = env.invoke_contract(&contract, &func, &());
    }
}
"#
            .to_string()
    })
}

fn benchmark_whole_tree_scan(c: &mut Criterion) {
    let source = black_box(load_fixture("counter"));

    c.bench_function("whole_tree_scan_medium_contract", |b| {
        b.iter(|| {
            analyze_source(&source, "contract.rs")
        });
    });
}

fn benchmark_per_check_cost(c: &mut Criterion) {
    let source = black_box(load_fixture("counter"));

    // This demonstrates the typical pattern; in practice we'd profile
    // individual checks by name or by modifying the analyzer to expose timing
    c.bench_function("per_check_parsing_overhead", |b| {
        b.iter(|| {
            let _ast = syn::parse_file(&source);
        });
    });
}

fn benchmark_large_contract(c: &mut Criterion) {
    // Create a large-ish contract with many functions
    let mut large_source = String::from(
        r#"
use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct Large;

#[contractimpl]
impl Large {
"#,
    );

    for i in 0..50 {
        large_source.push_str(&format!(
            r#"
    pub fn func_{i}(env: Env, addr: Address) {{
        addr.require_auth();
        let _val: i128 = env.storage().instance().get(&()).unwrap_or(0);
    }}
"#
        ));
    }

    large_source.push_str("}\n");
    let large = black_box(large_source);

    c.bench_function("whole_tree_scan_large_contract", |b| {
        b.iter(|| {
            analyze_source(&large, "large.rs")
        });
    });
}

fn benchmark_visitor_overhead(c: &mut Criterion) {
    let source = black_box(load_fixture("counter"));

    // Measure the cost of running multiple visitors over the same tree
    c.bench_function("visitor_fan_out_35_checks", |b| {
        b.iter(|| {
            analyze_source(&source, "contract.rs")
        });
    });
}

criterion_group!(
    benches,
    benchmark_whole_tree_scan,
    benchmark_per_check_cost,
    benchmark_large_contract,
    benchmark_visitor_overhead
);
criterion_main!(benches);
