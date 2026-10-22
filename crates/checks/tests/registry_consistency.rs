//! Registry consistency (Issue #609): every check in `default_checks()` must be
//! documented, exercised by `examples/all-findings`, and covered by a
//! `-vulnerable` / `-safe` fixture pair. CONTRIBUTING.md lists these steps for
//! new checks; this test makes them mandatory. Failures list every missing item.

use soroban_guard_checks::default_checks;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Fixture directory base per check (`test-contracts/<base>-vulnerable` and
/// `<base>-safe`). Fixture names don't always match check names, so the map is
/// explicit. An empty base means the original `vulnerable` / `safe` pair.
const FIXTURES: &[(&str, &str)] = &[
    ("missing-require-auth", ""),
    ("auth-after-storage-write", "auth-order"),
    ("unchecked-arithmetic", "arithmetic"),
    ("unprotected-admin", "admin"),
    ("unsafe-storage-patterns", "storage"),
    ("missing-ttl-extension", "ttl"),
    ("forbidden-std-imports", "std-imports"),
    ("hardcoded-address", "hardcoded-address"),
    ("unsafe-cross-contract-input", "xc-input"),
    ("missing-contract-annotation", "contract-annotation"),
    ("delegate-call-risk", "delegate"),
    ("integer-division-truncation", "division"),
    ("missing-event-emission", "event"),
    ("symbol-key-collision", "key-collision"),
    ("self-transfer", "self-transfer"),
    ("missing-zero-address-check", "zero-address"),
    ("mutable-global-state", "global-state"),
    ("re-initialization-risk", "reinit"),
    ("unchecked-invoke-return", "invoke-return"),
    ("missing-balance-check", "balance"),
    ("unbounded-vec-growth", "vec-growth"),
    ("unsafe-randomness", "unsafe-randomness"),
    ("unchecked-divisor", "unchecked-divisor"),
    ("panic-in-contract", "panic"),
    ("unprotected-upgrade", "upgrade"),
    ("unprotected-token-mint", "token-mint"),
    ("unprotected-contract-deployment", "contract-deployment"),
    ("unchecked-token-amount", "token-amount"),
    ("large-loop", "large-loop"),
    ("missing-nonce", "nonce"),
    ("uninitialized-storage-read", "uninitialized-storage-read"),
    ("reentrancy-risk", "reentrancy"),
    ("missing-event-for-admin-change", "admin-event"),
    ("missing-input-length-bound", "input-length"),
    ("unchecked-negation-or-abs", "negation"),
];

/// Checks allowed to have no `// Triggers` comment in examples/all-findings,
/// each with the reason. Keep this list short and justified.
const TRIGGERS_ALLOW_LIST: &[(&str, &str)] = &[(
    "missing-event-emission",
    "fires on almost every state-mutating method in all-findings (26 findings), so no single \
     method is dedicated to it",
)];

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(relative: &str) -> String {
    let path = repo_root().join(relative);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()))
}

/// Backticked names in `## \`<name>\` (Severity)` headings of docs/checks.md.
fn documented_checks() -> BTreeSet<String> {
    read("docs/checks.md")
        .lines()
        .filter_map(|l| l.strip_prefix("## `"))
        .filter_map(|l| l.split_once('`').map(|(name, _)| name.to_string()))
        .collect()
}

/// Every backticked name on a `// Triggers ...` line of examples/all-findings
/// (one comment may name several checks).
fn triggered_checks() -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    for line in read("examples/all-findings/src/lib.rs").lines() {
        let Some((_, rest)) = line.split_once("// Triggers") else {
            continue;
        };
        let head = rest.split(':').next().unwrap_or(rest);
        names.extend(head.split('`').skip(1).step_by(2).map(str::to_string));
    }
    names
}

fn fixture_dirs(base: &str) -> [String; 2] {
    if base.is_empty() {
        ["vulnerable".into(), "safe".into()]
    } else {
        [format!("{base}-vulnerable"), format!("{base}-safe")]
    }
}

#[test]
fn every_registered_check_is_documented_exercised_and_has_fixtures() {
    let registered: Vec<String> = default_checks()
        .iter()
        .map(|c| c.name().to_string())
        .collect();
    let documented = documented_checks();
    let triggered = triggered_checks();
    let mut missing = Vec::new();

    for name in &registered {
        if !documented.contains(name) {
            missing.push(format!(
                "{name}: no `## `{name}` (Severity)` heading in docs/checks.md"
            ));
        }
        let allowed = TRIGGERS_ALLOW_LIST.iter().any(|(n, _)| n == name);
        if !triggered.contains(name) && !allowed {
            missing.push(format!(
                "{name}: no `// Triggers `{name}`` comment in examples/all-findings/src/lib.rs"
            ));
        }
        match FIXTURES.iter().find(|(n, _)| n == name) {
            None => missing.push(format!(
                "{name}: no entry in FIXTURES (add its fixture pair to this test)"
            )),
            Some((_, base)) => {
                for dir in fixture_dirs(base) {
                    let path = repo_root()
                        .join("test-contracts")
                        .join(&dir)
                        .join("src/lib.rs");
                    if !path.is_file() {
                        missing.push(format!(
                            "{name}: missing fixture test-contracts/{dir}/src/lib.rs"
                        ));
                    }
                }
            }
        }
    }

    assert!(
        missing.is_empty(),
        "{} registry consistency problem(s):\n  - {}",
        missing.len(),
        missing.join("\n  - ")
    );
}

#[test]
fn test_tables_only_name_registered_checks() {
    let registered: BTreeSet<String> = default_checks()
        .iter()
        .map(|c| c.name().to_string())
        .collect();
    let stale: Vec<&str> = FIXTURES
        .iter()
        .map(|(n, _)| *n)
        .chain(TRIGGERS_ALLOW_LIST.iter().map(|(n, _)| *n))
        .filter(|n| !registered.contains(*n))
        .collect();
    assert!(
        stale.is_empty(),
        "entries for checks that are not registered: {stale:?}"
    );
}
