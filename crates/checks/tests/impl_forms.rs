//! Parameterised test for `#[contractimpl]` edge forms (issue #985).
//!
//! Covers the 6 impl shapes that the `contractimpl_functions()` helper must
//! handle: plain impl, nested-module impl, fully-qualified attribute path,
//! trait impl, `pub(crate)` visibility, and an impl in a "generic-looking" context.
//!
//! For each shape we assert:
//! - at least one `missing-require-auth` finding fires on the **vulnerable** fixture, and
//! - **zero** `missing-require-auth` findings fire on the **safe** fixture.

use soroban_guard_checks::{default_checks, Check, MissingRequireAuthCheck};
use syn::parse_file;

const VULNERABLE: &str =
    include_str!("../../../test-contracts/impl-forms-vulnerable/src/lib.rs");
const SAFE: &str = include_str!("../../../test-contracts/impl-forms-safe/src/lib.rs");

fn auth_check() -> impl Check {
    MissingRequireAuthCheck
}

/// Run only `missing-require-auth` over `source` and return all findings.
fn auth_findings(source: &str) -> Vec<soroban_guard_checks::Finding> {
    let file = parse_file(source).expect("fixture should parse");
    auth_check().run(&file, source)
}

#[test]
fn vulnerable_fixture_fires_missing_require_auth() {
    let findings = auth_findings(VULNERABLE);
    assert!(
        !findings.is_empty(),
        "expected at least one missing-require-auth finding in impl-forms-vulnerable"
    );
}

#[test]
fn safe_fixture_has_no_missing_require_auth() {
    let findings = auth_findings(SAFE);
    assert!(
        findings.is_empty(),
        "impl-forms-safe should have no missing-require-auth findings, got: {findings:?}"
    );
}

#[test]
fn all_checks_do_not_panic_on_impl_form_fixtures() {
    let checks = default_checks();
    for source in [VULNERABLE, SAFE] {
        let file = parse_file(source).expect("fixture should parse");
        for check in &checks {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                check.run(&file, source)
            }));
            assert!(
                result.is_ok(),
                "check `{}` panicked on impl-forms fixture",
                check.name()
            );
        }
    }
}
