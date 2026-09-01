//! Vulnerability detectors for Soroban smart contracts.

pub mod admin;
pub mod annotations;
pub mod auth;
pub mod auth_order;
pub mod balance;
pub mod delegate;
pub mod division;
pub mod events;
pub mod global_state;
pub mod hardcoded_address;
pub mod invoke_return;
pub mod key_collision;
pub mod large_loop;
pub mod missing_event_for_admin_change;
pub mod missing_input_length_bound;
pub mod missing_nonce;
pub mod overflow;
pub mod panics;
pub mod reentrancy;
pub mod reinit;
pub mod std_imports;
pub mod storage;
pub mod transfer;
pub mod ttl;
pub mod unchecked_divisor;
pub mod unsafe_randomness;
pub mod vec_growth;
pub mod xc_input;
pub mod zero_address;
pub mod unchecked_token_amount;
pub mod uninitialized_storage_read;
pub mod unprotected_contract_deployment;
pub mod unprotected_token_mint;
pub mod unprotected_upgrade;
pub mod util;

pub use admin::UnprotectedAdminCheck;
pub use annotations::MissingContractAnnotationCheck;
pub use auth::MissingRequireAuthCheck;
pub use auth_order::AuthAfterStorageWriteCheck;
pub use balance::MissingBalanceCheck;
pub use delegate::DelegateCallRiskCheck;
pub use division::IntegerDivisionTruncationCheck;
pub use events::MissingEventEmissionCheck;
pub use global_state::MutableGlobalStateCheck;
pub use hardcoded_address::HardcodedAddressCheck;
pub use invoke_return::UncheckedInvokeReturnCheck;
pub use key_collision::SymbolKeyCollisionCheck;
pub use large_loop::LargeLoopCheck;
pub use missing_event_for_admin_change::MissingEventForAdminChangeCheck;
pub use missing_input_length_bound::MissingInputLengthBoundCheck;
pub use missing_nonce::MissingNonceCheck;
pub use overflow::UncheckedArithmeticCheck;
pub use panics::PanicInContractCheck;
pub use reentrancy::ReentrancyRiskCheck;
pub use reinit::ReInitializationRiskCheck;
pub use std_imports::ForbiddenStdImportsCheck;
pub use storage::UnsafeStoragePatternsCheck;
pub use transfer::SelfTransferCheck;
pub use ttl::MissingTtlExtensionCheck;
pub use unchecked_divisor::UncheckedDivisorCheck;
pub use unsafe_randomness::UnsafeRandomnessCheck;
pub use vec_growth::UnboundedVecGrowthCheck;
pub use xc_input::UnsafeCrossContractInputCheck;
pub use zero_address::MissingZeroAddressCheck;
pub use unchecked_token_amount::UncheckedTokenAmountCheck;
pub use uninitialized_storage_read::UninitializedStorageReadCheck;
pub use unprotected_contract_deployment::UnprotectedContractDeploymentCheck;
pub use unprotected_token_mint::UnprotectedTokenMintCheck;
pub use unprotected_upgrade::UnprotectedUpgradeCheck;

use serde::Serialize;
use std::collections::BTreeMap;
use std::collections::HashSet;
use syn::File;

/// Severity of a finding.
///
/// The `PartialOrd`/`Ord` implementation orders variants High → Medium → Low so
/// that `BTreeMap<Severity, _>` naturally sorts from most to least severe.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    High,
    Medium,
    Low,
}

// Manual ordering so High < Medium < Low in BTreeMap iteration (High first).
impl PartialOrd for Severity {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Severity {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        fn rank(s: &Severity) -> u8 {
            match s {
                Severity::High => 0,
                Severity::Medium => 1,
                Severity::Low => 2,
            }
        }
        rank(self).cmp(&rank(other))
    }
}

/// One issue reported by a check.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Finding {
    pub check_name: String,
    pub severity: Severity,
    pub file_path: String,
    pub line: usize,
    pub function_name: String,
    pub description: String,
    /// Link to the check's documentation section (exposed in `--json` output for
    /// dashboard integrations).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_url: Option<String>,
    /// One-liner fix hint shown in pretty output and included in `--json`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suggestion: Option<String>,
}

/// A static analyzer check implemented against a parsed `syn::File`.
pub trait Check {
    fn name(&self) -> &str;
    fn run(&self, file: &File, source: &str) -> Vec<Finding>;
}

/// Group a flat findings slice by `file_path`.
///
/// Returns a [`BTreeMap`] so callers iterate over files in deterministic
/// (lexicographic) order — useful for Markdown reports, GitHub annotations,
/// and per-file output formatters.
///
/// # Example
/// ```
/// use soroban_guard_checks::{Finding, Severity, group_by_file};
///
/// let findings = vec![
///     Finding {
///         check_name: "a".into(), severity: Severity::High,
///         file_path: "src/foo.rs".into(), line: 1,
///         function_name: "f".into(), description: "d".into(),
///         rule_url: None, suggestion: None,
///     },
/// ];
/// let grouped = group_by_file(&findings);
/// assert!(grouped.contains_key("src/foo.rs"));
/// ```
pub fn group_by_file<'a>(findings: &'a [Finding]) -> BTreeMap<&'a str, Vec<&'a Finding>> {
    let mut map: BTreeMap<&'a str, Vec<&'a Finding>> = BTreeMap::new();
    for finding in findings {
        map.entry(finding.file_path.as_str()).or_default().push(finding);
    }
    map
}

/// Group a flat findings slice by [`Severity`].
///
/// Returns a [`BTreeMap`] whose iteration order is **High → Medium → Low** (most
/// severe first) thanks to the manual [`Ord`] implementation on [`Severity`].
///
/// # Example
/// ```
/// use soroban_guard_checks::{Finding, Severity, group_by_severity};
///
/// let findings = vec![
///     Finding {
///         check_name: "a".into(), severity: Severity::Low,
///         file_path: "src/lib.rs".into(), line: 1,
///         function_name: "f".into(), description: "d".into(),
///         rule_url: None, suggestion: None,
///     },
/// ];
/// let grouped = group_by_severity(&findings);
/// assert!(grouped.contains_key(&Severity::Low));
/// ```
pub fn group_by_severity<'a>(findings: &'a [Finding]) -> BTreeMap<Severity, Vec<&'a Finding>> {
    let mut map: BTreeMap<Severity, Vec<&'a Finding>> = BTreeMap::new();
    for finding in findings {
        map.entry(finding.severity).or_default().push(finding);
    }
    map
}

/// Base list of all built-in checks, using the plain (no-config) constructor for every check.
///
/// This is the single source of truth for the check list. Both [`default_checks`] and
/// [`default_checks_with_config`] derive their lists from this function so that adding or
/// removing a check only requires editing one place.
fn all_checks_base() -> Vec<Box<dyn Check + Send + Sync>> {
    vec![
        Box::new(MissingRequireAuthCheck),
        Box::new(AuthAfterStorageWriteCheck),
        Box::new(UncheckedArithmeticCheck),
        Box::new(UnprotectedAdminCheck::new()),
        Box::new(UnsafeStoragePatternsCheck),
        Box::new(MissingTtlExtensionCheck),
        Box::new(ForbiddenStdImportsCheck),
        Box::new(HardcodedAddressCheck),
        Box::new(UnsafeCrossContractInputCheck),
        Box::new(MissingContractAnnotationCheck),
        Box::new(DelegateCallRiskCheck),
        Box::new(IntegerDivisionTruncationCheck),
        Box::new(MissingEventEmissionCheck),
        Box::new(SymbolKeyCollisionCheck),
        Box::new(SelfTransferCheck),
        Box::new(MissingZeroAddressCheck),
        Box::new(MutableGlobalStateCheck),
        Box::new(ReInitializationRiskCheck),
        Box::new(UncheckedInvokeReturnCheck),
        Box::new(MissingBalanceCheck),
        Box::new(UnboundedVecGrowthCheck),
        Box::new(UnsafeRandomnessCheck),
        Box::new(UncheckedDivisorCheck),
        Box::new(PanicInContractCheck),
        Box::new(UnprotectedUpgradeCheck),
        Box::new(UnprotectedTokenMintCheck),
        Box::new(UnprotectedContractDeploymentCheck),
        Box::new(UncheckedTokenAmountCheck),
        Box::new(LargeLoopCheck),
        Box::new(MissingNonceCheck),
        Box::new(UninitializedStorageReadCheck),
        Box::new(ReentrancyRiskCheck),
        Box::new(MissingEventForAdminChangeCheck),
        Box::new(MissingInputLengthBoundCheck),
    ]
}

fn ensure_unique_check_names(checks: &[Box<dyn Check + Send + Sync>]) {
    let mut names = HashSet::new();
    for check in checks {
        let name = check.name();
        assert!(names.insert(name), "duplicate check name: {name}");
    }
}

/// All checks executed by the analyzer (extend here as you add detectors).
///
/// Checks are **stateless and isolated**: implementations must not use shared
/// mutable static state or assume a particular invocation order. The analyzer
/// runs each check against the same parsed `syn::File` independently and
/// concatenates `Finding`s.
///
/// # Panics
///
/// Panics immediately if any two checks share the same [`Check::name`] string.
/// This catches copy-paste errors when adding a new detector before they can
/// cause silent finding collisions at runtime.
pub fn default_checks() -> Vec<Box<dyn Check + Send + Sync>> {
    let checks = all_checks_base();
    ensure_unique_check_names(&checks);
    checks
}

#[cfg(test)]
mod tests {
    use super::{default_checks, default_checks_with_config};

    #[test]
    fn default_and_configured_check_lists_share_same_names() {
        let default_names: Vec<_> = default_checks().iter().map(|check| check.name().to_string()).collect();
        let configured_names: Vec<_> = default_checks_with_config(&[], &[])
            .iter()
            .map(|check| check.name().to_string())
            .collect();

        assert_eq!(default_names, configured_names);
    }

    #[test]
    fn no_duplicate_check_names_in_default_lists() {
        use std::collections::HashSet;

        for names in [
            default_checks().iter().map(|c| c.name().to_string()).collect::<Vec<_>>(),
            default_checks_with_config(&[], &[]).iter().map(|c| c.name().to_string()).collect::<Vec<_>>(),
        ] {
            let unique: HashSet<_> = names.iter().cloned().collect();
            assert_eq!(names.len(), unique.len(), "duplicate check name found in {names:?}");
        }
    }
}

/// Like [`default_checks`] but applies config-file settings:
/// - `disabled`: check names to omit
/// - `extra_sensitive_names`: extra names added to `UnprotectedAdminCheck`
pub fn default_checks_with_config(
    disabled: &[String],
    extra_sensitive_names: &[String],
) -> Vec<Box<dyn Check + Send + Sync>> {
    let mut checks = all_checks_base();
    // `UnprotectedAdminCheck` is the only check whose construction is config-driven; swap the
    // plain instance from `all_checks_base()` for one built with the extra sensitive names.
    for check in checks.iter_mut() {
        if check.name() == UnprotectedAdminCheck::new().name() {
            *check = Box::new(UnprotectedAdminCheck::with_extra_names(extra_sensitive_names.to_vec()));
        }
    }
    checks.retain(|c| !disabled.contains(&c.name().to_string()));
    ensure_unique_check_names(&checks);
    checks
}

#[cfg(test)]
mod tests {
    use super::{default_checks, ensure_unique_check_names, Check, MissingRequireAuthCheck};
    use syn::parse_file;

    const VULNERABLE_FIXTURES: &[&str] = &[
        include_str!("../../../test-contracts/admin-event-vulnerable/src/lib.rs"),
        include_str!("../../../test-contracts/admin-vulnerable/src/lib.rs"),
        include_str!("../../../test-contracts/arithmetic-vulnerable/src/lib.rs"),
        include_str!("../../../test-contracts/auth-order-vulnerable/src/lib.rs"),
        include_str!("../../../test-contracts/balance-vulnerable/src/lib.rs"),
        include_str!("../../../test-contracts/contract-annotation-vulnerable/src/lib.rs"),
        include_str!("../../../test-contracts/contract-deployment-vulnerable/src/lib.rs"),
        include_str!("../../../test-contracts/delegate-vulnerable/src/lib.rs"),
        include_str!("../../../test-contracts/division-vulnerable/src/lib.rs"),
        include_str!("../../../test-contracts/event-vulnerable/src/lib.rs"),
        include_str!("../../../test-contracts/global-state-vulnerable/src/lib.rs"),
        include_str!("../../../test-contracts/hardcoded-address-vulnerable/src/lib.rs"),
        include_str!("../../../test-contracts/input-length-vulnerable/src/lib.rs"),
        include_str!("../../../test-contracts/invoke-return-vulnerable/src/lib.rs"),
        include_str!("../../../test-contracts/key-collision-vulnerable/src/lib.rs"),
        include_str!("../../../test-contracts/large-loop-vulnerable/src/lib.rs"),
        include_str!("../../../test-contracts/nonce-vulnerable/src/lib.rs"),
        include_str!("../../../test-contracts/panic-vulnerable/src/lib.rs"),
        include_str!("../../../test-contracts/reentrancy-vulnerable/src/lib.rs"),
        include_str!("../../../test-contracts/reinit-vulnerable/src/lib.rs"),
        include_str!("../../../test-contracts/self-transfer-vulnerable/src/lib.rs"),
        include_str!("../../../test-contracts/std-imports-vulnerable/src/lib.rs"),
        include_str!("../../../test-contracts/storage-vulnerable/src/lib.rs"),
        include_str!("../../../test-contracts/token-amount-vulnerable/src/lib.rs"),
        include_str!("../../../test-contracts/token-mint-vulnerable/src/lib.rs"),
        include_str!("../../../test-contracts/ttl-vulnerable/src/lib.rs"),
        include_str!("../../../test-contracts/unchecked-divisor-vulnerable/src/lib.rs"),
        include_str!("../../../test-contracts/uninitialized-storage-read-vulnerable/src/lib.rs"),
        include_str!("../../../test-contracts/unsafe-randomness-vulnerable/src/lib.rs"),
        include_str!("../../../test-contracts/upgrade-vulnerable/src/lib.rs"),
        include_str!("../../../test-contracts/vec-growth-vulnerable/src/lib.rs"),
        include_str!("../../../test-contracts/xc-input-vulnerable/src/lib.rs"),
        include_str!("../../../test-contracts/zero-address-vulnerable/src/lib.rs"),
    ];

    #[test]
    fn findings_from_default_checks_have_rule_urls() {
        let checks = default_checks();

        for source in VULNERABLE_FIXTURES {
            let file = parse_file(source).expect("fixture should parse");
            for check in &checks {
                for finding in check.run(&file, source) {
                    assert!(
                        finding.rule_url.is_some(),
                        "check {} emitted a finding without rule_url",
                        finding.check_name
                    );
                }
            }
        }
    }

    #[test]
    #[should_panic(expected = "duplicate check name: missing-require-auth")]
    fn duplicate_check_names_panic() {
        let checks: Vec<Box<dyn Check + Send + Sync>> = vec![
            Box::new(MissingRequireAuthCheck),
            Box::new(MissingRequireAuthCheck),
        ];
        ensure_unique_check_names(&checks);
    }
}
