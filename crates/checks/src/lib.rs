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

/// Compute the Levenshtein edit distance between two strings.
///
/// Dependency-free implementation used to power "did you mean" suggestions for
/// unknown check names. Operates on `char`s so multi-byte input is handled
/// correctly.
fn levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut curr = vec![0usize; b.len() + 1];
    for (i, ca) in a.iter().enumerate() {
        curr[0] = i + 1;
        for (j, cb) in b.iter().enumerate() {
            let cost = if ca == cb { 0 } else { 1 };
            curr[j + 1] = (prev[j] + cost).min(prev[j + 1] + 1).min(curr[j] + 1);
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[b.len()]
}

/// Suggest up to three registered check names closest to `unknown`.
///
/// Candidates are ranked by Levenshtein edit distance against the registered
/// check names, keeping only those within a small distance threshold (or that
/// share a common prefix). Returns an empty vector when nothing is close enough.
pub fn suggest_check_names(unknown: &str) -> Vec<String> {
    let names: Vec<String> = default_checks().iter().map(|c| c.name().to_string()).collect();
    suggest_from_names(unknown, &names)
}

/// Suggest up to three names from `names` closest to `unknown`.
///
/// Exposed so callers that already hold a name list (e.g. `explain`) can reuse
/// the ranking without rebuilding the check registry.
pub fn suggest_from_names(unknown: &str, names: &[String]) -> Vec<String> {
    let unknown_lower = unknown.to_ascii_lowercase();
    let mut scored: Vec<(usize, &String)> = names
        .iter()
        .map(|name| (levenshtein(&unknown_lower, &name.to_ascii_lowercase()), name))
        .filter(|(dist, name)| {
            let threshold = (unknown.len() / 3).max(2);
            *dist <= threshold || shares_prefix(&unknown_lower, &name.to_ascii_lowercase())
        })
        .collect();
    scored.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(b.1)));
    scored.into_iter().take(3).map(|(_, name)| name.clone()).collect()
}

/// Whether two names share a non-trivial common prefix (at least 4 chars).
fn shares_prefix(a: &str, b: &str) -> bool {
    let common = a.chars().zip(b.chars()).take_while(|(x, y)| x == y).count();
    common >= 4
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
        Box::new(MissingN

/* … truncated 7280 chars — edit only what you need near the top … */
