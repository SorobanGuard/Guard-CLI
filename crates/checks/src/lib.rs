//! Vulnerability detectors for Soroban smart contracts.

pub mod admin;
pub mod annotations;
pub mod auth;
pub mod delegate;
pub mod division;
pub mod events;
pub mod global_state;
pub mod hardcoded_address;
pub mod key_collision;
pub mod overflow;
pub mod panics;
pub mod reentrancy;
pub mod std_imports;
pub mod storage;
pub mod transfer;
pub mod ttl;
pub mod xc_input;
pub mod zero_address;
mod util;

pub use admin::UnprotectedAdminCheck;
pub use annotations::MissingContractAnnotationCheck;
pub use auth::MissingRequireAuthCheck;
pub use delegate::DelegateCallRiskCheck;
pub use division::IntegerDivisionTruncationCheck;
pub use events::MissingEventEmissionCheck;
pub use global_state::MutableGlobalStateCheck;
pub use hardcoded_address::HardcodedAddressCheck;
pub use key_collision::SymbolKeyCollisionCheck;
pub use overflow::UncheckedArithmeticCheck;
pub use panics::PanicInContractCheck;
pub use reentrancy::ReentrancyRiskCheck;
pub use std_imports::ForbiddenStdImportsCheck;
pub use storage::UnsafeStoragePatternsCheck;
pub use transfer::SelfTransferCheck;
pub use ttl::MissingTtlExtensionCheck;
pub use xc_input::UnsafeCrossContractInputCheck;
pub use zero_address::MissingZeroAddressCheck;

use serde::Serialize;
use std::collections::BTreeMap;
use syn::File;

/// Severity of a finding.
///
/// The `PartialOrd`/`Ord` implementation orders variants High → Medium → Low so
/// that `BTreeMap<Severity, _>` naturally sorts from most to least severe.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
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

/// All checks executed by the analyzer (extend here as you add detectors).
///
/// Checks are **stateless and isolated**: implementations must not use shared
/// mutable static state or assume a particular invocation order. The analyzer
/// runs each check against the same parsed `syn::File` independently and
/// concatenates `Finding`s.
pub fn default_checks() -> Vec<Box<dyn Check + Send + Sync>> {
    vec![
        Box::new(MissingRequireAuthCheck),
        Box::new(UncheckedArithmeticCheck),
        Box::new(UnprotectedAdminCheck),
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
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_finding(file_path: &str, severity: Severity) -> Finding {
        Finding {
            check_name: "test-check".into(),
            severity,
            file_path: file_path.into(),
            line: 1,
            function_name: "f".into(),
            description: "desc".into(),
            rule_url: None,
            suggestion: None,
        }
    }

    // ── Issue 1: group_by_file ────────────────────────────────────────────────

    #[test]
    fn group_by_file_groups_across_multiple_files() {
        let findings = vec![
            make_finding("src/foo.rs", Severity::High),
            make_finding("src/bar.rs", Severity::Medium),
            make_finding("src/foo.rs", Severity::Low),
        ];

        let grouped = group_by_file(&findings);

        // Two distinct files
        assert_eq!(grouped.len(), 2);

        // foo.rs has 2 findings, bar.rs has 1
        assert_eq!(grouped["src/foo.rs"].len(), 2);
        assert_eq!(grouped["src/bar.rs"].len(), 1);

        // BTreeMap order: bar.rs < foo.rs
        let mut keys = grouped.keys();
        assert_eq!(*keys.next().unwrap(), "src/bar.rs");
        assert_eq!(*keys.next().unwrap(), "src/foo.rs");
    }

    #[test]
    fn group_by_file_empty_slice_returns_empty_map() {
        let grouped = group_by_file(&[]);
        assert!(grouped.is_empty());
    }

    // ── Issue 2: group_by_severity ────────────────────────────────────────────

    #[test]
    fn group_by_severity_spans_all_three_levels() {
        let findings = vec![
            make_finding("src/a.rs", Severity::Low),
            make_finding("src/b.rs", Severity::High),
            make_finding("src/c.rs", Severity::Medium),
            make_finding("src/d.rs", Severity::High),
        ];

        let grouped = group_by_severity(&findings);

        assert_eq!(grouped[&Severity::High].len(), 2);
        assert_eq!(grouped[&Severity::Medium].len(), 1);
        assert_eq!(grouped[&Severity::Low].len(), 1);

        // Iteration order must be High → Medium → Low
        let order: Vec<Severity> = grouped.keys().copied().collect();
        assert_eq!(order, vec![Severity::High, Severity::Medium, Severity::Low]);
    }

    #[test]
    fn group_by_severity_empty_slice_returns_empty_map() {
        let grouped = group_by_severity(&[]);
        assert!(grouped.is_empty());
    }
}
