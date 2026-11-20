//! Baseline filtering for CLI findings.
//!
//! A baseline records previously-seen findings so that only *new* findings are
//! reported. Baselines are stored as a **multiset** (fingerprint -> count) rather
//! than a set: if a function has two identical findings and the baseline only
//! recorded one, the second must still be reported as new.
//!
//! ## Fingerprint stability
//!
//! A [`FindingFingerprint`] is derived from the *stable* fields of a finding
//! (check, file, function) plus an occurrence index that disambiguates identical
//! findings within the same function. The human-readable `description` is
//! deliberately **excluded** from the fingerprint so that wording tweaks to a
//! check do not invalidate every stored baseline for that check.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// A single finding produced by a check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub check: String,
    pub file: String,
    pub function: String,
    pub description: String,
}

/// Stable identity of a finding, used to match against a baseline.
///
/// Only stable fields are hashed; `description` is intentionally omitted.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FindingFingerprint {
    pub check: String,
    pub file: String,
    pub function: String,
    /// Disambiguates identical findings within the same function.
    pub occurrence: usize,
}

/// A baseline is a multiset of fingerprints: fingerprint -> number of times it
/// was observed.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Baseline {
    counts: HashMap<FindingFingerprint, usize>,
}

impl Baseline {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a finding in the baseline, incrementing its occurrence count.
    pub fn insert(&mut self, fingerprint: FindingFingerprint) {
        *self.counts.entry(fingerprint).or_insert(0) += 1;
    }

    pub fn len(&self) -> usize {
        self.counts.values().sum()
    }

    pub fn is_empty(&self) -> bool {
        self.counts.is_empty()
    }
}

/// Compute fingerprints for a list of findings, assigning an occurrence index
/// to identical (check, file, function) tuples in order of appearance.
pub fn fingerprint_findings(findings: &[Finding]) -> Vec<FindingFingerprint> {
    let mut seen: HashMap<(String, String, String), usize> = HashMap::new();
    findings
        .iter()
        .map(|f| {
            let key = (f.check.clone(), f.file.clone(), f.function.clone());
            let occurrence = seen.entry(key).or_insert(0);
            let fingerprint = FindingFingerprint {
                check: f.check.clone(),
                file: f.file.clone(),
                function: f.function.clone(),
                occurrence: *occurrence,
            };
            *occurrence += 1;
            fingerprint
        })
        .collect()
}

/// Result of filtering findings against a baseline.
#[derive(Debug, Clone)]
pub struct FilterResult {
    /// Findings not present in the baseline (reported to the user).
    pub new_findings: Vec<Finding>,
    /// Number of current findings matched by the baseline.
    pub hidden_count: usize,
}

/// Filter `findings` against `baseline`, returning the new findings and the
/// number of findings hidden by the baseline.
///
/// Matching is multiset-aware: each baseline entry can hide at most as many
/// findings as its recorded count.
pub fn filter_findings(findings: &[Finding], baseline: &Baseline) -> FilterResult {
    let fingerprints = fingerprint_findings(findings);
    let mut remaining = baseline.counts.clone();

    let mut new_findings = Vec::new();
    let mut hidden_count = 0usize;

    for (finding, fingerprint) in findings.iter().zip(fingerprints.iter()) {
        match remaining.get_mut(fingerprint) {
            Some(count) if *count > 0 => {
                *count -= 1;
                hidden_count += 1;
            }
            _ => new_findings.push(finding.clone()),
        }
    }

    FilterResult {
        new_findings,
        hidden_count,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rfc3339_now;

    fn finding(check: &str, file: &str, function: &str, description: &str) -> Finding {
        Finding {
            check: check.to_string(),
            file: file.to_string(),
            function: function.to_string(),
            description: description.to_string(),
        }
    }

    #[test]
    fn test_filter_findings_with_baseline() {
        let findings = vec![
            finding("check-a", "a.rs", "foo", "first"),
            finding("check-b", "b.rs", "bar", "second"),
        ];

        let mut baseline = Baseline::new();
        for fp in fingerprint_findings(&findings) {
            baseline.insert(fp);
        }

        let result = filter_findings(&findings, &baseline);
        assert!(result.new_findings.is_empty());
        assert_eq!(result.hidden_count, 2);
    }

    #[test]
    fn test_filter_findings_reports_new() {
        let baseline_findings = vec![finding("check-a", "a.rs", "foo", "first")];
        let mut baseline = Baseline::new();
        for fp in fingerprint_findings(&baseline_findings) {
            baseline.insert(fp);
        }

        let current = vec![
            finding("check-a", "a.rs", "foo", "first"),
            finding("check-b", "b.rs", "bar", "second"),
        ];

        let result = filter_findings(&current, &baseline);
        assert_eq!(result.new_findings.len(), 1);
        assert_eq!(result.new_findings[0].check, "check-b");
        assert_eq!(result.hidden_count, 1);
    }

    #[test]
    fn test_multiset_duplicate_findings() {
        // Baseline recorded one occurrence of an identical finding.
        let baseline_findings = vec![finding("check-a", "a.rs", "foo", "dup")];
        let mut baseline = Baseline::new();
        for fp in fingerprint_findings(&baseline_findings) {
            baseline.insert(fp);
        }

        // Current run has two identical findings.
        let current = vec![
            finding("check-a", "a.rs", "foo", "dup"),
            finding("check-a", "a.rs", "foo", "dup"),
        ];

        let result = filter_findings(&current, &baseline);
        assert_eq!(result.new_findings.len(), 1);
        assert_eq!(result.hidden_count, 1);
    }

    #[test]
    fn test_fingerprint_ignores_description() {
        let a = vec![finding("check-a", "a.rs", "foo", "old wording")];
        let b = vec![finding("check-a", "a.rs", "foo", "new wording")];
        assert_eq!(fingerprint_findings(&a), fingerprint_findings(&b));
    }

    #[test]
    fn test_rfc3339_now_format() {
        let ts = rfc3339_now();
        assert!(ts.ends_with('Z'));
        assert_eq!(ts.len(), 20);
        assert_eq!(&ts[4..5], "-");
        assert_eq!(&ts[10..11], "T");
    }
}
