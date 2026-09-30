/// Baseline support for adopting soroban-guard on existing codebases.
///
/// Baseline records findings that exist today and fails only on new findings,
/// allowing projects to adopt soroban-guard without suppressing existing issues.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct FindingFingerprint {
    pub check_name: String,
    pub file_path: String,
    pub function_name: Option<String>,
    pub description: String,
}

impl FindingFingerprint {
    /// Create a fingerprint from a finding (deliberately excluding line number).
    pub fn from_finding(
        check_name: String,
        file_path: String,
        function_name: Option<String>,
        description: String,
    ) -> Self {
        Self {
            check_name,
            file_path,
            function_name,
            description,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineFile {
    pub version: String,
    pub created_at: String,
    pub findings: Vec<FindingFingerprint>,
}

impl BaselineFile {
    pub fn new(findings: Vec<FindingFingerprint>) -> Self {
        Self {
            version: "1.0".to_string(),
            created_at: chrono::Utc::now().to_rfc3339(),
            findings,
        }
    }

    pub fn save(&self, path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }

    pub fn load(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let baseline = serde_json::from_str(&content)?;
        Ok(baseline)
    }

    pub fn as_set(&self) -> HashSet<FindingFingerprint> {
        self.findings.iter().cloned().collect()
    }
}

/// Filter findings against baseline, returning only new findings.
pub fn filter_findings(
    current_findings: Vec<FindingFingerprint>,
    baseline: Option<&BaselineFile>,
) -> (Vec<FindingFingerprint>, usize) {
    if let Some(baseline) = baseline {
        let baseline_set = baseline.as_set();
        let new_findings: Vec<FindingFingerprint> = current_findings
            .into_iter()
            .filter(|f| !baseline_set.contains(f))
            .collect();
        let hidden_count = baseline_set.len() - (baseline_set.len() - new_findings.len());
        (new_findings, hidden_count)
    } else {
        (current_findings, 0)
    }
}

/// Compare baseline against current findings to identify fixed issues.
pub fn identify_fixed_findings(
    baseline: &BaselineFile,
    current_findings: &[FindingFingerprint],
) -> Vec<FindingFingerprint> {
    let current_set: HashSet<_> = current_findings.iter().cloned().collect();
    baseline
        .findings
        .iter()
        .filter(|f| !current_set.contains(f))
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_finding_fingerprint_creation() {
        let fp = FindingFingerprint::from_finding(
            "missing-zero-address-check".to_string(),
            "src/contract.rs".to_string(),
            Some("transfer".to_string()),
            "Admin address not checked for zero".to_string(),
        );

        assert_eq!(fp.check_name, "missing-zero-address-check");
        assert_eq!(fp.file_path, "src/contract.rs");
        assert_eq!(fp.function_name, Some("transfer".to_string()));
    }

    #[test]
    fn test_filter_findings_no_baseline() {
        let findings = vec![
            FindingFingerprint::from_finding(
                "check1".to_string(),
                "file1.rs".to_string(),
                None,
                "Issue 1".to_string(),
            ),
        ];

        let (filtered, hidden) = filter_findings(findings.clone(), None);
        assert_eq!(filtered.len(), 1);
        assert_eq!(hidden, 0);
    }

    #[test]
    fn test_filter_findings_with_baseline() {
        let baseline = BaselineFile::new(vec![
            FindingFingerprint::from_finding(
                "check1".to_string(),
                "file1.rs".to_string(),
                None,
                "Issue 1".to_string(),
            ),
        ]);

        let findings = vec![
            FindingFingerprint::from_finding(
                "check1".to_string(),
                "file1.rs".to_string(),
                None,
                "Issue 1".to_string(),
            ),
            FindingFingerprint::from_finding(
                "check2".to_string(),
                "file2.rs".to_string(),
                None,
                "Issue 2".to_string(),
            ),
        ];

        let (filtered, hidden) = filter_findings(findings, Some(&baseline));
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].check_name, "check2");
    }

    #[test]
    fn test_identify_fixed_findings() {
        let baseline = BaselineFile::new(vec![
            FindingFingerprint::from_finding(
                "check1".to_string(),
                "file1.rs".to_string(),
                None,
                "Issue 1".to_string(),
            ),
            FindingFingerprint::from_finding(
                "check2".to_string(),
                "file2.rs".to_string(),
                None,
                "Issue 2".to_string(),
            ),
        ]);

        let current = vec![
            FindingFingerprint::from_finding(
                "check1".to_string(),
                "file1.rs".to_string(),
                None,
                "Issue 1".to_string(),
            ),
        ];

        let fixed = identify_fixed_findings(&baseline, &current);
        assert_eq!(fixed.len(), 1);
        assert_eq!(fixed[0].check_name, "check2");
    }
}
