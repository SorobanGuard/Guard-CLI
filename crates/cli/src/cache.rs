//! On-disk scan cache for `--cache` (Issue #808).
//!
//! Cache entries are stored as JSON files in a user-specified directory (default
//! `.soroban-guard-cache/`).  Each entry is keyed by a fast non-cryptographic
//! hash of:
//!
//! - The file's byte content
//! - The tool version (`CARGO_PKG_VERSION`)
//! - The sorted list of enabled-check names
//!
//! The hash is intentionally non-cryptographic (uses `std::collections::hash_map::DefaultHasher`)
//! because this is a dev-time performance cache, not a security boundary.
//! Corrupt or missing entries are silently ignored — the cache is never fatal.

use soroban_guard_checks::Finding;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};

/// An on-disk scan-result cache.
pub struct ScanCache {
    dir: PathBuf,
    tool_version: &'static str,
}

impl ScanCache {
    /// Create a cache rooted at `dir`.
    pub fn new(dir: PathBuf) -> Self {
        ScanCache {
            dir,
            tool_version: env!("CARGO_PKG_VERSION"),
        }
    }

    /// Compute the cache key for a file given its content and enabled check names.
    pub fn key(&self, content: &str, check_names: &[&str]) -> String {
        let mut hasher = DefaultHasher::new();
        content.hash(&mut hasher);
        self.tool_version.hash(&mut hasher);
        // Sort for determinism.
        let mut sorted: Vec<&str> = check_names.to_vec();
        sorted.sort_unstable();
        for name in sorted {
            name.hash(&mut hasher);
        }
        format!("{:016x}", hasher.finish())
    }

    fn entry_path(&self, key: &str) -> PathBuf {
        self.dir.join(format!("{key}.json"))
    }

    /// Try to read a cached finding list.  Returns `None` on any error.
    pub fn get(&self, key: &str) -> Option<Vec<Finding>> {
        let data = std::fs::read_to_string(self.entry_path(key)).ok()?;
        serde_json::from_str(&data).ok()
    }

    /// Write findings to the cache.  Silently ignores all errors.
    pub fn put(&self, key: &str, findings: &[Finding]) {
        if std::fs::create_dir_all(&self.dir).is_err() {
            return;
        }
        if let Ok(data) = serde_json::to_string(findings) {
            let _ = std::fs::write(self.entry_path(key), data);
        }
    }
}

/// Read a file's content and return `(content, cache_key)` using the given cache.
/// Returns `None` on read error.
pub fn file_key(path: &Path, cache: &ScanCache, check_names: &[&str]) -> Option<(String, String)> {
    let content = std::fs::read_to_string(path).ok()?;
    let key = cache.key(&content, check_names);
    Some((content, key))
}
