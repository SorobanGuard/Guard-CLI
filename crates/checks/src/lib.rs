//! Default checks run against parsed Rust source.
//!
//! The public entry point is [`default_checks`], which returns the list of
//! checks that run by default. Each check operates on a `syn::File` and must
//! never panic on arbitrary input — fuzz targets rely on this guarantee.

use syn::File;

/// A single check that inspects a parsed Rust source file.
pub trait Check {
    /// Human-readable name of the check.
    fn name(&self) -> &'static str;

    /// Run the check against `file`, returning any findings.
    fn run(&self, file: &File) -> Vec<String>;
}

/// Returns every check that runs by default.
pub fn default_checks() -> Vec<Box<dyn Check>> {
    vec![]
}

/// Parse `source` as Rust and, if it parses, run every default check.
///
/// Returns `None` when `source` is not valid Rust. Never panics on arbitrary
/// input; this is the entry point exercised by the `cargo-fuzz` target.
pub fn parse_and_check(source: &str) -> Option<Vec<String>> {
    let file = syn::parse_file(source).ok()?;
    let mut findings = Vec::new();
    for check in default_checks() {
        findings.extend(check.run(&file));
    }
    Some(findings)
}
