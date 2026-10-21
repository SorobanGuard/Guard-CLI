pub mod baseline;
pub mod config;

use config::Config;

/// Returns true if a finding for `path` with check id `check_id` should be
/// suppressed by any `[[overrides]]` entry in `config`.
///
/// Overrides stack in file order: a finding is dropped if *any* matching
/// override lists its check id in `disabled`.
pub fn is_finding_overridden(config: &Config, path: &str, check_id: &str) -> bool {
    config.overrides.iter().any(|ov| {
        ov.disabled.iter().any(|d| d == check_id)
            && ov.paths.iter().any(|glob| config::glob_matches(glob, path))
    })
}
