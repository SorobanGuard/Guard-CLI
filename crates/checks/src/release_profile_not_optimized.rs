//! Check release-like Cargo profiles for Soroban WASM size optimizations.

use crate::util::is_cfg_test;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::{Attribute, File, Item};
use toml::Value;

const CHECK_NAME: &str = "release-profile-not-optimized";
const REQUIRED_SETTINGS: &[(&str, &str)] = &[
    ("opt-level", "\"z\""),
    ("lto", "true"),
    ("panic", "\"abort\""),
    ("codegen-units", "1"),
    ("strip", "\"symbols\""),
];

pub struct ReleaseProfileNotOptimizedCheck;

fn has_contract_attribute(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|attr| {
        attr.path().segments.last().is_some_and(|segment| {
            matches!(
                segment.ident.to_string().as_str(),
                "contract" | "contractimpl"
            )
        })
    })
}

fn contains_contract(items: &[Item]) -> bool {
    items.iter().any(|item| match item {
        Item::Mod(module) => {
            !is_cfg_test(&module.attrs)
                && module.ident != "tests"
                && module.ident != "test"
                && module
                    .content
                    .as_ref()
                    .is_some_and(|(_, nested)| contains_contract(nested))
        }
        Item::Struct(item) => !is_cfg_test(&item.attrs) && has_contract_attribute(&item.attrs),
        Item::Impl(item) => !is_cfg_test(&item.attrs) && has_contract_attribute(&item.attrs),
        _ => false,
    })
}

fn collect_test_module_ranges(items: &[Item], ranges: &mut Vec<(usize, usize)>) {
    for item in items {
        if let Item::Mod(module) = item {
            if is_cfg_test(&module.attrs) || module.ident == "tests" || module.ident == "test" {
                ranges.push((module.span().start().line, module.span().end().line));
            } else if let Some((_, nested)) = &module.content {
                collect_test_module_ranges(nested, ranges);
            }
        }
    }
}

fn allows_check(source: &str) -> bool {
    let Ok(file) = syn::parse_file(source) else {
        return false;
    };
    let mut test_ranges = Vec::new();
    collect_test_module_ranges(&file.items, &mut test_ranges);
    source.lines().enumerate().any(|(index, line)| {
        let line_number = index + 1;
        if test_ranges
            .iter()
            .any(|(start, end)| *start <= line_number && line_number <= *end)
        {
            return false;
        }
        let Some(comment) = line.trim_start().strip_prefix("//") else {
            return false;
        };
        if comment.starts_with('/') {
            return false;
        }
        let Some(rest) = comment.trim_start().strip_prefix("soroban-guard") else {
            return false;
        };
        let Some(rest) = rest.trim_start().strip_prefix(':') else {
            return false;
        };
        let Some((checks, _)) = rest
            .trim_start()
            .strip_prefix("allow(")
            .and_then(|s| s.split_once(')'))
        else {
            return false;
        };
        checks
            .split(',')
            .map(str::trim)
            .any(|check| check == CHECK_NAME)
    })
}

fn inherited_profile_value<'a>(
    profile_name: &str,
    key: &str,
    profiles: &'a toml::map::Map<String, Value>,
    depth: usize,
) -> Option<&'a Value> {
    if depth > profiles.len() {
        return None;
    }
    let profile = profiles.get(profile_name)?.as_table()?;
    if let Some(value) = profile.get(key) {
        return Some(value);
    }
    let inherited = profile.get("inherits")?.as_str()?;
    inherited_profile_value(inherited, key, profiles, depth + 1)
}

fn profile_header_line(source: &str, profile_name: &str) -> usize {
    let header = format!("[profile.{profile_name}]");
    source
        .lines()
        .position(|line| line.trim() == header)
        .map_or(1, |index| index + 1)
}

fn check_profile(
    source: &str,
    profiles: &toml::map::Map<String, Value>,
    profile_name: &str,
    findings: &mut Vec<Finding>,
) {
    for (key, expected_toml) in REQUIRED_SETTINGS {
        let expected_document: Value = toml::from_str(&format!("expected = {expected_toml}"))
            .expect("required profile value should be valid TOML");
        let expected_value = expected_document
            .get("expected")
            .expect("expected profile value should be present");
        if inherited_profile_value(profile_name, key, profiles, 0) == Some(&expected_value) {
            continue;
        }
        findings.push(Finding {
            check_name: CHECK_NAME.to_string(),
            severity: Severity::Low,
            file_path: String::new(),
            line: profile_header_line(source, profile_name),
            function_name: profile_name.to_string(),
            description: format!(
                "`[profile.{profile_name}]` is missing the recommended `{key} = {expected_toml}` \
                 setting for compact Soroban WASM output."
            ),
            rule_url: Some(
                "https://github.com/SorobanGuard/Guard-CLI/blob/main/docs/checks.md#release-profile-not-optimized-low"
                    .to_string(),
            ),
            suggestion: Some(format!(
                "Add or update this setting:\n[profile.{profile_name}]\n{key} = {expected_toml}"
            )),
        });
    }
}

impl Check for ReleaseProfileNotOptimizedCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, _file: &File, _source: &str) -> Vec<Finding> {
        Vec::new()
    }

    fn run_manifest(
        &self,
        manifest_source: &str,
        workspace_manifest_source: Option<&str>,
        contract_sources: &[String],
    ) -> Result<Vec<Finding>, String> {
        let contract_files: Vec<File> = contract_sources
            .iter()
            .filter_map(|source| syn::parse_file(source).ok())
            .collect();
        if !contract_files
            .iter()
            .any(|file| contains_contract(&file.items))
            || contract_sources.iter().any(|source| allows_check(source))
        {
            return Ok(Vec::new());
        }

        let profile_source = workspace_manifest_source.unwrap_or(manifest_source);
        let document: Value = toml::from_str(profile_source)
            .map_err(|error| format!("failed to parse Cargo manifest: {error}"))?;
        let profiles = document
            .get("profile")
            .and_then(Value::as_table)
            .cloned()
            .unwrap_or_default();

        let mut profile_names = vec!["release".to_string()];
        profile_names.extend(
            profiles
                .keys()
                .filter(|name| name.starts_with("release-"))
                .cloned(),
        );
        profile_names.sort();
        profile_names.dedup();

        let mut findings = Vec::new();
        for profile_name in profile_names {
            check_profile(profile_source, &profiles, &profile_name, &mut findings);
        }
        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONTRACT: &str = r#"
use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Contract;
#[contractimpl]
impl Contract {}
"#;

    fn run(manifest: &str, workspace: Option<&str>, source: &str) -> Vec<Finding> {
        ReleaseProfileNotOptimizedCheck
            .run_manifest(manifest, workspace, &[source.to_string()])
            .expect("manifest should parse")
    }

    #[test]
    fn reports_each_missing_release_setting() {
        let findings = run("[package]\nname = \"contract\"\n", None, CONTRACT);
        assert_eq!(findings.len(), REQUIRED_SETTINGS.len());
        assert!(findings.iter().all(|finding| {
            finding.severity == Severity::Low
                && finding.rule_url.is_some()
                && finding.suggestion.is_some()
        }));
    }

    #[test]
    fn accepts_complete_release_profile() {
        let findings = run(
            r#"[profile.release]
opt-level = "z"
lto = true
panic = "abort"
codegen-units = 1
strip = "symbols"
"#,
            None,
            CONTRACT,
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn reports_contrary_profile_values() {
        let findings = run(
            r#"[profile.release]
opt-level = "3"
lto = false
panic = "abort"
codegen-units = 16
strip = "debuginfo"
"#,
            None,
            CONTRACT,
        );
        assert_eq!(findings.len(), 4);
        assert!(findings
            .iter()
            .any(|finding| finding.description.contains("opt-level = \"z\"")));
        assert!(findings
            .iter()
            .any(|finding| finding.description.contains("lto = true")));
    }

    #[test]
    fn ignores_contract_annotations_gated_to_cfg_test() {
        let test_contract = r#"
#[cfg(test)]
mod tests {
    #[contract]
    pub struct TestContract;
}
"#;
        assert!(run("[package]\nname = \"non-contract\"\n", None, test_contract).is_empty());
    }

    #[test]
    fn honors_source_suppression() {
        let source = format!("// soroban-guard: allow({CHECK_NAME})\n{CONTRACT}");
        assert!(run("[package]\nname = \"contract\"\n", None, &source).is_empty());
    }

    #[test]
    fn ignores_crates_without_contract_annotations() {
        let source = "pub struct OrdinaryLibrary;\n";
        assert!(run("[package]\nname = \"library\"\n", None, source).is_empty());
    }

    #[test]
    fn inherits_settings_from_workspace_profile() {
        let workspace = r#"[workspace]
members = []
[profile.release]
opt-level = "z"
lto = true
panic = "abort"
codegen-units = 1
strip = "symbols"
"#;
        assert!(run(
            "[package]\nname = \"contract\"\n",
            Some(workspace),
            CONTRACT
        )
        .is_empty());
    }

    #[test]
    fn checks_custom_release_profiles_and_inheritance() {
        let workspace = r#"[profile.release]
opt-level = "z"
lto = true
panic = "abort"
codegen-units = 1
strip = "symbols"
[profile.release-with-logs]
inherits = "release"
debug = true
"#;
        assert!(run(
            "[package]\nname = \"contract\"\n",
            Some(workspace),
            CONTRACT
        )
        .is_empty());
    }
}
