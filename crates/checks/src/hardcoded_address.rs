//! Hardcoded Stellar public-key strings (`G...`, 56 chars) baked into contract source.

use crate::{Check, Finding, Severity};
use syn::File;

const CHECK_NAME: &str = "hardcoded-address";
const KEY_LEN: usize = 56;

/// Stellar `StrKey` public keys are 56-char base32 strings starting with `G`. Hardcoding one
/// bakes a fixed address into the contract, which breaks if the account or contract is
/// redeployed. Works on the raw source text rather than the parsed AST.
pub struct HardcodedAddressCheck;

impl Check for HardcodedAddressCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, _file: &File, source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for (idx, line) in source.lines().enumerate() {
            for key in find_candidate_keys(line) {
                out.push(Finding {
                    check_name: CHECK_NAME.to_string(),
                    severity: Severity::Medium,
                    file_path: String::new(),
                    line: idx + 1,
                    function_name: "module".to_string(),
                    description: format!(
                        "String literal `{key}` looks like a hardcoded Stellar public key. \
                         Pass addresses in as contract parameters or configuration instead of \
                         baking them into source."
                    ),
                });
            }
        }
        out
    }
}

fn is_strkey_char(b: u8) -> bool {
    b.is_ascii_uppercase() || (b'2'..=b'7').contains(&b)
}

/// Finds `G`-prefixed, 56-char base32 runs on a line that aren't part of a larger identifier.
fn find_candidate_keys(line: &str) -> Vec<&str> {
    let bytes = line.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'G' {
            let boundary_before =
                i == 0 || !(bytes[i - 1].is_ascii_alphanumeric() || bytes[i - 1] == b'_');
            let end = i + KEY_LEN;
            if boundary_before && end <= bytes.len() && bytes[i..end].iter().all(|&b| is_strkey_char(b))
            {
                let boundary_after =
                    end == bytes.len() || !(bytes[end].is_ascii_alphanumeric() || bytes[end] == b'_');
                if boundary_after {
                    out.push(&line[i..end]);
                    i = end;
                    continue;
                }
            }
        }
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Check;
    use syn::parse_file;

    #[test]
    fn flags_hardcoded_address_in_string_literal() -> Result<(), syn::Error> {
        let key = format!("G{}", "A".repeat(55));
        let source = format!(
            r#"
use soroban_sdk::{{contractimpl, Address, Env}};

pub struct C;

#[contractimpl]
impl C {{
    pub fn hello(env: Env) {{
        let addr = Address::from_str(&env, "{key}");
        let _ = addr;
    }}
}}
"#
        );
        let file = parse_file(&source)?;
        let hits = HardcodedAddressCheck.run(&file, &source);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Medium);
        Ok(())
    }

    #[test]
    fn ignores_short_strings() -> Result<(), syn::Error> {
        let source = r#"
use soroban_sdk::{contractimpl, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn hello(env: Env) {
        let _ = env;
        let _ = "GSHORT";
    }
}
"#;
        let file = parse_file(source)?;
        let hits = HardcodedAddressCheck.run(&file, source);
        assert!(hits.is_empty());
        Ok(())
    }
}
