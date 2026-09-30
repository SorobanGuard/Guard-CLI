//! Hardcoded Stellar address strings (`G...` or `C...`, 56 chars) baked into contract source.

use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::File;

const CHECK_NAME: &str = "hardcoded-address";
const KEY_LEN: usize = 56;

/// Stellar `StrKey` addresses are 56-char base32 strings starting with `G` (Ed25519 public keys)
/// or `C` (Soroban contract addresses). Hardcoding one bakes a fixed address into the contract,
/// which breaks if the account or contract is redeployed. Works on the raw source text rather
/// than the parsed AST.
pub struct HardcodedAddressCheck;

impl Check for HardcodedAddressCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        let spans = function_spans(file);
        for (idx, line) in effective_lines(source).into_iter().enumerate() {
            let raw_line = source.lines().nth(idx).unwrap_or("");
            if raw_line.trim_start().starts_with("#[doc") {
                continue;
            }
            for key in find_candidate_keys(&line) {
                let line_no = idx + 1;
                out.push(Finding {
                    check_name: CHECK_NAME.to_string(),
                    severity: Severity::Medium,
                    file_path: String::new(),
                    line: line_no,
                    function_name: enclosing_function(&spans, line_no).to_string(),
                    description: format!(
                        "String literal `{key}` looks like a hardcoded Stellar public key. \
                         Pass addresses in as contract parameters or configuration instead of \
                         baking them into source."
                    ),
                    rule_url: Some(
                        "https://github.com/SorobanGuard/Guard-CLI/blob/main/docs/checks.md#hardcoded-address-medium"
                            .to_string(),
                    ),
                    suggestion: Some(
                        "Accept the address as a contract parameter or read it from storage instead of hardcoding."
                            .to_string(),
                    ),
                });
            }
        }
        out
    }
}

/// Returns the enclosing `#[contractimpl]` method name for a given source line, or
/// `"module"` if the line falls outside any such method.
fn enclosing_function(spans: &[(usize, usize, String)], line: usize) -> &str {
    spans
        .iter()
        .find(|(start, end, _)| line >= *start && line <= *end)
        .map(|(_, _, name)| name.as_str())
        .unwrap_or("module")
}

/// Line-range/name triples for every `#[contractimpl]` method in the file.
fn function_spans(file: &File) -> Vec<(usize, usize, String)> {
    crate::util::contractimpl_functions_excluding_test(file)
        .into_iter()
        .map(|m| {
            let start = m.span().start().line;
            let end = m.span().end().line;
            (start, end, m.sig.ident.to_string())
        })
        .collect()
}

/// Strips `//` and `/* ... */` comments from each line (block comments may span lines), so
/// keys that only appear in a comment aren't reported as real string literals.
fn effective_lines(source: &str) -> Vec<String> {
    let mut out = Vec::with_capacity(source.lines().count());
    let mut in_block_comment = false;
    for line in source.lines() {
        let mut effective = String::new();
        let mut rest = line;
        loop {
            if in_block_comment {
                match rest.find("*/") {
                    Some(end) => {
                        rest = &rest[end + 2..];
                        in_block_comment = false;
                    }
                    None => break,
                }
            } else {
                let line_comment = rest.find("//");
                let block_comment = rest.find("/*");
                match (line_comment, block_comment) {
                    // A block comment starts strictly before any `//` on the
                    // line (or there is no `//` at all): consume through
                    // its `*/` (or the rest of the line, if unterminated)
                    // and keep scanning what follows on this line.
                    (lc, Some(bc)) if lc.map_or(true, |lc| bc < lc) => {
                        effective.push_str(&rest[..bc]);
                        rest = &rest[bc + 2..];
                        in_block_comment = true;
                    }
                    // Otherwise a `//` (if any) is what ends the line.
                    (Some(lc), _) => {
                        effective.push_str(&rest[..lc]);
                        break;
                    }
                    (None, _) => {
                        effective.push_str(rest);
                        break;
                    }
                }
            }
        }
        out.push(effective);
    }
    out
}

fn is_strkey_char(b: u8) -> bool {
    b.is_ascii_uppercase() || (b'2'..=b'7').contains(&b)
}

/// Finds `G`- or `C`-prefixed, 56-char base32 runs on a line that aren't part of a larger identifier.
fn find_candidate_keys(line: &str) -> Vec<&str> {
    let bytes = line.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'G' || bytes[i] == b'C' {
            let boundary_before =
                i == 0 || !(bytes[i - 1].is_ascii_alphanumeric() || bytes[i - 1] == b'_');
            let end = i + KEY_LEN;
            if boundary_before
                && end <= bytes.len()
                && bytes[i..end].iter().all(|&b| is_strkey_char(b))
            {
                let boundary_after = end == bytes.len()
                    || !(bytes[end].is_ascii_alphanumeric() || bytes[end] == b'_');
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
    fn flags_hardcoded_soroban_contract_address() -> Result<(), syn::Error> {
        let key = format!("C{}", "A".repeat(55));
        let source = format!(
            r#"
use soroban_sdk::{{contractimpl, Address, Env}};

pub struct C;

#[contractimpl]
impl C {{
    pub fn invoke(env: Env) {{
        let token_contract = Address::from_str(&env, "{key}");
        let _ = token_contract;
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
        let _ = "CSHORT";
    }
}
"#;
        let file = parse_file(source)?;
        let hits = HardcodedAddressCheck.run(&file, source);
        assert!(hits.is_empty());
        Ok(())
    }
}
