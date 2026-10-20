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
        let test_ranges = test_only_line_ranges(file);
        for (idx, line) in effective_lines(source).into_iter().enumerate() {
            // Test-only code (a contract's own unit tests building a fake
            // Address, say) is skipped, as every other check skips it.
            if in_any_range(&test_ranges, idx + 1) {
                continue;
            }
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
                column: None,
                end_line: None,
                end_column: None,
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

/// 1-based, inclusive line ranges of test-only code: modules gated by
/// `#[cfg(test)]` or named `tests` / `test` (the same rule as
/// [`crate::util::contractimpl_functions_excluding_test`]), and any other item
/// carrying `#[cfg(test)]` or `#[test]`. Spans include the item's attributes.
fn test_only_line_ranges(file: &File) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    collect_test_ranges(&file.items, &mut out);
    out
}

fn collect_test_ranges(items: &[syn::Item], out: &mut Vec<(usize, usize)>) {
    for item in items {
        let attrs: &[syn::Attribute] = match item {
            syn::Item::Mod(m) => {
                if crate::util::is_cfg_test(&m.attrs) || m.ident == "tests" || m.ident == "test" {
                    out.push(line_range(item));
                } else if let Some((_, nested)) = &m.content {
                    collect_test_ranges(nested, out);
                }
                continue;
            }
            syn::Item::Fn(f) => &f.attrs,
            syn::Item::Impl(i) => &i.attrs,
            syn::Item::Const(c) => &c.attrs,
            syn::Item::Static(st) => &st.attrs,
            syn::Item::Struct(st) => &st.attrs,
            syn::Item::Enum(e) => &e.attrs,
            _ => continue,
        };
        if crate::util::is_cfg_test(attrs) || attrs.iter().any(|a| a.path().is_ident("test")) {
            out.push(line_range(item));
        }
    }
}

fn line_range(item: &syn::Item) -> (usize, usize) {
    let span = item.span();
    (span.start().line, span.end().line)
}

fn in_any_range(ranges: &[(usize, usize)], line: usize) -> bool {
    ranges
        .iter()
        .any(|(start, end)| line >= *start && line <= *end)
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
///
/// The scanner is string-literal-aware: `//` or `/*` that appear inside a `"..."` string
/// are **not** treated as comment delimiters, avoiding false negatives on lines such as:
/// ```rust
/// let url = "https://api.example.com"; let admin = "GABC...(56 chars)";
/// ```
/// where the `//` inside the URL string would otherwise truncate the line and miss the address.
fn effective_lines(source: &str) -> Vec<String> {
    let mut out = Vec::with_capacity(source.lines().count());
    let mut in_block_comment = false;
    for line in source.lines() {
        let mut effective = String::new();
        let bytes = line.as_bytes();
        let len = bytes.len();
        let mut i = 0;

        // Walk the line byte-by-byte so we can properly track string literals.
        'line: while i < len {
            if in_block_comment {
                // Inside a block comment – look for the closing `*/`.
                if i + 1 < len && bytes[i] == b'*' && bytes[i + 1] == b'/' {
                    in_block_comment = false;
                    i += 2;
                } else {
                    i += 1;
                }
            } else if i + 1 < len && bytes[i] == b'/' && bytes[i + 1] == b'/' {
                // Line comment – everything from here to end of line is discarded.
                break 'line;
            } else if i + 1 < len && bytes[i] == b'/' && bytes[i + 1] == b'*' {
                // Block comment opens – do not emit these two chars.
                in_block_comment = true;
                i += 2;
            } else if bytes[i] == b'"' {
                // Enter a string literal – copy it verbatim (including the delimiters)
                // so the address scanner can still find keys inside string literals,
                // while NOT treating `//` or `/*` inside the string as comment markers.
                effective.push('"');
                i += 1;
                loop {
                    if i >= len {
                        // Unterminated string – stop (handles raw-ish edge cases gracefully).
                        break;
                    }
                    if bytes[i] == b'\\' {
                        // Escaped character: copy both bytes and skip.
                        effective.push(bytes[i] as char);
                        i += 1;
                        if i < len {
                            effective.push(bytes[i] as char);
                            i += 1;
                        }
                    } else if bytes[i] == b'"' {
                        // Closing quote.
                        effective.push('"');
                        i += 1;
                        break;
                    } else {
                        effective.push(bytes[i] as char);
                        i += 1;
                    }
                }
            } else {
                effective.push(bytes[i] as char);
                i += 1;
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

    /// Issue #733: the vulnerable fixture must demonstrate both the `G…` and the
    /// `C…` detection its comments describe. A literal one character too long
    /// fails the boundary checks and is silently never matched.
    #[test]
    fn vulnerable_fixture_flags_both_g_and_c_literals() -> Result<(), syn::Error> {
        let source =
            include_str!("../../../test-contracts/hardcoded-address-vulnerable/src/lib.rs");
        let file = parse_file(source)?;
        let findings = HardcodedAddressCheck.run(&file, source);
        let mut flagged: Vec<&str> = findings.iter().map(|f| f.function_name.as_str()).collect();
        flagged.sort_unstable();
        assert_eq!(flagged, ["get_admin", "get_token"], "{findings:#?}");
        Ok(())
    }

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

    /// Regression test for #684: a `//` inside a URL string literal must NOT be treated as a
    /// line-comment start. The hardcoded address that follows on the same line must still be
    /// flagged.
    #[test]
    fn url_string_does_not_suppress_address_on_same_line() -> Result<(), syn::Error> {
        let addr = format!("G{}", "A".repeat(55));
        let source = format!(
            r#"
use soroban_sdk::{{contractimpl, Address, Env}};

pub struct C;

#[contractimpl]
impl C {{
    pub fn setup(env: Env) {{
        let _url = "https://api.example.com"; let admin = "{addr}";
        let _ = admin;
    }}
}}
"#
        );
        let file = parse_file(&source)?;
        let hits = HardcodedAddressCheck.run(&file, &source);
        assert!(
            hits.iter().any(|h| h.description.contains(&addr)),
            "address after URL string should be flagged; hits: {hits:#?}"
        );
        Ok(())
    }

    /// A `//` comment that genuinely follows code on the same line should still be stripped.
    #[test]
    fn real_line_comment_after_code_is_stripped() -> Result<(), syn::Error> {
        let addr = format!("G{}", "A".repeat(55));
        // The address appears only in the comment — should NOT be flagged.
        let source = format!(
            r#"
use soroban_sdk::{{contractimpl, Env}};

pub struct C;

#[contractimpl]
impl C {{
    pub fn noop(env: Env) {{
        let _ = env; // key: {addr}
    }}
}}
"#
        );
        let file = parse_file(&source)?;
        let hits = HardcodedAddressCheck.run(&file, &source);
        assert!(
            hits.is_empty(),
            "address inside a real line comment must not be flagged; hits: {hits:#?}"
        );
        Ok(())
    }

    /// Issue #732: an address literal inside `#[cfg(test)] mod tests` is test
    /// data, not a hardcoded production address.
    #[test]
    fn ignores_address_in_cfg_test_module() -> Result<(), syn::Error> {
        let key = format!("G{}", "A".repeat(55));
        let source = format!(
            r#"
use soroban_sdk::{{contractimpl, Address, Env}};

pub struct C;

#[contractimpl]
impl C {{
    pub fn ping(env: Env) {{
        let _ = env;
    }}
}}

#[cfg(test)]
mod tests {{
    use super::*;

    #[test]
    fn builds_fake_admin() {{
        let env = Env::default();
        let _admin = Address::from_str(&env, "{key}");
    }}
}}
"#
        );
        let file = parse_file(&source)?;
        let findings = HardcodedAddressCheck.run(&file, &source);
        assert!(findings.is_empty(), "{findings:#?}");
        Ok(())
    }

    /// `#[test]` / `#[cfg(test)]` on a free function or a `cfg(all(test, ..))`
    /// module are test-only too; production code in the same file is still checked.
    #[test]
    fn skips_test_items_but_still_flags_production_code() -> Result<(), syn::Error> {
        let key = format!("G{}", "B".repeat(55));
        let source = format!(
            r#"
use soroban_sdk::{{contractimpl, Address, Env}};

pub struct C;

#[contractimpl]
impl C {{
    pub fn admin(env: Env) -> Address {{
        Address::from_str(&env, "{key}")
    }}
}}

#[test]
fn free_test_fn() {{
    let _ = "{key}";
}}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod native_tests {{
    const FAKE: &str = "{key}";
}}
"#
        );
        let file = parse_file(&source)?;
        let findings = HardcodedAddressCheck.run(&file, &source);
        assert_eq!(findings.len(), 1, "{findings:#?}");
        assert_eq!(findings[0].function_name, "admin");
        Ok(())
    }
}
