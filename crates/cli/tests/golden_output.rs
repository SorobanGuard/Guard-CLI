//! Golden-file tests for the machine-readable scan outputs (Issue #608).
//!
//! `scan test-contracts/vulnerable` is run through the real binary in each
//! structured format and compared byte-for-byte with `tests/golden/`. Path
//! separators and line endings are normalised so the files match on every OS.
//!
//! Issue #871 additionally validates the `--json` output against the field
//! types documented in `docs/json-schema.md` using hand-rolled assertions.

use std::path::{Path, PathBuf};
use std::process::Command;

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn normalise(text: &str) -> String {
    text.replace("\r\n", "\n").replace('\\', "/")
}

fn scan_vulnerable(format_flag: &str) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-guard"))
        .current_dir(workspace_root())
        .args(["scan", "test-contracts/vulnerable", format_flag])
        .env("NO_COLOR", "1")
        .output()
        .expect("failed to run soroban-guard");
    // Exit code 1 is expected: the fixture has High findings.
    assert_eq!(
        output.status.code(),
        Some(1),
        "unexpected exit status; stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    normalise(&String::from_utf8(output.stdout).expect("stdout is UTF-8"))
}

fn assert_matches_golden(format_flag: &str, golden_file: &str) {
    let golden_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/golden")
        .join(golden_file);
    let expected = normalise(
        &std::fs::read_to_string(&golden_path)
            .unwrap_or_else(|e| panic!("reading {}: {e}", golden_path.display())),
    );
    let actual = scan_vulnerable(format_flag);
    assert!(
        actual == expected,
        "`scan test-contracts/vulnerable {format_flag}` no longer matches {}.\n\
         If the change is intended, update the golden file.\n--- expected\n{expected}\n--- actual\n{actual}",
        golden_path.display()
    );
}

#[test]
fn json_output_matches_golden() {
    assert_matches_golden("--json", "scan-vulnerable.json");
}

#[test]
fn sarif_output_matches_golden() {
    assert_matches_golden("--sarif", "scan-vulnerable.sarif");
}

#[test]
fn markdown_output_matches_golden() {
    assert_matches_golden("--markdown", "scan-vulnerable.md");
}

// --- Issue #871: validate `--json` output against docs/json-schema.md -------

/// Minimal JSON value model so the assertions need no external crate.
#[derive(Debug)]
enum Json {
    Null,
    Bool(bool),
    Number(f64),
    String(String),
    Array(Vec<Json>),
    Object(Vec<(String, Json)>),
}

impl Json {
    fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Object(entries) => entries.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    fn as_array(&self) -> Option<&[Json]> {
        match self {
            Json::Array(items) => Some(items),
            _ => None,
        }
    }

    fn is_integer(&self) -> bool {
        matches!(self, Json::Number(n) if n.fract() == 0.0)
    }

    fn as_str(&self) -> Option<&str> {
        match self {
            Json::String(s) => Some(s),
            _ => None,
        }
    }
}

/// A tiny recursive-descent JSON parser (objects, arrays, strings, numbers,
/// booleans, null). Sufficient for the CLI's own output; no dependencies.
struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn new(input: &'a str) -> Self {
        Parser { bytes: input.as_bytes(), pos: 0 }
    }

    fn parse(mut self) -> Result<Json, String> {
        let value = self.value()?;
        self.skip_ws();
        if self.pos != self.bytes.len() {
            return Err(format!("trailing data at byte {}", self.pos));
        }
        Ok(value)
    }

    fn skip_ws(&mut self) {
        while let Some(&b) = self.bytes.get(self.pos) {
            if b == b' ' || b == b'\t' || b == b'\n' || b == b'\r' {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    fn value(&mut self) -> Result<Json, String> {
        self.skip_ws();
        match self.bytes.get(self.pos) {
            Some(b'{') => self.object(),
            Some(b'[') => self.array(),
            Some(b'"') => self.string().map(Json::String),
            Some(b't') => self.literal("true", Json::Bool(true)),
            Some(b'f') => self.literal("false", Json::Bool(false)),
            Some(b'n') => self.literal("null", Json::Null),
            Some(_) => self.number(),
            None => Err("unexpected end of input".to_string()),
        }
    }

    fn literal(&mut self, word: &str, value: Json) -> Result<Json, String> {
        if self.bytes[self.pos..].starts_with(word.as_bytes()) {
            self.pos += word.len();
            Ok(value)
        } else {
            Err(format!("invalid literal at byte {}", self.pos))
        }
    }

    fn object(&mut self) -> Result<Json, String> {
        self.pos += 1; // consume '{'
        let mut entries = Vec::new();
        self.skip_ws();
        if self.bytes.get(self.pos) == Some(&b'}') {
            self.pos += 1;
            return Ok(Json::Object(entries));
        }
        loop {
            self.skip_ws();
            let key = self.string()?;
            self.skip_ws();
            if self.bytes.get(self.pos) != Some(&b':') {
                return Err(format!("expected ':' at byte {}", self.pos));
            }
            self.pos += 1;
            let value = self.value()?;
            entries.push((key, value));
            self.skip_ws();
            match self.bytes.get(self.pos) {
                Some(b',') => self.pos += 1,
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(Json::Object(entries));
                }
                _ => return Err(format!("expected ',' or '}}' at byte {}", self.pos)),
            }
        }
    }

    fn array(&mut self) -> Result<Json, String> {
        self.pos += 1; // consume '['
        let mut items = Vec::new();
        self.skip_ws();
        if self.bytes.get(self.pos) == Some(&b']') {
            self.pos += 1;
            return Ok(Json::Array(items));
        }
        loop {
            items.push(self.value()?);
            self.skip_ws();
            match self.bytes.get(self.pos) {
                Some(b',') => self.pos += 1,
                Some(b']') => {
                    self.pos += 1;
                    return Ok(Json::Array(items));
                }
                _ => return Err(format!("expected ',' or ']' at byte {}", self.pos)),
            }
        }
    }

    fn string(&mut self) -> Result<String, String> {
        if self.bytes.get(self.pos) != Some(&b'"') {
            return Err(format!("expected string at byte {}", self.pos));
        }
        self.pos += 1;
        let mut out = String::new();
        loop {
            let b = *self
                .bytes
                .get(self.pos)
                .ok_or_else(|| "unterminated string".to_string())?;
            self.pos += 1;
            match b {
                b'"' => return Ok(out),
                b'\\' => {
                    let esc = *self
                        .bytes
                        .get(self.pos)
                        .ok_or_else(|| "unterminated escape".to_string())?;
                    self.pos += 1;
                    match esc {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'n' => out.push('\n'),
                        b't' => out.push('\t'),
                        b'r' => out.push('\r'),
                        b'b' => out.push('\u{0008}'),
                        b'f' => out.push('\u{000C}'),
                        b'u' => {
                            let hex = self
                                .bytes
                                .get(self.pos..self.pos + 4)
                                .ok_or_else(|| "truncated unicode escape".to_string())?;
                            let hex = std::str::from_utf8(hex)
                                .map_err(|_| "invalid unicode escape".to_string())?;
                            let code = u32::from_str_radix(hex, 16)
                                .map_err(|_| "invalid unicode escape".to_string())?;
                            self.pos += 4;
                            out.push(char::from_u32(code).unwrap_or('\u{FFFD}'));
                        }
                        other => return Err(format!("invalid escape '\\{}'", other as char)),
                    }
                }
                _ => out.push(b as char),
            }
        }
    }

    fn number(&mut self) -> Result<Json, String> {
        let start = self.pos;
        while let Some(&b) = self.bytes.get(self.pos) {
            if b.is_ascii_digit() || b == b'-' || b == b'+' || b == b'.' || b == b'e' || b == b'E' {
                self.pos += 1;
            } else {
                break;
            }
        }
        let text = std::str::from_utf8(&self.bytes[start..self.pos])
            .map_err(|_| "invalid number".to_string())?;
        text.parse::<f64>()
            .map(Json::Number)
            .map_err(|_| format!("invalid number '{text}' at byte {start}"))
    }
}

/// Collect every vulnerable fixture directory under `test-contracts/vulnerable`.
fn vulnerable_fixtures() -> Vec<PathBuf> {
    let root = workspace_root().join("test-contracts/vulnerable");
    let mut fixtures = Vec::new();
    let entries = std::fs::read_dir(&root)
        .unwrap_or_else(|e| panic!("reading {}: {e}", root.display()));
    for entry in entries {
        let path = entry.expect("reading fixture entry").path();
        if path.is_dir() {
            fixtures.push(path);
        }
    }
    fixtures.sort();
    assert!(!fixtures.is_empty(), "no fixtures found under {}", root.display());
    fixtures
}

/// Run `scan <fixture> --json` and return the parsed JSON document.
fn scan_fixture_json(fixture: &Path) -> Json {
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-guard"))
        .current_dir(workspace_root())
        .arg("scan")
        .arg(fixture)
        .arg("--json")
        .env("NO_COLOR", "1")
        .output()
        .expect("failed to run soroban-guard");
    let stdout = String::from_utf8(output.stdout).expect("stdout is UTF-8");
    Parser::new(&stdout)
        .parse()
        .unwrap_or_else(|e| panic!("{}: invalid JSON output: {e}", fixture.display()))
}

fn assert_integer(doc: &Json, pointer: &str, fixture: &Path) {
    let value = doc
        .get(pointer)
        .unwrap_or_else(|| panic!("{}: missing field '{pointer}'", fixture.display()));
    assert!(
        value.is_integer(),
        "{}: field '{pointer}' must be an integer, got {value:?}",
        fixture.display()
    );
}

#[test]
fn json_output_validates_against_documented_schema() {
    for fixture in vulnerable_fixtures() {
        let doc = scan_fixture_json(&fixture);

        // `summary.*` counters are documented as integers.
        for field in ["total", "high", "medium", "low"] {
            assert_integer(&doc, &format!("summary.{field}"), &fixture);
        }

        // `findings[]` entries must carry a documented severity.
        let findings = doc
            .get("findings")
            .and_then(Json::as_array)
            .unwrap_or_else(|| panic!("{}: missing 'findings' array", fixture.display()));
        for (index, finding) in findings.iter().enumerate() {
            let severity = finding
                .get("severity")
                .and_then(Json::as_str)
                .unwrap_or_else(|| {
                    panic!(
                        "{}: findings[{index}].severity missing or not a string",
                        fixture.display()
                    )
                });
            assert!(
                matches!(severity, "High" | "Medium" | "Low"),
                "{}: findings[{index}].severity must be one of High/Medium/Low, got '{severity}'",
                fixture.display()
            );
        }
    }
}
