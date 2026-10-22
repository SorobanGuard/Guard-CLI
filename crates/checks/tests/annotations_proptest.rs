//! Property-based tests for the `// soroban-guard: allow(...)` suppression-comment parser.
//!
//! These tests complement the hand-written examples in the analyzer's unit tests by
//! exercising the public parsing API with randomly generated inputs. They cover:
//!
//! * Arbitrary strings never cause the parser to panic.
//! * A generated valid annotation (random whitespace, case, comma-separated check
//!   names) always parses to exactly the expected set of names.
//! * Adding a suppression for check `A` never suppresses a finding for check `B`.
//!
//! Failing seeds are persisted by proptest under `proptest-regressions/` so they can
//! be committed and replayed in CI.

use std::collections::BTreeSet;

use proptest::prelude::*;

// The suppression-comment parser lives in the `checks` crate. Adjust the import path
// below if the public API is re-exported from a different module.
use soroban_guard_checks::annotations::{parse_annotation, Annotation};

/// Fixed case count so the suite stays well under ~10s in CI.
fn config() -> ProptestConfig {
    ProptestConfig {
        cases: 256,
        ..ProptestConfig::default()
    }
}

/// A small pool of check names that the parser is expected to understand. Using a
/// fixed pool keeps the "expected set" computation straightforward while still
/// exercising comma handling and whitespace trimming.
const CHECK_NAMES: &[&str] = &[
    "unchecked-return",
    "missing-auth",
    "integer-overflow",
    "unused-variable",
    "shadowed-storage",
    "unsafe-cast",
];

/// Strategy producing a random, non-empty subset of `CHECK_NAMES` (as a `Vec` so we
/// can shuffle the order and inject duplicates/whitespace later).
fn check_name_subset() -> impl Strategy<Value = Vec<&'static str>> {
    prop::sample::subsequence(CHECK_NAMES.to_vec(), 1..=CHECK_NAMES.len())
}

/// Strategy producing arbitrary whitespace (including the empty string).
fn whitespace() -> impl Strategy<Value = String> {
    prop::collection::vec(
        prop_oneof![Just(' '), Just('\t'), Just('\n'), Just('\r')],
        0..=4,
    )
    .prop_map(|chars| chars.into_iter().collect())
}

/// Strategy producing a random casing of an ASCII identifier.
fn random_case(name: &'static str) -> impl Strategy<Value = String> {
    let chars: Vec<char> = name.chars().collect();
    prop::collection::vec(any::<bool>(), chars.len()).prop_map(move |flags| {
        chars
            .iter()
            .zip(flags)
            .map(|(&c, upper)| {
                if upper {
                    c.to_ascii_uppercase()
                } else {
                    c.to_ascii_lowercase()
                }
            })
            .collect()
    })
}

proptest! {
    #![proptest_config(config())]

    /// Parsing an arbitrary string must never panic.
    #[test]
    fn arbitrary_string_never_panics(input in "\\PC*") {
        // The parser may return `None` or an `Annotation`; either is fine. We only
        // care that it does not panic.
        let _ = parse_annotation(&input);
    }

    /// Parsing arbitrary bytes-as-string (including control characters) must not panic.
    #[test]
    fn arbitrary_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..=256)) {
        let input = String::from_utf8_lossy(&bytes);
        let _ = parse_annotation(&input);
    }

    /// A generated valid annotation always parses to exactly the expected name set.
    #[test]
    fn valid_annotation_round_trips(
        names in check_name_subset(),
        leading_ws in whitespace(),
        trailing_ws in whitespace(),
        sep_ws in whitespace(),
        comma_ws in whitespace(),
        use_upper in any::<bool>(),
    ) {
        // Build the comma-separated list of (possibly re-cased) names.
        let rendered: Vec<String> = names
            .iter()
            .map(|name| {
                if use_upper {
                    name.to_ascii_uppercase()
                } else {
                    name.to_string()
                }
            })
            .collect();

        let joined = rendered.join(&format!("{comma_ws},{sep_ws}"));

        let line = format!(
            "{leading_ws}// soroban-guard: allow({joined}){trailing_ws}"
        );

        let parsed = parse_annotation(&line)
            .unwrap_or_else(|| panic!("expected annotation to parse: {line:?}"));

        let expected: BTreeSet<String> = names.iter().map(|n| n.to_string()).collect();
        let actual: BTreeSet<String> = parsed.checks().iter().cloned().collect();

        prop_assert_eq!(actual, expected, "input: {:?}", line);
    }

    /// Random casing of the directive keyword is still recognized.
    #[test]
    fn directive_keyword_is_case_insensitive(
        names in check_name_subset(),
        keyword in random_case("soroban-guard"),
    ) {
        let joined = names.join(", ");
        let line = format!("// {keyword}: allow({joined})");

        let parsed = parse_annotation(&line)
            .unwrap_or_else(|| panic!("expected annotation to parse: {line:?}"));

        let expected: BTreeSet<String> = names.iter().map(|n| n.to_string()).collect();
        let actual: BTreeSet<String> = parsed.checks().iter().cloned().collect();

        prop_assert_eq!(actual, expected, "input: {:?}", line);
    }

    /// Suppressing check `A` never suppresses a finding for a different check `B`.
    #[test]
    fn suppression_does_not_leak_between_checks(
        a_idx in 0..CHECK_NAMES.len(),
        b_idx in 0..CHECK_NAMES.len(),
    ) {
        prop_assume!(a_idx != b_idx);

        let a = CHECK_NAMES[a_idx];
        let b = CHECK_NAMES[b_idx];

        let line = format!("// soroban-guard: allow({a})");
        let parsed = parse_annotation(&line)
            .unwrap_or_else(|| panic!("expected annotation to parse: {line:?}"));

        prop_assert!(parsed.suppresses(a), "expected {a:?} to be suppressed");
        prop_assert!(
            !parsed.suppresses(b),
            "check {b:?} must not be suppressed by an annotation for {a:?}"
        );
    }

    /// Suppressing a set of checks suppresses exactly those checks and nothing else.
    #[test]
    fn suppression_set_is_exact(names in check_name_subset()) {
        let joined = names.join(", ");
        let line = format!("// soroban-guard: allow({joined})");
        let parsed = parse_annotation(&line)
            .unwrap_or_else(|| panic!("expected annotation to parse: {line:?}"));

        let suppressed: BTreeSet<&str> = names.iter().copied().collect();

        for name in CHECK_NAMES {
            let expected = suppressed.contains(name);
            prop_assert_eq!(
                parsed.suppresses(name),
                expected,
                "check {:?} suppression mismatch for input {:?}",
                name,
                line
            );
        }
    }
}

// Keep the `Annotation` import used even if the public API changes shape slightly;
// this also documents the expected return type of `parse_annotation`.
#[allow(dead_code)]
fn _assert_annotation_type(a: Annotation) -> BTreeSet<String> {
    a.checks().iter().cloned().collect()
}