//! Typo suggestions for check names using Levenshtein distance and prefix matching.

/// Compute Levenshtein distance between two strings using bytes (all check names are ASCII).
pub fn levenshtein_distance(a: &str, b: &str) -> usize {
    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();
    let mut prev: Vec<usize> = (0..=b_bytes.len()).collect();
    let mut curr = vec![0; b_bytes.len() + 1];

    for (i, &ca) in a_bytes.iter().enumerate() {
        curr[0] = i + 1;
        for (j, &cb) in b_bytes.iter().enumerate() {
            let cost = if ca == cb { 0 } else { 1 };
            curr[j + 1] = (prev[j + 1] + 1)
                .min(curr[j] + 1)
                .min(prev[j] + cost);
        }
        prev.copy_from_slice(&curr);
    }
    prev[b_bytes.len()]
}

/// Find up to 3 candidate check names matching a typo by small edit distance or shared prefix.
pub fn suggest_check_names<'a>(typo: &str, known_names: &[&'a str]) -> Vec<&'a str> {
    if typo.is_empty() {
        return Vec::new();
    }
    let typo_lower = typo.to_ascii_lowercase();
    let typo_len = typo_lower.len();
    let max_dist = if typo_len <= 4 {
        1
    } else if typo_len <= 8 {
        2
    } else {
        3
    };

    let mut scored: Vec<(usize, &'a str)> = known_names
        .iter()
        .filter_map(|&name| {
            let name_lower = name.to_ascii_lowercase();
            let is_prefix = (typo_len >= 3 && name_lower.starts_with(&typo_lower))
                || (name_lower.len() >= 4 && typo_lower.starts_with(&name_lower));
            let dist = levenshtein_distance(&typo_lower, &name_lower);
            if dist <= max_dist || is_prefix {
                let effective_dist = if is_prefix && dist > max_dist {
                    max_dist
                } else {
                    dist
                };
                Some((effective_dist, name))
            } else {
                None
            }
        })
        .collect();

    // Sort by distance ascending, then alphabetically for deterministic output
    scored.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(b.1)));
    scored.into_iter().take(3).map(|(_, name)| name).collect()
}

/// Format an error message for an unknown check name, including a "Did you mean" hint if available.
pub fn format_unknown_check_error(name: &str, known_names: &[&str]) -> String {
    let suggestions = suggest_check_names(name, known_names);
    let hint = match suggestions.as_slice() {
        [] => String::new(),
        [single] => format!(" Did you mean `{single}`?"),
        [first, second] => format!(" Did you mean `{first}` or `{second}`?"),
        [first, second, third] => format!(" Did you mean `{first}`, `{second}`, or `{third}`?"),
        _ => String::new(),
    };
    format!("unknown check `{name}`.{hint} Run `soroban-guard list-checks` to see available checks.")
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_CHECKS: &[&str] = &[
        "auth-after-storage-write",
        "delegate-call-risk",
        "hardcoded-address",
        "integer-division-truncation",
        "missing-balance",
        "missing-event-emission",
        "missing-require-auth",
        "reentrancy-risk",
        "unchecked-arithmetic",
    ];

    #[test]
    fn test_levenshtein_distance() {
        assert_eq!(levenshtein_distance("kitten", "sitting"), 3);
        assert_eq!(levenshtein_distance("auth", "auth"), 0);
        assert_eq!(
            levenshtein_distance("missing-require-aut", "missing-require-auth"),
            1
        );
    }

    #[test]
    fn test_single_character_typo_suggests_exact_target() {
        let suggestions = suggest_check_names("missing-require-aut", SAMPLE_CHECKS);
        assert_eq!(suggestions, vec!["missing-require-auth"]);
    }

    #[test]
    fn test_underscore_typo_suggests_hyphenated_check() {
        let suggestions = suggest_check_names("hardcoded_address", SAMPLE_CHECKS);
        assert_eq!(suggestions, vec!["hardcoded-address"]);
    }

    #[test]
    fn test_prefix_matching() {
        let suggestions = suggest_check_names("reentrancy", SAMPLE_CHECKS);
        assert_eq!(suggestions, vec!["reentrancy-risk"]);
    }

    #[test]
    fn test_completely_unknown_gives_no_suggestions() {
        let suggestions = suggest_check_names("nonexistent-check-name-xyz", SAMPLE_CHECKS);
        assert!(suggestions.is_empty());
    }

    #[test]
    fn test_format_unknown_check_error_with_hint() {
        let msg = format_unknown_check_error("missing-require-aut", SAMPLE_CHECKS);
        assert_eq!(
            msg,
            "unknown check `missing-require-aut`. Did you mean `missing-require-auth`? Run `soroban-guard list-checks` to see available checks."
        );
    }

    #[test]
    fn test_format_unknown_check_error_without_hint() {
        let msg = format_unknown_check_error("xyz-check", SAMPLE_CHECKS);
        assert_eq!(
            msg,
            "unknown check `xyz-check`. Run `soroban-guard list-checks` to see available checks."
        );
    }
}
