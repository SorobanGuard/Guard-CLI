//! Did-you-mean suggestion engine for unrecognized check names.
//!
//! Provides a dependency-free Levenshtein edit distance and candidate
//! ranking function to suggest close matches for typos in `--disable-check`
//! or `explain <name>`.

/// Compute the Levenshtein distance between two strings.
pub fn levenshtein_distance(a: &str, b: &str) -> usize {
    let b_chars: Vec<char> = b.chars().collect();
    let mut distances: Vec<usize> = (0..=b_chars.len()).collect();

    for (i, ca) in a.chars().enumerate() {
        let mut prev = i;
        distances[0] = i + 1;
        for (j, &cb) in b_chars.iter().enumerate() {
            let cur = distances[j + 1];
            distances[j + 1] = if ca == cb {
                prev
            } else {
                1 + prev.min(distances[j]).min(distances[j + 1])
            };
            prev = cur;
        }
    }

    distances[b_chars.len()]
}

/// Find up to `max_candidates` closest registered check names for an unknown query.
///
/// Returns candidates within an edit distance of <= 3 or that share a common prefix,
/// ordered by edit distance ascending and then alphabetically.
pub fn closest_check_candidates<'a>(
    query: &str,
    candidates: &'a [&'a str],
    max_candidates: usize,
) -> Vec<&'a str> {
    if query.is_empty() {
        return Vec::new();
    }
    let query_lower = query.to_ascii_lowercase();
    let query_len = query_lower.len();
    let max_allowed = if query_len <= 4 {
        1
    } else if query_len <= 8 {
        2
    } else {
        3.max(query_len / 3)
    };

    let mut scored: Vec<(usize, &'a str)> = Vec::new();

    for &candidate in candidates {
        let cand_lower = candidate.to_ascii_lowercase();
        let dist = levenshtein_distance(&query_lower, &cand_lower);

        let is_prefix = (query_len >= 4 && cand_lower.starts_with(&query_lower))
            || (cand_lower.len() >= 4 && query_lower.starts_with(&cand_lower));

        if dist <= max_allowed || is_prefix {
            scored.push((dist, candidate));
        }
    }

    scored.sort_by(|(d1, c1), (d2, c2)| d1.cmp(d2).then_with(|| c1.cmp(c2)));
    scored
        .into_iter()
        .take(max_candidates)
        .map(|(_, c)| c)
        .collect()
}

/// Format the "Did you mean ...?" hint.
///
/// Returns a string with a leading space (e.g. `" Did you mean `foo`?"`)
/// or an empty string if no candidates matched.
pub fn format_did_you_mean(query: &str, candidates: &[&str]) -> String {
    let matches = closest_check_candidates(query, candidates, 3);
    if matches.is_empty() {
        return String::new();
    }

    match matches.len() {
        1 => format!(" Did you mean `{}`?", matches[0]),
        2 => format!(" Did you mean `{}` or `{}`?", matches[0], matches[1]),
        _ => format!(
            " Did you mean `{}`, `{}`, or `{}`?",
            matches[0], matches[1], matches[2]
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_levenshtein_distance() {
        assert_eq!(levenshtein_distance("", ""), 0);
        assert_eq!(levenshtein_distance("a", ""), 1);
        assert_eq!(levenshtein_distance("", "b"), 1);
        assert_eq!(levenshtein_distance("kitten", "sitting"), 3);
        assert_eq!(
            levenshtein_distance("missing-require-auth", "missing-require-aut"),
            1
        );
    }

    #[test]
    fn test_format_did_you_mean_single() {
        let candidates = ["missing-require-auth", "unchecked-arithmetic"];
        let hint = format_did_you_mean("missing-require-aut", &candidates);
        assert_eq!(hint, " Did you mean `missing-require-auth`?");
    }

    #[test]
    fn test_format_did_you_mean_prefix() {
        let candidates = ["reentrancy-risk", "unchecked-arithmetic"];
        let hint = format_did_you_mean("reentrancy", &candidates);
        assert_eq!(hint, " Did you mean `reentrancy-risk`?");
    }

    #[test]
    fn test_format_did_you_mean_multiple() {
        let candidates = [
            "auth-after-storage-write",
            "unprotected-admin",
            "missing-require-auth",
        ];
        let hint = format_did_you_mean("auth", &candidates);
        assert!(hint.contains("Did you mean"));
    }

    #[test]
    fn test_format_did_you_mean_empty() {
        let candidates = ["missing-require-auth", "unchecked-arithmetic"];
        let hint = format_did_you_mean("completely-unrelated-random-word", &candidates);
        assert_eq!(hint, "");
    }
}
