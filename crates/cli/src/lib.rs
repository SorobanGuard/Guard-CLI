pub mod baseline;
pub mod config;

/// Returns true when the terminal advertises OSC 8 hyperlink support.
///
/// Detection is based on well-known environment variables set by modern
/// terminal emulators. `FORCE_HYPERLINK` can be used to opt in explicitly.
pub fn terminal_supports_hyperlinks() -> bool {
    if let Ok(force) = std::env::var("FORCE_HYPERLINK") {
        let force = force.trim();
        if !force.is_empty() && force != "0" {
            return true;
        }
    }

    ["TERM_PROGRAM", "VTE_VERSION", "WT_SESSION"]
        .iter()
        .any(|key| std::env::var_os(key).is_some())
}

/// Builds an OSC 8 hyperlink escape sequence wrapping `text`.
///
/// The returned string is `ESC ] 8 ; ; <url> ST <text> ESC ] 8 ; ; ST`, where
/// `ST` is the String Terminator (`ESC \\`). When `enabled` is false the text
/// is returned unchanged so callers can gate on capability/color/TTY checks.
pub fn osc8_hyperlink(url: &str, text: &str, enabled: bool) -> String {
    if !enabled {
        return text.to_string();
    }
    format!("\u{1b}]8;;{url}\u{1b}\\{text}\u{1b}]8;;\u{1b}\\")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hyperlink_disabled_returns_plain_text() {
        assert_eq!(osc8_hyperlink("https://example.com", "check", false), "check");
    }

    #[test]
    fn hyperlink_enabled_wraps_with_osc8() {
        let out = osc8_hyperlink("https://example.com/rule", "check", true);
        assert_eq!(
            out,
            "\u{1b}]8;;https://example.com/rule\u{1b}\\check\u{1b}]8;;\u{1b}\\"
        );
    }

    #[test]
    fn hyperlink_contains_url_and_text() {
        let out = osc8_hyperlink("https://docs.example/r", "my-check", true);
        assert!(out.contains("https://docs.example/r"));
        assert!(out.contains("my-check"));
        assert!(out.starts_with("\u{1b}]8;;"));
        assert!(out.ends_with("\u{1b}]8;;\u{1b}\\"));
    }

    #[test]
    fn capability_detection_force_hyperlink() {
        // Serialize env access within this test to avoid cross-test races.
        std::env::set_var("FORCE_HYPERLINK", "1");
        assert!(terminal_supports_hyperlinks());
        std::env::remove_var("FORCE_HYPERLINK");
    }

    #[test]
    fn capability_detection_force_hyperlink_zero_disables() {
        std::env::set_var("FORCE_HYPERLINK", "0");
        let saved: Vec<(&str, Option<std::ffi::OsString>)> =
            ["TERM_PROGRAM", "VTE_VERSION", "WT_SESSION"]
                .iter()
                .map(|k| (*k, std::env::var_os(k)))
                .collect();
        for (k, _) in &saved {
            std::env::remove_var(k);
        }
        assert!(!terminal_supports_hyperlinks());
        for (k, v) in saved {
            match v {
                Some(val) => std::env::set_var(k, val),
                None => std::env::remove_var(k),
            }
        }
        std::env::remove_var("FORCE_HYPERLINK");
    }

    #[test]
    fn capability_detection_term_program() {
        std::env::remove_var("FORCE_HYPERLINK");
        let saved: Vec<(&str, Option<std::ffi::OsString>)> =
            ["TERM_PROGRAM", "VTE_VERSION", "WT_SESSION"]
                .iter()
                .map(|k| (*k, std::env::var_os(k)))
                .collect();
        for (k, _) in &saved {
            std::env::remove_var(k);
        }
        std::env::set_var("TERM_PROGRAM", "iTerm.app");
        assert!(terminal_supports_hyperlinks());
        for (k, v) in saved {
            match v {
                Some(val) => std::env::set_var(k, val),
                None => std::env::remove_var(k),
            }
        }
    }
}
