pub mod baseline;
pub mod config;

use std::fs;
use std::path::Path;

/// Render a source snippet around a finding for pretty terminal output.
///
/// Returns `None` when `context == 0`, when the file cannot be read, or when
/// the reported line is out of range. Never fails the scan.
pub fn render_context_snippet(
    path: &Path,
    line: usize,
    context: usize,
    color: bool,
) -> Option<String> {
    if context == 0 || line == 0 {
        return None;
    }

    let source = fs::read_to_string(path).ok()?;
    let lines: Vec<&str> = source.lines().collect();
    if lines.is_empty() || line > lines.len() {
        return None;
    }

    let start = line.saturating_sub(context).max(1);
    let end = (line + context).min(lines.len());
    let width = end.to_string().len();

    let (marker, reset) = if color {
        ("\u{1b}[1;31m>", "\u{1b}[0m")
    } else {
        (">", "")
    };

    let mut out = String::new();
    for n in start..=end {
        let text = lines[n - 1];
        if n == line {
            out.push_str(&format!(
                "{marker} {:>width$} | {text}{reset}\n",
                n,
                width = width
            ));
        } else {
            out.push_str(&format!("  {:>width$} | {text}\n", n, width = width));
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn temp_file(name: &str, contents: &str) -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!("handsoff_ctx_{}_{}", std::process::id(), name));
        let mut f = fs::File::create(&path).unwrap();
        f.write_all(contents.as_bytes()).unwrap();
        path
    }

    #[test]
    fn zero_context_returns_none() {
        let p = temp_file("zero", "a\nb\nc\n");
        assert!(render_context_snippet(&p, 2, 0, false).is_none());
        let _ = fs::remove_file(&p);
    }

    #[test]
    fn renders_surrounding_lines_with_marker() {
        let p = temp_file("mid", "one\ntwo\nthree\nfour\nfive\n");
        let out = render_context_snippet(&p, 3, 1, false).unwrap();
        assert!(out.contains("  2 | two"));
        assert!(out.contains("> 3 | three"));
        assert!(out.contains("  4 | four"));
        assert!(!out.contains("one"));
        let _ = fs::remove_file(&p);
    }

    #[test]
    fn clamps_at_start_and_end_of_file() {
        let p = temp_file("edges", "a\nb\nc\n");
        let start = render_context_snippet(&p, 1, 5, false).unwrap();
        assert!(start.contains("> 1 | a"));
        assert!(start.contains("  3 | c"));
        let end = render_context_snippet(&p, 3, 5, false).unwrap();
        assert!(end.contains("> 3 | c"));
        assert!(end.contains("  1 | a"));
        let _ = fs::remove_file(&p);
    }

    #[test]
    fn honors_color_flag() {
        let p = temp_file("color", "x\ny\n");
        let plain = render_context_snippet(&p, 1, 1, false).unwrap();
        assert!(!plain.contains("\u{1b}["));
        let colored = render_context_snippet(&p, 1, 1, true).unwrap();
        assert!(colored.contains("\u{1b}[1;31m"));
        let _ = fs::remove_file(&p);
    }

    #[test]
    fn unreadable_or_out_of_range_returns_none() {
        let missing = std::path::Path::new("/nonexistent/handsoff/ctx/file.rs");
        assert!(render_context_snippet(missing, 1, 2, false).is_none());
        let p = temp_file("range", "only\n");
        assert!(render_context_snippet(&p, 99, 2, false).is_none());
        let _ = fs::remove_file(&p);
    }
}
