//! #1058: every default check must name the enclosing method on findings that sit inside
//! a method body. An empty `function_name` shows up as ``function: `` `` in pretty output,
//! breaks baseline fingerprints keyed on the function, and pushes suppression onto its
//! line-range fallback.

use std::fs;
use std::path::{Path, PathBuf};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if path.file_name().is_some_and(|n| n == "target") {
                continue;
            }
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// `(first line, last line, name)` of every method in an `impl` block.
#[derive(Default)]
struct MethodRanges(Vec<(usize, usize, String)>);

impl<'ast> Visit<'ast> for MethodRanges {
    fn visit_impl_item_fn(&mut self, f: &'ast syn::ImplItemFn) {
        let span = f.span();
        self.0
            .push((span.start().line, span.end().line, f.sig.ident.to_string()));
        visit::visit_impl_item_fn(self, f);
    }
}

#[test]
fn findings_inside_methods_carry_the_method_name() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut files = Vec::new();
    rust_files(&root.join("examples"), &mut files);
    rust_files(&root.join("test-contracts"), &mut files);
    files.sort();
    assert!(!files.is_empty(), "no fixture sources found");

    let mut problems = Vec::new();
    let mut checked = 0usize;
    for path in &files {
        let src = fs::read_to_string(path).expect("read fixture");
        let Ok(file) = syn::parse_file(&src) else {
            continue;
        };
        let mut ranges = MethodRanges::default();
        ranges.visit_file(&file);
        for check in soroban_guard_checks::default_checks() {
            for finding in check.run(&file, &src) {
                let inside = ranges
                    .0
                    .iter()
                    .any(|(start, end, _)| (*start..=*end).contains(&finding.line));
                if !inside {
                    continue;
                }
                checked += 1;
                if finding.function_name.is_empty() {
                    problems.push(format!(
                        "{} at {}:{} has an empty function_name",
                        finding.check_name,
                        path.strip_prefix(&root).unwrap_or(path).display(),
                        finding.line
                    ));
                }
            }
        }
    }
    assert!(checked > 0, "no in-method findings were produced");
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}
