pub mod baseline;
pub mod config;

/// Header row emitted for `scan --csv` output.
pub const CSV_HEADER: &str = "check,severity,file,line,function,message,suggestion,rule_url";

/// Quote a single CSV field per RFC 4180: wrap in double quotes when the field
/// contains a comma, double quote, CR, or LF, and double any embedded quotes.
pub fn csv_escape_field(field: &str) -> String {
    let needs_quoting = field
        .chars()
        .any(|c| c == ',' || c == '"' || c == '\n' || c == '\r');
    if needs_quoting {
        let mut out = String::with_capacity(field.len() + 2);
        out.push('"');
        for c in field.chars() {
            if c == '"' {
                out.push('"');
            }
            out.push(c);
        }
        out.push('"');
        out
    } else {
        field.to_string()
    }
}

/// Render a single CSV row from already-stringified fields.
pub fn csv_row(fields: &[&str]) -> String {
    fields
        .iter()
        .map(|f| csv_escape_field(f))
        .collect::<Vec<_>>()
        .join(",")
}
