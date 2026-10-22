//! Unchecked `+`, `-`, `*`, and compound assignments in contract methods, plus
//! unary negation / `.abs()` overflow.

use crate::util::contractimpl_functions_excluding_test;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{BinOp, Expr, ExprBinary, ExprMethodCall, ExprUnary, File, UnOp};

const CHECK_NAME: &str = "unchecked-arithmetic";
const NEGATION_CHECK_NAME: &str = "unchecked-negation-or-abs";
const NEGATION_RULE_URL: &str =
    "https://github.com/SorobanGuard/Guard-CLI/blob/main/docs/checks.md#unchecked-negation-or-abs-medium";

/// Variable-name fragments that suggest index/counter math → downgrade to Low.
const INDEX_NAMES: &[&str] = &["idx", "index", "count", "len", "offset", "pos", "step"];
/// Single-char index variables (exact match).
const INDEX_CHARS: &[&str] = &["i", "j", "k", "n", "x", "y", "z"];
/// Variable-name fragments that suggest financial math → upgrade to High.
const FINANCIAL_NAMES: &[&str] = &[
    "amount", "balance", "fee", "price", "supply", "reward", "stake", "fund", "value", "total",
    "deposit", "discount",
];

/// Split an identifier into lowercase words on `_` and camelCase boundaries.
fn name_words(name: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut prev_lower = false;
    for c in name.chars() {
        if (c == '_' || (c.is_uppercase() && prev_lower)) && !current.is_empty() {
            words.push(std::mem::take(&mut current));
        }
        if c != '_' {
            current.extend(c.to_lowercase());
        }
        prev_lower = c.is_lowercase() || c.is_ascii_digit();
    }
    if !current.is_empty() {
        words.push(current);
    }
    words
}

fn severity_for_operand_name(name: &str) -> Option<Severity> {
    let lower = name.to_lowercase();
    for &fin in FINANCIAL_NAMES {
        if lower.contains(fin) {
            return Some(Severity::High);
        }
    }
    // Match index fragments only at the start of a word (`idx`, `item_count`,
    // `posIndex`), so financial names like `deposit`/`discount` don't collide
    // with `pos`/`count` mid-word.
    if name_words(name)
        .iter()
        .any(|word| INDEX_NAMES.iter().any(|idx| word.starts_with(idx)))
    {
        return Some(Severity::Low);
    }
    if INDEX_CHARS.contains(&lower.as_str()) {
        return Some(Severity::Low);
    }
    None
}

/// Extract a name fragment from an operand for the severity heuristic. Handles bare
/// idents plus the common shapes of contract arithmetic: `self.balance` (field access),
/// `balances[i]` (index base), and `pool.reserve()` (method call).
fn operand_name(e: &Expr) -> Option<String> {
    match e {
        Expr::Path(p) => p.path.get_ident().map(|i| i.to_string()),
        Expr::Field(f) => match &f.member {
            syn::Member::Named(id) => Some(id.to_string()),
            syn::Member::Unnamed(_) => None,
        },
        Expr::Index(i) => operand_name(&i.expr),
        Expr::MethodCall(m) => Some(m.method.to_string()),
        Expr::Reference(r) => operand_name(&r.expr),
        Expr::Paren(p) => operand_name(&p.expr),
        _ => None,
    }
}

fn infer_severity(e: &ExprBinary) -> Severity {
    for operand in [&*e.left, &*e.right] {
        if let Some(name) = operand_name(operand) {
            if let Some(sev) = severity_for_operand_name(&name) {
                return sev;
            }
        }
    }
    Severity::Medium
}

/// Returns true if `block` contains any `checked_*` or `saturating_*` method call,
/// indicating the function already uses safe arithmetic and should not be flagged.
fn uses_safe_arithmetic(block: &syn::Block, binary_expr: &ExprBinary) -> bool {
    let mut v = SafeArithScan {
        binary_expr,
        found: false,
    };
    v.visit_block(block);
    v.found
}

struct SafeArithScan<'a> {
    binary_expr: &'a ExprBinary,
    found: bool,
}

impl<'ast> Visit<'ast> for SafeArithScan<'_> {
    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        if !self.found {
            let name = i.method.to_string();
            if name.starts_with("checked_") || name.starts_with("saturating_") {
                if let Some(arg) = i.args.first() {
                    let left = &*self.binary_expr.left;
                    let right = &*self.binary_expr.right;
                    let recv = &*i.receiver;
                    let operands_match =
                        (left == recv && right == arg) || (right == recv && left == arg);
                    // Only suppress when the `checked_*` call guards *this* expression, i.e.
                    // it sits at the same source location. An operand-equal `checked_*` on
                    // another line (e.g. an earlier discarded computation) is unrelated and
                    // must not silence a genuinely unchecked `a + b`.
                    let same_site = i.span().start().line == self.binary_expr.span().start().line;
                    if operands_match && same_site {
                        self.found = true;
                    }
                }
            }
        }
        visit::visit_expr_method_call(self, i);
    }
}

/// Flags wrapping integer arithmetic that is not expressed via checked/saturating APIs.
///
/// Heuristic: in `#[contractimpl]` methods, binary `+`, `-`, `*` (and `+=`, `-=`, `*=`) where
/// both operands are not compile-time literals. Functions inside `#[cfg(test)]` or `mod tests`
/// are excluded.
///
/// `/` and `%` are intentionally excluded from this check: division cannot overflow (except
/// `i*/i*::MIN / -1` which panics rather than wraps), and truncation/remainder concerns are
/// covered by the dedicated `integer-division-truncation` check instead.
pub struct UncheckedArithmeticCheck;

impl Check for UncheckedArithmeticCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions_excluding_test(file) {
            let fn_name = method.sig.ident.to_string();
            let mut v = ArithVisitor {
                fn_name: fn_name.clone(),
                block: &method.block,
                out: &mut out,
            };
            v.visit_block(&method.block);
        }
        out
    }
}

fn is_literal_expr(expr: &Expr) -> bool {
    matches!(expr, Expr::Lit(_))
}

/// In syn 2, `a += b` is `ExprBinary` with `BinOp::AddAssign`, not a separate assign-op node.
fn is_unchecked_binary(e: &ExprBinary) -> bool {
    match &e.op {
        BinOp::Add(_) | BinOp::Sub(_) | BinOp::Mul(_) => {
            !(is_literal_expr(&e.left) && is_literal_expr(&e.right))
        }
        BinOp::AddAssign(_) | BinOp::SubAssign(_) | BinOp::MulAssign(_) => {
            !is_literal_expr(&e.right)
        }
        _ => false,
    }
}

struct ArithVisitor<'a> {
    fn_name: String,
    block: &'a syn::Block,
    out: &'a mut Vec<Finding>,
}

impl Visit<'_> for ArithVisitor<'_> {
    fn visit_expr_binary(&mut self, i: &ExprBinary) {
        if is_unchecked_binary(i) && !uses_safe_arithmetic(self.block, i) {
            let op = match &i.op {
                BinOp::Add(_) => "+",
                BinOp::Sub(_) => "-",
                BinOp::Mul(_) => "*",
                BinOp::AddAssign(_) => "+=",
                BinOp::SubAssign(_) => "-=",
                BinOp::MulAssign(_) => "*=",
                _ => "?",
            };
            let severity = infer_severity(i);
            self.out.push(Finding {
                check_name: CHECK_NAME.to_string(),
                severity,
                file_path: String::new(),
                line: i.span().start().line,
                function_name: self.fn_name.clone(),
                description: format!(
                    "Expression uses wrapping integer arithmetic (`{op}`) in `{}`. \
                     For asset amounts and balances prefer `checked_add`, `checked_sub`, \
                     `checked_mul`, or `saturating_*` to avoid silent overflow.",
                    self.fn_name
                ),
                rule_url: Some(
                    "https://github.com/SorobanGuard/Guard-CLI/blob/main/docs/checks.md#unchecked-arithmetic-high--medium--low"
                        .to_string(),
                ),
                suggestion: Some(format!(
                    "Replace `{op}` with `checked_add`/`checked_sub`/`checked_mul` and \
                     handle overflow explicitly, or use `saturating_add`/`saturating_sub` \
                     if saturating semantics are acceptable."
                )),
            });
        }
        visit::visit_expr_binary(self, i);
    }
}

/// Flags unary `-` and `.abs()` on non-literal operands inside `#[contractimpl]` methods.
///
/// `-x` and `x.abs()` overflow (panic under `overflow-checks = true`) when `x == i128::MIN`,
/// which a caller can trigger by passing `i128::MIN` as an amount. Findings are suppressed
/// when the operand is guarded by a comparison against `MIN`/`0`, or when the value is
/// produced via `checked_neg`, `checked_abs`, `unsigned_abs`, or `saturating_neg`.
pub struct UncheckedNegationOrAbsCheck;

impl Check for UncheckedNegationOrAbsCheck {
    fn name(&self) -> &str {
        NEGATION_CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions_excluding_test(file) {
            let fn_name = method.sig.ident.to_string();
            let mut v = NegationVisitor {
                fn_name: fn_name.clone(),
                block: &method.block,
                out: &mut out,
            };
            v.visit_block(&method.block);
        }
        out
    }
}

/// Returns true if the operand is a compile-time literal (or a negated literal).
fn is_literal_operand(expr: &Expr) -> bool {
    match expr {
        Expr::Lit(_) => true,
        Expr::Unary(u) => matches!(u.op, UnOp::Neg(_)) && is_literal_operand(&u.expr),
        Expr::Paren(p) => is_literal_operand(&p.expr),
        _ => false,
    }
}

/// Returns true if `block` guards the operand with a comparison against `MIN` or `0`,
/// or computes it via a safe negation/abs API.
fn is_guarded(block: &syn::Block, operand: &Expr) -> bool {
    let mut v = GuardScan {
        operand,
        found: false,
    };
    v.visit_block(block);
    v.found
}

struct GuardScan<'a> {
    operand: &'a Expr,
    found: bool,
}

impl<'ast> Visit<'ast> for GuardScan<'_> {
    fn visit_expr_binary(&mut self, i: &'ast ExprBinary) {
        if !self.found {
            let is_cmp = matches!(
                &i.op,
                BinOp::Eq(_)
                    | BinOp::Ne(_)
                    | BinOp::Lt(_)
                    | BinOp::Le(_)
                    | BinOp::Gt(_)
                    | BinOp::Ge(_)
            );
            if is_cmp {
                let mentions_operand = &*i.left == self.operand || &*i.right == self.operand;
                let mentions_bound = mentions_min_or_zero(&i.left) || mentions_min_or_zero(&i.right);
                if mentions_operand && mentions_bound {
                    self.found = true;
                }
            }
        }
        visit::visit_expr_binary(self, i);
    }

    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        if !self.found {
            let name = i.method.to_string();
            let safe = matches!(
                name.as_str(),
                "checked_neg" | "checked_abs" | "unsigned_abs" | "saturating_neg"
            );
            if safe && &*i.receiver == self.operand {
                self.found = true;
            }
        }
        visit::visit_expr_method_call(self, i);
    }
}

/// True if the expression references `MIN` (e.g. `i128::MIN`) or the literal `0`.
fn mentions_min_or_zero(expr: &Expr) -> bool {
    match expr {
        Expr::Path(p) => p
            .path
            .segments
            .last()
            .map(|s| s.ident == "MIN")
            .unwrap_or(false),
        Expr::Lit(l) => matches!(&l.lit, syn::Lit::Int(i) if i.base10_digits() == "0"),
        Expr::Paren(p) => mentions_min_or_zero(&p.expr),
        Expr::Unary(u) => matches!(u.op, UnOp::Neg(_)) && mentions_min_or_zero(&u.expr),
        _ => false,
    }
}

struct NegationVisitor<'a> {
    fn_name: String,
    block: &'a syn::Block,
    out: &'a mut Vec<Finding>,
}

impl NegationVisitor<'_> {
    fn report(&mut self, span: proc_macro2::Span, form: &str, operand: &Expr) {
        if is_literal_operand(operand) || is_guarded(self.block, operand) {
            return;
        }
        let severity = operand_name(operand)
            .and_then(|n| severity_for_operand_name(&n))
            .unwrap_or(Severity::Medium);
        self.out.push(Finding {
            check_name: NEGATION_CHECK_NAME.to_string(),
            severity,
            file_path: String::new(),
            line: span.start().line,
            function_name: self.fn_name.clone(),
            description: format!(
                "Expression uses `{form}` on a signed integer in `{}`. This panics when the \
                 operand is the minimum value (e.g. `i128::MIN`) under `overflow-checks = true`, \
                 which a caller can trigger by passing `i128::MIN` as an amount.",
                self.fn_name
            ),
            rule_url: Some(NEGATION_RULE_URL.to_string()),
            suggestion: Some(
                "Use `checked_neg`/`checked_abs` and handle `None`, or `unsigned_abs`/\
                 `saturating_neg` if those semantics are acceptable."
                    .to_string(),
            ),
        });
    }
}

impl Visit<'_> for NegationVisitor<'_> {
    fn visit_expr_unary(&mut self, i: &ExprUnary) {
        if matches!(i.op, UnOp::Neg(_)) {
            self.report(i.span(), "-", &i.expr);
        }
        visit::visit_expr_unary(self, i);
    }

    fn visit_expr_method_call(&mut self, i: &ExprMethodCall) {
        if i.method == "abs" {
            self.report(i.span(), ".abs()", &i.receiver);
        }
        visit::visit_expr_method_call(self, i);
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn financial_names_with_index_substrings_stay_high() {
        use super::{severity_for_operand_name as sev, Severity};
        assert_eq!(sev("deposit"), Some(Severity::High));
        assert_eq!(sev("discount"), Some(Severity::High));
        assert_eq!(sev("user_deposit"), Some(Severity::High));
    }

    #[test]
    fn index_names_still_low() {
        use super::{severity_for_operand_name as sev, Severity};
        assert_eq!(sev("item_count"), Some(Severity::Low));
        assert_eq!(sev("posIndex"), Some(Severity::Low));
        assert_eq!(sev("counter"), Some(Severity::Low));
        assert_eq!(sev("i"), Some(Severity::Low));
    }

    use super::*;
    use crate::Check;
    use syn::parse_file;

    #[test]
    fn flags_add_of_parameters() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn sum(env: Env, a: i128, b: i128) -> i128 {
        let _ = env;
        a + b
    }
}
"#,
        )?;
        let hits = UncheckedArithmeticCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Medium);
        Ok(())
    }

    #[test]
    fn ignores_literal_plus_literal() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn f(env: Env) -> i128 {
        let _ = env;
        1 + 2
    }
}
"#,
        )?;
        let hits = UncheckedArithmeticCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn passes_with_checked_add() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn sum(env: Env, a: i128, b: i128) -> Option<i128> {
        let _ = env;
        a.checked_add(b)
    }
}
"#,
        )?;
        let hits = UncheckedArithmeticCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn flags_add_assign() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn acc(env: Env, mut x: i128, y: i128) {
        let _ = env;
        x += y;
    }
}
"#,
        )?;
        let hits = UncheckedArithmeticCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        Ok(())
    }

    #[test]
    fn ignores_add_assign_of_literal() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn acc(env: Env, mut x: i128) {
        let _ = env;
        x += 1;
    }
}
"#,
        )?;
        let hits = UncheckedArithmeticCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn flags_add_assign_of_non_literal() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn acc(env: Env, mut x: i128, y: i128) {
        let _ = env;
        x += y;
    }
}
"#,
        )?;
        let hits = UncheckedArithmeticCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        Ok(())
    }

    #[test]
    fn ignores_non_contractimpl() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::Env;

pub struct C;

impl C {
    pub fn sum(env: Env, a: i128, b: i128) -> i128 {
        let _ = env;
        a + b
    }
}
"#,
        )?;
        let hits = UncheckedArithmeticCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn financial_name_gets_high_severity() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn transfer(env: Env, amount: i128, fee: i128) -> i128 {
        let _ = env;
        amount - fee
    }
}
"#,
        )?;
        let hits = UncheckedArithmeticCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::High);
        Ok(())
    }

    #[test]
    fn field_operand_gets_high_severity() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn credit(env: Env, amount: i128) -> i128 {
        let _ = env;
        self.balance + amount
    }
}
"#,
        )?;
        let hits = UncheckedArithmeticCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::High);
        Ok(())
    }

    #[test]
    fn index_name_gets_low_severity() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn next(env: Env, i: u32) -> u32 {
        let _ = env;
        i + 1
    }
}
"#,
        )?;
        let hits = UncheckedArithmeticCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Low);
        Ok(())
    }

    #[test]
    fn discarded_checked_add_does_not_suppress_later_unchecked_add() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn f(env: Env, a: i128, b: i128) -> i128 {
        let _ = env;
        let _preview = a.checked_add(b);
        a + b
    }
}
"#,
        )?;
        let hits = UncheckedArithmeticCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        Ok(())
    }

    #[test]
    fn flags_unguarded_arithmetic_despite_guarded_arithmetic_in_same_function() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn f(env: Env, a: i128, b: i128) -> i128 {
        let _ = env;
        let _ = a.checked_add(1);
        b + a
    }
}
"#,
        )?;
        let hits = UncheckedArithmeticCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Medium);
        Ok(())
    }

    #[test]
    fn flags_unary_negation_of_parameter() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn negate(env: Env, amount: i128) -> i128 {
        let _ = env;
        -amount
    }
}
"#,
        )?;
        let hits = UncheckedNegationOrAbsCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].check_name, "unchecked-negation-or-abs");
        assert_eq!(hits[0].severity, Severity::High);
        assert!(hits[0].rule_url.is_some());
        Ok(())
    }

    #[test]
    fn flags_abs_of_parameter() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn magnitude(env: Env, amount: i128) -> i128 {
        let _ = env;
        amount.abs()
    }
}
"#,
        )?;
        let hits = UncheckedNegationOrAbsCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::High);
        Ok(())
    }

    #[test]
    fn ignores_negation_of_literal() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn f(env: Env) -> i128 {
        let _ = env;
        -1
    }
}
"#,
        )?;
        let hits = UncheckedNegationOrAbsCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn ignores_guarded_by_min_comparison() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn negate(env: Env, amount: i128) -> i128 {
        let _ = env;
        if amount == i128::MIN {
            return 0;
        }
        -amount
    }
}
"#,
        )?;
        let hits = UncheckedNegationOrAbsCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn ignores_guarded_by_zero_comparison() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn magnitude(env: Env, amount: i128) -> i128 {
        let _ = env;
        if amount < 0 {
            return -amount;
        }
        amount
    }
}
"#,
        )?;
        let hits = UncheckedNegationOrAbsCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn ignores_checked_neg_and_abs() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn f(env: Env, amount: i128) -> Option<i128> {
        let _ = env;
        let _ = amount.checked_neg();
        amount.checked_abs()
    }
}
"#,
        )?;
        let hits = UncheckedNegationOrAbsCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn ignores_non_contractimpl_negation() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::Env;
pub struct C;
impl C {
    pub fn negate(env: Env, amount: i128) -> i128 {
        let _ = env;
        -amount
    }
}
"#,
        )?;
        let hits = UncheckedNegationOrAbsCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }
}
