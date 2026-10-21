use crate::util::{contractimpl_functions_excluding_test, is_cfg_test};
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;

const CHECK_NAME: &str = "contract-fn-name-too-long";
const MAX_SYMBOL_LENGTH: usize = 32;

pub struct ContractFnNameTooLongCheck;

impl Check for ContractFnNameTooLongCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &syn::File, _source: &str) -> Vec<Finding> {
        contractimpl_functions_excluding_test(file)
            .into_iter()
            .filter(|method| !is_cfg_test(&method.attrs))
            .filter(|method| matches!(&method.vis, syn::Visibility::Public(_)))
            .filter_map(|method| {
                let function_name = method.sig.ident.to_string();
                let length = function_name.chars().count();
                (length > MAX_SYMBOL_LENGTH).then(|| Finding {
                    check_name: CHECK_NAME.to_string(),
                    severity: Severity::Low,
                    file_path: String::new(),
                    line: method.sig.ident.span().start().line,
                    function_name: function_name.clone(),
                    description: format!(
                        "Public contract entrypoint `{function_name}` is {length} characters long; Soroban symbols are limited to {MAX_SYMBOL_LENGTH} characters."
                    ),
                    rule_url: Some(
                        "https://github.com/SorobanGuard/Guard-CLI/blob/main/docs/checks.md#contract-fn-name-too-long-low"
                            .to_string(),
                    ),
                    suggestion: Some(
                        "Rename the entrypoint to 32 characters or fewer.".to_string(),
                    ),
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_file;

    fn source_for(name: &str) -> String {
        format!("#[contractimpl]\nimpl C {{\n    pub fn {name}() {{}}\n}}\n")
    }

    #[test]
    fn accepts_name_at_symbol_limit() -> Result<(), syn::Error> {
        let name = "a".repeat(MAX_SYMBOL_LENGTH);
        let source = source_for(&name);
        let findings = ContractFnNameTooLongCheck.run(&parse_file(&source)?, &source);
        assert!(findings.is_empty());
        Ok(())
    }

    #[test]
    fn flags_name_over_symbol_limit_and_reports_length() -> Result<(), syn::Error> {
        let name = "a".repeat(MAX_SYMBOL_LENGTH + 1);
        let source = source_for(&name);
        let findings = ContractFnNameTooLongCheck.run(&parse_file(&source)?, &source);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Low);
        assert!(findings[0].description.contains("33 characters"));
        Ok(())
    }

    #[test]
    fn ignores_private_and_test_only_functions() -> Result<(), syn::Error> {
        let source = format!(
            "#[contractimpl]\nimpl C {{\n    fn private_{}() {{}}\n    #[cfg(test)]\n    pub fn test_{}() {{}}\n}}\n",
            "a".repeat(MAX_SYMBOL_LENGTH),
            "b".repeat(MAX_SYMBOL_LENGTH)
        );
        let findings = ContractFnNameTooLongCheck.run(&parse_file(&source)?, &source);
        assert!(findings.is_empty());
        Ok(())
    }
}