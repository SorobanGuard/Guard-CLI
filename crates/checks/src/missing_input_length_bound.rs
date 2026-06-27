use crate::{Check, Finding, Severity};
use syn::visit::{self, Visit};
use syn::{ImplItem, ItemImpl, FnArg, Pat, PatType};

const CHECK_NAME: &str = "missing-input-length-bound";

pub struct MissingInputLengthBoundCheck;

impl Check for MissingInputLengthBoundCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &syn::File, _source: &str) -> Vec<Finding> {
        let mut visitor = InputLengthVisitor::default();
        visit::visit_file(&mut visitor, file);
        visitor.findings
    }
}

#[derive(Default)]
struct InputLengthVisitor {
    findings: Vec<Finding>,
}

impl<'ast> Visit<'ast> for InputLengthVisitor {
    fn visit_item_impl(&mut self, node: &'ast ItemImpl) {
        if has_contractimpl_attr(&node.attrs) {
            for item in &node.items {
                if let ImplItem::Fn(method) = item {
                    if method.sig.vis.is_pub() {
                        let bytes_vec_params = find_bytes_vec_params(&method.sig.inputs);
                        for (param_name, _) in bytes_vec_params {
                            if !has_length_check(&method.block, &param_name) {
                                self.findings.push(Finding {
                                    check_name: CHECK_NAME.to_string(),
                                    severity: Severity::Medium,
                                    file_path: String::new(),
                                    line: method.span().start().line,
                                    function_name: method.sig.ident.to_string(),
                                    description: format!(
                                        "Parameter `{}` (Bytes/Vec) lacks length validation",
                                        param_name
                                    ),
                                    rule_url: None,
                                    suggestion: Some(
                                        "Validate parameter length with .len() or .is_empty()"
                                            .to_string(),
                                    ),
                                });
                            }
                        }
                    }
                }
            }
        }
        visit::visit_item_impl(self, node);
    }
}

fn has_contractimpl_attr(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        if let syn::Meta::Path(path) = &attr.meta {
            path.segments
                .last()
                .map(|seg| seg.ident == "contractimpl")
                .unwrap_or(false)
        } else {
            false
        }
    })
}

fn find_bytes_vec_params(
    inputs: &syn::punctuated::Punctuated<FnArg, syn::token::Comma>,
) -> Vec<(String, String)> {
    let mut params = Vec::new();
    for arg in inputs {
        if let FnArg::Typed(pat_type) = arg {
            let ty_str = format!("{:?}", pat_type.ty);
            if ty_str.contains("Bytes") || ty_str.contains("Vec") {
                if let Pat::Ident(pat_ident) = &*pat_type.pat {
                    params.push((pat_ident.ident.to_string(), ty_str));
                }
            }
        }
    }
    params
}

fn has_length_check(block: &syn::Block, param_name: &str) -> bool {
    let block_text = format!("{:?}", block);
    let len_check = format!("{}.len()", param_name);
    let is_empty = format!("{}.is_empty()", param_name);
    block_text.contains(&len_check) || block_text.contains(&is_empty)
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_file;

    #[test]
    fn flags_unbounded_bytes() -> Result<(), syn::Error> {
        let src = r#"
#[contractimpl]
impl C {
    pub fn process(env: Env, data: Bytes) {
        let x = data;
    }
}
        "#;
        let file = parse_file(src)?;
        let check = MissingInputLengthBoundCheck;
        let findings = check.run(&file, src);
        assert_eq!(findings.len(), 1);
        Ok(())
    }
}
