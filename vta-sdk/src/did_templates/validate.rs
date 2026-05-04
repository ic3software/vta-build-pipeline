//! Structural + semantic validation for [`DidTemplate`].
//!
//! Runs automatically on `from_json` / `load_file` / `load_embedded`. Also
//! exposed via [`DidTemplate::validate`] for CLI linters that want to re-check
//! a template without re-parsing.

use std::collections::HashSet;

use serde_json::Value;

use super::{
    DidTemplate, RESERVED_VARS, SCHEMA_VERSION_MAX, SCHEMA_VERSION_MIN, TemplateError,
    render::walk_placeholders,
};

pub(super) fn validate(tpl: &DidTemplate) -> Result<(), TemplateError> {
    check_schema_version(tpl)?;
    check_name(&tpl.name)?;
    check_kind(&tpl.kind)?;
    check_reserved_vars(tpl)?;
    check_var_overlap(tpl)?;
    check_document_has_id_placeholder(&tpl.document)?;
    check_placeholders_declared(tpl)?;
    Ok(())
}

fn check_schema_version(tpl: &DidTemplate) -> Result<(), TemplateError> {
    if tpl.schema_version < SCHEMA_VERSION_MIN || tpl.schema_version > SCHEMA_VERSION_MAX {
        return Err(TemplateError::UnsupportedSchema {
            found: tpl.schema_version,
            min: SCHEMA_VERSION_MIN,
            max: SCHEMA_VERSION_MAX,
        });
    }
    Ok(())
}

fn check_name(name: &str) -> Result<(), TemplateError> {
    if name.is_empty() || name.len() > 64 {
        return Err(TemplateError::Invalid(format!(
            "name '{name}' must be 1..=64 characters"
        )));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err(TemplateError::Invalid(format!(
            "name '{name}' must match [a-z0-9-]+"
        )));
    }
    Ok(())
}

fn check_kind(kind: &str) -> Result<(), TemplateError> {
    if kind.is_empty() {
        return Err(TemplateError::Invalid("kind must not be empty".into()));
    }
    Ok(())
}

fn check_reserved_vars(tpl: &DidTemplate) -> Result<(), TemplateError> {
    let reserved: HashSet<&str> = RESERVED_VARS.iter().copied().collect();
    for v in &tpl.required_vars {
        if reserved.contains(v.as_str()) {
            return Err(TemplateError::ReservedVar(v.clone()));
        }
    }
    for k in tpl.optional_vars.keys() {
        if reserved.contains(k.as_str()) {
            return Err(TemplateError::ReservedVar(k.clone()));
        }
    }
    Ok(())
}

fn check_var_overlap(tpl: &DidTemplate) -> Result<(), TemplateError> {
    let required: HashSet<&str> = tpl.required_vars.iter().map(String::as_str).collect();
    for k in tpl.optional_vars.keys() {
        if required.contains(k.as_str()) {
            return Err(TemplateError::Invalid(format!(
                "variable '{k}' appears in both requiredVars and optionalVars"
            )));
        }
    }
    Ok(())
}

fn check_document_has_id_placeholder(doc: &Value) -> Result<(), TemplateError> {
    let id = doc.get("id").and_then(Value::as_str).ok_or_else(|| {
        TemplateError::Invalid(
            "document.id is missing or not a string — must be the `{DID}` placeholder".into(),
        )
    })?;
    if !id.contains("{DID}") {
        return Err(TemplateError::Invalid(format!(
            "document.id ('{id}') must contain the `{{DID}}` placeholder"
        )));
    }
    Ok(())
}

/// Every placeholder found in the document must be either declared (required
/// or optional) or a reserved ambient name. Unknown placeholders fail fast at
/// validation time rather than silently producing an unresolved render error.
fn check_placeholders_declared(tpl: &DidTemplate) -> Result<(), TemplateError> {
    let declared: HashSet<String> = tpl
        .required_vars
        .iter()
        .cloned()
        .chain(tpl.optional_vars.keys().cloned())
        .chain(RESERVED_VARS.iter().map(|s| s.to_string()))
        .collect();

    let mut found = HashSet::new();
    walk_placeholders(&tpl.document, &mut found);

    let undeclared: Vec<String> = found.difference(&declared).cloned().collect();
    if !undeclared.is_empty() {
        let mut names = undeclared;
        names.sort();
        return Err(TemplateError::Invalid(format!(
            "undeclared placeholder(s) {{ {} }} in document — add them to requiredVars or optionalVars",
            names.join(", ")
        )));
    }
    Ok(())
}
