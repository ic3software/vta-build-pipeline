//! Template rendering — substitutes `{TOKEN}` placeholders with values from
//! a [`TemplateVars`] map, returning a concrete [`serde_json::Value`].
//!
//! # Substitution semantics
//!
//! - **Embedded token** — `{TOKEN}` appearing inside a larger string gets
//!   replaced with the *string form* of the variable value. For a variable
//!   whose value is a non-string JSON type, the compact JSON serialization
//!   is used (useful for building URLs from scalar values, etc.).
//!
//! - **Whole-string token** — a JSON string value that is *exactly* `"{TOKEN}"`
//!   is replaced with the variable's native JSON type. This lets a template
//!   write `"routingKeys": "{ROUTING_KEYS}"` and get back an array, not a
//!   string containing `"[]"`.
//!
//! - **Object keys** are treated as strings and substituted the same way as
//!   values. Whole-string substitution does not apply to keys (keys must
//!   remain strings).
//!
//! Placeholders are recognised by the regex-equivalent `\{([A-Z_][A-Z0-9_]*)\}`.
//! Lower-case braces like `{did}` are ignored — there's no need to escape
//! them in templates.

use std::collections::{HashMap, HashSet};

use serde_json::{Map, Value};

use super::{DidTemplate, TemplateError, TemplateVars};

pub(super) fn render(tpl: &DidTemplate, vars: &TemplateVars) -> Result<Value, TemplateError> {
    // Build the effective variable map: optionalVars defaults, then
    // caller-supplied `vars` override.
    let mut effective: HashMap<String, Value> = tpl
        .optional_vars
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    for k in vars.keys() {
        if let Some(v) = vars.get(k) {
            effective.insert(k.clone(), v.clone());
        }
    }

    // Required vars must be resolvable (either from caller or — if the caller
    // chose to treat it as optional by supplying a default — from optionalVars
    // via the earlier insert, though the validator rejects overlap, so this
    // path is effectively caller-only).
    let mut missing: Vec<String> = Vec::new();
    for required in &tpl.required_vars {
        if !effective.contains_key(required) {
            missing.push(required.clone());
        }
    }
    if !missing.is_empty() {
        missing.sort();
        return Err(TemplateError::MissingVars(missing.join(", ")));
    }

    // Substitute.
    let rendered = substitute_value(&tpl.document, &effective);

    // Any leftover `{TOKEN}` in the rendered output is a bug (either an
    // undeclared placeholder we didn't catch at validate, or an ambient var
    // the caller forgot to supply).
    let mut unresolved = HashSet::new();
    walk_placeholders(&rendered, &mut unresolved);
    if !unresolved.is_empty() {
        let mut names: Vec<String> = unresolved.into_iter().collect();
        names.sort();
        return Err(TemplateError::Unresolved(names.join(", ")));
    }

    Ok(rendered)
}

fn substitute_value(value: &Value, vars: &HashMap<String, Value>) -> Value {
    match value {
        Value::String(s) => substitute_string(s, vars),
        Value::Array(items) => {
            Value::Array(items.iter().map(|v| substitute_value(v, vars)).collect())
        }
        Value::Object(map) => {
            let mut out = Map::with_capacity(map.len());
            for (k, v) in map {
                let new_key = match substitute_string(k, vars) {
                    Value::String(s) => s,
                    // A whole-string key substitution to a non-string would
                    // break JSON object semantics — fall back to compact JSON.
                    other => other.to_string(),
                };
                out.insert(new_key, substitute_value(v, vars));
            }
            Value::Object(out)
        }
        other => other.clone(),
    }
}

/// Substitute a single string. If the string is exactly one `{TOKEN}`, return
/// the variable's native JSON type. Otherwise return a String with embedded
/// substitutions (undefined tokens are left intact for the later unresolved
/// check to surface).
fn substitute_string(s: &str, vars: &HashMap<String, Value>) -> Value {
    if let Some(name) = whole_string_token(s) {
        if let Some(v) = vars.get(name) {
            return v.clone();
        }
        // Unresolved — leave the literal `{TOKEN}` so the later walk flags it.
        return Value::String(s.to_string());
    }

    // Scan by byte index using `find('{')` to locate token starts. `{` is
    // ASCII, so byte indices returned by `find` align with char boundaries
    // and slicing is UTF-8 safe.
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(brace) = rest.find('{') {
        out.push_str(&rest[..brace]);
        let after = &rest[brace..];
        if let Some(close) = find_token_end(after.as_bytes(), 0) {
            let name = &after[1..close];
            if is_token_name(name) {
                match vars.get(name) {
                    Some(Value::String(vs)) => out.push_str(vs),
                    Some(other) => out.push_str(&other.to_string()),
                    None => out.push_str(&after[..=close]), // leave literal
                }
                rest = &after[close + 1..];
                continue;
            }
        }
        // Not a token — emit the `{` and advance past it.
        out.push('{');
        rest = &after[1..];
    }
    out.push_str(rest);
    Value::String(out)
}

/// If `s` is exactly a single token like `"{NAME}"`, return the inner name.
fn whole_string_token(s: &str) -> Option<&str> {
    let bytes = s.as_bytes();
    if bytes.len() < 3 || bytes[0] != b'{' || bytes[bytes.len() - 1] != b'}' {
        return None;
    }
    let name = &s[1..s.len() - 1];
    if is_token_name(name) {
        Some(name)
    } else {
        None
    }
}

/// Find the matching `}` for an opening `{` at `start`. Returns the index of
/// the closing brace, or `None` if the enclosed content isn't a valid token.
fn find_token_end(bytes: &[u8], start: usize) -> Option<usize> {
    debug_assert_eq!(bytes[start], b'{');
    let mut j = start + 1;
    while j < bytes.len() {
        let c = bytes[j];
        if c == b'}' {
            return Some(j);
        }
        if !(c.is_ascii_uppercase() || c.is_ascii_digit() || c == b'_') {
            return None;
        }
        j += 1;
    }
    None
}

/// Valid token names: `[A-Z_][A-Z0-9_]*`.
fn is_token_name(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.is_empty() {
        return false;
    }
    let first = bytes[0];
    if !(first.is_ascii_uppercase() || first == b'_') {
        return false;
    }
    bytes[1..]
        .iter()
        .all(|&c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == b'_')
}

/// Walk a `Value` and collect every `{TOKEN}` name it finds (embedded or
/// whole-string). Used by both validation (reject undeclared) and rendering
/// (detect unresolved after substitution).
pub(super) fn walk_placeholders(value: &Value, out: &mut HashSet<String>) {
    match value {
        Value::String(s) => scan_string(s, out),
        Value::Array(items) => {
            for item in items {
                walk_placeholders(item, out);
            }
        }
        Value::Object(map) => {
            for (k, v) in map {
                scan_string(k, out);
                walk_placeholders(v, out);
            }
        }
        _ => {}
    }
}

fn scan_string(s: &str, out: &mut HashSet<String>) {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'{'
            && let Some(end) = find_token_end(bytes, i)
        {
            let name = &s[i + 1..end];
            if is_token_name(name) {
                out.insert(name.to_string());
                i = end + 1;
                continue;
            }
        }
        i += 1;
    }
}
