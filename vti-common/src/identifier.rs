//! Validators for caller-supplied identifiers that compose into
//! store-keyspace keys.
//!
//! Several route handlers build keys by formatting caller-supplied
//! strings directly into templates like `tpl:ctx:{context_id}:{name}`
//! or `ctx:{id}`. A caller that supplies a string containing the
//! separator character `:` could collide with or inject into adjacent
//! namespaces. Today the routes that accept these identifiers require
//! super-admin, so exposure is limited, but this module enforces the
//! invariant at the boundary so future lower-privilege surfaces
//! can't inherit the footgun.
//!
//! The accepted character class is deliberately narrow:
//! `[A-Za-z0-9._-]` with a length cap of 64 bytes. If you think you
//! need `:` or `/` in an identifier, you probably want the identifier
//! split into two fields instead — collisions are not worth the
//! convenience.

use crate::error::AppError;

/// Maximum length of a validated identifier in bytes. 64 is generous
/// for slugs, context IDs, template names; anything longer is almost
/// certainly a mistake or an injection attempt.
pub const MAX_IDENTIFIER_LEN: usize = 64;

/// Validate a caller-supplied identifier (context ID, template name,
/// slug). Accepts ASCII alphanumerics plus `.`, `_`, `-`. Rejects
/// empty strings, anything over [`MAX_IDENTIFIER_LEN`] bytes, and any
/// character outside the allowed class — including the separator
/// characters (`:`, `/`, whitespace) that would let a caller collide
/// with or traverse into adjacent store-keyspace prefixes.
///
/// `label` names the field being validated so the resulting
/// `AppError::Validation` message is self-describing.
pub fn validate_identifier(label: &str, value: &str) -> Result<(), AppError> {
    if value.is_empty() {
        return Err(AppError::Validation(format!("{label} must not be empty")));
    }
    if value.len() > MAX_IDENTIFIER_LEN {
        return Err(AppError::Validation(format!(
            "{label} is {} bytes; maximum is {MAX_IDENTIFIER_LEN}",
            value.len()
        )));
    }
    for (i, ch) in value.chars().enumerate() {
        let ok = ch.is_ascii_alphanumeric() || ch == '.' || ch == '_' || ch == '-';
        if !ok {
            return Err(AppError::Validation(format!(
                "{label} contains an invalid character {ch:?} at position {i}; \
                 allowed: A-Z, a-z, 0-9, '.', '_', '-'"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_common_identifier_shapes() {
        for ok in [
            "myapp",
            "My-App_1",
            "context.v2",
            "a",
            "0",
            "didcomm-mediator",
            "_private",
            "CamelCase",
        ] {
            validate_identifier("id", ok).unwrap_or_else(|e| panic!("{ok:?} rejected: {e:?}"));
        }
    }

    #[test]
    fn rejects_empty() {
        let err = validate_identifier("id", "").expect_err("empty must be rejected");
        assert!(matches!(err, AppError::Validation(_)), "got {err:?}");
    }

    #[test]
    fn rejects_separator_injection() {
        // These are the concrete attack shapes: a caller who can inject
        // `:` can collide with or escape adjacent store namespaces.
        for bad in [
            "global:evil",     // collides with tpl:global: prefix
            "../../etc",       // path traversal shape
            "a:b:c",           // keyspace separator
            "my/ctx",          // path separator
            "with space",      // whitespace
            "tab\there",       // control chars
            "with\nnewline",   // newline injection
            "null\0byte",      // null byte
            "unicode:§§",      // non-ASCII
            "quote\"injected", // quote shape
        ] {
            validate_identifier("id", bad).expect_err(&format!("{bad:?} must be rejected"));
        }
    }

    #[test]
    fn rejects_too_long() {
        let long = "a".repeat(MAX_IDENTIFIER_LEN + 1);
        let err = validate_identifier("id", &long).expect_err("overlong must be rejected");
        assert!(matches!(err, AppError::Validation(_)), "got {err:?}");
    }

    #[test]
    fn accepts_exactly_at_limit() {
        let edge = "a".repeat(MAX_IDENTIFIER_LEN);
        validate_identifier("id", &edge).expect("exactly-at-limit must pass");
    }

    #[test]
    fn error_message_names_the_field() {
        let err = validate_identifier("context_id", "bad:id").expect_err("rejected");
        let msg = format!("{err:?}");
        assert!(
            msg.contains("context_id"),
            "error must name the field it is validating — got {msg}"
        );
    }
}
