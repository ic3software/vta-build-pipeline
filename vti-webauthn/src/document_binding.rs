//! Document-binding helper for trust-task-bound assertions.
//!
//! When a trust-task carries a WebAuthn assertion in its payload, we want
//! the assertion to be bound to the *entire* trust-task — tampering with
//! any field after signing should invalidate the assertion.
//!
//! The recipe:
//!
//! 1. Take the trust-task body.
//! 2. Locate the assertion at a known JSON pointer (e.g.
//!    `/payload/passkey_assertion`).
//! 3. Set the assertion's mutable fields (`signature`,
//!    `authenticatorData`, `clientDataJSON`) to JSON `null` so the
//!    challenge isn't computed over its own future bytes.
//! 4. Canonicalise the resulting document via JCS (RFC 8785).
//! 5. SHA-256 the canonical bytes.
//!
//! The same routine runs on both prover and verifier. The prover passes
//! the result as the `challenge` argument to
//! `navigator.credentials.get()`; the verifier passes it as
//! `expected_challenge` to [`crate::verify_assertion`].
//!
//! The three fields nulled by this helper are exactly the ones the
//! authenticator produces — the assertion's `credential_id` and
//! `verification_method` (which the prover knows in advance) are
//! preserved in the hash, so tampering with either invalidates the
//! signature.

use sha2::{Digest, Sha256};
use thiserror::Error;

/// JSON fields zeroed before canonicalisation. These are exactly the
/// values the authenticator produces; nulling them lets prover and
/// verifier compute the same challenge despite the prover not knowing
/// them when it constructs the request.
const NULLED_FIELDS: &[&str] = &["signature", "authenticatorData", "clientDataJSON"];

/// Compute the document-binding challenge for a trust-task that carries
/// an [`crate::AssertionPayload`]-shaped sub-field at a known JSON
/// pointer.
///
/// `assertion_pointer` follows [RFC 6901](https://www.rfc-editor.org/rfc/rfc6901)
/// JSON-pointer syntax (e.g. `"/payload/passkey_assertion"`). The pointed-to
/// value MUST be a JSON object.
pub fn document_binding_challenge(
    trust_task_body: &serde_json::Value,
    assertion_pointer: &str,
) -> Result<[u8; 32], BindingError> {
    let mut cloned = trust_task_body.clone();

    let assertion = cloned
        .pointer_mut(assertion_pointer)
        .ok_or_else(|| BindingError::AssertionPointerMissing(assertion_pointer.to_string()))?;

    let Some(obj) = assertion.as_object_mut() else {
        return Err(BindingError::AssertionPointerMissing(format!(
            "{assertion_pointer} (value is not a JSON object)"
        )));
    };

    // Unconditionally set the three fields to null. If the prover hasn't
    // yet filled them in, the field will be inserted; if it has, the
    // value is replaced. Either way the canonical form is identical.
    for field in NULLED_FIELDS {
        obj.insert((*field).to_string(), serde_json::Value::Null);
    }

    let canonical = serde_json_canonicalizer::to_string(&cloned)
        .map_err(|e| BindingError::Canonicalisation(e.to_string()))?;

    let hash = Sha256::digest(canonical.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&hash);
    Ok(out)
}

/// Errors computing a document-binding challenge.
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum BindingError {
    /// No value at the supplied JSON pointer, or the pointed-to value
    /// is not a JSON object.
    #[error("assertion pointer not found in document: {0}")]
    AssertionPointerMissing(String),
    /// JCS canonicalisation failed (typically because the document
    /// contains values JCS can't canonicalise — NaN, infinities, etc.).
    #[error("JCS canonicalisation failed: {0}")]
    Canonicalisation(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn task_with_assertion(extra_field_value: &str) -> serde_json::Value {
        json!({
            "id": "urn:uuid:00000000-0000-0000-0000-000000000001",
            "type": "https://trusttasks.org/did-hosting/auth/passkey-login-finish/1.0",
            "issuer": "did:webvh:vta.example.com:alice",
            "recipient": "did:web:control.example.com",
            "issuedAt": "2026-05-20T12:00:00Z",
            "payload": {
                "session_id": "s-1",
                "passkey_assertion": {
                    "credential_id": "cred-abc",
                    "verification_method": "did:webvh:vta.example.com:alice#passkey-abc",
                    "extra_thing": extra_field_value,
                    "signature": "to-be-filled",
                    "authenticatorData": "to-be-filled",
                    "clientDataJSON": "to-be-filled"
                }
            }
        })
    }

    #[test]
    fn produces_32_byte_hash() {
        let task = task_with_assertion("value-a");
        let h = document_binding_challenge(&task, "/payload/passkey_assertion").unwrap();
        assert_eq!(h.len(), 32);
    }

    #[test]
    fn hash_is_deterministic_regardless_of_sig_fields() {
        // Two tasks differing only in the three nulled fields' values
        // must produce identical hashes.
        let mut a = task_with_assertion("same");
        let assertion_a = a
            .pointer_mut("/payload/passkey_assertion")
            .unwrap()
            .as_object_mut()
            .unwrap();
        assertion_a.insert("signature".to_string(), json!("AAAA"));
        assertion_a.insert("authenticatorData".to_string(), json!("BBBB"));
        assertion_a.insert("clientDataJSON".to_string(), json!("CCCC"));

        let mut b = task_with_assertion("same");
        let assertion_b = b
            .pointer_mut("/payload/passkey_assertion")
            .unwrap()
            .as_object_mut()
            .unwrap();
        assertion_b.insert("signature".to_string(), json!("xxxxx-different-yyyyy"));
        assertion_b.insert("authenticatorData".to_string(), json!("zzz-also-different"));
        assertion_b.insert("clientDataJSON".to_string(), json!("totally-different"));

        let h_a = document_binding_challenge(&a, "/payload/passkey_assertion").unwrap();
        let h_b = document_binding_challenge(&b, "/payload/passkey_assertion").unwrap();
        assert_eq!(h_a, h_b);
    }

    #[test]
    fn hash_changes_when_credential_id_changes() {
        // Tampering with a *preserved* field must change the hash —
        // that's the whole point of document binding.
        let mut a = task_with_assertion("same");
        let mut b = task_with_assertion("same");
        b.pointer_mut("/payload/passkey_assertion")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("credential_id".to_string(), json!("attacker-cred"));

        let h_a = document_binding_challenge(&a, "/payload/passkey_assertion").unwrap();
        let h_b = document_binding_challenge(&b, "/payload/passkey_assertion").unwrap();
        assert_ne!(h_a, h_b);

        // Silence unused mut warnings.
        let _ = a.pointer_mut("/payload/passkey_assertion");
    }

    #[test]
    fn hash_changes_when_outer_field_changes() {
        // Tampering with any field anywhere in the trust-task changes the
        // hash — JCS canonicalises the whole document.
        let a = task_with_assertion("v1");
        let b = task_with_assertion("v2");
        let h_a = document_binding_challenge(&a, "/payload/passkey_assertion").unwrap();
        let h_b = document_binding_challenge(&b, "/payload/passkey_assertion").unwrap();
        assert_ne!(h_a, h_b);
    }

    #[test]
    fn hash_invariant_to_key_order() {
        // JCS canonicalises key order; two semantically-identical
        // documents must hash identically regardless of input order.
        let a = json!({
            "outer": "x",
            "payload": {
                "zzz": 1,
                "passkey_assertion": {
                    "credential_id": "cred",
                    "alpha": "a",
                    "beta": "b"
                },
                "aaa": 2
            }
        });
        let b = json!({
            "payload": {
                "aaa": 2,
                "passkey_assertion": {
                    "beta": "b",
                    "credential_id": "cred",
                    "alpha": "a"
                },
                "zzz": 1
            },
            "outer": "x"
        });
        let h_a = document_binding_challenge(&a, "/payload/passkey_assertion").unwrap();
        let h_b = document_binding_challenge(&b, "/payload/passkey_assertion").unwrap();
        assert_eq!(h_a, h_b);
    }

    #[test]
    fn rejects_missing_pointer() {
        let task = task_with_assertion("x");
        let err = document_binding_challenge(&task, "/payload/nope").unwrap_err();
        assert!(
            matches!(err, BindingError::AssertionPointerMissing(_)),
            "got {err:?}"
        );
    }

    #[test]
    fn rejects_non_object_target() {
        let task = task_with_assertion("x");
        // Point at a string value instead of an object.
        let err = document_binding_challenge(&task, "/id").unwrap_err();
        assert!(
            matches!(err, BindingError::AssertionPointerMissing(ref s) if s.contains("not a JSON object")),
            "got {err:?}"
        );
    }

    #[test]
    fn works_with_empty_assertion_object() {
        // If the prover constructs the trust-task with an empty
        // assertion object (about to fill in fields after WebAuthn
        // call), the binding still computes — the helper unconditionally
        // inserts the three nulled fields.
        let task = json!({
            "payload": { "passkey_assertion": {} }
        });
        let h = document_binding_challenge(&task, "/payload/passkey_assertion").unwrap();
        assert_eq!(h.len(), 32);
    }
}
