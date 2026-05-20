//! `clientDataJSON` parsing + validation.
//!
//! Per WebAuthn L3, `clientDataJSON` is a UTF-8 JSON document with
//! at least the fields `type`, `challenge`, and `origin`. This module
//! parses it, validates the three fields against verifier expectations,
//! and returns nothing — failures surface as [`VerifyError`].

use base64::Engine as _;
use base64::engine::general_purpose;
use serde::Deserialize;

use crate::error::VerifyError;

/// Subset of `clientDataJSON` fields we care about. The spec permits
/// browsers to add additional members; we deliberately ignore them
/// (forward-compat per WebAuthn L3 §5.8.1).
#[derive(Deserialize)]
struct ClientData<'a> {
    #[serde(rename = "type", borrow)]
    type_field: &'a str,
    #[serde(borrow)]
    challenge: &'a str,
    #[serde(borrow)]
    origin: &'a str,
}

/// Parse and validate `clientDataJSON` bytes against verifier expectations.
///
/// Validates:
/// - `type == "webauthn.get"`
/// - `origin == expected_origin` (caller has already normalised)
/// - `base64url-decode(challenge) == expected_challenge`
///
/// Returns `Ok(())` on success. Other clientData fields (e.g.
/// `crossOrigin`, `topOrigin`) are intentionally ignored at this layer —
/// callers needing them parse separately.
pub(crate) fn parse_and_validate(
    bytes: &[u8],
    expected_origin: &str,
    expected_challenge: &[u8],
) -> Result<(), VerifyError> {
    let parsed: ClientData<'_> = serde_json::from_slice(bytes)
        .map_err(|_| VerifyError::MalformedAssertion("clientDataJSON is not valid JSON"))?;

    if parsed.type_field != "webauthn.get" {
        return Err(VerifyError::WrongClientDataType);
    }

    if parsed.origin != expected_origin {
        return Err(VerifyError::WrongOrigin);
    }

    // Browsers emit base64url without padding; accept padded too for
    // forward-compatibility with implementations that include it.
    let decoded = general_purpose::URL_SAFE_NO_PAD
        .decode(parsed.challenge.as_bytes())
        .or_else(|_| general_purpose::URL_SAFE.decode(parsed.challenge.as_bytes()))
        .map_err(|_| VerifyError::MalformedAssertion("clientData.challenge is not base64url"))?;

    if decoded != expected_challenge {
        return Err(VerifyError::ChallengeMismatch);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_client_data(type_field: &str, challenge_b64: &str, origin: &str) -> Vec<u8> {
        format!(r#"{{"type":"{type_field}","challenge":"{challenge_b64}","origin":"{origin}"}}"#)
            .into_bytes()
    }

    #[test]
    fn accepts_valid_client_data() {
        let challenge = b"the-nonce-bytes";
        let challenge_b64 = general_purpose::URL_SAFE_NO_PAD.encode(challenge);
        let bytes = make_client_data("webauthn.get", &challenge_b64, "https://example.com");

        parse_and_validate(&bytes, "https://example.com", challenge).expect("valid");
    }

    #[test]
    fn accepts_padded_challenge() {
        let challenge = b"different-nonce-bytes!";
        let challenge_b64 = general_purpose::URL_SAFE.encode(challenge); // includes padding
        let bytes = make_client_data("webauthn.get", &challenge_b64, "https://example.com");

        parse_and_validate(&bytes, "https://example.com", challenge).expect("valid");
    }

    #[test]
    fn ignores_extra_fields() {
        let challenge = b"nonce";
        let challenge_b64 = general_purpose::URL_SAFE_NO_PAD.encode(challenge);
        let json = format!(
            r#"{{"type":"webauthn.get","challenge":"{challenge_b64}","origin":"https://example.com","crossOrigin":false,"topOrigin":"https://parent.example.com"}}"#
        );
        parse_and_validate(json.as_bytes(), "https://example.com", challenge).expect("valid");
    }

    #[test]
    fn rejects_wrong_type() {
        let challenge = b"x";
        let challenge_b64 = general_purpose::URL_SAFE_NO_PAD.encode(challenge);
        let bytes = make_client_data("webauthn.create", &challenge_b64, "https://example.com");

        let err = parse_and_validate(&bytes, "https://example.com", challenge).unwrap_err();
        assert!(
            matches!(err, VerifyError::WrongClientDataType),
            "got {err:?}"
        );
    }

    #[test]
    fn rejects_wrong_origin() {
        let challenge = b"x";
        let challenge_b64 = general_purpose::URL_SAFE_NO_PAD.encode(challenge);
        let bytes = make_client_data("webauthn.get", &challenge_b64, "https://attacker.example");

        let err = parse_and_validate(&bytes, "https://example.com", challenge).unwrap_err();
        assert!(matches!(err, VerifyError::WrongOrigin), "got {err:?}");
    }

    #[test]
    fn rejects_wrong_challenge() {
        let issued = b"issued-nonce";
        let presented = b"different-nonce";
        let presented_b64 = general_purpose::URL_SAFE_NO_PAD.encode(presented);
        let bytes = make_client_data("webauthn.get", &presented_b64, "https://example.com");

        let err = parse_and_validate(&bytes, "https://example.com", issued).unwrap_err();
        assert!(matches!(err, VerifyError::ChallengeMismatch), "got {err:?}");
    }

    #[test]
    fn rejects_malformed_json() {
        let err = parse_and_validate(b"not json", "https://example.com", b"nonce").unwrap_err();
        assert!(
            matches!(err, VerifyError::MalformedAssertion(s) if s.contains("clientDataJSON")),
            "got {err:?}"
        );
    }

    #[test]
    fn rejects_malformed_base64_challenge() {
        // Challenge field contains invalid base64.
        let bytes = make_client_data("webauthn.get", "!!!not-base64!!!", "https://example.com");
        let err = parse_and_validate(&bytes, "https://example.com", b"x").unwrap_err();
        assert!(
            matches!(err, VerifyError::MalformedAssertion(s) if s.contains("challenge")),
            "got {err:?}"
        );
    }
}
