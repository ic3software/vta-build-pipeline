//! `authenticatorData` parsing + validation.
//!
//! Per WebAuthn L3, `authenticatorData` is a binary structure:
//!
//! ```text
//! +-----------+------+-----------+
//! | rpIdHash  | flag | signCount |
//! |  32 B     | 1 B  |   4 B     |
//! +-----------+------+-----------+
//! [ optional: attestedCredentialData | extensions ]
//! ```
//!
//! Authentication assertions don't include `attestedCredentialData` (the
//! AT flag is unset); this validator does NOT parse the optional trailer.
//! Extensions (ED flag) are permitted but ignored at this layer.

use sha2::{Digest, Sha256};

use crate::error::VerifyError;

/// Minimum length of `authenticatorData`: 32 (rpIdHash) + 1 (flags) + 4 (signCount).
const MIN_AUTH_DATA_LEN: usize = 37;

/// Flag bit positions per WebAuthn L3 §6.1.
const FLAG_UP: u8 = 1 << 0; // User Present
const FLAG_UV: u8 = 1 << 2; // User Verified

/// Parsed and validated `authenticatorData` summary.
///
/// Internal to the crate — surfaced to callers via
/// [`crate::VerifiedAssertion`] after a successful
/// [`crate::verify_assertion`].
#[derive(Debug)]
pub(crate) struct AuthData {
    pub user_present: bool,
    pub user_verified: bool,
    pub sign_count: u32,
}

/// Parse `authenticator_data` bytes and validate against verifier policy.
///
/// Validates:
/// - Length ≥ 37 bytes.
/// - `bytes[0..32] == SHA-256(expected_rp_id)`.
/// - UP bit set (always required by WebAuthn for an assertion).
/// - If `require_uv` is true: UV bit set.
pub(crate) fn parse_and_validate(
    bytes: &[u8],
    expected_rp_id: &str,
    require_uv: bool,
) -> Result<AuthData, VerifyError> {
    if bytes.len() < MIN_AUTH_DATA_LEN {
        return Err(VerifyError::MalformedAssertion(
            "authenticatorData shorter than 37 bytes",
        ));
    }

    // rpIdHash check.
    let expected_rp_hash = Sha256::digest(expected_rp_id.as_bytes());
    if bytes[0..32] != expected_rp_hash[..] {
        return Err(VerifyError::WrongRpId);
    }

    // Flags.
    let flags = bytes[32];
    let user_present = (flags & FLAG_UP) != 0;
    let user_verified = (flags & FLAG_UV) != 0;

    if !user_present {
        return Err(VerifyError::UserPresenceMissing);
    }
    if require_uv && !user_verified {
        return Err(VerifyError::UserVerificationMissing);
    }

    // signCount (big-endian u32).
    let sign_count = u32::from_be_bytes([bytes[33], bytes[34], bytes[35], bytes[36]]);

    Ok(AuthData {
        user_present,
        user_verified,
        sign_count,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: build a 37-byte authenticatorData with the given rp_id, flags, signCount.
    fn make_auth_data(rp_id: &str, flags: u8, sign_count: u32) -> Vec<u8> {
        let mut out = Vec::with_capacity(37);
        out.extend_from_slice(&Sha256::digest(rp_id.as_bytes()));
        out.push(flags);
        out.extend_from_slice(&sign_count.to_be_bytes());
        out
    }

    #[test]
    fn accepts_valid_assertion_with_up_only() {
        let bytes = make_auth_data("example.com", FLAG_UP, 42);
        let parsed = parse_and_validate(&bytes, "example.com", false).expect("valid");
        assert!(parsed.user_present);
        assert!(!parsed.user_verified);
        assert_eq!(parsed.sign_count, 42);
    }

    #[test]
    fn accepts_valid_assertion_with_uv() {
        let bytes = make_auth_data("example.com", FLAG_UP | FLAG_UV, 100);
        let parsed = parse_and_validate(&bytes, "example.com", true).expect("valid");
        assert!(parsed.user_present);
        assert!(parsed.user_verified);
        assert_eq!(parsed.sign_count, 100);
    }

    #[test]
    fn accepts_trailing_bytes_after_minimum() {
        // Real assertions may carry extensions; our validator must tolerate them.
        let mut bytes = make_auth_data("example.com", FLAG_UP, 0);
        bytes.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        parse_and_validate(&bytes, "example.com", false).expect("valid with trailer");
    }

    #[test]
    fn rejects_too_short() {
        let err = parse_and_validate(&[0u8; 36], "example.com", false).unwrap_err();
        assert!(
            matches!(err, VerifyError::MalformedAssertion(s) if s.contains("37 bytes")),
            "got {err:?}"
        );
    }

    #[test]
    fn rejects_wrong_rp_id_hash() {
        let bytes = make_auth_data("attacker.example", FLAG_UP, 0);
        let err = parse_and_validate(&bytes, "example.com", false).unwrap_err();
        assert!(matches!(err, VerifyError::WrongRpId), "got {err:?}");
    }

    #[test]
    fn rejects_missing_user_presence() {
        // No UP flag set.
        let bytes = make_auth_data("example.com", 0, 0);
        let err = parse_and_validate(&bytes, "example.com", false).unwrap_err();
        assert!(
            matches!(err, VerifyError::UserPresenceMissing),
            "got {err:?}"
        );
    }

    #[test]
    fn rejects_missing_uv_when_required() {
        let bytes = make_auth_data("example.com", FLAG_UP, 0);
        let err = parse_and_validate(&bytes, "example.com", true).unwrap_err();
        assert!(
            matches!(err, VerifyError::UserVerificationMissing),
            "got {err:?}"
        );
    }

    #[test]
    fn permits_uv_clear_when_not_required() {
        let bytes = make_auth_data("example.com", FLAG_UP, 0);
        let parsed = parse_and_validate(&bytes, "example.com", false).expect("valid");
        assert!(!parsed.user_verified);
    }

    #[test]
    fn parses_sign_count_big_endian() {
        let bytes = make_auth_data("example.com", FLAG_UP, 0xDEADBEEF);
        let parsed = parse_and_validate(&bytes, "example.com", false).expect("valid");
        assert_eq!(parsed.sign_count, 0xDEADBEEF);
    }
}
