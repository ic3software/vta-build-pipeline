//! VTC WebAuthn helpers — Ed25519-only registration enforcement.
//!
//! Implements **M0.5.1** of the VTC MVP Phase 0 plan. Wraps
//! `vti_common::auth::passkey::build_webauthn` with the VTC-specific
//! invariant that **only Ed25519 (`COSEAlgorithm::EDDSA`,
//! `COSEAlgorithmIdentifier = -8`) registrations are accepted**.
//! The candidate admin DID is a `did:key` projected directly from the
//! passkey's COSE public key — every other COSE curve breaks that
//! projection (spec §4.2 second bullet).
//!
//! ## Why a wrapper
//!
//! `webauthn-rs` 0.5 builds its safe `Webauthn` instance with
//! `COSEAlgorithm::secure_algs()`, which today returns
//! `[ES256, RS256]` — `EDDSA` is commented out in the upstream
//! `secure_algs` constructor. The high-level builder exposes no
//! `algorithms(…)` setter, so the only way to advertise EdDSA on the
//! wire **and** accept it at finish-time is to post-process the
//! ceremony state.
//!
//! This module provides two helpers that callers must use instead of
//! `Webauthn::start_passkey_registration` /
//! `Webauthn::finish_passkey_registration` directly:
//!
//! - [`start_eddsa_passkey_registration`] — runs the upstream start,
//!   then rewrites `CreationChallengeResponse.public_key.pub_key_cred_params`
//!   and `PasskeyRegistration.rs.credential_algorithms` to contain
//!   **only** EDDSA. The rewrite uses the `danger-allow-state-serialisation`
//!   feature (enabled workspace-wide) to round-trip the state through
//!   JSON — there is no other public path into the private
//!   `credential_algorithms` field.
//! - [`finish_eddsa_passkey_registration`] — runs the upstream finish,
//!   then rejects any returned `Passkey` whose `cred_algorithm()` is
//!   not `EDDSA` (defence-in-depth: upstream's own check already
//!   asserts the credential matches `credential_algorithms`, but we
//!   double-check before the caller derives a `did:key`).
//!
//! ## When upstream gains an `algorithms` setter
//!
//! Replace the JSON-rewrite path with the setter and keep the
//! finish-time check (it's cheap). Until then this is the only safe
//! way to honour the spec's "Ed25519-only" invariant without forking
//! `webauthn-rs` or dropping to `webauthn-rs-core::WebauthnCore::new_unsafe_experts_only`.

use webauthn_rs::prelude::{
    CreationChallengeResponse, Passkey, PasskeyRegistration, RegisterPublicKeyCredential, Webauthn,
};
use webauthn_rs_proto::{COSEAlgorithm, PubKeyCredParams};

use crate::error::AppError;

/// COSE algorithm identifier for EdDSA. Pinned in code so the
/// runtime check is independent of upstream renaming `COSEAlgorithm::EDDSA`.
pub const EDDSA_ALG: i64 = -8;

/// Start a passkey registration ceremony constrained to Ed25519.
///
/// Calls `Webauthn::start_passkey_registration` then post-processes
/// both the wire challenge and the persisted ceremony state so that:
///
/// - The browser's `navigator.credentials.create()` call advertises
///   **only** `{type: "public-key", alg: -8}` in `pubKeyCredParams`.
/// - Upstream's finish-time check
///   (`credential_algorithms.iter().any(|alg| alg == &cred.type_)`)
///   only accepts EdDSA credentials.
pub fn start_eddsa_passkey_registration(
    webauthn: &Webauthn,
    user_unique_id: uuid::Uuid,
    user_name: &str,
    user_display_name: &str,
    exclude_credentials: Option<Vec<webauthn_rs::prelude::CredentialID>>,
) -> Result<(CreationChallengeResponse, PasskeyRegistration), AppError> {
    let (mut ccr, reg_state) = webauthn
        .start_passkey_registration(
            user_unique_id,
            user_name,
            user_display_name,
            exclude_credentials,
        )
        .map_err(|e| AppError::Internal(format!("webauthn registration start failed: {e}")))?;

    restrict_ccr_to_eddsa(&mut ccr);
    let reg_state = restrict_state_to_eddsa(&reg_state)?;

    Ok((ccr, reg_state))
}

/// Finish a passkey registration ceremony and assert the resulting
/// credential is Ed25519.
///
/// `Webauthn::finish_passkey_registration` already validates the
/// credential's algorithm against the state's
/// `credential_algorithms` list — but only because
/// [`start_eddsa_passkey_registration`] mutated that list to
/// `[EDDSA]`. This second check defends against a future bug where
/// the start-side mutation silently fails to apply (e.g. a serde
/// schema change in upstream): we'd still reject the non-EdDSA
/// credential here rather than emit a malformed `did:key`.
pub fn finish_eddsa_passkey_registration(
    webauthn: &Webauthn,
    credential: &RegisterPublicKeyCredential,
    state: &PasskeyRegistration,
) -> Result<Passkey, AppError> {
    let passkey = webauthn
        .finish_passkey_registration(credential, state)
        .map_err(|e| AppError::Authentication(format!("passkey registration failed: {e}")))?;

    let cred_alg = passkey.cred_algorithm();
    if *cred_alg != COSEAlgorithm::EDDSA {
        return Err(AppError::Authentication(format!(
            "passkey registration rejected: VTC requires Ed25519 (EdDSA), authenticator returned {cred_alg:?}",
        )));
    }

    Ok(passkey)
}

/// Mutate a [`CreationChallengeResponse`] in place so that
/// `public_key.pub_key_cred_params` lists **only** EdDSA. Public so
/// the unit tests can drive it directly without spinning up a full
/// `Webauthn`.
pub(crate) fn restrict_ccr_to_eddsa(ccr: &mut CreationChallengeResponse) {
    ccr.public_key.pub_key_cred_params = vec![PubKeyCredParams {
        type_: "public-key".to_string(),
        alg: EDDSA_ALG,
    }];
}

/// Round-trip a [`PasskeyRegistration`] through JSON and rewrite the
/// inner state's `credential_algorithms` to `[EDDSA]`. Requires the
/// `danger-allow-state-serialisation` feature on `webauthn-rs`
/// (enabled workspace-wide in the root `Cargo.toml`).
///
/// Returns an [`AppError::Internal`] if the state's JSON shape ever
/// drifts and the rewrite cannot find the expected
/// `rs.credential_algorithms` path. That is a hard upstream-breakage
/// signal, not an operator-facing condition.
pub(crate) fn restrict_state_to_eddsa(
    state: &PasskeyRegistration,
) -> Result<PasskeyRegistration, AppError> {
    let mut value = serde_json::to_value(state).map_err(|e| {
        AppError::Internal(format!(
            "failed to serialise passkey registration state: {e}"
        ))
    })?;

    let rs = value
        .get_mut("rs")
        .and_then(|v| v.as_object_mut())
        .ok_or_else(|| {
            AppError::Internal("passkey registration state missing 'rs' object".into())
        })?;

    if !rs.contains_key("credential_algorithms") {
        return Err(AppError::Internal(
            "passkey registration state missing 'rs.credential_algorithms'".into(),
        ));
    }

    // `Vec<COSEAlgorithm>` serialises as a sequence of *enum-variant
    // strings* (the upstream enum has no `#[serde(repr)]`), not as
    // COSE integer identifiers. Use `"EDDSA"` to match the round-trip
    // shape — `[-8]` would fail with "invalid type: number, expected
    // string or map".
    rs.insert(
        "credential_algorithms".to_string(),
        serde_json::json!(["EDDSA"]),
    );

    serde_json::from_value(value).map_err(|e| {
        AppError::Internal(format!(
            "failed to deserialise rewritten passkey registration state: {e}"
        ))
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;
    use vti_common::auth::passkey::build_webauthn;

    fn webauthn() -> Webauthn {
        build_webauthn("https://vtc.example.com").expect("webauthn builder")
    }

    #[test]
    fn start_rewrites_ccr_to_eddsa_only() {
        let w = webauthn();
        let (ccr, _state) = start_eddsa_passkey_registration(
            &w,
            Uuid::new_v4(),
            "did:key:zABC",
            "did:key:zABC",
            None,
        )
        .unwrap();

        assert_eq!(
            ccr.public_key.pub_key_cred_params.len(),
            1,
            "expected exactly one cred params entry after EdDSA restriction"
        );
        let params = &ccr.public_key.pub_key_cred_params[0];
        assert_eq!(params.type_, "public-key");
        assert_eq!(params.alg, EDDSA_ALG, "alg must be EdDSA (-8)");
    }

    #[test]
    fn start_rewrites_state_credential_algorithms_to_eddsa_only() {
        let w = webauthn();
        let (_ccr, state) = start_eddsa_passkey_registration(
            &w,
            Uuid::new_v4(),
            "did:key:zABC",
            "did:key:zABC",
            None,
        )
        .unwrap();

        // `PasskeyRegistration` exposes no public algorithms accessor;
        // serialise and inspect the JSON instead. This is the same
        // mechanism the implementation uses to perform the rewrite,
        // so the round-trip is the assertion.
        let json = serde_json::to_value(&state).unwrap();
        let algs = json
            .get("rs")
            .and_then(|rs| rs.get("credential_algorithms"))
            .expect("credential_algorithms present");
        assert_eq!(
            algs,
            &serde_json::json!(["EDDSA"]),
            "credential_algorithms must contain only EdDSA (serialised as the enum-variant name)"
        );
    }

    #[test]
    fn restrict_ccr_overwrites_default_algorithm_list() {
        let w = webauthn();
        let (mut ccr, _state) = w
            .start_passkey_registration(Uuid::new_v4(), "u", "u", None)
            .unwrap();

        // Sanity: upstream's default list contains more than one entry
        // and does NOT include EdDSA today (see workspace CLAUDE.md
        // discussion). If this assertion ever fails it means upstream
        // started shipping EdDSA in `secure_algs()` — at which point the
        // rewrite becomes pure defence-in-depth and we can simplify.
        assert!(ccr.public_key.pub_key_cred_params.len() >= 2);
        assert!(
            !ccr.public_key
                .pub_key_cred_params
                .iter()
                .any(|p| p.alg == EDDSA_ALG)
        );

        restrict_ccr_to_eddsa(&mut ccr);

        assert_eq!(ccr.public_key.pub_key_cred_params.len(), 1);
        assert_eq!(ccr.public_key.pub_key_cred_params[0].alg, EDDSA_ALG);
    }

    #[test]
    fn restrict_state_round_trips_through_serde() {
        let w = webauthn();
        let (_ccr, state) = w
            .start_passkey_registration(Uuid::new_v4(), "u", "u", None)
            .unwrap();

        let rewritten = restrict_state_to_eddsa(&state).unwrap();

        let json = serde_json::to_value(&rewritten).unwrap();
        assert_eq!(
            json["rs"]["credential_algorithms"],
            serde_json::json!(["EDDSA"])
        );

        // Other state fields survive the round-trip — pick `policy`
        // and `require_resident_key` as representative sentinels.
        let original_json = serde_json::to_value(&state).unwrap();
        for field in ["policy", "require_resident_key"] {
            assert_eq!(
                json["rs"][field], original_json["rs"][field],
                "field {field} must survive the rewrite",
            );
        }
    }
}
