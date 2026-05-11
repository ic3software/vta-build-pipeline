//! Shared WebAuthn / passkey infrastructure (types + storage).
//!
//! The shape — `PasskeyState` trait, `build_webauthn(public_url)` helper,
//! `Enrollment` / `PasskeyUser` / `CredentialMapping` storage types,
//! `claimed_at` ceremony-lock pattern — is adopted from
//! [`affinidi/affinidi-webvh-service`](https://github.com/affinidi/affinidi-webvh-service)
//! (`webvh-common/src/server/passkey/`), which already proves the
//! pattern in production. Both VTA and VTC implement `PasskeyState`
//! on their `AppState` and reuse the same enrolment + login
//! primitives.
//!
//! ## Module scope
//!
//! This crate ships the **storage layer + supporting types**:
//!
//! - [`PasskeyState`] trait, defining what state services must expose.
//! - [`build_webauthn`] helper that turns a `public_url` config into a
//!   [`webauthn_rs::Webauthn`] instance using the URL's domain as the
//!   relying-party ID and the full URL as the origin.
//! - The persistence layer (see [`store`] sub-module) — enrolment
//!   tokens, passkey users, credential mappings, registration /
//!   authentication ceremony state.
//!
//! The matching route handlers (`enroll_start`, `enroll_finish`,
//! `login_start`, `login_finish`) ship in a follow-up; this PR is
//! intentionally storage-only so consumers can build their own
//! orchestration on top.

pub mod store;

use std::sync::Arc;

use url::Url;
use webauthn_rs::prelude::*;

use crate::auth::extractor::AuthState;
use crate::error::AppError;
use crate::store::KeyspaceHandle;

/// How long an in-progress enrolment claim blocks other concurrent
/// claims on the same token. Sized for a generous WebAuthn ceremony
/// (browser dialog + key tap); a legitimate user retrying after a
/// failed ceremony only waits this long before the claim expires.
///
/// Lifted unchanged from `webvh-common`.
pub const ENROLLMENT_CLAIM_WINDOW_SECS: u64 = 300;

/// Trait that application states implement to support passkey routes.
///
/// Extends [`AuthState`] (which provides JWT keys + sessions keyspace)
/// with the WebAuthn and ACL access that the enrolment + login flows
/// need. The intentionally narrow surface keeps services free to add
/// their own state without leaking it into the shared module.
pub trait PasskeyState: AuthState {
    /// Returns the WebAuthn relying-party handle if configured. `None`
    /// means the service didn't supply a `public_url` at startup —
    /// passkey routes should 503 in that case.
    fn webauthn(&self) -> Option<&Arc<Webauthn>>;

    /// ACL keyspace. Used to confirm the enrolling DID has a matching
    /// ACL entry and to issue the post-ceremony session with the
    /// correct role.
    fn acl_ks(&self) -> &KeyspaceHandle;

    /// Access-token lifetime in seconds (returned by enrolment + login).
    fn access_token_expiry(&self) -> u64;

    /// Refresh-token lifetime in seconds.
    fn refresh_token_expiry(&self) -> u64;

    /// Public base URL used by admin endpoints to render enrolment
    /// links. `None` disables admin invite endpoints.
    fn public_url(&self) -> Option<&str>;

    /// Default enrolment-invite TTL in seconds, used when an admin
    /// creates a new invite without an explicit expiry.
    fn enrollment_ttl(&self) -> u64;
}

/// Build a [`Webauthn`] instance from the service's `public_url`.
///
/// - **Relying-party ID** = the URL's domain (e.g. `example.com`).
/// - **Origin** = the parsed URL (e.g. `https://example.com`).
///
/// Single-source derivation matches the workspace's spec decision
/// (see `docs/05-design-notes/vtc-mvp.md` §4.2 + the M0.1.6 plan
/// entry under D7). Operators who migrate to a different base domain
/// re-register every passkey — documented in the operator runbook.
pub fn build_webauthn(public_url: &str) -> Result<Webauthn, AppError> {
    let url = Url::parse(public_url)
        .map_err(|e| AppError::Config(format!("invalid public_url '{public_url}': {e}")))?;

    let rp_id = url
        .domain()
        .ok_or_else(|| AppError::Config("public_url has no domain".into()))?
        .to_string();

    let builder = WebauthnBuilder::new(&rp_id, &url)
        .map_err(|e| AppError::Config(format!("failed to build WebauthnBuilder: {e}")))?;

    let webauthn = builder
        .rp_name("Verifiable Trust Infrastructure")
        .build()
        .map_err(|e| AppError::Config(format!("failed to build Webauthn: {e}")))?;

    Ok(webauthn)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_webauthn_happy_path() {
        let w = build_webauthn("https://vtc.example.com").expect("ok");
        // Sanity: the builder constructed something usable. The
        // webauthn-rs API doesn't expose its `rp_id` directly, but if
        // we got this far the URL parsing + builder both worked.
        // Subsequent ceremony-level tests cover the actual binding.
        drop(w);
    }

    #[test]
    fn build_webauthn_rejects_invalid_url() {
        let err = build_webauthn("not-a-url").expect_err("invalid URL");
        assert!(
            matches!(err, AppError::Config(ref m) if m.contains("invalid public_url")),
            "got: {err}"
        );
    }

    #[test]
    fn build_webauthn_rejects_url_without_domain() {
        let err = build_webauthn("file:///tmp/foo").expect_err("no domain");
        assert!(
            matches!(err, AppError::Config(ref m) if m.contains("no domain")),
            "got: {err}"
        );
    }
}
