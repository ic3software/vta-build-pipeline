//! VTC-side [`AuthBackend`] implementation.
//!
//! Wires the canonical `/auth/*` handlers in
//! `vti_common::auth::handlers` to VTC's storage, JWT minter,
//! and ACL system.
//!
//! Differs from VTA's backend in:
//! - No TEE attestation surface (`attest_challenge` uses the
//!   trait default → not-attested).
//! - No DID-method allowlist (`validate_did` uses the trait
//!   default → accept-any).
//! - JWT audience `"VTC"` (set by the `JwtKeys` instance held
//!   on `AppState`).
//! - Role type is `VtcRole` (re-exported as `crate::acl::Role`).
//!
//! Role enum and ACL helper signatures are otherwise identical
//! to VTA's — both consume `vti_common::acl::check_acl_full`,
//! which the canonical handler invokes uniformly through
//! [`AuthBackend::check_acl`].

use async_trait::async_trait;
use std::sync::Arc;

use vti_common::auth::backend::{AuthBackend, AuthError, RoleResolution};
use vti_common::auth::handlers::KeyspaceSessionStore;
use vti_common::auth::jwt::JwtKeys;

use crate::acl::Role;
use crate::error::AppError;
use crate::server::AppState;

/// VTC `AuthBackend`. Holds an `Arc<AppState>` clone plus a
/// TTL snapshot read once at construction.
pub struct VtcAuthBackend {
    state: Arc<AppState>,
    sessions: KeyspaceSessionStore,
    jwt_keys: Arc<JwtKeys>,
    challenge_ttl: u64,
    access_token_ttl: u64,
    refresh_token_ttl: u64,
}

impl VtcAuthBackend {
    pub async fn from_state(state: &AppState) -> Result<Self, AppError> {
        let jwt_keys = state
            .jwt_keys
            .clone()
            .ok_or_else(|| AppError::Internal("JWT keys not configured".to_string()))?;
        let sessions = KeyspaceSessionStore::new(state.sessions_ks.clone());

        let (challenge_ttl, access_token_ttl, refresh_token_ttl) = {
            let cfg = state.config.read().await;
            (
                cfg.auth.challenge_ttl,
                cfg.auth.access_token_expiry,
                cfg.auth.refresh_token_expiry,
            )
        };

        Ok(Self {
            state: Arc::new(state.clone()),
            sessions,
            jwt_keys,
            challenge_ttl,
            access_token_ttl,
            refresh_token_ttl,
        })
    }
}

#[async_trait]
impl AuthBackend for VtcAuthBackend {
    type Store = KeyspaceSessionStore;
    type Error = AppError;
    type Role = Role;

    fn sessions(&self) -> &Self::Store {
        &self.sessions
    }

    async fn mint_access_token(
        &self,
        subject: &str,
        session_id: &str,
        role: &Self::Role,
        contexts: &[String],
        amr: &[String],
        acr: &str,
        tee_attested: bool,
        ttl_secs: u64,
    ) -> Result<String, Self::Error> {
        let claims = self
            .jwt_keys
            .new_claims(
                subject.to_string(),
                session_id.to_string(),
                role.to_string(),
                contexts.to_vec(),
                ttl_secs,
                tee_attested,
            )
            .with_aal(amr.to_vec(), acr.to_string());
        self.jwt_keys
            .encode(&claims)
            .map_err(|e| AppError::Internal(format!("jwt encode failed: {e:?}")))
    }

    async fn check_acl(&self, did: &str) -> Result<RoleResolution<Self::Role>, Self::Error> {
        let (role, allowed_contexts) =
            vti_common::acl::check_acl_full(&self.state.acl_ks, did).await?;
        Ok(RoleResolution::with_contexts(role, allowed_contexts))
    }

    // validate_did, attest_challenge, max_pending_challenges_per_did,
    // audit, didcomm_freshness_window: trait defaults are correct
    // for VTC.

    fn challenge_ttl(&self) -> u64 {
        self.challenge_ttl
    }

    fn access_token_ttl(&self) -> u64 {
        self.access_token_ttl
    }

    fn refresh_token_ttl(&self) -> u64 {
        self.refresh_token_ttl
    }
}

// VTC's AppError -> AuthError glue: just delegate to vti-common's
// impl, since VTC reexports vti-common's AppError as its own.
// This is here as a sanity-check anchor; if VTC ever forks AppError
// the From impl moves alongside.
const _: fn() = || {
    fn assert_from_authentication_error<E: From<AuthError>>() {}
    assert_from_authentication_error::<AppError>();
};
