//! Install carve-out state machine.
//!
//! Implements **M0.4.2** of the VTC MVP Phase 0 plan. Adopts the
//! claim-window pattern from `webvh-common::server::passkey::store`
//! (plan **D12**): an in-flight WebAuthn ceremony locks out
//! concurrent claims for [`ENROLLMENT_CLAIM_WINDOW_SECS`] (5
//! minutes) but is **not** consumed until the ceremony succeeds —
//! a failed ceremony leaves the token redeemable by the legitimate
//! operator after the window expires.
//!
//! Storage:
//!
//! - `install:token:<jti>` → [`InstallTokenState`] (`Issued` /
//!   `Consumed`).
//! - `install:carveout:closed` → presence marker (any non-empty
//!   value) — once written, every subsequent state transition
//!   that would issue or claim a token rejects with the carve-out-
//!   closed variant.
//!
//! Concurrency: every transition takes [`super::INSTALL_CARVEOUT_LOCK`]
//! before reading + writing state. The lock serialises across
//! Axum tasks so two `start_claim` calls on the same JTI cannot
//! both pass the "claimed_at not set within the window" check.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use super::INSTALL_CARVEOUT_LOCK;
use crate::error::AppError;
use vti_common::store::KeyspaceHandle;

/// How long an in-flight WebAuthn ceremony locks out concurrent
/// claims on the same install token. Tracks the same value as
/// `vti_common::auth::passkey::ENROLLMENT_CLAIM_WINDOW_SECS` (300 s).
/// Duplicated locally rather than depending on the `passkey` feature
/// of `vti-common` — the install state machine doesn't need anything
/// else from that module, and feature-gating one constant through
/// the dependency tree adds more friction than it's worth. M0.5 will
/// switch to the shared constant when it enables the `passkey`
/// feature.
pub const ENROLLMENT_CLAIM_WINDOW_SECS: u64 = 300;

const TOKEN_KEY_PREFIX: &[u8] = b"install:token:";
const CARVEOUT_CLOSED_KEY: &[u8] = b"install:carveout:closed";
const EMERGENCY_PENDING_KEY: &[u8] = b"install:emergency_pending";

fn token_key(jti: &Uuid) -> Vec<u8> {
    let mut out = TOKEN_KEY_PREFIX.to_vec();
    out.extend_from_slice(jti.to_string().as_bytes());
    out
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Per-token state held in the `install` keyspace.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum InstallTokenState {
    /// Issued but not yet successfully consumed. `claimed_at` is set
    /// when a `start_claim` call is in progress; the window
    /// expires after [`ENROLLMENT_CLAIM_WINDOW_SECS`] so a failed
    /// ceremony doesn't permanently lock the token.
    Issued {
        /// Wall-clock expiry; once exceeded, the token cannot
        /// progress to `Consumed`.
        exp: DateTime<Utc>,
        /// Raw 32 cnonce bytes; the WebAuthn ceremony's
        /// `clientDataJSON.challenge` is validated against this.
        #[serde(with = "raw_bytes_b64")]
        cnonce: [u8; 32],
        /// Raw 32 ephemeral Ed25519 private key bytes. Only present
        /// in `Issued`; nulled on transition to `Consumed`.
        #[serde(with = "raw_bytes_b64")]
        ephemeral_signing_key: [u8; 32],
        /// Wall-clock when an in-flight `start_claim` set the
        /// ceremony lock. `None` means no ceremony has been
        /// initiated since issuance.
        claimed_at: Option<DateTime<Utc>>,
    },
    /// Ceremony succeeded — token is permanently spent. Retained for
    /// idempotency / audit; a later `start_claim` for the same JTI
    /// returns [`AppError::Unauthorized`].
    Consumed { at: DateTime<Utc> },
}

mod raw_bytes_b64 {
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serializer};

    const B64: base64::engine::general_purpose::GeneralPurpose =
        base64::engine::general_purpose::URL_SAFE_NO_PAD;

    pub fn serialize<S: Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&B64.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        let v = B64.decode(&s).map_err(serde::de::Error::custom)?;
        v.try_into()
            .map_err(|_| serde::de::Error::custom("expected 32 bytes"))
    }
}

/// Successful [`InstallTokenStore::start_claim`] outcome. The
/// caller hands `ephemeral_signing_key` + `cnonce` to the WebAuthn
/// route handler; on ceremony success the route calls
/// [`InstallTokenStore::finish_claim`] to consume.
#[derive(Debug)]
pub struct StartClaimOutcome {
    pub ephemeral_signing_key: Zeroizing<[u8; 32]>,
    pub cnonce: [u8; 32],
}

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

/// Wraps the `install` keyspace with the state-machine semantics.
/// Cheap to clone (the underlying handle is `Arc`-shared).
#[derive(Clone)]
pub struct InstallTokenStore {
    ks: KeyspaceHandle,
}

impl InstallTokenStore {
    pub fn new(ks: KeyspaceHandle) -> Self {
        Self { ks }
    }

    /// Persist a freshly-minted token's state. Refuses if the
    /// carve-out is closed — once admin bootstrap completes, no
    /// further install tokens may be issued.
    ///
    /// Caller must hold no other lock on the install keyspace; we
    /// take [`INSTALL_CARVEOUT_LOCK`] internally for the
    /// check-then-write sequence.
    pub async fn record_issued(
        &self,
        jti: &Uuid,
        cnonce: [u8; 32],
        ephemeral_signing_key: [u8; 32],
        exp: DateTime<Utc>,
    ) -> Result<(), AppError> {
        let _guard = INSTALL_CARVEOUT_LOCK.lock().await;
        if self.carveout_is_closed_raw().await? {
            return Err(AppError::Conflict("install carve-out is closed".into()));
        }
        let state = InstallTokenState::Issued {
            exp,
            cnonce,
            ephemeral_signing_key,
            claimed_at: None,
        };
        self.ks.insert(token_key(jti), &state).await
    }

    /// Begin a WebAuthn ceremony on `jti`.
    ///
    /// Returns `Ok(StartClaimOutcome)` if the token is `Issued`,
    /// not expired, the carve-out is open, and no concurrent
    /// ceremony has set `claimed_at` within the
    /// [`ENROLLMENT_CLAIM_WINDOW_SECS`] window. Sets `claimed_at`
    /// as a side-effect so a second concurrent caller sees the
    /// in-progress lock.
    ///
    /// Errors with [`AppError::Unauthorized`] on every other state
    /// — the structured detail stays out of the response for
    /// defence in depth.
    pub async fn start_claim(&self, jti: &Uuid) -> Result<StartClaimOutcome, AppError> {
        let _guard = INSTALL_CARVEOUT_LOCK.lock().await;
        if self.carveout_is_closed_raw().await? {
            return Err(AppError::Unauthorized("install carve-out is closed".into()));
        }

        let key = token_key(jti);
        let state: Option<InstallTokenState> = self.ks.get(key.clone()).await?;
        let state =
            state.ok_or_else(|| AppError::Unauthorized("install token not found".into()))?;

        match state {
            InstallTokenState::Consumed { .. } => {
                Err(AppError::Unauthorized("install token consumed".into()))
            }
            InstallTokenState::Issued {
                exp,
                cnonce,
                ephemeral_signing_key,
                claimed_at,
            } => {
                let now = Utc::now();
                if now >= exp {
                    return Err(AppError::Unauthorized("install token expired".into()));
                }
                if let Some(prev) = claimed_at {
                    let elapsed = now - prev;
                    if elapsed < Duration::seconds(ENROLLMENT_CLAIM_WINDOW_SECS as i64) {
                        return Err(AppError::Conflict(
                            "install ceremony already in progress".into(),
                        ));
                    }
                }
                let next = InstallTokenState::Issued {
                    exp,
                    cnonce,
                    ephemeral_signing_key,
                    claimed_at: Some(now),
                };
                self.ks.insert(key, &next).await?;
                Ok(StartClaimOutcome {
                    cnonce,
                    ephemeral_signing_key: Zeroizing::new(ephemeral_signing_key),
                })
            }
        }
    }

    /// Complete the ceremony — transitions `Issued` → `Consumed`.
    /// Errors with [`AppError::Unauthorized`] if the token is already
    /// consumed or expired.
    ///
    /// The caller (M0.5 `/install/claim/finish` handler) calls this
    /// **only** after the WebAuthn assertion validates against the
    /// `cnonce` and the candidate DID signature has been verified.
    pub async fn finish_claim(&self, jti: &Uuid) -> Result<(), AppError> {
        let _guard = INSTALL_CARVEOUT_LOCK.lock().await;
        let key = token_key(jti);
        let state: Option<InstallTokenState> = self.ks.get(key.clone()).await?;
        let state =
            state.ok_or_else(|| AppError::Unauthorized("install token not found".into()))?;
        match state {
            InstallTokenState::Consumed { .. } => {
                Err(AppError::Unauthorized("install token consumed".into()))
            }
            InstallTokenState::Issued { exp, .. } => {
                let now = Utc::now();
                if now >= exp {
                    return Err(AppError::Unauthorized("install token expired".into()));
                }
                let next = InstallTokenState::Consumed { at: now };
                self.ks.insert(key, &next).await
            }
        }
    }

    /// Permanently close the install carve-out. Once written, every
    /// subsequent [`Self::record_issued`] returns
    /// [`AppError::Conflict`], and every [`Self::start_claim`] /
    /// [`Self::finish_claim`] returns [`AppError::Unauthorized`].
    ///
    /// Idempotent — calling on an already-closed store is a no-op.
    pub async fn close_carveout(&self) -> Result<(), AppError> {
        let _guard = INSTALL_CARVEOUT_LOCK.lock().await;
        self.ks
            .insert_raw(CARVEOUT_CLOSED_KEY.to_vec(), b"1".to_vec())
            .await
    }

    /// Inspect carve-out status. Read-only; doesn't take the lock.
    pub async fn carveout_is_closed(&self) -> Result<bool, AppError> {
        self.carveout_is_closed_raw().await
    }

    async fn carveout_is_closed_raw(&self) -> Result<bool, AppError> {
        Ok(self
            .ks
            .get_raw(CARVEOUT_CLOSED_KEY.to_vec())
            .await?
            .is_some())
    }

    /// **Destructive.** Clear the `install:carveout:closed` marker
    /// so a fresh `record_issued` + `start_claim` round can take
    /// place. Called by `vtc admin emergency-bootstrap` (M0.10)
    /// after verifying the operator holds the master-seed mnemonic.
    /// Never called from request-handling code paths — the carve-out
    /// is one-shot from the daemon's perspective.
    pub async fn reopen_carveout(&self) -> Result<(), AppError> {
        let _guard = INSTALL_CARVEOUT_LOCK.lock().await;
        self.ks.remove(CARVEOUT_CLOSED_KEY.to_vec()).await
    }

    /// Stamp the `install:emergency_pending` marker carrying the
    /// operator's hostname + the wall-clock at CLI-invoke time. The
    /// daemon reads + consumes the marker on next boot via
    /// [`Self::take_pending_emergency`] and emits the
    /// `EmergencyBootstrapInvoked` audit event from it.
    pub async fn mark_emergency_pending(
        &self,
        pending: PendingEmergencyBootstrap,
    ) -> Result<(), AppError> {
        self.ks
            .insert(EMERGENCY_PENDING_KEY.to_vec(), &pending)
            .await
    }

    /// Read + delete the pending-emergency-bootstrap marker. The
    /// daemon calls this once at startup; a returned `Some(...)`
    /// fires the `EmergencyBootstrapInvoked` audit event. Subsequent
    /// startups (after the marker is consumed) see `None`.
    pub async fn take_pending_emergency(
        &self,
    ) -> Result<Option<PendingEmergencyBootstrap>, AppError> {
        let key = EMERGENCY_PENDING_KEY.to_vec();
        let value: Option<PendingEmergencyBootstrap> = self.ks.get(key.clone()).await?;
        if value.is_some() {
            self.ks.remove(key).await?;
        }
        Ok(value)
    }

    /// List every persisted install-token state row keyed by `jti`.
    /// Used by the `/v1/admin/invites` list surface. Returns the
    /// (jti, state) pairs; the handler derives status (Issued /
    /// Consumed / Expired) and strips secret material before
    /// emitting wire JSON.
    pub async fn list_tokens(&self) -> Result<Vec<(Uuid, InstallTokenState)>, AppError> {
        let raw = self.ks.prefix_iter_raw(TOKEN_KEY_PREFIX.to_vec()).await?;
        let mut out = Vec::with_capacity(raw.len());
        for (k, v) in raw {
            let Some(suffix) = k.strip_prefix(TOKEN_KEY_PREFIX) else {
                continue;
            };
            let Ok(jti_str) = std::str::from_utf8(suffix) else {
                continue;
            };
            let Ok(jti) = jti_str.parse::<Uuid>() else {
                continue;
            };
            match serde_json::from_slice::<InstallTokenState>(&v) {
                Ok(state) => out.push((jti, state)),
                Err(e) => {
                    tracing::warn!(error = %e, %jti, "skipping unparseable install token state")
                }
            }
        }
        Ok(out)
    }

    /// Peek a token's state row without mutating it. Used by the
    /// invite revoke surface to refuse `Consumed` rows before any
    /// destructive call.
    pub async fn get_token(&self, jti: &Uuid) -> Result<Option<InstallTokenState>, AppError> {
        self.ks.get(token_key(jti)).await
    }

    /// Delete a token's state row. Used by the invite revoke
    /// surface after a [`Self::get_token`] check has confirmed
    /// the row is not `Consumed`. Returns `true` if a row was
    /// removed.
    pub async fn delete_token(&self, jti: &Uuid) -> Result<bool, AppError> {
        let _guard = INSTALL_CARVEOUT_LOCK.lock().await;
        let key = token_key(jti);
        let existed: Option<InstallTokenState> = self.ks.get(key.clone()).await?;
        if existed.is_some() {
            self.ks.remove(key).await?;
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

/// State persisted to `install:emergency_pending` by the
/// `vtc admin emergency-bootstrap` CLI. The daemon consumes it on
/// next boot and feeds it into [`crate::audit`]'s
/// `EmergencyBootstrapInvoked` event.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingEmergencyBootstrap {
    pub operator_hostname: String,
    pub invoked_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use vti_common::config::StoreConfig;
    use vti_common::store::Store;

    fn temp_store() -> (InstallTokenStore, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let cfg = StoreConfig {
            data_dir: dir.path().to_path_buf(),
        };
        let store = Store::open(&cfg).expect("store");
        let ks = store.keyspace("install-test").expect("ks");
        (InstallTokenStore::new(ks), dir)
    }

    async fn issue(store: &InstallTokenStore, ttl: i64) -> Uuid {
        let jti = Uuid::new_v4();
        let exp = Utc::now() + Duration::seconds(ttl);
        store
            .record_issued(&jti, [0xAB; 32], [0xCD; 32], exp)
            .await
            .unwrap();
        jti
    }

    #[tokio::test]
    async fn start_then_finish_consumes_token() {
        let (store, _dir) = temp_store();
        let jti = issue(&store, 600).await;

        let outcome = store.start_claim(&jti).await.unwrap();
        assert_eq!(outcome.cnonce, [0xAB; 32]);
        assert_eq!(*outcome.ephemeral_signing_key, [0xCD; 32]);

        store.finish_claim(&jti).await.unwrap();
        // Second finish returns "consumed".
        let err = store.finish_claim(&jti).await.expect_err("second finish");
        assert!(matches!(err, AppError::Unauthorized(_)));
    }

    #[tokio::test]
    async fn second_concurrent_start_within_window_is_rejected() {
        let (store, _dir) = temp_store();
        let jti = issue(&store, 600).await;

        let _first = store.start_claim(&jti).await.unwrap();
        // Immediately try a second start — the claim window is 5
        // minutes, so this must be rejected.
        let err = store.start_claim(&jti).await.expect_err("conflict");
        assert!(matches!(err, AppError::Conflict(_)));
    }

    #[tokio::test]
    async fn retry_after_window_succeeds() {
        let (store, _dir) = temp_store();
        let jti = issue(&store, 600).await;

        let _first = store.start_claim(&jti).await.unwrap();
        // Backdate `claimed_at` past the window so the next call
        // sees a stale lock and overwrites it.
        let key = token_key(&jti);
        let mut state: InstallTokenState = store.ks.get(key.clone()).await.unwrap().unwrap();
        if let InstallTokenState::Issued {
            ref mut claimed_at, ..
        } = state
        {
            *claimed_at =
                Some(Utc::now() - Duration::seconds((ENROLLMENT_CLAIM_WINDOW_SECS as i64) + 10));
        }
        store.ks.insert(key, &state).await.unwrap();

        let _retry = store.start_claim(&jti).await.expect("retry after window");
    }

    #[tokio::test]
    async fn expired_token_rejected_on_start() {
        let (store, _dir) = temp_store();
        let jti = issue(&store, -1).await;
        let err = store.start_claim(&jti).await.expect_err("expired");
        assert!(matches!(err, AppError::Unauthorized(_)));
    }

    #[tokio::test]
    async fn expired_token_rejected_on_finish() {
        let (store, _dir) = temp_store();
        let jti = issue(&store, 600).await;
        let _ = store.start_claim(&jti).await.unwrap();

        // Backdate the expiry to now-1s.
        let key = token_key(&jti);
        let mut state: InstallTokenState = store.ks.get(key.clone()).await.unwrap().unwrap();
        if let InstallTokenState::Issued { ref mut exp, .. } = state {
            *exp = Utc::now() - Duration::seconds(1);
        }
        store.ks.insert(key, &state).await.unwrap();

        let err = store.finish_claim(&jti).await.expect_err("expired");
        assert!(matches!(err, AppError::Unauthorized(_)));
    }

    #[tokio::test]
    async fn close_carveout_blocks_subsequent_issuance() {
        let (store, _dir) = temp_store();
        store.close_carveout().await.unwrap();
        assert!(store.carveout_is_closed().await.unwrap());

        let jti = Uuid::new_v4();
        let exp = Utc::now() + Duration::seconds(600);
        let err = store
            .record_issued(&jti, [0u8; 32], [0u8; 32], exp)
            .await
            .expect_err("conflict");
        assert!(matches!(err, AppError::Conflict(_)));
    }

    #[tokio::test]
    async fn close_carveout_blocks_subsequent_start_claim() {
        let (store, _dir) = temp_store();
        let jti = issue(&store, 600).await;
        store.close_carveout().await.unwrap();
        let err = store.start_claim(&jti).await.expect_err("closed");
        assert!(matches!(err, AppError::Unauthorized(_)));
    }

    #[tokio::test]
    async fn close_carveout_is_idempotent() {
        let (store, _dir) = temp_store();
        store.close_carveout().await.unwrap();
        store.close_carveout().await.unwrap();
        assert!(store.carveout_is_closed().await.unwrap());
    }

    #[tokio::test]
    async fn missing_token_returns_unauthorized() {
        let (store, _dir) = temp_store();
        let phantom_jti = Uuid::new_v4();
        let err = store
            .start_claim(&phantom_jti)
            .await
            .expect_err("not found");
        assert!(matches!(err, AppError::Unauthorized(_)));
    }

    #[tokio::test]
    async fn state_machine_serde_round_trip() {
        let state = InstallTokenState::Issued {
            exp: Utc::now() + Duration::seconds(60),
            cnonce: [0xAB; 32],
            ephemeral_signing_key: [0xCD; 32],
            claimed_at: Some(Utc::now()),
        };
        let s = serde_json::to_string(&state).unwrap();
        let back: InstallTokenState = serde_json::from_str(&s).unwrap();
        assert_eq!(back, state);
    }
}
