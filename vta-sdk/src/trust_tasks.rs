//! Canonical Trust-Task URLs for every VTA operation.
//!
//! Mirrors the
//! [`did-hosting-common::did_hosting_tasks`](https://github.com/affinidi/did-hosting-service)
//! pattern: one `pub const` per registered URI; grep `TASK_*` to
//! enumerate the full wire surface. Each URI is routed both on REST
//! (via the trust-task envelope's `type` field on
//! `POST /api/trust-tasks`) and on DIDComm (via the inbound message
//! `type`).
//!
//! ## URI shape (deliberately non-spec-canonical)
//!
//! ```text
//! https://trusttasks.org/{namespace}/{op-path}/{maj}.{min}
//! ```
//!
//! The framework SPEC.md §6.1 prescribes the canonical form
//! `https://trusttasks.org/spec/<slug>/<MAJOR.MINOR>` (with `/spec/`).
//! Both this workspace and `affinidi-webvh-service` use the flatter
//! form *without* `/spec/`. The two services' dispatchers accept this
//! flat form via local URL-newtype wrappers; consumers exchange URIs
//! by exact-string match, so the divergence is operator-invisible.
//!
//! Reason for the divergence: the URI is just an identifier (the
//! workspace treats it as opaque). The `/spec/` segment isn't useful
//! for routing and adds noise to every wire message. If/when the
//! framework spec evolves to allow the flat form, no migration needed.
//!
//! ## Namespace
//!
//! - `https://trusttasks.org/vta/...` — VTA operations (this module).
//! - `https://trusttasks.org/did-hosting/...` — webvh-service.
//! - `https://trusttasks.org/webvh/...` — webvh-protocol ops.
//!
//! ## Versioning
//!
//! `{maj}.{min}` only per the canonical Trust-Tasks spec — no patch
//! component. Bumping requires registering a NEW const at a new URL;
//! the old URL keeps routing to its handler until removed in a future
//! release. The router does NOT do version-family matching — `1.0` and
//! `1.1` are completely separate identifiers.
//!
//! ## Cross-crate consistency
//!
//! Every const here is reflected in the migration mapping in
//! `docs/05-design-notes/trust-task-uri-registry.md`. A parity harness
//! in `vta-service` confirms the dispatcher knows about every const
//! declared here.
//!
//! ## What lives here vs is planned
//!
//! v0.1 of this module ships the **auth slice only** — the six URIs
//! needed for the trust-task migration's Phase 2 "first-light" gate.
//! Remaining slices (keys, contexts, ACL, services, etc., ~70 more
//! URIs) land in Phase 3 of the migration initiative.

// ─── Auth slice (vta/auth/*) ─────────────────────────────────────────────

/// `vta/auth/challenge/1.0` — request a nonce for a DID.
pub const TASK_AUTH_CHALLENGE_1_0: &str = "https://trusttasks.org/vta/auth/challenge/1.0";

/// `vta/auth/authenticate/1.0` — sign the challenge with a DID-key JWS
/// (legacy auth flow; passkey login uses `passkey-login-finish/1.0`).
pub const TASK_AUTH_AUTHENTICATE_1_0: &str = "https://trusttasks.org/vta/auth/authenticate/1.0";

/// `vta/auth/refresh/1.0` — refresh an access token.
pub const TASK_AUTH_REFRESH_1_0: &str = "https://trusttasks.org/vta/auth/refresh/1.0";

/// `vta/auth/revoke-session/1.0` — revoke a session by id.
pub const TASK_AUTH_REVOKE_SESSION_1_0: &str = "https://trusttasks.org/vta/auth/revoke-session/1.0";

/// `vta/auth/passkey-login-start/1.0` — request a passkey-bound login
/// challenge. Payload: `{ did }` → response: `{ session_id, challenge,
/// allowCredentials[] }`.
pub const TASK_AUTH_PASSKEY_LOGIN_START_1_0: &str =
    "https://trusttasks.org/vta/auth/passkey-login-start/1.0";

/// `vta/auth/passkey-login-finish/1.0` — present a WebAuthn assertion
/// against a DID-resolved VM. Payload carries assertion bytes
/// (authenticatorData, clientDataJSON, signature, credential_id) plus
/// `session_pubkey_b58btc` for DPoP-style binding of subsequent
/// trust-task proofs to this session.
pub const TASK_AUTH_PASSKEY_LOGIN_FINISH_1_0: &str =
    "https://trusttasks.org/vta/auth/passkey-login-finish/1.0";

// ─── Future slices ───────────────────────────────────────────────────────
//
// keys, seeds, contexts, acl, audit, attestation, services, webvh,
// did-templates, passkey-vms, backup, config, discovery, management,
// join-requests, bootstrap.
//
// Each slice ships in its own Phase 3 PR. The migration mapping table
// in docs/05-design-notes/trust-task-uri-registry.md enumerates the
// full target surface (~75 URIs).

/// Every URI registered in this module — handy for the dispatcher's
/// parity harness and for operator tooling that wants to enumerate
/// the VTA's wire surface programmatically.
pub const ALL_URIS: &[&str] = &[
    TASK_AUTH_CHALLENGE_1_0,
    TASK_AUTH_AUTHENTICATE_1_0,
    TASK_AUTH_REFRESH_1_0,
    TASK_AUTH_REVOKE_SESSION_1_0,
    TASK_AUTH_PASSKEY_LOGIN_START_1_0,
    TASK_AUTH_PASSKEY_LOGIN_FINISH_1_0,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_uri_in_vta_namespace() {
        for uri in ALL_URIS {
            assert!(
                uri.starts_with("https://trusttasks.org/vta/"),
                "VTA URI must be under /vta/: {uri}"
            );
        }
    }

    #[test]
    fn every_uri_has_maj_min_version_suffix() {
        for uri in ALL_URIS {
            let tail = uri.rsplit('/').next().unwrap();
            let parts: Vec<&str> = tail.split('.').collect();
            assert_eq!(parts.len(), 2, "version must be maj.min only: {uri}");
            assert!(
                parts[0].chars().all(|c| c.is_ascii_digit())
                    && parts[1].chars().all(|c| c.is_ascii_digit()),
                "version components must be digits: {uri}"
            );
        }
    }

    #[test]
    fn no_duplicate_uris() {
        let mut sorted: Vec<&str> = ALL_URIS.to_vec();
        sorted.sort();
        for window in sorted.windows(2) {
            assert_ne!(window[0], window[1], "duplicate URI: {}", window[0]);
        }
    }
}
