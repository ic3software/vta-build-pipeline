//! Canonical Trust-Task URIs for every VTA operation.
//!
//! One `pub const` per registered URI; grep `TASK_*` to enumerate the
//! full wire surface. Each URI is routed both on REST (via the
//! trust-task envelope's `type` field on `POST /api/trust-tasks` or
//! a dedicated unauth route) and on DIDComm (via the inbound message
//! `type`).
//!
//! ## URI shape (framework-canonical)
//!
//! ```text
//! https://trusttasks.org/spec/{namespace}/{op-path}/{maj}.{min}
//! ```
//!
//! Per framework SPEC.md §6.1 + the `slug` grammar in
//! `dtgwg-trust-tasks-tf/specs/spec.meta.schema.json` — hierarchical
//! slugs with `/`-delimited path segments are supported (the spec's
//! own example is `acl/grant`). The `/spec/` segment is mandatory;
//! `TypeUri::from_str` rejects URIs missing it (pinned by the
//! `framework_requires_canonical_uri_in_wire_type_field` test in
//! `vta-service::routes::trust_tasks`).
//!
//! Earlier drafts of this workspace used a flat form (no `/spec/`),
//! which deserialised cleanly as a Rust `&'static str` but failed
//! `serde_json::from_slice::<TrustTask<Value>>`. Resolved by adopting
//! the framework's canonical hierarchical-slug form throughout —
//! breaking change made before any external clients existed.
//!
//! ## Namespace
//!
//! - `https://trusttasks.org/spec/vta/...` — VTA operations (this module).
//! - `https://trusttasks.org/spec/did-hosting/...` — webvh-service.
//! - `https://trusttasks.org/spec/webvh/...` — webvh-protocol ops.
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
//! in `vta-service::routes::trust_tasks` confirms the dispatcher knows
//! about every const declared here.
//!
//! ## What lives here vs is planned
//!
//! v0.1 of this module ships the **auth slice only** — the six URIs
//! needed for the trust-task migration's Phase 2 "first-light" gate.
//! Remaining slices (keys, contexts, ACL, services, etc., ~70 more
//! URIs) land in Phase 3 of the migration initiative.

// ─── Auth slice (spec/vta/auth/*) ────────────────────────────────────────

/// `spec/vta/auth/challenge/1.0` — request a nonce for a DID.
pub const TASK_AUTH_CHALLENGE_1_0: &str = "https://trusttasks.org/spec/vta/auth/challenge/1.0";

/// `spec/vta/auth/authenticate/1.0` — sign the challenge with a
/// DID-key JWS (legacy auth flow; passkey login uses
/// `passkey-login-finish/1.0`).
pub const TASK_AUTH_AUTHENTICATE_1_0: &str =
    "https://trusttasks.org/spec/vta/auth/authenticate/1.0";

/// `spec/vta/auth/refresh/1.0` — refresh an access token.
pub const TASK_AUTH_REFRESH_1_0: &str = "https://trusttasks.org/spec/vta/auth/refresh/1.0";

/// `spec/vta/auth/revoke-session/1.0` — revoke a session by id.
pub const TASK_AUTH_REVOKE_SESSION_1_0: &str =
    "https://trusttasks.org/spec/vta/auth/revoke-session/1.0";

/// `spec/vta/auth/passkey-login-start/1.0` — request a passkey-bound
/// login challenge. Payload: `{ did }` → response: `{ session_id,
/// challenge, allowCredentials[] }`.
pub const TASK_AUTH_PASSKEY_LOGIN_START_1_0: &str =
    "https://trusttasks.org/spec/vta/auth/passkey-login-start/1.0";

/// `spec/vta/auth/passkey-login-finish/1.0` — present a WebAuthn
/// assertion against a DID-resolved VM. Payload carries assertion
/// bytes (authenticatorData, clientDataJSON, signature, credential_id)
/// plus `session_pubkey_b58btc` for DPoP-style binding of subsequent
/// trust-task proofs to this session.
pub const TASK_AUTH_PASSKEY_LOGIN_FINISH_1_0: &str =
    "https://trusttasks.org/spec/vta/auth/passkey-login-finish/1.0";

// ─── ACL slice (spec/vta/acl/*) ──────────────────────────────────────────

/// `spec/vta/acl/list/1.0` — list ACL entries, optionally filtered by
/// context. Payload: [`crate::protocols::acl_management::list::ListAclBody`].
pub const TASK_ACL_LIST_1_0: &str = "https://trusttasks.org/spec/vta/acl/list/1.0";

/// `spec/vta/acl/create/1.0` — add an ACL entry. Payload:
/// [`crate::protocols::acl_management::create::CreateAclBody`].
/// Auth: Admin or Initiator.
pub const TASK_ACL_CREATE_1_0: &str = "https://trusttasks.org/spec/vta/acl/create/1.0";

/// `spec/vta/acl/get/1.0` — retrieve a single entry. Payload:
/// [`crate::protocols::acl_management::get::GetAclBody`].
pub const TASK_ACL_GET_1_0: &str = "https://trusttasks.org/spec/vta/acl/get/1.0";

/// `spec/vta/acl/update/1.0` — patch role, label, or allowed contexts.
/// Payload: [`crate::protocols::acl_management::update::UpdateAclBody`].
/// Auth: Admin only.
pub const TASK_ACL_UPDATE_1_0: &str = "https://trusttasks.org/spec/vta/acl/update/1.0";

/// `spec/vta/acl/delete/1.0` — remove an entry. Payload:
/// [`crate::protocols::acl_management::delete::DeleteAclBody`].
/// Auth: Admin or Initiator.
pub const TASK_ACL_DELETE_1_0: &str = "https://trusttasks.org/spec/vta/acl/delete/1.0";

// ─── Contexts slice (spec/vta/contexts/*) ────────────────────────────────

/// `spec/vta/contexts/list/1.0` — list contexts visible to caller.
/// Payload: [`crate::protocols::context_management::list::ListContextsBody`]
/// (empty). Auth: any authenticated user.
pub const TASK_CONTEXTS_LIST_1_0: &str = "https://trusttasks.org/spec/vta/contexts/list/1.0";

/// `spec/vta/contexts/create/1.0` — create a new context. Payload:
/// [`crate::protocols::context_management::create::CreateContextBody`].
/// Auth: Super Admin only.
pub const TASK_CONTEXTS_CREATE_1_0: &str = "https://trusttasks.org/spec/vta/contexts/create/1.0";

/// `spec/vta/contexts/get/1.0` — retrieve a context by id. Payload:
/// [`crate::protocols::context_management::get::GetContextBody`].
pub const TASK_CONTEXTS_GET_1_0: &str = "https://trusttasks.org/spec/vta/contexts/get/1.0";

/// `spec/vta/contexts/update/1.0` — update name/did/description.
/// Payload: [`crate::protocols::context_management::update::UpdateContextBody`].
/// Auth: Super Admin only.
pub const TASK_CONTEXTS_UPDATE_1_0: &str = "https://trusttasks.org/spec/vta/contexts/update/1.0";

/// `spec/vta/contexts/update-did/1.0` — set the context's bound DID.
/// Payload:
/// [`crate::protocols::context_management::update_did::UpdateContextDidBody`].
/// Auth: Admin with context access.
pub const TASK_CONTEXTS_UPDATE_DID_1_0: &str =
    "https://trusttasks.org/spec/vta/contexts/update-did/1.0";

/// `spec/vta/contexts/preview-delete/1.0` — preview resources affected
/// by deletion. Payload:
/// [`crate::protocols::context_management::delete::DeleteContextPreviewBody`].
/// Auth: Super Admin only.
pub const TASK_CONTEXTS_PREVIEW_DELETE_1_0: &str =
    "https://trusttasks.org/spec/vta/contexts/preview-delete/1.0";

/// `spec/vta/contexts/delete/1.0` — delete a context and its
/// associated resources. Payload:
/// [`crate::protocols::context_management::delete::DeleteContextBody`].
/// Auth: Super Admin only.
pub const TASK_CONTEXTS_DELETE_1_0: &str = "https://trusttasks.org/spec/vta/contexts/delete/1.0";

// ─── Keys slice (spec/vta/keys/*) ────────────────────────────────────────

/// `spec/vta/keys/list/1.0` — list key records (paginated, filterable).
/// Payload: [`crate::protocols::key_management::list::ListKeysBody`].
pub const TASK_KEYS_LIST_1_0: &str = "https://trusttasks.org/spec/vta/keys/list/1.0";

/// `spec/vta/keys/create/1.0` — derive a new key from the active seed.
/// Payload: [`crate::protocols::key_management::create::CreateKeyBody`].
/// Auth: Admin.
pub const TASK_KEYS_CREATE_1_0: &str = "https://trusttasks.org/spec/vta/keys/create/1.0";

/// `spec/vta/keys/get/1.0` — retrieve a single key record.
/// Payload: [`crate::protocols::key_management::get::GetKeyBody`].
pub const TASK_KEYS_GET_1_0: &str = "https://trusttasks.org/spec/vta/keys/get/1.0";

/// `spec/vta/keys/rename/1.0` — rename a key's identifier.
/// Payload: [`crate::protocols::key_management::rename::RenameKeyBody`].
/// Auth: Admin.
pub const TASK_KEYS_RENAME_1_0: &str = "https://trusttasks.org/spec/vta/keys/rename/1.0";

/// `spec/vta/keys/revoke/1.0` — invalidate a key.
/// Payload: [`crate::protocols::key_management::revoke::RevokeKeyBody`].
/// Auth: Admin.
pub const TASK_KEYS_REVOKE_1_0: &str = "https://trusttasks.org/spec/vta/keys/revoke/1.0";

/// `spec/vta/keys/sign/1.0` — sign a base64url-encoded payload with a
/// stored key (raw-bytes signing oracle).
/// Payload: [`crate::protocols::key_management::sign::SignRequestBody`].
/// Auth: write (Application or higher).
pub const TASK_KEYS_SIGN_1_0: &str = "https://trusttasks.org/spec/vta/keys/sign/1.0";

// ─── Seeds slice (spec/vta/seeds/*) ──────────────────────────────────────

/// `spec/vta/seeds/list/1.0` — list all seed records.
/// Payload: [`crate::protocols::seed_management::list::ListSeedsBody`]
/// (empty). Auth: Admin.
pub const TASK_SEEDS_LIST_1_0: &str = "https://trusttasks.org/spec/vta/seeds/list/1.0";

/// `spec/vta/seeds/rotate/1.0` — rotate the active seed, optionally
/// supplying a new mnemonic.
/// Payload: [`crate::protocols::seed_management::rotate::RotateSeedBody`].
/// Auth: Admin.
pub const TASK_SEEDS_ROTATE_1_0: &str = "https://trusttasks.org/spec/vta/seeds/rotate/1.0";

/// `spec/vta/seeds/export-mnemonic/1.0` — one-shot BIP-39 mnemonic
/// export under `MnemonicExportGuard`. Was `/keys/{id}/secret` in
/// the legacy REST surface — relocated to the seeds slice because it
/// operates on the seed identifier, not an individual key.
/// Payload: [`crate::protocols::key_management::secret::GetKeySecretBody`].
/// Auth: Admin only. Zeroized on drop.
pub const TASK_SEEDS_EXPORT_MNEMONIC_1_0: &str =
    "https://trusttasks.org/spec/vta/seeds/export-mnemonic/1.0";

// ─── Future slices ───────────────────────────────────────────────────────
//
// audit, attestation, services, webvh, did-templates, passkey-vms,
// backup, config, discovery, management, join-requests, bootstrap.
// Keys import + wrapping-key defer to follow-on work (import has
// transport-unwrap complexity at the route boundary).
//
// Each slice ships in its own Phase 3 PR. The migration mapping table
// in docs/05-design-notes/trust-task-uri-registry.md enumerates the
// full target surface (~75 URIs).

/// Every URI registered in this module — handy for the dispatcher's
/// parity harness and for operator tooling that wants to enumerate
/// the VTA's wire surface programmatically.
pub const ALL_URIS: &[&str] = &[
    // Auth slice
    TASK_AUTH_CHALLENGE_1_0,
    TASK_AUTH_AUTHENTICATE_1_0,
    TASK_AUTH_REFRESH_1_0,
    TASK_AUTH_REVOKE_SESSION_1_0,
    TASK_AUTH_PASSKEY_LOGIN_START_1_0,
    TASK_AUTH_PASSKEY_LOGIN_FINISH_1_0,
    // ACL slice
    TASK_ACL_LIST_1_0,
    TASK_ACL_CREATE_1_0,
    TASK_ACL_GET_1_0,
    TASK_ACL_UPDATE_1_0,
    TASK_ACL_DELETE_1_0,
    // Contexts slice
    TASK_CONTEXTS_LIST_1_0,
    TASK_CONTEXTS_CREATE_1_0,
    TASK_CONTEXTS_GET_1_0,
    TASK_CONTEXTS_UPDATE_1_0,
    TASK_CONTEXTS_UPDATE_DID_1_0,
    TASK_CONTEXTS_PREVIEW_DELETE_1_0,
    TASK_CONTEXTS_DELETE_1_0,
    // Keys slice
    TASK_KEYS_LIST_1_0,
    TASK_KEYS_CREATE_1_0,
    TASK_KEYS_GET_1_0,
    TASK_KEYS_RENAME_1_0,
    TASK_KEYS_REVOKE_1_0,
    TASK_KEYS_SIGN_1_0,
    // Seeds slice
    TASK_SEEDS_LIST_1_0,
    TASK_SEEDS_ROTATE_1_0,
    TASK_SEEDS_EXPORT_MNEMONIC_1_0,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_uri_in_vta_namespace() {
        for uri in ALL_URIS {
            assert!(
                uri.starts_with("https://trusttasks.org/spec/vta/"),
                "VTA URI must be under /spec/vta/: {uri}"
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

    /// Every URI must round-trip through the framework's TypeUri
    /// deserialiser — the wire-format `type` field on a trust-task
    /// document goes through this path. Catches a regression where a
    /// future const is added that doesn't match the framework's
    /// canonical shape.
    #[test]
    fn every_uri_parses_as_framework_type_uri() {
        use std::str::FromStr;
        for uri in ALL_URIS {
            let parsed = trust_tasks_rs::TypeUri::from_str(uri);
            assert!(
                parsed.is_ok(),
                "URI must parse as framework TypeUri: {uri}, error: {:?}",
                parsed.err()
            );
            let parsed = parsed.unwrap();
            // Round-trip via Display must equal the input byte-for-byte.
            assert_eq!(
                parsed.to_string(),
                *uri,
                "URI must round-trip through TypeUri::Display unchanged"
            );
        }
    }
}
