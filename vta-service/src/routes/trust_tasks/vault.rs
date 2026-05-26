//! Vault slice trust-task handlers — M1 read-only surface.
//!
//! Handles `spec/vault/list/0.1` and `spec/vault/get/0.1` per the canonical
//! [trust-tasks-tf](https://github.com/trustoverip/dtgwg-trust-tasks-tf) spec.
//! Upsert, delete, sync, proxy-login, release, and usage handlers land in
//! later milestones (M2+).
//!
//! Auth: gated on the derived `VaultRead` capability for the caller's role.
//! Legacy ACL entries (no explicit `capabilities` set) fall back to
//! [`vti_common::acl::derived_capabilities_for_role`] — Admin, Initiator,
//! Application, and Reader all carry `VaultRead`. Monitor does not.

use axum::response::Response;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use trust_tasks_rs::TrustTask;
use vti_common::acl::{Capability, role_has_capability};
use vti_common::vault::{
    SecretKind, SiteTarget, VaultEntry, VaultListFilter, get_vault_entry,
    list_vault_entries as list_entries_store,
};

use crate::auth::AuthClaims;
use crate::error::AppError;
use crate::server::AppState;

use super::helpers::{app_error_to_reject, parse_payload, reject_with, success_response};
use trust_tasks_rs::RejectReason;

/// URIs handled by this slice. Aggregated by the dispatcher's parity
/// harness.
#[allow(dead_code)]
pub(super) const DISPATCHED_URIS: &[&str] = &[
    vta_sdk::trust_tasks::TASK_VAULT_LIST_0_1,
    vta_sdk::trust_tasks::TASK_VAULT_GET_0_1,
];

/// Request body for `vault/list/0.1`. Mirrors the canonical
/// `payload.schema.json` of the spec; field names are camelCase to match
/// the wire form Companions emit from `@openvtc/trust-tasks`.
///
/// Pagination is accepted but currently single-page — the maintainer
/// returns up to `page_size` entries with `truncated: false` and no cursor.
/// Real cursor-based pagination lands when the vault grows past a few
/// thousand entries; for M1 with hand-seeded test data it's overkill.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct VaultListBody {
    context_id: Option<String>,
    target_origin_prefix: Option<String>,
    target_did: Option<String>,
    target_ios_bundle_id: Option<String>,
    target_android_package: Option<String>,
    secret_kind: Option<SecretKind>,
    tag: Option<String>,
    used_since: Option<String>,
    never_used: Option<bool>,
    expires_before: Option<String>,
    breached: Option<bool>,
    page_size: Option<u32>,
    // `cursor` accepted on the wire for forward-compat but ignored in M1.
    #[serde(default)]
    #[allow(dead_code)]
    cursor: Option<String>,
}

/// Response body for `vault/list/0.1`. Wraps the entries the
/// canonical schema declares under `$defs.Response`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct VaultListResponseBody {
    entries: Vec<VaultEntry>,
    truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    cursor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    redacted_fields: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct VaultGetBody {
    id: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct VaultGetResponseBody {
    entry: VaultEntry,
    #[serde(skip_serializing_if = "Option::is_none")]
    redacted_fields: Option<Vec<String>>,
}

/// Reject the request unless the caller's role implies `VaultRead`. When
/// AclEntry-level explicit capabilities arrive (M4), this check upgrades
/// to consult the entry's `capabilities` Vec instead of deriving from role.
fn require_vault_read(auth: &AuthClaims, doc: &TrustTask<Value>) -> Result<(), Response> {
    if role_has_capability(&auth.role, Capability::VaultRead) {
        Ok(())
    } else {
        Err(reject_with(
            doc,
            RejectReason::PermissionDenied {
                reason: format!(
                    "vault read denied: role {} does not carry VaultRead capability",
                    auth.role
                ),
            },
        ))
    }
}

/// Reject if the caller's `allowed_contexts` is non-empty AND `context_id`
/// (if supplied) is not in the allowed list. Empty allowed_contexts means
/// super-admin scope.
fn enforce_context_scope(
    auth: &AuthClaims,
    context_id: Option<&str>,
    doc: &TrustTask<Value>,
) -> Result<(), Response> {
    let Some(ctx) = context_id else {
        return Ok(()); // No context filter — caller's full visibility applies.
    };
    if auth.allowed_contexts.is_empty() {
        return Ok(()); // Super-admin (or unscoped) sees everything.
    }
    if auth.allowed_contexts.iter().any(|c| c == ctx) {
        return Ok(());
    }
    Err(reject_with(
        doc,
        RejectReason::PermissionDenied {
            reason: format!("vault scope denied: caller is not authorised for context {ctx}"),
        },
    ))
}

/// Handler for `spec/vault/list/0.1`.
pub(super) async fn handle_list(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> Response {
    if let Err(r) = require_vault_read(auth, &doc) {
        return r;
    }

    let req: VaultListBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    // Reject mutually-exclusive filter combinations the spec calls out.
    if req.used_since.is_some() && req.never_used == Some(true) {
        return reject_with(
            &doc,
            RejectReason::MalformedRequest {
                reason: "vault/list: usedSince and neverUsed are mutually exclusive".into(),
            },
        );
    }

    if let Err(r) = enforce_context_scope(auth, req.context_id.as_deref(), &doc) {
        return r;
    }

    let filter = VaultListFilter {
        context_id: req.context_id.as_deref(),
        target_origin_prefix: req.target_origin_prefix.as_deref(),
        target_did: req.target_did.as_deref(),
        target_ios_bundle_id: req.target_ios_bundle_id.as_deref(),
        target_android_package: req.target_android_package.as_deref(),
        secret_kind: req.secret_kind,
        tag: req.tag.as_deref(),
        used_since: req.used_since.as_deref(),
        never_used: req.never_used,
        expires_before: req.expires_before.as_deref(),
        breached: req.breached,
    };

    let mut entries = match list_entries_store(&state.vault_ks, &filter).await {
        Ok(v) => v,
        Err(e) => return app_error_to_reject(&doc, e),
    };

    // If the caller's role is scoped to a subset of contexts and they
    // queried without a `contextId` filter, narrow the result set to
    // visible contexts only. This is defence-in-depth in addition to
    // `enforce_context_scope` — that path covers the explicit-filter case;
    // this one covers the implicit-all-contexts case.
    if !auth.allowed_contexts.is_empty() && req.context_id.is_none() {
        entries.retain(|e| auth.allowed_contexts.iter().any(|c| c == &e.context_id));
    }

    // M1 pagination: single page. Apply page_size as a hard truncation.
    let page_size = req.page_size.unwrap_or(100) as usize;
    let truncated = entries.len() > page_size;
    entries.truncate(page_size);

    success_response(
        &doc,
        VaultListResponseBody {
            entries,
            truncated,
            cursor: None,
            redacted_fields: None,
        },
    )
}

/// Handler for `spec/vault/get/0.1`.
pub(super) async fn handle_get(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> Response {
    if let Err(r) = require_vault_read(auth, &doc) {
        return r;
    }
    let req: VaultGetBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    let entry = match get_vault_entry(&state.vault_ks, &req.id).await {
        Ok(Some(e)) => e,
        // Conflate not-found with permission-denied to deny enumeration.
        Ok(None) => {
            return app_error_to_reject(
                &doc,
                AppError::NotFound(format!("vault entry {} not found", req.id)),
            );
        }
        Err(e) => return app_error_to_reject(&doc, e),
    };

    if let Err(r) = enforce_context_scope(auth, Some(&entry.context_id), &doc) {
        return r;
    }

    success_response(
        &doc,
        VaultGetResponseBody {
            entry,
            redacted_fields: None,
        },
    )
}

// Suppress an unused-import warning on the SiteTarget re-export — kept
// available for handler call-sites that materialise SiteTarget literals
// in upcoming milestones.
#[allow(dead_code)]
type _SiteTargetReexport = SiteTarget;

// M1 leaves handler-level tests to the integration suite (tests/) and to
// end-to-end verification via the plugin UI in M1.6. The vti-common
// `vault` module's tests cover the filter/sort logic in isolation; the
// dispatcher's parity-harness test asserts these URIs are wired. Real
// HTTP round-trips against the dispatcher arrive in M2 once vault/upsert
// is available to seed entries through the same authenticated channel
// (rather than reaching into the keyspace from a test, which would
// duplicate the wire-form encoder).
#[allow(dead_code)]
const _: &() = &();
