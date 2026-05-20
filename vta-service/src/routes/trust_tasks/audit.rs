//! Audit slice trust-task handlers.
//!
//! Auth: Admin for list-logs and get-retention; Super-Admin for
//! update-retention (enforced inside the operation function).

use axum::response::Response;
use serde_json::Value;
use trust_tasks_rs::TrustTask;
use vta_sdk::protocols::audit_management::list::ListAuditLogsBody;
use vta_sdk::protocols::audit_management::retention::{GetRetentionBody, UpdateRetentionBody};

use crate::auth::AuthClaims;
use crate::operations;
use crate::server::AppState;

use super::helpers::{TRANSPORT_TRUST_TASK, app_error_to_reject, parse_payload, success_response};

/// URIs handled by this slice. Aggregated by the dispatcher's parity
/// harness — see the feature-gating convention in
/// `docs/05-design-notes/trust-task-feature-gating.md`.
#[allow(dead_code)] // consumed by the dispatcher's test-only parity harness
pub(super) const DISPATCHED_URIS: &[&str] = &[
    vta_sdk::trust_tasks::TASK_AUDIT_LIST_LOGS_1_0,
    vta_sdk::trust_tasks::TASK_AUDIT_GET_RETENTION_1_0,
    vta_sdk::trust_tasks::TASK_AUDIT_UPDATE_RETENTION_1_0,
];

/// Handler for `spec/vta/audit/list-logs/1.0`. Admin only.
pub(super) async fn handle_list_logs(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> Response {
    let req: ListAuditLogsBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match operations::audit::list_audit_logs(&state.audit_ks, auth, &req, TRANSPORT_TRUST_TASK)
        .await
    {
        Ok(body) => success_response(&doc, body),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

/// Handler for `spec/vta/audit/get-retention/1.0`. Admin only.
pub(super) async fn handle_get_retention(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> Response {
    let _req: GetRetentionBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match operations::audit::get_retention(&state.config, auth, TRANSPORT_TRUST_TASK).await {
        Ok(body) => success_response(&doc, body),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

/// Handler for `spec/vta/audit/update-retention/1.0`. Super-admin only.
pub(super) async fn handle_update_retention(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> Response {
    let req: UpdateRetentionBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match operations::audit::update_retention(
        &state.config,
        &state.audit_ks,
        auth,
        req.retention_days,
        TRANSPORT_TRUST_TASK,
    )
    .await
    {
        Ok(body) => success_response(&doc, body),
        Err(e) => app_error_to_reject(&doc, e),
    }
}
