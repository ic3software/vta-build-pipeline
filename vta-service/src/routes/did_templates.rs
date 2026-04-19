//! REST routes for DID templates (global + context scope).
//!
//! Global-scope writes (`POST`, `PUT`, `DELETE` under `/did-templates`)
//! gate on [`SuperAdminAuth`]; reads and render accept any authenticated
//! caller via [`AuthClaims`].
//!
//! Context-scope routes (`/contexts/{id}/did-templates/...`) use
//! [`AuthClaims`] for every handler and delegate authz to the operations
//! layer, which accepts super admin OR admin-with-context for writes,
//! and any caller with context access for reads.

use std::collections::HashMap;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use vta_sdk::did_templates::{DidTemplate, DidTemplateRecord, TemplateVars};

use crate::auth::{AuthClaims, SuperAdminAuth};
use crate::error::AppError;
use crate::operations;
use crate::server::AppState;

/// Response body for `GET /did-templates`.
#[derive(Debug, Serialize, Deserialize)]
pub struct ListDidTemplatesResponse {
    pub templates: Vec<DidTemplateRecord>,
}

/// Request body for `POST /did-templates/{name}/render`.
#[derive(Debug, Deserialize)]
pub struct RenderDidTemplateRequest {
    #[serde(default)]
    pub vars: HashMap<String, Value>,
}

/// Response body for `POST /did-templates/{name}/render`.
#[derive(Debug, Serialize)]
pub struct RenderDidTemplateResponse {
    pub document: Value,
}

/// `GET /did-templates` — list all global templates. Any authenticated caller.
pub async fn list_handler(
    auth: AuthClaims,
    State(state): State<AppState>,
) -> Result<Json<ListDidTemplatesResponse>, AppError> {
    let templates =
        operations::did_templates::list_global(&state.did_templates_ks, &auth, "rest").await?;
    Ok(Json(ListDidTemplatesResponse { templates }))
}

/// `POST /did-templates` — create a global template. Super admin only.
pub async fn create_handler(
    auth: SuperAdminAuth,
    State(state): State<AppState>,
    Json(template): Json<DidTemplate>,
) -> Result<(StatusCode, Json<DidTemplateRecord>), AppError> {
    let record = operations::did_templates::create_global(
        &state.did_templates_ks,
        &state.audit_ks,
        &auth.0,
        template,
        "rest",
    )
    .await?;
    Ok((StatusCode::CREATED, Json(record)))
}

/// `GET /did-templates/{name}` — fetch one global template. Any authed caller.
pub async fn get_handler(
    auth: AuthClaims,
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Json<DidTemplateRecord>, AppError> {
    let record =
        operations::did_templates::get_global(&state.did_templates_ks, &auth, &name, "rest")
            .await?;
    Ok(Json(record))
}

/// `PUT /did-templates/{name}` — replace a global template. Super admin only.
pub async fn update_handler(
    auth: SuperAdminAuth,
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(template): Json<DidTemplate>,
) -> Result<Json<DidTemplateRecord>, AppError> {
    let record = operations::did_templates::update_global(
        &state.did_templates_ks,
        &state.audit_ks,
        &auth.0,
        &name,
        template,
        "rest",
    )
    .await?;
    Ok(Json(record))
}

/// `DELETE /did-templates/{name}` — delete a global template. Super admin only.
pub async fn delete_handler(
    auth: SuperAdminAuth,
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<StatusCode, AppError> {
    operations::did_templates::delete_global(
        &state.did_templates_ks,
        &state.audit_ks,
        &auth.0,
        &name,
        "rest",
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /did-templates/{name}/render` — render a template with caller vars.
/// Any authenticated caller. Server injects ambient variables.
pub async fn render_handler(
    auth: AuthClaims,
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(req): Json<RenderDidTemplateRequest>,
) -> Result<Json<RenderDidTemplateResponse>, AppError> {
    let mut caller_vars = TemplateVars::new();
    for (k, v) in req.vars {
        caller_vars.insert(k, v);
    }

    let config = state.config.read().await.clone();
    let document = operations::did_templates::render_global(
        &state.did_templates_ks,
        &config,
        &auth,
        &name,
        caller_vars,
        "rest",
    )
    .await?;
    Ok(Json(RenderDidTemplateResponse { document }))
}

// ── Context-scoped handlers ──────────────────────────────────────────

/// `GET /contexts/{id}/did-templates` — list context-scoped templates.
pub async fn list_context_handler(
    auth: AuthClaims,
    State(state): State<AppState>,
    Path(context_id): Path<String>,
) -> Result<Json<ListDidTemplatesResponse>, AppError> {
    let templates = operations::did_templates::list_context(
        &state.did_templates_ks,
        &auth,
        &context_id,
        "rest",
    )
    .await?;
    Ok(Json(ListDidTemplatesResponse { templates }))
}

/// `POST /contexts/{id}/did-templates` — create a context-scoped template.
pub async fn create_context_handler(
    auth: AuthClaims,
    State(state): State<AppState>,
    Path(context_id): Path<String>,
    Json(template): Json<DidTemplate>,
) -> Result<(StatusCode, Json<DidTemplateRecord>), AppError> {
    let record = operations::did_templates::create_context(
        &state.did_templates_ks,
        &state.contexts_ks,
        &state.audit_ks,
        &auth,
        &context_id,
        template,
        "rest",
    )
    .await?;
    Ok((StatusCode::CREATED, Json(record)))
}

/// `GET /contexts/{id}/did-templates/{name}` — fetch one context template.
pub async fn get_context_handler(
    auth: AuthClaims,
    State(state): State<AppState>,
    Path((context_id, name)): Path<(String, String)>,
) -> Result<Json<DidTemplateRecord>, AppError> {
    let record = operations::did_templates::get_context(
        &state.did_templates_ks,
        &auth,
        &context_id,
        &name,
        "rest",
    )
    .await?;
    Ok(Json(record))
}

/// `PUT /contexts/{id}/did-templates/{name}` — replace a context template.
pub async fn update_context_handler(
    auth: AuthClaims,
    State(state): State<AppState>,
    Path((context_id, name)): Path<(String, String)>,
    Json(template): Json<DidTemplate>,
) -> Result<Json<DidTemplateRecord>, AppError> {
    let record = operations::did_templates::update_context(
        &state.did_templates_ks,
        &state.audit_ks,
        &auth,
        &context_id,
        &name,
        template,
        "rest",
    )
    .await?;
    Ok(Json(record))
}

/// `DELETE /contexts/{id}/did-templates/{name}` — remove a context template.
pub async fn delete_context_handler(
    auth: AuthClaims,
    State(state): State<AppState>,
    Path((context_id, name)): Path<(String, String)>,
) -> Result<StatusCode, AppError> {
    operations::did_templates::delete_context(
        &state.did_templates_ks,
        &state.audit_ks,
        &auth,
        &context_id,
        &name,
        "rest",
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /contexts/{id}/did-templates/{name}/render` — render a context template.
pub async fn render_context_handler(
    auth: AuthClaims,
    State(state): State<AppState>,
    Path((context_id, name)): Path<(String, String)>,
    Json(req): Json<RenderDidTemplateRequest>,
) -> Result<Json<RenderDidTemplateResponse>, AppError> {
    let mut caller_vars = TemplateVars::new();
    for (k, v) in req.vars {
        caller_vars.insert(k, v);
    }

    let config = state.config.read().await.clone();
    let document = operations::did_templates::render_context(
        &state.did_templates_ks,
        &state.contexts_ks,
        &config,
        &auth,
        &context_id,
        &name,
        caller_vars,
        "rest",
    )
    .await?;
    Ok(Json(RenderDidTemplateResponse { document }))
}
