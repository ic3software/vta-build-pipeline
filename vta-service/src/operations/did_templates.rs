//! DID template CRUD + render operations.
//!
//! Phase 2: **global** scope only. All writes gated on super admin
//! (Admin role with no `allowed_contexts`). Reads allowed for any
//! authenticated caller — templates are advisory shapes, not secrets.
//!
//! Context-scoped templates (Phase 3) will follow the same pattern with
//! an additional `context_id` in the key and a context-admin authz gate.

use chrono::Utc;
use serde_json::Value;
use tracing::info;

use vta_sdk::did_templates::{DidTemplate, DidTemplateRecord, Scope, TemplateVars};

use crate::audit;
use crate::auth::AuthClaims;
use crate::did_templates as store;
use crate::error::AppError;
use crate::store::KeyspaceHandle;

/// Create a new global template. Super admin only.
///
/// Rejects duplicates — updates must go through [`update_global`].
pub async fn create_global(
    templates_ks: &KeyspaceHandle,
    audit_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    template: DidTemplate,
    channel: &str,
) -> Result<DidTemplateRecord, AppError> {
    auth.require_super_admin()?;

    // The SDK validator already ran in `DidTemplate::from_json` if the
    // caller built it through the parse path; re-run it here to defend
    // against programmatic construction with invalid shapes.
    template
        .validate()
        .map_err(|e| AppError::Validation(e.to_string()))?;

    if store::get_global_template(templates_ks, &template.name)
        .await?
        .is_some()
    {
        return Err(AppError::Conflict(format!(
            "template already exists: {}",
            template.name
        )));
    }

    let now = unix_secs();
    let record = DidTemplateRecord {
        template,
        scope: Scope::Global,
        created_at: now,
        updated_at: now,
        created_by: auth.did.clone(),
    };

    store::store_global_template(templates_ks, &record).await?;
    let _ = audit::record(
        audit_ks,
        "did_template.created",
        &auth.did,
        Some(&record.template.name),
        "success",
        Some(channel),
        None,
    )
    .await;

    info!(channel, name = %record.template.name, "did template created");
    Ok(record)
}

/// Update an existing global template. Super admin only.
///
/// `created_at` and `created_by` are preserved from the stored record;
/// `updated_at` advances to now. The entire [`DidTemplate`] body is
/// replaced — partial updates go through delete + create.
pub async fn update_global(
    templates_ks: &KeyspaceHandle,
    audit_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    name: &str,
    template: DidTemplate,
    channel: &str,
) -> Result<DidTemplateRecord, AppError> {
    auth.require_super_admin()?;

    if template.name != name {
        return Err(AppError::Validation(format!(
            "template name in body ('{}') does not match path ('{name}')",
            template.name
        )));
    }

    template
        .validate()
        .map_err(|e| AppError::Validation(e.to_string()))?;

    let existing = store::get_global_template(templates_ks, name)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("template not found: {name}")))?;

    let record = DidTemplateRecord {
        template,
        scope: Scope::Global,
        created_at: existing.created_at,
        updated_at: unix_secs(),
        created_by: existing.created_by,
    };

    store::store_global_template(templates_ks, &record).await?;
    let _ = audit::record(
        audit_ks,
        "did_template.updated",
        &auth.did,
        Some(&record.template.name),
        "success",
        Some(channel),
        None,
    )
    .await;

    info!(channel, name = %record.template.name, "did template updated");
    Ok(record)
}

/// Fetch a single global template by name.
///
/// Open to any authenticated caller — templates don't carry secrets and
/// any admin or manager may want to preview one.
pub async fn get_global(
    templates_ks: &KeyspaceHandle,
    _auth: &AuthClaims,
    name: &str,
    _channel: &str,
) -> Result<DidTemplateRecord, AppError> {
    store::get_global_template(templates_ks, name)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("template not found: {name}")))
}

/// List every stored global template.
///
/// Open to any authenticated caller. Return is sorted by name.
pub async fn list_global(
    templates_ks: &KeyspaceHandle,
    _auth: &AuthClaims,
    _channel: &str,
) -> Result<Vec<DidTemplateRecord>, AppError> {
    store::list_global_templates(templates_ks).await
}

/// Delete a global template. Super admin only.
pub async fn delete_global(
    templates_ks: &KeyspaceHandle,
    audit_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    name: &str,
    channel: &str,
) -> Result<(), AppError> {
    auth.require_super_admin()?;

    if store::get_global_template(templates_ks, name)
        .await?
        .is_none()
    {
        return Err(AppError::NotFound(format!("template not found: {name}")));
    }

    store::delete_global_template(templates_ks, name).await?;
    let _ = audit::record(
        audit_ks,
        "did_template.deleted",
        &auth.did,
        Some(name),
        "success",
        Some(channel),
        None,
    )
    .await;

    info!(channel, name, "did template deleted");
    Ok(())
}

/// Render a stored global template with caller-supplied variables.
///
/// Renders never audit — they're read-only and frequent. Ambient variables
/// the server knows about are injected automatically (`VTA_DID`, `VTA_URL`,
/// `NOW`). The caller supplies everything else.
pub async fn render_global(
    templates_ks: &KeyspaceHandle,
    config: &crate::config::AppConfig,
    _auth: &AuthClaims,
    name: &str,
    caller_vars: TemplateVars,
    _channel: &str,
) -> Result<Value, AppError> {
    let record = store::get_global_template(templates_ks, name)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("template not found: {name}")))?;

    let mut vars = ambient_vars(config);
    vars.extend(caller_vars);

    record
        .template
        .render(&vars)
        .map_err(|e| AppError::Validation(e.to_string()))
}

/// Build the ambient variable set the server can fill in without caller input.
///
/// Phase 4 extends this with DID-creation-flow vars (DID, SIGNING_KEY_MB,
/// KA_KEY_MB, CONTEXT_ID, CONTEXT_DID). Phase 2 only has config-level vars.
fn ambient_vars(config: &crate::config::AppConfig) -> TemplateVars {
    let mut vars = TemplateVars::new();
    if let Some(vta_did) = config.vta_did.as_deref() {
        vars.insert_string("VTA_DID", vta_did);
    }
    if let Some(vta_url) = config.public_url.as_deref() {
        vars.insert_string("VTA_URL", vta_url);
    }
    vars.insert_string("NOW", Utc::now().to_rfc3339());
    vars
}

fn unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
