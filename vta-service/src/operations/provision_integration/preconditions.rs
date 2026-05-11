//! Authorization + request-shape checks that run before the VTA
//! mutates any state. Failing here leaves the store untouched — a typo
//! in a template name or a missing context is surfaced with a concrete
//! operator remediation before we mint keys or write ACL rows.

use std::collections::BTreeMap;

use serde_json::Value;

use crate::auth::AuthClaims;
use crate::error::AppError;
use crate::store::KeyspaceHandle;
use vta_sdk::provision_integration::{BootstrapAsk, DidTemplateRef, VerifiedBootstrapRequest};

use super::ProvisionIntegrationDeps;

/// Ensure the target `context` exists, optionally creating it
/// inline when `create_context` is set. Centralised here so REST,
/// DIDComm, and the offline CLI all enforce the same semantics:
///
/// - Context exists → returns `Ok(false)` (idempotent, no-op).
/// - Context missing + `create_context: false` → `AppError::NotFound`
///   with the existing precondition message.
/// - Context missing + `create_context: true` → calls
///   [`crate::operations::contexts::create_context`], which itself
///   checks `auth.require_super_admin()`. Context-admin callers
///   land here and surface as `AppError::Forbidden`. Returns
///   `Ok(true)` on success so callers can populate
///   `summary.context_created`.
///
/// Auth concentration: the super-admin gate lives inside
/// `operations::contexts::create_context` exclusively. We don't
/// re-check it here so the boundary stays in one place.
pub async fn ensure_target_context_or_create(
    contexts_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    context: &str,
    create_context: bool,
) -> Result<bool, AppError> {
    if crate::contexts::get_context(contexts_ks, context)
        .await?
        .is_some()
    {
        return Ok(false);
    }
    if !create_context {
        return Err(AppError::NotFound(format!(
            "context '{context}' is not registered on this VTA — create it first via \
             'vta contexts create --id {context}' (offline) or 'pnm contexts create' (online), \
             or pass '--create-context' to provision it inline"
        )));
    }
    crate::operations::contexts::create_context(
        contexts_ks,
        auth,
        context,
        context.to_string(),
        None,
        "provision-integration",
    )
    .await?;
    Ok(true)
}

pub(super) async fn preconditions(
    state: &ProvisionIntegrationDeps,
    auth: &AuthClaims,
    context: &str,
    request: &VerifiedBootstrapRequest,
) -> Result<(), AppError> {
    auth.require_admin()?;
    auth.require_context(context)?;

    // Context must exist.
    if crate::contexts::get_context(&state.contexts_ks, context)
        .await?
        .is_none()
    {
        return Err(AppError::NotFound(format!(
            "context '{context}' is not registered on this VTA — create it first via \
             'vta context create --id {context}' (offline) or 'pnm contexts create' (online), \
             or pass '--create-context' to provision it inline"
        )));
    }

    // If the request carries a context hint, it must agree with the
    // chosen context. Silently normalizing hides operator bugs.
    let hint = match request.ask() {
        BootstrapAsk::TemplateBootstrap(ask) => ask.context_hint.as_deref(),
        BootstrapAsk::AdminRotation(ask) => ask.context_hint.as_deref(),
    };
    if let Some(hint) = hint
        && hint != context
    {
        return Err(AppError::Validation(format!(
            "request contextHint '{hint}' does not match provisioning context '{context}'"
        )));
    }

    // Template must be registered. Resolve order matches template-render:
    // context scope → global → built-in. Built-ins always resolve via the
    // SDK's embedded loader; only operator-uploaded templates need a
    // stored record.
    //
    // For TemplateBootstrap: integration template is required, admin
    // template is optional.
    // For AdminRotation: there is no integration template; admin
    // template is required.
    let (integration_template_name, admin_template_name): (Option<String>, Option<String>) =
        match request.ask() {
            BootstrapAsk::TemplateBootstrap(ask) => (
                Some(ask.template.name.clone()),
                ask.admin_template.as_ref().map(|t| t.name.clone()),
            ),
            BootstrapAsk::AdminRotation(ask) => (None, Some(ask.admin_template.name.clone())),
        };

    if let Some(template_name) = integration_template_name.as_deref() {
        let template_registered = crate::did_templates::get_context_template(
            &state.did_templates_ks,
            context,
            template_name,
        )
        .await?
        .is_some()
            || crate::did_templates::get_global_template(&state.did_templates_ks, template_name)
                .await?
                .is_some()
            || vta_sdk::did_templates::load_embedded(template_name).is_ok();
        if !template_registered {
            return Err(AppError::Validation(format!(
                "template '{template_name}' is not registered on this VTA. Register it via \
                 'pnm did-templates create {template_name} --file <path>' then retry"
            )));
        }
    }

    // Admin-template registration check. For AdminRotation this is the
    // primary template; for TemplateBootstrap it's the optional rollover
    // template. Built-ins (`vta-admin`) always resolve via the SDK's
    // embedded loader; only operator-uploaded templates need a stored
    // record.
    if let Some(name) = admin_template_name {
        let registered =
            crate::did_templates::get_context_template(&state.did_templates_ks, context, &name)
                .await?
                .is_some()
                || crate::did_templates::get_global_template(&state.did_templates_ks, &name)
                    .await?
                    .is_some()
                || vta_sdk::did_templates::load_embedded(&name).is_ok();
        if !registered {
            return Err(AppError::Validation(format!(
                "admin template '{name}' is not registered on this VTA. Register it via \
                 'pnm did-templates create {name} --file <path>' then retry, or use the \
                 built-in 'vta-admin' template."
            )));
        }
    }

    Ok(())
}

/// Extract the integration template name + variables from a
/// `TemplateBootstrap` ask. Returns `None` for `AdminRotation` (which
/// has no integration template — caller must dispatch on the variant
/// before reaching the integration mint).
pub(super) fn extract_template(
    ask: &BootstrapAsk,
) -> Result<Option<(String, BTreeMap<String, Value>)>, AppError> {
    match ask {
        BootstrapAsk::TemplateBootstrap(ask) => {
            Ok(Some((ask.template.name.clone(), ask.template.vars.clone())))
        }
        BootstrapAsk::AdminRotation(_) => Ok(None),
    }
}

/// Extract the admin-template reference from an `ask`.
///
/// - `TemplateBootstrap` → `Some(_)` only when `admin_template` is set
///   (operator opted into rollover).
/// - `AdminRotation` → always `Some(_)` (admin template is required).
pub(super) fn extract_admin_template(ask: &BootstrapAsk) -> Option<DidTemplateRef> {
    match ask {
        BootstrapAsk::TemplateBootstrap(ask) => ask.admin_template.clone(),
        BootstrapAsk::AdminRotation(ask) => Some(ask.admin_template.clone()),
    }
}
