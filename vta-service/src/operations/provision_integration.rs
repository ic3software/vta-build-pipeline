//! `provision-integration` — shared library function driven by both the
//! VTA CLI (`vta bootstrap provision-integration`) and the HTTP endpoint
//! (`POST /bootstrap/provision-integration`).
//!
//! See `docs/bootstrap-provision-integration.md` for the full design.
//!
//! Flow, at the broadest level:
//! 1. Precondition checks — caller is admin of the target context;
//!    context exists; template registered.
//! 2. Orchestrate key minting + template rendering via
//!    [`super::did_webvh::create_did_webvh`] — it already handles the
//!    mint-keys, render-template, build-log, publish-if-not-serverless
//!    flow end-to-end.
//! 3. Read back the minted private key material via
//!    [`super::keys::get_key_secret`] for inclusion in the sealed bundle.
//! 4. Register the holder (`client_did`) as admin of the target context
//!    via [`super::acl::create_acl`].
//! 5. Build + sign a [`VtaAuthorizationCredential`] using the VTA's
//!    `{vta_did}#key-0` signing key (see [`load_vta_vc_issuance_secret`]).
//! 6. Assemble the [`TemplateBootstrapPayload`] and seal it to the
//!    holder's X25519 (derived from `client_did`) via
//!    `sealed_transfer::seal_payload`. Producer assertion is
//!    `DidSigned` by `{vta_did}#sealed-transfer-0` (a purpose-specific
//!    key, distinct from `#key-0`) unless the caller overrides to
//!    `PinnedOnly` via [`AssertionMode`] (dev-only escape hatch).
//! 7. Armor and return, plus a summary for the CLI/HTTP response.
//!
//! Everything persistent (admin ACL row, minted key records, webvh log
//! entry) lands atomically as part of the `create_did_webvh` +
//! `create_acl` calls — the sealed bundle is derived from that state
//! rather than being a separate source of truth.

use std::collections::BTreeMap;
use std::sync::Arc;

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use affinidi_secrets_resolver::secrets::Secret;
use chrono::Duration;
use ed25519_dalek::{Signer as Ed25519Signer, SigningKey};
use serde_json::Value;
use tokio::sync::RwLock;
use tracing::info;

use crate::acl::Role;
use crate::auth::AuthClaims;
use crate::config::AppConfig;
use crate::didcomm_bridge::DIDCommBridge;
use crate::error::AppError;
use crate::keys::seed_store::SeedStore;
use crate::sealed_nonce_store::PersistentNonceStore;
use crate::server::AppState;
use crate::store::KeyspaceHandle;
use vta_sdk::did_key::decode_private_key_multibase;
use vta_sdk::did_templates::TemplateVars;
use vta_sdk::provision_integration::{
    AdminOfClaim, BootstrapAsk, DidTemplateRef, OperatorOfClaim, VerifiedBootstrapRequest,
    VtaAuthorizationClaim,
    credential::{VtaAuthorizationParams, issue_vta_authorization_credential},
};
use vta_sdk::sealed_transfer::{
    AssertionProof, DidSignedAssertion, ProducerAssertion, SealedPayloadV1, armor, bundle_digest,
    seal_payload,
    template_bootstrap::{
        DidKeyMaterial, KeyPair, TemplateBootstrapConfig, TemplateBootstrapPayload, TemplateOutput,
        VtaTrustBundle,
    },
};

/// How the producer assertion on the returned sealed bundle should be
/// constructed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum AssertionMode {
    /// Sign the producer assertion with the VTA's purpose-specific
    /// `{vta_did}#sealed-transfer-0` key. Default for production.
    /// See [`load_vta_sealed_transfer_secret`].
    #[default]
    DidSigned,
    /// No in-band signature — consumer relies purely on the out-of-band
    /// digest to anchor trust. Dev/test escape hatch, not for
    /// production flows.
    PinnedOnly,
}

/// Cloned subset of every keystore + handle [`provision_integration`]
/// needs. Both the REST [`AppState`] and the DIDComm
/// [`crate::messaging::router::VtaState`] expose the underlying handles
/// (all `Clone` and Arc-backed); this struct lets the library function
/// be called from either transport without taking on a
/// transport-specific `*State` dependency. Construction is cheap — every
/// field is `Clone` and Arc-shared, so cloning is two pointer bumps per
/// keyspace.
#[derive(Clone)]
pub struct ProvisionIntegrationDeps {
    pub keys_ks: KeyspaceHandle,
    pub acl_ks: KeyspaceHandle,
    pub audit_ks: KeyspaceHandle,
    pub contexts_ks: KeyspaceHandle,
    pub did_templates_ks: KeyspaceHandle,
    pub imported_ks: KeyspaceHandle,
    pub webvh_ks: KeyspaceHandle,
    /// Sealed-bundle nonce store, for replay protection.
    pub sealed_nonces_ks: KeyspaceHandle,
    pub seed_store: Arc<dyn SeedStore>,
    pub config: Arc<RwLock<AppConfig>>,
    pub did_resolver: Option<DIDCacheClient>,
    pub didcomm_bridge: Arc<DIDCommBridge>,
}

impl From<&AppState> for ProvisionIntegrationDeps {
    fn from(state: &AppState) -> Self {
        Self {
            keys_ks: state.keys_ks.clone(),
            acl_ks: state.acl_ks.clone(),
            audit_ks: state.audit_ks.clone(),
            contexts_ks: state.contexts_ks.clone(),
            did_templates_ks: state.did_templates_ks.clone(),
            imported_ks: state.imported_ks.clone(),
            webvh_ks: state.webvh_ks.clone(),
            sealed_nonces_ks: state.sealed_nonces_ks.clone(),
            seed_store: state.seed_store.clone(),
            config: state.config.clone(),
            did_resolver: state.did_resolver.clone(),
            didcomm_bridge: state.didcomm_bridge.clone(),
        }
    }
}

/// Caller-supplied inputs to [`provision_integration`].
pub struct ProvisionIntegrationParams {
    pub request: VerifiedBootstrapRequest,
    /// The context the integration will live in. May be explicit (from
    /// an operator `--context` flag) or match the `contextHint` on the
    /// request. If both are present and disagree, the caller should
    /// reject before calling us — we don't silently normalize.
    pub context: String,
    /// See [`AssertionMode`].
    pub assertion_mode: AssertionMode,
    /// Override for the VC's `validUntil` window. Defaults to 1 hour
    /// per [`DEFAULT_VALIDITY`].
    pub vc_validity: Option<Duration>,
}

/// Output of [`provision_integration`] — the armored bundle plus the
/// out-of-band digest the operator communicates to the integration's
/// operator, plus a small summary for CLI display / HTTP response.
pub struct ProvisionIntegrationOutput {
    pub armored: String,
    pub digest: String,
    pub summary: ProvisionSummary,
}

#[derive(Debug)]
pub struct ProvisionSummary {
    /// Ephemeral DID that signed the VP and opens the sealed bundle.
    pub client_did: String,
    /// Long-term admin DID — `client_did` when no rollover, or the
    /// VTA-minted DID when the request carried an `adminTemplate`.
    pub admin_did: String,
    /// True when the VTA minted a fresh long-term admin DID for this
    /// provisioning (i.e. `adminTemplate` was present in the VP).
    pub admin_rolled_over: bool,
    pub integration_did: String,
    pub template_name: String,
    pub template_kind: String,
    /// Name of the admin template, when one was requested.
    pub admin_template_name: Option<String>,
    pub bundle_id_hex: String,
    /// Number of minted secrets in the payload — at least 1
    /// (integration). +1 when the admin DID was minted by the VTA.
    pub secret_count: usize,
    /// Number of template-emitted side outputs (1 `WebvhLog` for now).
    pub output_count: usize,
    /// Resolved id of the registered webvh hosting server the VTA
    /// published the integration's `did.jsonl` to. `None` when the
    /// integration is self-hosted (no `WEBVH_SERVER` template var, or
    /// it was explicitly null).
    pub webvh_server_id: Option<String>,
}

/// Main entry point. See module docs for the flow.
pub async fn provision_integration(
    state: &ProvisionIntegrationDeps,
    auth: &AuthClaims,
    params: ProvisionIntegrationParams,
) -> Result<ProvisionIntegrationOutput, AppError> {
    let ProvisionIntegrationParams {
        request,
        context,
        assertion_mode,
        vc_validity,
    } = params;

    let client_did = request.holder().to_string();
    let bundle_id = request
        .decode_nonce()
        .map_err(|e| AppError::Validation(format!("bootstrap request nonce decode: {e}")))?;
    let client_x25519_pub = request
        .decode_client_x25519_pub()
        .map_err(|e| AppError::Validation(format!("bootstrap request X25519 derivation: {e}")))?;

    // ── 1. Preconditions ────────────────────────────────────────────
    preconditions(state, auth, &context, &request).await?;

    // ── 2. Extract templates + vars from the ask ────────────────────
    let (template_name, mut template_vars) = extract_template(request.ask())?;
    let admin_template_ref = extract_admin_template(request.ask());

    // ── 3. Mint + render + publish via create_did_webvh ─────────────
    //
    // Templates ship with a `URL` required var that becomes the
    // integration's own service endpoint inside the rendered DID
    // document (mediator's DIDComm endpoint, webvh hosting URL, etc.).
    // It is *content* of the DID document, separate from where the
    // `did.jsonl` log itself gets published.
    //
    // Publication target is selected by the optional `WEBVH_SERVER`
    // template var:
    //
    //   WEBVH_SERVER absent or null → serverless mode (VTA does not
    //     publish; the integration self-hosts at the URL above).
    //   WEBVH_SERVER set to a registered server id → VTA publishes
    //     `did.jsonl` to that server via its WebVHHosting endpoint.
    //
    // The id is validated against the registered-server catalogue
    // before any state mutation so a typo or stale id fails fast,
    // before key minting writes anything.
    //
    // `URL` is optional at this layer — templates that need it declare
    // it in `requiredVars` and the renderer enforces presence. Keeping
    // it mandatory here would block templates (e.g. non-webvh
    // integrations, tests, internal tooling) that legitimately don't
    // ship a URL as document content.
    let integration_url = template_vars
        .get("URL")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let webvh_server_id = resolve_webvh_server(&template_vars, &state.webvh_ks).await?;

    // Optional `WEBVH_PATH` template var: when the webvh server should
    // allocate a specific path (rather than letting the server pick),
    // the operator sets it in `mediator_template_vars`. Removed from the
    // map so the template renderer doesn't also see it — it is transport
    // metadata, not document content.
    let webvh_path = take_webvh_path(&mut template_vars)?;

    // Decide whether the minted DID should become the context's primary
    // DID. First-integration wins: when the context has no DID yet, bind
    // the newly-minted one so downstream operations (fetch_did_secrets_bundle,
    // build_did_secrets_bundle) resolve without a separate update step.
    // When the context already has a primary (e.g. provisioning a second
    // mediator into the same context), leave it alone — we don't want a
    // later integration silently displacing the first.
    let ctx_before_mint = crate::contexts::get_context(&state.contexts_ks, &context)
        .await?
        .ok_or_else(|| {
            AppError::Internal(format!(
                "context '{context}' disappeared between precondition check and DID mint"
            ))
        })?;
    let set_primary = ctx_before_mint.did.is_none();

    // `create_did_webvh` takes exactly one of `server_id` / `url`.
    // - WEBVH_SERVER set → `server_id` wins; `url` is unused by that
    //   path, so we drop it even if supplied.
    // - WEBVH_SERVER unset → serverless mode; we need a `url`. This is
    //   the only path where an absent URL is a hard error; surface it
    //   with guidance naming the `WEBVH_SERVER` alternative.
    let (params_server_id, params_url) = match &webvh_server_id {
        Some(id) => (Some(id.clone()), None),
        None => {
            let url = integration_url.clone().ok_or_else(|| {
                AppError::Validation(
                    "serverless provisioning requires the template to supply a 'URL' variable \
                     (the integration's webvh host URL). Either add it to the template's \
                     `requiredVars` and pass it in `template_vars`, or set `WEBVH_SERVER` to \
                     route publication through a registered webvh hosting server instead."
                        .into(),
                )
            })?;
            (None, Some(url))
        }
    };

    let template_vars_hashmap: std::collections::HashMap<String, Value> =
        template_vars.clone().into_iter().collect();

    let create_result = super::did_webvh::create_did_webvh(
        &state.keys_ks,
        &state.imported_ks,
        &state.contexts_ks,
        &state.webvh_ks,
        &state.did_templates_ks,
        &*state.seed_store,
        &*state.config.read().await,
        auth,
        super::did_webvh::CreateDidWebvhParams {
            context_id: context.clone(),
            server_id: params_server_id,
            url: params_url,
            path: webvh_path,
            label: Some(client_did.clone()),
            portable: true,
            add_mediator_service: false,
            additional_services: None,
            pre_rotation_count: 0,
            did_document: None,
            did_log: None,
            set_primary,
            signing_key_id: None,
            ka_key_id: None,
            template: Some(template_name.clone()),
            template_context: None,
            template_vars: template_vars_hashmap,
            // provision-integration always creates an integration DID,
            // never the VTA's own identity.
            is_vta_identity: false,
        },
        state
            .did_resolver
            .as_ref()
            .ok_or_else(|| AppError::Internal("DID resolver not initialized".into()))?,
        &state.didcomm_bridge,
        "provision-integration",
    )
    .await?;

    let integration_did = create_result.did.clone();
    let signing_key_id = create_result.signing_key_id.clone();
    let ka_key_id = create_result.ka_key_id.clone();
    let did_document = create_result
        .did_document
        .clone()
        .ok_or_else(|| AppError::Internal("create_did_webvh did not return did_document".into()))?;
    let did_log = create_result.log_entry.clone();

    // ── 4. Read back minted secrets ─────────────────────────────────
    //
    // `get_key_secret` applies the same context-access gating as we
    // enforced at precondition time, so this is a straightforward
    // server-side read.
    let signing_secret_resp = super::keys::get_key_secret(
        &state.keys_ks,
        &state.imported_ks,
        &state.seed_store,
        &state.audit_ks,
        auth,
        &signing_key_id,
        "provision-integration",
    )
    .await?;
    let ka_secret_resp = super::keys::get_key_secret(
        &state.keys_ks,
        &state.imported_ks,
        &state.seed_store,
        &state.audit_ks,
        auth,
        &ka_key_id,
        "provision-integration",
    )
    .await?;

    let mut secrets = BTreeMap::new();
    secrets.insert(
        integration_did.clone(),
        DidKeyMaterial {
            did: integration_did.clone(),
            signing_key: KeyPair {
                key_id: signing_key_id.clone(),
                public_key_multibase: signing_secret_resp.public_key_multibase.clone(),
                private_key_multibase: signing_secret_resp.private_key_multibase.clone(),
            },
            ka_key: KeyPair {
                key_id: ka_key_id.clone(),
                public_key_multibase: ka_secret_resp.public_key_multibase.clone(),
                private_key_multibase: ka_secret_resp.private_key_multibase.clone(),
            },
        },
    );

    // ── 4.5. Optional admin-DID rollover ───────────────────────────
    //
    // When the request carries an `adminTemplate`, the VTA mints a
    // long-term admin DID under its own key custody and binds the VC
    // subject + ACL row to that DID instead of `client_did`. The
    // ephemeral `client_did` then has no authority at the VTA — it
    // only opened the bundle. See `docs/bootstrap-provision-integration.md`
    // §"Admin-DID rollover" and CLAUDE.md "Use DID templates" /
    // "Authorization claims … VC/VP".
    let admin_did = if let Some(ref admin_ref) = admin_template_ref {
        let minted = mint_admin_via_template(state, &context, admin_ref).await?;
        secrets.insert(minted.material.did.clone(), minted.material.clone());
        minted.material.did
    } else {
        client_did.clone()
    };

    // ── 5. Register the (possibly rolled-over) admin as admin ──────
    //
    // ACL principal is `admin_did`: equals `client_did` when no
    // rollover, equals the freshly-minted VTA-derived DID when
    // rollover. The ephemeral `client_did` is never written to the
    // ACL when rollover is in effect — its only role is opening the
    // bundle.
    match super::acl::create_acl(
        &state.acl_ks,
        &state.audit_ks,
        auth,
        &admin_did,
        Role::Admin,
        request.label().map(str::to_string),
        vec![context.clone()],
        None,
        "provision-integration",
    )
    .await
    {
        Ok(_) => {}
        // Re-running provision-integration against the same admin_did
        // while the ACL row already exists is either a retry or an
        // operator-driven refresh. Either way the intent is harmless
        // — carry on without bumping the row, surface the conflict in
        // the returned summary if callers need to log.
        Err(AppError::Conflict(_)) => {
            info!(
                admin_did = %admin_did,
                context = %context,
                "ACL row already exists — reusing for provision-integration"
            );
        }
        Err(e) => return Err(e),
    }

    // ── 6. Build + sign the VTA authorization VC ────────────────────
    let config = state.config.read().await;
    let vta_did = config
        .vta_did
        .as_ref()
        .ok_or_else(|| AppError::Internal("VTA DID not configured".into()))?
        .clone();
    drop(config);

    let template_kind = resolve_template_kind(&state.did_templates_ks, &template_name, &context)
        .await
        .unwrap_or_else(|_| "integration".to_string());

    let claim = VtaAuthorizationClaim {
        // Subject is the long-term admin DID — `client_did` when no
        // rollover, the VTA-minted DID when an `adminTemplate` was
        // requested. Holders verify this VC offline at bundle open
        // and install the matching keys from the `secrets` map.
        id: admin_did.clone(),
        admin_of: AdminOfClaim {
            vta: vta_did.clone(),
            context: context.clone(),
            role: "admin".into(),
        },
        operator_of: Some(OperatorOfClaim {
            did: integration_did.clone(),
            template: template_name.clone(),
        }),
    };
    let mut vc_params = VtaAuthorizationParams::new(claim);
    if let Some(validity) = vc_validity {
        vc_params = vc_params.with_validity(validity);
    }

    // Split key-use: `#key-0` issues the VC's Data-Integrity proof;
    // `#sealed-transfer-0` signs the sealed-transfer producer assertion
    // below. Keeping them disjoint means a leak of one doesn't void the
    // other and each can rotate independently.
    let vc_issuer_secret = load_vta_vc_issuance_secret(state, &vta_did).await?;
    let vc = issue_vta_authorization_credential(&vc_issuer_secret, vc_params)
        .await
        .map_err(|e| AppError::Internal(format!("issue VTA authorization VC: {e}")))?;
    let vc_value =
        serde_json::to_value(&vc).map_err(|e| AppError::Internal(format!("serialize VC: {e}")))?;

    // ── 7. Build VtaTrustBundle — VTA DID doc + log ──────────────────
    let vta_trust = load_vta_trust_bundle(state, &vta_did).await?;

    // Template side outputs: today we always ship the webvh log for the
    // integration DID if create_did_webvh produced one. Future template
    // kinds (e.g., `webvh-hosting`) may emit additional outputs.
    let mut outputs = Vec::new();
    if let Some(log) = did_log {
        outputs.push(TemplateOutput::WebvhLog {
            did: integration_did.clone(),
            log,
        });
    }

    // Snapshot counts before the payload is moved into the seal. The
    // summary at the bottom of this fn (`secret_count`, `output_count`)
    // must reflect what is actually in the bundle — hard-coding "1 or 2"
    // based on `admin_rolled_over` silently lies when a future template
    // mints pre-rotation keys or emits multiple side outputs.
    let secret_count = secrets.len();
    let output_count = outputs.len();

    let payload = TemplateBootstrapPayload {
        authorization: vc_value,
        secrets,
        config: TemplateBootstrapConfig {
            template_name: template_name.clone(),
            template_kind: template_kind.clone(),
            did_document,
            outputs,
            vta_url: state.config.read().await.public_url.clone(),
            vta_trust,
        },
    };

    // ── 8. Seal ─────────────────────────────────────────────────────
    let producer_assertion = match assertion_mode {
        AssertionMode::DidSigned => {
            let sealed_transfer_secret = load_vta_sealed_transfer_secret(state, &vta_did).await?;
            build_did_signed_assertion(&sealed_transfer_secret, &client_x25519_pub, bundle_id)?
        }
        AssertionMode::PinnedOnly => ProducerAssertion {
            producer_did: vta_did.clone(),
            proof: AssertionProof::PinnedOnly,
        },
    };

    let nonce_store = PersistentNonceStore::new(state.sealed_nonces_ks.clone());
    let bundle = seal_payload(
        &client_x25519_pub,
        bundle_id,
        producer_assertion,
        &SealedPayloadV1::TemplateBootstrap(Box::new(payload)),
        &nonce_store,
    )
    .await
    .map_err(|e| AppError::Internal(format!("sealed-transfer seal failed: {e}")))?;

    let armored = armor::encode(&bundle);
    let digest = bundle_digest(&bundle);
    let bundle_id_hex = hex_lower(&bundle_id);

    let admin_rolled_over = admin_template_ref.is_some();
    let admin_template_name = admin_template_ref.as_ref().map(|r| r.name.clone());

    info!(
        client_did = %client_did,
        admin_did = %admin_did,
        admin_rolled_over,
        integration_did = %integration_did,
        context = %context,
        template = %template_name,
        admin_template = ?admin_template_name,
        bundle_id = %bundle_id_hex,
        "provision-integration bundle sealed"
    );

    Ok(ProvisionIntegrationOutput {
        armored,
        digest,
        summary: ProvisionSummary {
            client_did,
            admin_did,
            admin_rolled_over,
            integration_did,
            template_name,
            template_kind,
            admin_template_name,
            bundle_id_hex,
            secret_count,
            output_count,
            webvh_server_id,
        },
    })
}

/// Read the optional `WEBVH_SERVER` template var, validate it against
/// the registered-server catalogue, and return the resolved id.
///
/// Returns `Ok(None)` when the var is absent, JSON-null, or the empty
/// string (treated as "not set"). Returns `Err(AppError::NotFound)` when
/// the var names an id that isn't registered with this VTA — caller
/// surfaces that to the operator before any state is written.
async fn resolve_webvh_server(
    template_vars: &BTreeMap<String, Value>,
    webvh_ks: &crate::store::KeyspaceHandle,
) -> Result<Option<String>, AppError> {
    let raw = match template_vars.get("WEBVH_SERVER") {
        None | Some(Value::Null) => return Ok(None),
        Some(Value::String(s)) => s,
        Some(other) => {
            let actual = match other {
                Value::Bool(_) => "bool",
                Value::Number(_) => "number",
                Value::Array(_) => "array",
                Value::Object(_) => "object",
                _ => "non-string",
            };
            return Err(AppError::Validation(format!(
                "WEBVH_SERVER must be a string (registered webvh-server id), got {actual}"
            )));
        }
    };
    let id = raw.trim();
    if id.is_empty() {
        return Ok(None);
    }
    if crate::webvh_store::get_server(webvh_ks, id)
        .await?
        .is_none()
    {
        return Err(AppError::NotFound(format!(
            "WEBVH_SERVER '{id}' is not a registered webvh hosting server on this VTA \
             — register it via `vta webvh add-server` first, or omit `WEBVH_SERVER` \
             to self-host at the URL"
        )));
    }
    Ok(Some(id.to_string()))
}

/// Remove and return the optional `WEBVH_PATH` template var.
///
/// `WEBVH_PATH` is transport metadata — it tells the webvh server which
/// path to allocate when the VTA calls `POST /api/dids`. It is removed
/// from `template_vars` before the renderer sees the map so that a
/// template author never accidentally picks it up as document content.
///
/// `Ok(None)` when the var is absent or JSON-null. `Ok(Some(path))` when
/// it is a non-empty string. Empty strings and non-string types fail
/// loud — the operator set the var intentionally and a silent fallback
/// would mask a typo.
fn take_webvh_path(
    template_vars: &mut BTreeMap<String, Value>,
) -> Result<Option<String>, AppError> {
    let removed = match template_vars.remove("WEBVH_PATH") {
        None | Some(Value::Null) => return Ok(None),
        Some(v) => v,
    };
    let s = match removed {
        Value::String(s) => s,
        _ => {
            return Err(AppError::Validation(
                "WEBVH_PATH must be a non-empty string".into(),
            ));
        }
    };
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Err(AppError::Validation(
            "WEBVH_PATH must be a non-empty string".into(),
        ));
    }
    Ok(Some(trimmed.to_string()))
}

// ── Preconditions ───────────────────────────────────────────────────

async fn preconditions(
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
             'vta context provision' or 'pnm contexts create'"
        )));
    }

    // If the request carries a context hint, it must agree with the
    // chosen context. Silently normalizing hides operator bugs.
    if let BootstrapAsk::TemplateBootstrap(ask) = request.ask()
        && let Some(ref hint) = ask.context_hint
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
    let (template_name, admin_template_name) = match request.ask() {
        BootstrapAsk::TemplateBootstrap(ask) => (
            ask.template.name.clone(),
            ask.admin_template.as_ref().map(|t| t.name.clone()),
        ),
    };
    let template_registered = crate::did_templates::get_context_template(
        &state.did_templates_ks,
        context,
        &template_name,
    )
    .await?
    .is_some()
        || crate::did_templates::get_global_template(&state.did_templates_ks, &template_name)
            .await?
            .is_some()
        || vta_sdk::did_templates::load_embedded(&template_name).is_ok();
    if !template_registered {
        return Err(AppError::Validation(format!(
            "template '{template_name}' is not registered on this VTA. Register it via \
             'pnm did-templates upload {template_name} --file <path>' then retry"
        )));
    }

    // Same check for the admin template, when present. Built-ins
    // (`vta-admin`) always resolve via the SDK's embedded loader; only
    // operator-uploaded templates need a stored record.
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
                 'pnm did-templates upload {name} --file <path>' then retry, or use the \
                 built-in 'vta-admin' template."
            )));
        }
    }

    Ok(())
}

// ── Helpers ─────────────────────────────────────────────────────────

fn extract_template(ask: &BootstrapAsk) -> Result<(String, BTreeMap<String, Value>), AppError> {
    let BootstrapAsk::TemplateBootstrap(ask) = ask;
    Ok((ask.template.name.clone(), ask.template.vars.clone()))
}

fn extract_admin_template(ask: &BootstrapAsk) -> Option<DidTemplateRef> {
    let BootstrapAsk::TemplateBootstrap(ask) = ask;
    ask.admin_template.clone()
}

/// Result of minting a long-term admin DID for the holder via a
/// `kind: "admin"` DID template. The minted key material is registered
/// in the VTA's keystore and returned here so the caller can drop it
/// into `payload.secrets` for the holder to install.
struct MintedAdmin {
    material: DidKeyMaterial,
}

/// Mint a fresh long-term admin DID under the VTA's key custody, using
/// the operator-named admin template. Phase 1: did:key (Ed25519) only.
///
/// The signing key is a fresh BIP-32 derivation under the context's
/// base path; the X25519 key-agreement view is derived from the same
/// Ed25519 seed (canonical did:key derivation) so DIDComm authcrypt
/// works without the holder needing to know about the Ed25519→X25519
/// derivation themselves.
async fn mint_admin_via_template(
    state: &ProvisionIntegrationDeps,
    context: &str,
    admin_template_ref: &DidTemplateRef,
) -> Result<MintedAdmin, AppError> {
    use crate::keys::derive_and_store_did_key;
    use crate::keys::seeds::{get_active_seed_id, load_seed_bytes};

    // 1. Resolve the template (built-in / global / context-scoped).
    let admin_tpl = resolve_admin_template(state, context, &admin_template_ref.name).await?;

    // 2. The template must declare admin kind — otherwise the operator
    //    pointed us at a non-admin shape (mediator, webvh-host, etc.)
    //    and the resulting VC binding would be wrong. Fail loud.
    if admin_tpl.kind != "admin" {
        return Err(AppError::Validation(format!(
            "template '{}' has kind '{}', not 'admin'. Admin-DID rollover \
             requires a template that declares kind=\"admin\" (e.g. the \
             built-in 'vta-admin' template).",
            admin_template_ref.name, admin_tpl.kind
        )));
    }

    // 3. Phase 1 only mints did:key admin DIDs. Templates targeting
    //    other methods are accepted at registration time but we reject
    //    them here until the corresponding mint path lands.
    if !admin_tpl.methods.is_empty() && !admin_tpl.methods.iter().any(|m| m == "key") {
        return Err(AppError::Validation(format!(
            "admin template '{}' targets methods {:?}; phase 1 only \
             supports 'key'. Use a did:key admin template (or omit \
             `methods` in the template to accept any).",
            admin_template_ref.name, admin_tpl.methods
        )));
    }

    // 4. Mint the Ed25519 admin key + register a KeyRecord at
    //    `{admin_did}#{multibase}` so the VTA can later look the
    //    admin's signing key up by DID URL during steady-state auth.
    let ctx = crate::contexts::get_context(&state.contexts_ks, context)
        .await?
        .ok_or_else(|| {
            AppError::Internal(format!(
                "context '{context}' disappeared between precondition check and admin mint"
            ))
        })?;
    let active_seed_id = get_active_seed_id(&state.keys_ks)
        .await
        .map_err(|e| AppError::Internal(format!("active seed id: {e}")))?;
    let seed = load_seed_bytes(&state.keys_ks, &*state.seed_store, Some(active_seed_id))
        .await
        .map_err(|e| AppError::Internal(format!("load seed: {e}")))?;

    let label = format!("admin DID for context {context} (provision-integration)");
    let (admin_did, signing_priv_mb) = derive_and_store_did_key(
        &seed,
        &ctx.base_path,
        context,
        &label,
        &state.keys_ks,
        Some(active_seed_id),
    )
    .await
    .map_err(|e| AppError::Internal(format!("derive admin did:key: {e}")))?;

    // 5. The did:key multibase IS the signing key's pub multibase by
    //    construction — the prefix `did:key:` is purely structural.
    let signing_pub_mb = admin_did
        .strip_prefix("did:key:")
        .ok_or_else(|| {
            AppError::Internal("derive_and_store_did_key returned a non-did:key DID".into())
        })?
        .to_string();
    let signing_key_id = format!("{admin_did}#{signing_pub_mb}");

    // 6. Render the template (validates required vars + the rendered
    //    document shape). For did:key the doc isn't published — the
    //    DID is self-resolving — but the render validates the operator's
    //    template is actually usable. The rendered doc is discarded
    //    here; future webvh-admin support will keep it for publication.
    let mut tpl_vars = TemplateVars::new();
    tpl_vars.insert_string("DID", &admin_did);
    tpl_vars.insert_string("SIGNING_KEY_MB", &signing_pub_mb);
    for (k, v) in &admin_template_ref.vars {
        tpl_vars.insert(k.clone(), v.clone());
    }
    let _rendered = admin_tpl.render(&tpl_vars).map_err(|e| {
        AppError::Validation(format!(
            "admin template '{}' render failed: {e}",
            admin_template_ref.name
        ))
    })?;

    // 7. Derive the X25519 KA view from the same Ed25519 seed. Holders
    //    that DIDComm-authenticate as the admin DID install both the
    //    signing key and this KA derivation — bundle is self-describing,
    //    holder doesn't need to know the Ed25519→X25519 derivation.
    let signing_seed: [u8; 32] = decode_private_key_multibase(&signing_priv_mb)
        .map_err(|e| AppError::Internal(format!("decode admin signing seed: {e}")))?;
    let signing_pub_bytes = affinidi_crypto::did_key::did_key_to_ed25519_pub(&admin_did)
        .map_err(|e| AppError::Internal(format!("decode admin did:key pub: {e}")))?;
    let ka_pub_bytes = affinidi_crypto::did_key::ed25519_pub_to_x25519_bytes(&signing_pub_bytes)
        .map_err(|e| AppError::Internal(format!("derive admin X25519 pub: {e}")))?;
    let ka_priv_bytes = affinidi_crypto::ed25519::ed25519_private_to_x25519(&signing_seed);

    let ka_pub_mb =
        crate::keys::encode_public_multibase(&crate::keys::KeyType::X25519, &ka_pub_bytes);
    let ka_priv_mb =
        crate::keys::encode_private_multibase(&crate::keys::KeyType::X25519, &ka_priv_bytes);
    // did:key Ed25519 resolvers use the X25519 multibase as the KA
    // verification-method fragment. Mirror that convention so the
    // installed key id matches what consumers expect to see in the
    // resolved DID document.
    let ka_key_id = format!("{admin_did}#{ka_pub_mb}");

    info!(
        admin_did = %admin_did,
        context = %context,
        template = %admin_template_ref.name,
        "minted long-term admin DID for provision-integration rollover"
    );

    Ok(MintedAdmin {
        material: DidKeyMaterial {
            did: admin_did,
            signing_key: KeyPair {
                key_id: signing_key_id,
                public_key_multibase: signing_pub_mb,
                private_key_multibase: signing_priv_mb,
            },
            ka_key: KeyPair {
                key_id: ka_key_id,
                public_key_multibase: ka_pub_mb,
                private_key_multibase: ka_priv_mb,
            },
        },
    })
}

/// Resolve an admin template by name. Mirrors the integration template
/// resolution in [`preconditions`] (context → global → built-in) but
/// returns the parsed [`DidTemplate`] instead of just a registration
/// boolean — we need to render it during the mint.
async fn resolve_admin_template(
    state: &ProvisionIntegrationDeps,
    context: &str,
    name: &str,
) -> Result<vta_sdk::did_templates::DidTemplate, AppError> {
    if let Some(rec) =
        crate::did_templates::get_context_template(&state.did_templates_ks, context, name).await?
    {
        return Ok(rec.template);
    }
    if let Some(rec) =
        crate::did_templates::get_global_template(&state.did_templates_ks, name).await?
    {
        return Ok(rec.template);
    }
    if let Ok(tpl) = vta_sdk::did_templates::load_embedded(name) {
        return Ok(tpl);
    }
    Err(AppError::Validation(format!(
        "admin template '{name}' is not registered on this VTA. Register it via \
         'pnm did-templates upload {name} --file <path>' then retry, or use \
         the built-in 'vta-admin' template."
    )))
}

async fn resolve_template_kind(
    templates_ks: &crate::store::KeyspaceHandle,
    name: &str,
    context: &str,
) -> Result<String, AppError> {
    if let Some(rec) =
        crate::did_templates::get_context_template(templates_ks, context, name).await?
    {
        return Ok(rec.template.kind);
    }
    if let Some(rec) = crate::did_templates::get_global_template(templates_ks, name).await? {
        return Ok(rec.template.kind);
    }
    if let Ok(tpl) = vta_sdk::did_templates::load_embedded(name) {
        return Ok(tpl.kind);
    }
    Err(AppError::NotFound(format!("template '{name}' not found")))
}

/// Load one of the VTA's Ed25519 keys as a `Secret` suitable for
/// signing. Used to fetch both the VC-issuance key (`#key-0`, see
/// [`load_vta_vc_issuance_secret`]) and the sealed-transfer
/// producer-assertion key (`#sealed-transfer-0`, see
/// [`load_vta_sealed_transfer_secret`]).
///
/// Internal-use: synthesises a super-admin `AuthClaims` to satisfy the
/// `get_key_secret` authz check. The real caller was already authorised
/// as a context admin at precondition time — loading the VTA's own
/// signing material here is a server-internal step, not an action
/// attributable to the user caller.
async fn load_vta_key_as_secret(
    state: &ProvisionIntegrationDeps,
    key_id: String,
) -> Result<Secret, AppError> {
    let internal_auth = AuthClaims::local_cli("provision-integration-internal");
    let resp = super::keys::get_key_secret(
        &state.keys_ks,
        &state.imported_ks,
        &state.seed_store,
        &state.audit_ks,
        &internal_auth,
        &key_id,
        "provision-integration-internal",
    )
    .await?;
    let _seed: [u8; 32] = decode_private_key_multibase(&resp.private_key_multibase)
        .map_err(|e| AppError::Internal(format!("decode VTA key secret for {key_id}: {e}")))?;
    let mut secret = Secret::from_multibase(&resp.private_key_multibase, None)
        .map_err(|e| AppError::Internal(format!("construct Secret for {key_id}: {e}")))?;
    secret.id = key_id;
    Ok(secret)
}

/// Load `{vta_did}#key-0` for issuing the VtaAuthorization VC's
/// Data-Integrity proof.
async fn load_vta_vc_issuance_secret(
    state: &ProvisionIntegrationDeps,
    vta_did: &str,
) -> Result<Secret, AppError> {
    load_vta_key_as_secret(state, format!("{vta_did}#key-0")).await
}

/// Load `{vta_did}#sealed-transfer-0` for signing the sealed-transfer
/// producer assertion. The key is minted at VTA DID creation
/// (see `operations::did_webvh::create_did_webvh` + `is_vta_identity`).
/// A VTA missing this key is mis-provisioned — surface the error rather
/// than silently falling back to `#key-0`, which would hide the defect
/// and re-introduce the key-reuse we split out.
async fn load_vta_sealed_transfer_secret(
    state: &ProvisionIntegrationDeps,
    vta_did: &str,
) -> Result<Secret, AppError> {
    load_vta_key_as_secret(state, format!("{vta_did}#sealed-transfer-0"))
        .await
        .map_err(|e| match e {
            AppError::NotFound(_) => AppError::Internal(format!(
                "VTA missing '{vta_did}#sealed-transfer-0' — re-bootstrap required (this VTA was \
                 provisioned before key-use split, see review item 12)"
            )),
            other => other,
        })
}

/// Assemble the trust bundle shipped alongside every provisioning
/// payload: VTA DID, resolved DID document, and webvh log if we have
/// one on disk (we should — the VTA's own DID was provisioned through
/// the same webvh path).
async fn load_vta_trust_bundle(
    state: &ProvisionIntegrationDeps,
    vta_did: &str,
) -> Result<VtaTrustBundle, AppError> {
    let resolver = state
        .did_resolver
        .as_ref()
        .ok_or_else(|| AppError::Internal("DID resolver not initialized".into()))?;
    let resolved = resolver
        .resolve(vta_did)
        .await
        .map_err(|e| AppError::Internal(format!("resolve VTA DID '{vta_did}': {e}")))?;

    let vta_did_document = serde_json::to_value(&resolved.doc)
        .map_err(|e| AppError::Internal(format!("serialize VTA DID doc: {e}")))?;

    #[cfg(feature = "webvh")]
    let vta_did_log = crate::webvh_store::get_did_log(&state.webvh_ks, vta_did).await?;
    #[cfg(not(feature = "webvh"))]
    let vta_did_log: Option<String> = None;

    Ok(VtaTrustBundle {
        vta_did: vta_did.to_string(),
        vta_did_document,
        vta_did_log,
    })
}

/// Sign the sealed-transfer producer assertion with the VTA's
/// purpose-specific Ed25519 key (`{vta_did}#sealed-transfer-0`).
///
/// Signed target: domain-tagged `client_x25519_pub || bundle_id`. The
/// domain tag (`"vta-sealed-transfer/v1\0"`) alone already prevents
/// signature replay into other signing contexts; separating this key
/// from `#key-0` adds defence-in-depth:
///   - a leak of one key doesn't void the other (VC issuance vs
///     producer assertion), and
///   - each can rotate independently (e.g. VC issuance eventually
///     moves to an HSM while sealed-transfer stays local for
///     throughput).
fn build_did_signed_assertion(
    vta_signing_secret: &Secret,
    client_x25519_pub: &[u8; 32],
    bundle_id: [u8; 16],
) -> Result<ProducerAssertion, AppError> {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;

    let (vta_did_frag, _) = vta_signing_secret
        .id
        .split_once('#')
        .ok_or_else(|| AppError::Internal("VTA signing secret id missing fragment".into()))?;
    let vta_did = vta_did_frag.to_string();

    // Decode the multibase-encoded private seed so we can use
    // ed25519-dalek directly. The `Secret` API is optimised for
    // Data-Integrity flows; for a raw sign-these-bytes we drop down.
    let priv_mb = vta_signing_secret
        .get_private_keymultibase()
        .map_err(|e| AppError::Internal(format!("get VTA private key multibase: {e}")))?;
    let seed: [u8; 32] = decode_private_key_multibase(&priv_mb)
        .map_err(|e| AppError::Internal(format!("decode VTA signing seed: {e}")))?;
    let signing_key = SigningKey::from_bytes(&seed);

    let mut to_sign = Vec::with_capacity(64);
    to_sign.extend_from_slice(b"vta-sealed-transfer/v1\0");
    to_sign.extend_from_slice(client_x25519_pub);
    to_sign.extend_from_slice(&bundle_id);

    let signature = signing_key.sign(&to_sign);
    let signature_b64 = B64URL.encode(signature.to_bytes());

    Ok(ProducerAssertion {
        producer_did: vta_did.clone(),
        proof: AssertionProof::DidSigned(DidSignedAssertion {
            did: vta_did,
            signature_b64,
            verification_method: vta_signing_secret.id.clone(),
        }),
    })
}

use vta_sdk::hex::lower as hex_lower;

#[cfg(test)]
mod tests {
    use super::*;
    use vta_sdk::provision_integration::{BootstrapAsk, DidTemplateRef, TemplateBootstrapAsk};

    fn sample_ask(template_name: &str, with_url: bool) -> BootstrapAsk {
        let mut vars = BTreeMap::new();
        if with_url {
            vars.insert(
                "URL".to_string(),
                Value::String("https://mediator.example.com".into()),
            );
        }
        BootstrapAsk::TemplateBootstrap(TemplateBootstrapAsk {
            context_hint: Some("prod-mediator".into()),
            template: DidTemplateRef {
                name: template_name.into(),
                vars,
            },
            admin_template: None,
            note: None,
        })
    }

    fn sample_ask_with_admin(template_name: &str, admin_template_name: &str) -> BootstrapAsk {
        let mut vars = BTreeMap::new();
        vars.insert(
            "URL".to_string(),
            Value::String("https://mediator.example.com".into()),
        );
        BootstrapAsk::TemplateBootstrap(TemplateBootstrapAsk {
            context_hint: Some("prod-mediator".into()),
            template: DidTemplateRef {
                name: template_name.into(),
                vars,
            },
            admin_template: Some(DidTemplateRef {
                name: admin_template_name.into(),
                vars: BTreeMap::new(),
            }),
            note: None,
        })
    }

    #[test]
    fn extract_template_pulls_name_and_vars() {
        let ask = sample_ask("didcomm-mediator", true);
        let (name, vars) = extract_template(&ask).unwrap();
        assert_eq!(name, "didcomm-mediator");
        assert_eq!(
            vars.get("URL").and_then(|v| v.as_str()),
            Some("https://mediator.example.com")
        );
    }

    #[test]
    fn extract_admin_template_returns_none_when_absent() {
        let ask = sample_ask("didcomm-mediator", true);
        assert!(extract_admin_template(&ask).is_none());
    }

    #[test]
    fn extract_admin_template_returns_some_when_present() {
        let ask = sample_ask_with_admin("didcomm-mediator", "vta-admin");
        let admin = extract_admin_template(&ask).expect("admin template");
        assert_eq!(admin.name, "vta-admin");
    }

    #[test]
    fn assertion_mode_default_is_did_signed() {
        assert_eq!(AssertionMode::default(), AssertionMode::DidSigned);
    }

    // ── resolve_webvh_server ────────────────────────────────────────

    use crate::config::StoreConfig;
    use crate::store::Store;
    use chrono::Utc;
    use vta_sdk::webvh::WebvhServerRecord;

    /// Open a fresh tempdir-backed store and return its `webvh` keyspace
    /// plus the dir guard so the caller can drop both at end-of-test.
    async fn fresh_webvh_keyspace() -> (tempfile::TempDir, Store, crate::store::KeyspaceHandle) {
        let dir = tempfile::tempdir().expect("temp dir");
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .expect("open store");
        let ks = store.keyspace("webvh").expect("open webvh ks");
        (dir, store, ks)
    }

    fn sample_server_record(id: &str) -> WebvhServerRecord {
        WebvhServerRecord {
            id: id.into(),
            did: format!("did:webvh:{id}"),
            label: None,
            access_token: None,
            access_expires_at: None,
            refresh_token: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[tokio::test]
    async fn resolve_webvh_server_absent_returns_none() {
        let (_dir, _store, ks) = fresh_webvh_keyspace().await;
        let vars = BTreeMap::new();
        assert_eq!(resolve_webvh_server(&vars, &ks).await.unwrap(), None);
    }

    #[tokio::test]
    async fn resolve_webvh_server_null_returns_none() {
        let (_dir, _store, ks) = fresh_webvh_keyspace().await;
        let mut vars = BTreeMap::new();
        vars.insert("WEBVH_SERVER".into(), Value::Null);
        assert_eq!(resolve_webvh_server(&vars, &ks).await.unwrap(), None);
    }

    #[tokio::test]
    async fn resolve_webvh_server_empty_string_returns_none() {
        let (_dir, _store, ks) = fresh_webvh_keyspace().await;
        let mut vars = BTreeMap::new();
        vars.insert("WEBVH_SERVER".into(), Value::String("   ".into()));
        assert_eq!(resolve_webvh_server(&vars, &ks).await.unwrap(), None);
    }

    #[tokio::test]
    async fn resolve_webvh_server_unknown_id_is_not_found() {
        let (_dir, _store, ks) = fresh_webvh_keyspace().await;
        let mut vars = BTreeMap::new();
        vars.insert(
            "WEBVH_SERVER".into(),
            Value::String("never-registered".into()),
        );
        let err = resolve_webvh_server(&vars, &ks).await.unwrap_err();
        assert!(matches!(err, AppError::NotFound(_)), "got: {err:?}");
        let msg = err.to_string();
        assert!(msg.contains("never-registered"), "got: {msg}");
        assert!(msg.contains("vta webvh add-server"), "got: {msg}");
    }

    #[tokio::test]
    async fn resolve_webvh_server_registered_id_returns_some() {
        let (_dir, _store, ks) = fresh_webvh_keyspace().await;
        crate::webvh_store::store_server(&ks, &sample_server_record("hosted-edge-1"))
            .await
            .unwrap();

        let mut vars = BTreeMap::new();
        vars.insert("WEBVH_SERVER".into(), Value::String("hosted-edge-1".into()));
        assert_eq!(
            resolve_webvh_server(&vars, &ks).await.unwrap(),
            Some("hosted-edge-1".into())
        );
    }

    #[tokio::test]
    async fn resolve_webvh_server_trims_whitespace() {
        let (_dir, _store, ks) = fresh_webvh_keyspace().await;
        crate::webvh_store::store_server(&ks, &sample_server_record("hosted-edge-1"))
            .await
            .unwrap();

        let mut vars = BTreeMap::new();
        vars.insert(
            "WEBVH_SERVER".into(),
            Value::String("  hosted-edge-1  ".into()),
        );
        assert_eq!(
            resolve_webvh_server(&vars, &ks).await.unwrap(),
            Some("hosted-edge-1".into())
        );
    }

    #[tokio::test]
    async fn resolve_webvh_server_wrong_type_is_validation_error() {
        let (_dir, _store, ks) = fresh_webvh_keyspace().await;
        let mut vars = BTreeMap::new();
        vars.insert("WEBVH_SERVER".into(), Value::Bool(true));
        let err = resolve_webvh_server(&vars, &ks).await.unwrap_err();
        assert!(matches!(err, AppError::Validation(_)), "got: {err:?}");
        assert!(err.to_string().contains("bool"), "got: {err}");
    }

    // ── take_webvh_path ─────────────────────────────────────────────

    #[test]
    fn take_webvh_path_absent_returns_none() {
        let mut vars = BTreeMap::new();
        vars.insert("URL".into(), Value::String("https://a".into()));
        assert_eq!(take_webvh_path(&mut vars).unwrap(), None);
        assert!(vars.contains_key("URL"), "unrelated keys must survive");
    }

    #[test]
    fn take_webvh_path_null_returns_none_and_removes_key() {
        let mut vars = BTreeMap::new();
        vars.insert("WEBVH_PATH".into(), Value::Null);
        assert_eq!(take_webvh_path(&mut vars).unwrap(), None);
        assert!(
            !vars.contains_key("WEBVH_PATH"),
            "null WEBVH_PATH must still be removed so the renderer never sees it"
        );
    }

    #[test]
    fn take_webvh_path_string_returns_some_and_removes_key() {
        let mut vars = BTreeMap::new();
        vars.insert("URL".into(), Value::String("https://a".into()));
        vars.insert("WEBVH_PATH".into(), Value::String("team/mediator".into()));
        assert_eq!(
            take_webvh_path(&mut vars).unwrap(),
            Some("team/mediator".into())
        );
        assert!(
            !vars.contains_key("WEBVH_PATH"),
            "WEBVH_PATH must be removed so it can't reach the renderer"
        );
        assert!(vars.contains_key("URL"), "unrelated keys must survive");
    }

    #[test]
    fn take_webvh_path_trims_whitespace() {
        let mut vars = BTreeMap::new();
        vars.insert(
            "WEBVH_PATH".into(),
            Value::String("  team/mediator  ".into()),
        );
        assert_eq!(
            take_webvh_path(&mut vars).unwrap(),
            Some("team/mediator".into())
        );
    }

    #[test]
    fn take_webvh_path_empty_string_is_validation_error() {
        let mut vars = BTreeMap::new();
        vars.insert("WEBVH_PATH".into(), Value::String(String::new()));
        let err = take_webvh_path(&mut vars).unwrap_err();
        assert!(matches!(err, AppError::Validation(_)), "got: {err:?}");
        assert!(
            err.to_string().contains("WEBVH_PATH"),
            "error must name the offending var: {err}"
        );
    }

    #[test]
    fn take_webvh_path_whitespace_only_is_validation_error() {
        let mut vars = BTreeMap::new();
        vars.insert("WEBVH_PATH".into(), Value::String("   ".into()));
        let err = take_webvh_path(&mut vars).unwrap_err();
        assert!(matches!(err, AppError::Validation(_)), "got: {err:?}");
    }

    #[test]
    fn take_webvh_path_non_string_is_validation_error() {
        let mut vars = BTreeMap::new();
        vars.insert("WEBVH_PATH".into(), Value::Bool(true));
        let err = take_webvh_path(&mut vars).unwrap_err();
        assert!(matches!(err, AppError::Validation(_)), "got: {err:?}");

        let mut vars = BTreeMap::new();
        vars.insert("WEBVH_PATH".into(), Value::Number(42.into()));
        let err = take_webvh_path(&mut vars).unwrap_err();
        assert!(matches!(err, AppError::Validation(_)), "got: {err:?}");
    }

    // ── preconditions / resolve_template_kind ───────────────────────
    //
    // Cover the three-tier template resolve (context → global → built-in)
    // that both `preconditions` and `resolve_template_kind` share with
    // `resolve_admin_template` and `did_webvh::resolve_template_for_render`.
    // Built-ins like `didcomm-mediator` ship inside `vta_sdk::did_templates`
    // and must resolve without an operator ever running
    // `pnm did-templates upload`.

    use crate::config::AppConfig;
    use crate::didcomm_bridge::DIDCommBridge;
    use crate::keys::seed_store::PlaintextSeedStore;
    use ed25519_dalek::SigningKey;
    use std::path::PathBuf;
    use vta_sdk::did_templates::{DidTemplate, DidTemplateRecord, Scope};
    use vta_sdk::provision_integration::request::BootstrapRequest;

    /// Seven keyspaces + dir guard for a fresh per-test store. Only
    /// `contexts_ks` and `did_templates_ks` are exercised by
    /// `preconditions`; the remainder are filled to satisfy the
    /// `ProvisionIntegrationDeps` shape.
    struct TestStore {
        _dir: tempfile::TempDir,
        _store: Store,
        contexts_ks: crate::store::KeyspaceHandle,
        did_templates_ks: crate::store::KeyspaceHandle,
        keys_ks: crate::store::KeyspaceHandle,
        acl_ks: crate::store::KeyspaceHandle,
        audit_ks: crate::store::KeyspaceHandle,
        imported_ks: crate::store::KeyspaceHandle,
        webvh_ks: crate::store::KeyspaceHandle,
        sealed_nonces_ks: crate::store::KeyspaceHandle,
        data_dir: PathBuf,
    }

    async fn open_test_store() -> TestStore {
        let dir = tempfile::tempdir().expect("temp dir");
        let data_dir = dir.path().to_path_buf();
        let store = Store::open(&StoreConfig {
            data_dir: data_dir.clone(),
        })
        .expect("open store");
        TestStore {
            contexts_ks: store.keyspace("contexts").expect("contexts ks"),
            did_templates_ks: store.keyspace("did_templates").expect("did_templates ks"),
            keys_ks: store.keyspace("keys").expect("keys ks"),
            acl_ks: store.keyspace("acl").expect("acl ks"),
            audit_ks: store.keyspace("audit").expect("audit ks"),
            imported_ks: store.keyspace("imported").expect("imported ks"),
            webvh_ks: store.keyspace("webvh").expect("webvh ks"),
            sealed_nonces_ks: store.keyspace("sealed_nonces").expect("nonces ks"),
            _dir: dir,
            _store: store,
            data_dir,
        }
    }

    fn test_app_config(data_dir: PathBuf) -> AppConfig {
        AppConfig {
            vta_did: None,
            vta_name: None,
            public_url: None,
            resolver_url: None,
            server: Default::default(),
            log: Default::default(),
            store: StoreConfig { data_dir },
            messaging: None,
            services: Default::default(),
            auth: Default::default(),
            audit: Default::default(),
            secrets: Default::default(),
            #[cfg(feature = "tee")]
            tee: Default::default(),
            config_path: PathBuf::new(),
        }
    }

    fn test_deps(ts: &TestStore) -> ProvisionIntegrationDeps {
        ProvisionIntegrationDeps {
            keys_ks: ts.keys_ks.clone(),
            acl_ks: ts.acl_ks.clone(),
            audit_ks: ts.audit_ks.clone(),
            contexts_ks: ts.contexts_ks.clone(),
            did_templates_ks: ts.did_templates_ks.clone(),
            imported_ks: ts.imported_ks.clone(),
            webvh_ks: ts.webvh_ks.clone(),
            sealed_nonces_ks: ts.sealed_nonces_ks.clone(),
            seed_store: Arc::new(PlaintextSeedStore::new(&ts.data_dir)),
            config: Arc::new(RwLock::new(test_app_config(ts.data_dir.clone()))),
            did_resolver: None,
            didcomm_bridge: Arc::new(DIDCommBridge::placeholder()),
        }
    }

    fn super_admin_claims() -> AuthClaims {
        AuthClaims {
            did: "did:key:zTestAdmin".into(),
            role: crate::acl::Role::Admin,
            allowed_contexts: Vec::new(),
        }
    }

    async fn signed_request(template_name: &str, context_hint: &str) -> VerifiedBootstrapRequest {
        signed_request_with_vars(template_name, context_hint, BTreeMap::new()).await
    }

    async fn signed_request_with_vars(
        template_name: &str,
        context_hint: &str,
        vars: BTreeMap<String, Value>,
    ) -> VerifiedBootstrapRequest {
        let seed = [7u8; 32];
        let signing = SigningKey::from_bytes(&seed);
        let pub_bytes: [u8; 32] = signing.verifying_key().to_bytes();
        let client_did = affinidi_crypto::did_key::ed25519_pub_to_did_key(&pub_bytes);

        let ask = BootstrapAsk::TemplateBootstrap(TemplateBootstrapAsk {
            context_hint: Some(context_hint.into()),
            template: DidTemplateRef {
                name: template_name.into(),
                vars,
            },
            admin_template: None,
            note: None,
        });

        let req = BootstrapRequest::sign(
            &seed,
            &client_did,
            [0u8; 16],
            Duration::minutes(10),
            None,
            ask,
        )
        .await
        .expect("sign bootstrap request");
        req.verify().expect("verify bootstrap request")
    }

    /// Bootstrap the minimum VTA state a full `provision_integration()`
    /// call needs: an active seed, the VTA's `{vta_did}#key-0` signing
    /// key saved in the keystore, a DID resolver that can resolve the
    /// VTA's own `did:key`, and an `AppConfig` with `vta_did` populated.
    ///
    /// Returns `(vta_did, deps_with_resolver)` — the caller plugs the
    /// returned deps into `provision_integration()` instead of `test_deps()`.
    async fn bootstrap_test_vta(ts: &TestStore) -> (String, ProvisionIntegrationDeps) {
        use crate::keys::KeyType as SdkKeyType;
        use crate::keys::save_key_record;
        use crate::keys::seeds::{SeedRecord, save_seed_record, set_active_seed_id};
        use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
        use ed25519_dalek_bip32::{DerivationPath, ExtendedSigningKey};
        use vta_sdk::did_key::ed25519_multibase_pubkey;

        // Deterministic 64-byte seed (BIP-32 wants ≥16 bytes; 64 mirrors
        // the mnemonic-derived seed shape used in production setup).
        let raw_seed = [0xC5u8; 64];
        let seed_store = PlaintextSeedStore::new(&ts.data_dir);
        seed_store
            .set(&raw_seed)
            .await
            .expect("write test seed to plaintext store");

        let now = chrono::Utc::now();
        save_seed_record(
            &ts.keys_ks,
            &SeedRecord {
                id: 0,
                seed_hex: None,
                created_at: now,
                retired_at: None,
            },
        )
        .await
        .expect("save seed record");
        set_active_seed_id(&ts.keys_ks, 0)
            .await
            .expect("set active seed id");

        // Derive a fresh Ed25519 key at a canonical VTA path, convert to
        // did:key, save a keystore record whose id matches the
        // `{vta_did}#key-0` convention `load_vta_vc_issuance_secret` looks up.
        let vta_base_path = "m/26'/1'/0'";
        let root = ExtendedSigningKey::from_seed(&raw_seed).expect("bip-32 root");
        let dp: DerivationPath = vta_base_path.parse().expect("derivation path");
        let derived = root.derive(&dp).expect("derive VTA key");
        let signing = ed25519_dalek::SigningKey::from_bytes(derived.signing_key.as_bytes());
        let pub_bytes = signing.verifying_key().to_bytes();
        let multibase = ed25519_multibase_pubkey(&pub_bytes);
        let vta_did = format!("did:key:{multibase}");
        let key_id = format!("{vta_did}#key-0");

        save_key_record(
            &ts.keys_ks,
            &key_id,
            vta_base_path,
            SdkKeyType::Ed25519,
            &multibase,
            "VTA signing key",
            None,
            Some(0),
        )
        .await
        .expect("save VTA key record");

        // Mirror the real VTA bootstrap: provision `#sealed-transfer-0`
        // (separate from `#key-0`) so `provision_integration` can sign
        // the producer assertion without hitting the "re-bootstrap
        // required" guard in `load_vta_sealed_transfer_secret`.
        let st_base_path = "m/26'/1'/1'";
        let st_dp: DerivationPath = st_base_path.parse().expect("st derivation path");
        let st_derived = root.derive(&st_dp).expect("derive VTA sealed-transfer key");
        let st_signing = ed25519_dalek::SigningKey::from_bytes(st_derived.signing_key.as_bytes());
        let st_pub_bytes = st_signing.verifying_key().to_bytes();
        let st_multibase = ed25519_multibase_pubkey(&st_pub_bytes);
        save_key_record(
            &ts.keys_ks,
            &format!("{vta_did}#sealed-transfer-0"),
            st_base_path,
            SdkKeyType::Ed25519,
            &st_multibase,
            "VTA sealed-transfer producer-assertion key",
            None,
            Some(0),
        )
        .await
        .expect("save VTA sealed-transfer key record");

        let mut config = test_app_config(ts.data_dir.clone());
        config.vta_did = Some(vta_did.clone());
        config.public_url = Some("https://vta.test".into());

        let resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
            .await
            .expect("DID resolver");

        let deps = ProvisionIntegrationDeps {
            keys_ks: ts.keys_ks.clone(),
            acl_ks: ts.acl_ks.clone(),
            audit_ks: ts.audit_ks.clone(),
            contexts_ks: ts.contexts_ks.clone(),
            did_templates_ks: ts.did_templates_ks.clone(),
            imported_ks: ts.imported_ks.clone(),
            webvh_ks: ts.webvh_ks.clone(),
            sealed_nonces_ks: ts.sealed_nonces_ks.clone(),
            seed_store: Arc::new(PlaintextSeedStore::new(&ts.data_dir)),
            config: Arc::new(RwLock::new(config)),
            did_resolver: Some(resolver),
            didcomm_bridge: Arc::new(DIDCommBridge::placeholder()),
        };
        (vta_did, deps)
    }

    fn mediator_template_vars() -> BTreeMap<String, Value> {
        let mut vars = BTreeMap::new();
        vars.insert("URL".into(), Value::String("https://mediator.test".into()));
        vars.insert("ROUTING_KEYS".into(), Value::Array(vec![]));
        vars
    }

    #[tokio::test]
    async fn preconditions_accepts_builtin_integration_template() {
        let ts = open_test_store().await;
        crate::contexts::create_context(&ts.contexts_ks, "prod-mediator", "Prod Mediator")
            .await
            .expect("create context");

        let deps = test_deps(&ts);
        let auth = super_admin_claims();
        let request = signed_request("didcomm-mediator", "prod-mediator").await;

        preconditions(&deps, &auth, "prod-mediator", &request)
            .await
            .expect("built-in didcomm-mediator should satisfy preconditions");
    }

    #[tokio::test]
    async fn preconditions_rejects_unknown_template() {
        let ts = open_test_store().await;
        crate::contexts::create_context(&ts.contexts_ks, "prod-mediator", "Prod Mediator")
            .await
            .expect("create context");

        let deps = test_deps(&ts);
        let auth = super_admin_claims();
        let request = signed_request("never-registered", "prod-mediator").await;

        let err = preconditions(&deps, &auth, "prod-mediator", &request)
            .await
            .expect_err("unknown template must be rejected");
        assert!(matches!(err, AppError::Validation(_)), "got: {err:?}");
        let msg = err.to_string();
        assert!(msg.contains("never-registered"), "got: {msg}");
        assert!(msg.contains("is not registered on this VTA"), "got: {msg}");
    }

    #[tokio::test]
    async fn resolve_template_kind_resolves_builtin_when_no_stored_record() {
        let ts = open_test_store().await;

        let kind = resolve_template_kind(&ts.did_templates_ks, "didcomm-mediator", "prod-mediator")
            .await
            .expect("built-in kind lookup should succeed");
        let expected = vta_sdk::did_templates::load_embedded("didcomm-mediator")
            .expect("built-in template available")
            .kind;
        assert_eq!(kind, expected);
    }

    #[tokio::test]
    async fn resolve_template_kind_prefers_stored_record_over_builtin() {
        // A context-scoped record must shadow the built-in, matching the
        // resolve order in `resolve_admin_template` and
        // `did_webvh::resolve_template_for_render`.
        let ts = open_test_store().await;
        let mut tpl: DidTemplate =
            vta_sdk::did_templates::load_embedded("didcomm-mediator").expect("built-in available");
        "shadowed-kind".clone_into(&mut tpl.kind);
        let record = DidTemplateRecord {
            template: tpl,
            scope: Scope::Context {
                context_id: "prod-mediator".into(),
            },
            created_at: 0,
            updated_at: 0,
            created_by: "test".into(),
        };
        crate::did_templates::store_context_template(
            &ts.did_templates_ks,
            "prod-mediator",
            &record,
        )
        .await
        .expect("store context template");

        let kind = resolve_template_kind(&ts.did_templates_ks, "didcomm-mediator", "prod-mediator")
            .await
            .expect("stored record resolves");
        assert_eq!(kind, "shadowed-kind");
    }

    // ── Full-flow E2E tests ─────────────────────────────────────────
    //
    // Exercise the whole `provision_integration()` orchestration, not
    // just individual helpers. These are the tests that would have
    // caught the 3f4d832 regression (set_primary=false leaving ctx.did
    // unset) and the recent count-bug fix (secret_count/output_count
    // hardcoded instead of computed from the payload).

    #[tokio::test]
    async fn provision_integration_binds_minted_did_when_context_has_none() {
        // This is the direct regression test for 3f4d832. Fresh context
        // with ctx.did = None → after provision_integration, ctx.did
        // must be populated with the newly-minted integration DID.
        let ts = open_test_store().await;
        let (_vta_did, deps) = bootstrap_test_vta(&ts).await;
        crate::contexts::create_context(&ts.contexts_ks, "prod-mediator", "Prod Mediator")
            .await
            .expect("create context");

        let ctx_before = crate::contexts::get_context(&ts.contexts_ks, "prod-mediator")
            .await
            .unwrap()
            .unwrap();
        assert!(
            ctx_before.did.is_none(),
            "precondition: fresh context has no DID"
        );

        let auth = super_admin_claims();
        let request = signed_request_with_vars(
            "didcomm-mediator",
            "prod-mediator",
            mediator_template_vars(),
        )
        .await;

        let output = provision_integration(
            &deps,
            &auth,
            ProvisionIntegrationParams {
                request,
                context: "prod-mediator".into(),
                assertion_mode: AssertionMode::PinnedOnly,
                vc_validity: None,
            },
        )
        .await
        .expect("provision_integration");

        let ctx_after = crate::contexts::get_context(&ts.contexts_ks, "prod-mediator")
            .await
            .unwrap()
            .unwrap();
        assert!(
            ctx_after.did.is_some(),
            "context DID must be populated after provisioning a fresh context"
        );
        assert_eq!(
            ctx_after.did.as_deref(),
            Some(output.summary.integration_did.as_str()),
            "bound DID must match the minted integration DID returned in the summary"
        );
    }

    #[tokio::test]
    async fn provision_integration_preserves_existing_context_did() {
        // The "first integration wins" invariant: a second provisioning
        // into a context that already has a primary DID must NOT
        // overwrite it. Without this guard a second mediator silently
        // displaces the first.
        let ts = open_test_store().await;
        let (_vta_did, deps) = bootstrap_test_vta(&ts).await;
        let mut ctx = crate::contexts::create_context(&ts.contexts_ks, "prod-mediator", "Prod")
            .await
            .expect("create context");
        let pre_existing_did = "did:webvh:pre-existing.example".to_string();
        ctx.did = Some(pre_existing_did.clone());
        crate::contexts::store_context(&ts.contexts_ks, &ctx)
            .await
            .expect("pre-populate context DID");

        let auth = super_admin_claims();
        let request = signed_request_with_vars(
            "didcomm-mediator",
            "prod-mediator",
            mediator_template_vars(),
        )
        .await;

        provision_integration(
            &deps,
            &auth,
            ProvisionIntegrationParams {
                request,
                context: "prod-mediator".into(),
                assertion_mode: AssertionMode::PinnedOnly,
                vc_validity: None,
            },
        )
        .await
        .expect("provision_integration");

        let ctx_after = crate::contexts::get_context(&ts.contexts_ks, "prod-mediator")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            ctx_after.did.as_deref(),
            Some(pre_existing_did.as_str()),
            "existing primary DID must not be displaced by a later integration"
        );
    }

    #[tokio::test]
    async fn provision_integration_summary_counts_match_payload() {
        // Regression test for the hardcoded `secret_count = if admin { 2 } else { 1 }`
        // and `count_outputs_in_payload` = 1 bugs. The summary must
        // report the actual counts derived from the sealed payload's
        // contents.
        let ts = open_test_store().await;
        let (_vta_did, deps) = bootstrap_test_vta(&ts).await;
        crate::contexts::create_context(&ts.contexts_ks, "prod-mediator", "Prod")
            .await
            .expect("create context");

        let auth = super_admin_claims();
        let request = signed_request_with_vars(
            "didcomm-mediator",
            "prod-mediator",
            mediator_template_vars(),
        )
        .await;

        let output = provision_integration(
            &deps,
            &auth,
            ProvisionIntegrationParams {
                request,
                context: "prod-mediator".into(),
                assertion_mode: AssertionMode::PinnedOnly,
                vc_validity: None,
            },
        )
        .await
        .expect("provision_integration");

        // Without admin_template rollover, exactly one DID's key material
        // is sealed in (integration DID: signing + KA keys).
        assert!(
            !output.summary.admin_rolled_over,
            "no admin rollover requested"
        );
        assert_eq!(
            output.summary.secret_count, 1,
            "exactly one minted integration DID should be in the payload's secrets map"
        );
        // Serverless webvh mint produces exactly one WebvhLog output.
        assert_eq!(
            output.summary.output_count, 1,
            "exactly one webvh log output"
        );
        // And the armored bundle + OOB digest are present.
        assert!(!output.armored.is_empty(), "armored bundle populated");
        assert_eq!(
            output.digest.len(),
            64,
            "SHA-256 digest is 32 bytes hex-encoded"
        );
    }
}
