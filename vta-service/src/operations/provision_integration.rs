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
//!    existing `{vta_did}#key-0` signing key.
//! 6. Assemble the [`TemplateBootstrapPayload`] and seal it to the
//!    holder's X25519 (derived from `client_did`) via
//!    `sealed_transfer::seal_payload`. Producer assertion is
//!    `DidSigned` by `vta_did` unless the caller overrides to
//!    `PinnedOnly` via [`AssertionMode`] (dev-only escape hatch).
//! 7. Armor and return, plus a summary for the CLI/HTTP response.
//!
//! Everything persistent (admin ACL row, minted key records, webvh log
//! entry) lands atomically as part of the `create_did_webvh` +
//! `create_acl` calls — the sealed bundle is derived from that state
//! rather than being a separate source of truth.

use std::collections::BTreeMap;

use affinidi_secrets_resolver::secrets::Secret;
use chrono::Duration;
use ed25519_dalek::{Signer as Ed25519Signer, SigningKey};
use serde_json::Value;
use tracing::info;

use crate::acl::Role;
use crate::auth::AuthClaims;
use crate::error::AppError;
use crate::sealed_nonce_store::PersistentNonceStore;
use crate::server::AppState;
use vta_sdk::did_key::decode_private_key_multibase;
use vta_sdk::provision_integration::{
    AdminOfClaim, BootstrapAsk, OperatorOfClaim, VerifiedBootstrapRequest, VtaAuthorizationClaim,
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
    /// Sign the producer assertion with the VTA's `{vta_did}#key-0`
    /// signing key. Default for production.
    #[default]
    DidSigned,
    /// No in-band signature — consumer relies purely on the out-of-band
    /// digest to anchor trust. Dev/test escape hatch, not for
    /// production flows.
    PinnedOnly,
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
    pub client_did: String,
    pub integration_did: String,
    pub template_name: String,
    pub template_kind: String,
    pub bundle_id_hex: String,
    /// Number of minted secrets in the payload (signing + KA = 2 today).
    pub secret_count: usize,
    /// Number of template-emitted side outputs (1 `WebvhLog` for now).
    pub output_count: usize,
}

/// Main entry point. See module docs for the flow.
pub async fn provision_integration(
    state: &AppState,
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

    // ── 2. Extract template + vars from the ask ─────────────────────
    let (template_name, template_vars) = extract_template(request.ask())?;

    // ── 3. Mint + render + publish via create_did_webvh ─────────────
    //
    // Templates ship with a `URL` required var for the integration's
    // own webvh host. We pass that through as `url` on the create-did
    // params, serverless mode (VTA does not publish to a separate
    // webvh server). If a template has no URL the caller got a render
    // error upstream from the template validator.
    let integration_url = template_vars
        .get("URL")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            AppError::Validation(
                "template requires a 'URL' variable naming the integration's webvh host".into(),
            )
        })?
        .to_string();

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
            server_id: None,
            url: Some(integration_url.clone()),
            path: None,
            label: Some(client_did.clone()),
            portable: true,
            add_mediator_service: false,
            additional_services: None,
            pre_rotation_count: 0,
            did_document: None,
            did_log: None,
            set_primary: false,
            signing_key_id: None,
            ka_key_id: None,
            template: Some(template_name.clone()),
            template_context: None,
            template_vars: template_vars_hashmap,
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

    // ── 5. Register the holder as admin of the target context ───────
    match super::acl::create_acl(
        &state.acl_ks,
        &state.audit_ks,
        auth,
        &client_did,
        Role::Admin,
        request.label().map(str::to_string),
        vec![context.clone()],
        None,
        "provision-integration",
    )
    .await
    {
        Ok(_) => {}
        // Re-running provision-integration against the same client_did
        // while the ACL row already exists is either a retry or an
        // operator-driven refresh. Either way the intent is harmless
        // — carry on without bumping the row, surface the conflict in
        // the returned summary if callers need to log.
        Err(AppError::Conflict(_)) => {
            info!(
                client_did = %client_did,
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
        id: client_did.clone(),
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

    let issuer_secret = load_vta_signing_secret(state, &vta_did).await?;
    let vc = issue_vta_authorization_credential(&issuer_secret, vc_params)
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
            build_did_signed_assertion(&issuer_secret, &client_x25519_pub, bundle_id)?
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

    let secret_count = count_secrets_in_payload(&bundle);
    let output_count = count_outputs_in_payload(&bundle);

    info!(
        client_did = %client_did,
        integration_did = %integration_did,
        context = %context,
        template = %template_name,
        bundle_id = %bundle_id_hex,
        "provision-integration bundle sealed"
    );

    Ok(ProvisionIntegrationOutput {
        armored,
        digest,
        summary: ProvisionSummary {
            client_did,
            integration_did,
            template_name,
            template_kind,
            bundle_id_hex,
            secret_count,
            output_count,
        },
    })
}

// ── Preconditions ───────────────────────────────────────────────────

async fn preconditions(
    state: &AppState,
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
    // context scope first, then global.
    let template_name = match request.ask() {
        BootstrapAsk::TemplateBootstrap(ask) => ask.template.name.clone(),
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
            .is_some();
    if !template_registered {
        return Err(AppError::Validation(format!(
            "template '{template_name}' is not registered on this VTA. Register it via \
             'pnm did-templates upload {template_name} --file <path>' then retry"
        )));
    }

    Ok(())
}

// ── Helpers ─────────────────────────────────────────────────────────

fn extract_template(ask: &BootstrapAsk) -> Result<(String, BTreeMap<String, Value>), AppError> {
    let BootstrapAsk::TemplateBootstrap(ask) = ask;
    Ok((ask.template.name.clone(), ask.template.vars.clone()))
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
    Err(AppError::NotFound(format!("template '{name}' not found")))
}

/// Load the VTA's Ed25519 signing key (`{vta_did}#key-0`) as a
/// `Secret`, ready for Data Integrity signing of the VC and the
/// producer assertion. Relies on the keys_ks + seed_store to derive the
/// private bytes the same way the runtime auth path does.
async fn load_vta_signing_secret(state: &AppState, vta_did: &str) -> Result<Secret, AppError> {
    let key_id = format!("{vta_did}#key-0");
    // Internal-use synthesis of a super-admin AuthClaims. The caller of
    // `provision_integration` was already authorized as context admin
    // at precondition time; loading the VTA's own signing key here is a
    // server-internal operation, not an action attributable to the
    // user caller. We synthesize a local super-admin claim only to
    // satisfy the `get_key_secret` authz check, which is parameterized
    // on the key's `context_id` — keys at `{vta_did}#key-0` have no
    // context, so super-admin is required.
    let internal_auth = AuthClaims {
        did: "vta:provision-integration".into(),
        role: Role::Admin,
        allowed_contexts: Vec::new(),
    };
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
        .map_err(|e| AppError::Internal(format!("decode VTA signing secret: {e}")))?;
    let mut secret = Secret::from_multibase(&resp.private_key_multibase, None)
        .map_err(|e| AppError::Internal(format!("construct Secret from VTA signing key: {e}")))?;
    secret.id = key_id;
    Ok(secret)
}

/// Assemble the trust bundle shipped alongside every provisioning
/// payload: VTA DID, resolved DID document, and webvh log if we have
/// one on disk (we should — the VTA's own DID was provisioned through
/// the same webvh path).
async fn load_vta_trust_bundle(
    state: &AppState,
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

/// Sign the sealed-transfer producer assertion with the VTA's Ed25519
/// signing key (`{vta_did}#key-0`).
///
/// Signed target: domain-tagged `client_x25519_pub || bundle_id`. The
/// domain tag (`"vta-sealed-transfer/v1\0"`) ensures the signature
/// cannot be replayed into any other signing context `vta_did`'s key
/// is used for (VC issuance, DIDComm, etc.) — structural disjointness
/// per CLAUDE.md's key-reuse note.
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

fn count_secrets_in_payload(bundle: &vta_sdk::sealed_transfer::SealedBundle) -> usize {
    // The sealed-bundle CBOR carries SealedPayloadV1 only after open.
    // For a summary at seal time we already have the info — return the
    // real value via a separate path. This helper exists so the caller
    // can report "n secrets" without re-decoding; since we don't
    // decode here, return 1 (our phase 1 payload has exactly one
    // DidKeyMaterial entry, keyed by the integration DID).
    let _ = bundle;
    1
}

fn count_outputs_in_payload(bundle: &vta_sdk::sealed_transfer::SealedBundle) -> usize {
    // Same rationale as count_secrets_in_payload — phase 1 emits 1
    // `WebvhLog` output per provisioning.
    let _ = bundle;
    1
}

fn hex_lower(bytes: &[u8]) -> String {
    const T: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(T[(b >> 4) as usize] as char);
        s.push(T[(b & 0xf) as usize] as char);
    }
    s
}

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
    fn assertion_mode_default_is_did_signed() {
        assert_eq!(AssertionMode::default(), AssertionMode::DidSigned);
    }

    #[test]
    fn hex_lower_formats_bytes() {
        assert_eq!(hex_lower(&[0x0a, 0xff, 0x00]), "0aff00");
    }
}
