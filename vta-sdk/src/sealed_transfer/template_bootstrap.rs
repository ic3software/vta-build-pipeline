//! `SealedPayloadV1::TemplateBootstrap` payload shape.
//!
//! Lives under `sealed_transfer` (not `provision_integration`) so the
//! enum variant compiles whenever the `sealed-transfer` feature is on —
//! opening a bundle never requires `affinidi-vc`. The VC inside is
//! stored as `serde_json::Value`; consumers that want a typed view parse
//! it via `crate::provision_integration::credential`.
//!
//! Carries:
//! - The VTA-issued admin-authorization VC (short-lived, opaque JSON).
//! - Private key material the VTA minted for DIDs the integration will
//!   operate (zeroized on drop).
//! - First-boot config (template outputs, VTA trust bundle, connect URL).
//!
//! See `docs/03-integrating/provision-integration.md` §"Payload" for the full
//! design.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Top-level payload for `SealedPayloadV1::TemplateBootstrap`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemplateBootstrapPayload {
    /// VTA-issued `VtaAuthorizationCredential`. Short-lived; verified at
    /// bundle open; never re-verified after that (ACL is the steady-
    /// state authority).
    pub authorization: serde_json::Value,

    /// Private key material for DIDs the VTA minted on the integration's
    /// behalf, keyed by DID URI. Usually one entry (the agent DID the
    /// template rendered); may be empty if the template only needed
    /// admin-level authorization.
    pub secrets: BTreeMap<String, DidKeyMaterial>,

    /// Non-credential first-boot configuration.
    pub config: TemplateBootstrapConfig,
}

/// Key material for a single DID the integration now controls. Secret
/// bytes are zeroized on drop.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DidKeyMaterial {
    /// The DID this material is for (e.g. the rendered integration DID).
    pub did: String,
    /// Ed25519 signing keypair.
    pub signing_key: KeyPair,
    /// X25519 key-agreement keypair.
    pub ka_key: KeyPair,
}

/// A single keypair with DID-URL-qualified key id. The private half is
/// held in a [`Zeroizing`] buffer at rest.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyPair {
    /// DID URL with fragment, e.g. `did:webvh:host/path#key-1`. Matches
    /// the `id` of the corresponding verification method in the DID doc.
    pub key_id: String,
    /// Multibase-encoded public key.
    pub public_key_multibase: String,
    /// Multibase-encoded private key. Not zeroized during serde to keep
    /// the derived `Serialize`/`Deserialize` simple; wrap in
    /// [`Zeroizing`] via [`Self::private_zeroizing`] when loading into
    /// live memory.
    pub private_key_multibase: String,
}

impl KeyPair {
    /// Take the private key out into a [`Zeroizing`] buffer. Call at
    /// the moment you use the key (e.g. feed to a signer) so the
    /// cleartext scalar lives on the stack for as little time as
    /// possible.
    pub fn private_zeroizing(&self) -> Zeroizing<String> {
        Zeroizing::new(self.private_key_multibase.clone())
    }
}

/// First-boot configuration carried alongside the authorization VC.
/// Non-credential data: template metadata, rendered DID document,
/// template-declared side outputs, connect URL, VTA trust material.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemplateBootstrapConfig {
    /// Name of the template the VTA rendered (audit).
    pub template_name: String,
    /// Template's `kind` field (`"mediator"`, `"webvh-hosting"`, etc.).
    /// Consumers dispatch on this for kind-specific handling.
    pub template_kind: String,
    /// The fully-rendered DID document for the integration's DID, as
    /// JSON. The integration's own webvh host should publish this.
    pub did_document: serde_json::Value,
    /// Template-declared side outputs (e.g. `did.jsonl` log for webvh,
    /// DIDComm service advertisement for mediators).
    pub outputs: Vec<TemplateOutput>,
    /// URL the integration should use to reach the VTA's REST API.
    /// None when the integration doesn't make outbound VTA calls.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vta_url: Option<String>,
    /// VTA identity material — enough for the integration to verify the
    /// authorization VC offline at first boot.
    pub vta_trust: VtaTrustBundle,
}

/// Side outputs a template renderer emits alongside the DID document.
///
/// Typed variants exist for output kinds every VTA deployment knows
/// about; a catch-all [`Self::Generic`] variant carries arbitrary
/// template-declared outputs so operator-uploaded templates that need
/// novel first-boot artefacts (status-list URLs, OOB invitations, TLS
/// CSRs, webhook configs, …) work without an SDK change.
///
/// Downstream consumers that understand a specific `kind` string match
/// on `Generic { kind, payload }` for that kind; everything else they
/// forward to a default handler or log-and-ignore. Preserves the
/// "uploading a template is the whole author surface for new
/// integrations" invariant from `CLAUDE.md`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TemplateOutput {
    /// Raw `did.jsonl` log for a `did:webvh` DID. The integration writes
    /// this to `/.well-known/did.jsonl` on its own webvh host at first
    /// boot.
    WebvhLog {
        /// Which DID the log describes.
        did: String,
        /// Raw newline-delimited JSON log content.
        log: String,
    },
    /// DIDComm v2 service-endpoint advertisement the integration should
    /// publish on its DID doc (and which the template already embedded
    /// there — duplicated here for operational config convenience).
    DidCommService {
        /// Which DID the service belongs to.
        did: String,
        url: String,
        accept: Vec<String>,
        routing_keys: Vec<String>,
    },
    /// Extensibility escape hatch for template-declared outputs the SDK
    /// doesn't know about. `kind` is a short string the template author
    /// picks (lowercase kebab-case by convention — e.g. `status-list`,
    /// `oob-invitation`, `tls-csr`). `payload` is whatever JSON the
    /// template emitted; consumers dispatch on `kind` and parse
    /// `payload` as their expected shape.
    Generic {
        /// Caller-chosen tag identifying the output kind. Must not
        /// collide with the snake_case discriminant of an existing
        /// typed variant (`webvh_log`, `didcomm_service`) — consumers
        /// match typed variants first, so a `Generic { kind:
        /// "webvh_log", … }` would still deserialize as
        /// `Generic` but shadow nothing, just confuse readers. Enforce
        /// naming elsewhere (template validator) rather than in the
        /// wire shape.
        kind: String,
        /// Free-form JSON the template author produced. Consumers that
        /// understand `kind` parse this into a typed shape of their
        /// own; consumers that don't log + skip.
        payload: serde_json::Value,
    },
}

/// VTA identity material an integration needs to verify the returned
/// sealed bundle's contents offline.
///
/// Shipped *inside* every provisioning bundle. On first boot the
/// integration:
///   1. Takes `vta_did_document` as the trust anchor.
///   2. If `vta_did_log` is present, replays the log and confirms the
///      rendered doc matches — cross-verifying the shipped doc.
///   3. Extracts the `assertionMethod` verification method from the doc
///      and uses it to verify the authorization VC's proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VtaTrustBundle {
    pub vta_did: String,
    pub vta_did_document: serde_json::Value,
    /// Raw `did.jsonl` for `did:webvh` VTAs — lets the integration
    /// verify the doc independently. None for self-resolving methods
    /// like `did:key`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vta_did_log: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sealed_transfer::SealedPayloadV1;
    use serde_json::json;

    fn sample_payload() -> TemplateBootstrapPayload {
        TemplateBootstrapPayload {
            authorization: json!({ "type": ["VerifiableCredential", "VtaAuthorizationCredential"] }),
            secrets: BTreeMap::from([(
                "did:webvh:mediator.example.com".to_string(),
                DidKeyMaterial {
                    did: "did:webvh:mediator.example.com".into(),
                    signing_key: KeyPair {
                        key_id: "did:webvh:mediator.example.com#key-1".into(),
                        public_key_multibase: "z6Mk...".into(),
                        private_key_multibase: "z...".into(),
                    },
                    ka_key: KeyPair {
                        key_id: "did:webvh:mediator.example.com#key-2".into(),
                        public_key_multibase: "z6LS...".into(),
                        private_key_multibase: "z...".into(),
                    },
                },
            )]),
            config: TemplateBootstrapConfig {
                template_name: "didcomm-mediator".into(),
                template_kind: "mediator".into(),
                did_document: json!({ "id": "did:webvh:mediator.example.com" }),
                outputs: vec![TemplateOutput::WebvhLog {
                    did: "did:webvh:mediator.example.com".into(),
                    log: "{...}".into(),
                }],
                vta_url: Some("https://vta.example.com".into()),
                vta_trust: VtaTrustBundle {
                    vta_did: "did:webvh:vta.example.com".into(),
                    vta_did_document: json!({ "id": "did:webvh:vta.example.com" }),
                    vta_did_log: Some("{...}".into()),
                },
            },
        }
    }

    #[test]
    fn template_bootstrap_payload_json_round_trip() {
        let payload = sample_payload();
        let json = serde_json::to_string(&payload).unwrap();
        let parsed: TemplateBootstrapPayload = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.config.template_name, "didcomm-mediator");
        assert_eq!(parsed.secrets.len(), 1);
    }

    #[test]
    fn sealed_payload_variant_round_trip() {
        let payload = SealedPayloadV1::TemplateBootstrap(Box::new(sample_payload()));
        // JSON round-trip.
        let json = serde_json::to_string(&payload).unwrap();
        let parsed: SealedPayloadV1 = serde_json::from_str(&json).unwrap();
        match parsed {
            SealedPayloadV1::TemplateBootstrap(p) => {
                assert_eq!(p.config.template_kind, "mediator");
                assert_eq!(p.config.outputs.len(), 1);
            }
            other => panic!("expected TemplateBootstrap, got {other:?}"),
        }
    }

    #[test]
    fn template_output_webvh_log_tag_on_wire() {
        // The `type` tag in the enum's wire form should be snake_case
        // (`webvh_log`, `did_comm_service`) — matches existing
        // SealedPayloadV1 convention and is stable across the wire.
        let out = TemplateOutput::WebvhLog {
            did: "did:webvh:x".into(),
            log: "line".into(),
        };
        let v = serde_json::to_value(&out).unwrap();
        assert_eq!(v["type"], "webvh_log");
    }

    #[test]
    fn template_output_generic_round_trips_arbitrary_payload() {
        // Generic extensibility: a template author who needs a novel
        // first-boot artefact (e.g. a status-list URL, OOB invitation,
        // TLS CSR) embeds it via TemplateOutput::Generic without an
        // SDK change. Wire shape preserves the kind tag + free-form
        // JSON payload verbatim through serialize → deserialize.
        let original = TemplateOutput::Generic {
            kind: "status-list".into(),
            payload: json!({
                "statusListUrl": "https://issuer.example.com/status",
                "expires": "2026-12-31T00:00:00Z",
            }),
        };
        let wire = serde_json::to_value(&original).unwrap();
        assert_eq!(wire["type"], "generic");
        assert_eq!(wire["kind"], "status-list");
        assert_eq!(
            wire["payload"]["statusListUrl"],
            "https://issuer.example.com/status"
        );

        let parsed: TemplateOutput = serde_json::from_value(wire).unwrap();
        match parsed {
            TemplateOutput::Generic { kind, payload } => {
                assert_eq!(kind, "status-list");
                assert_eq!(payload["expires"], "2026-12-31T00:00:00Z");
            }
            other => panic!("expected Generic, got {other:?}"),
        }
    }

    #[test]
    fn template_output_generic_coexists_with_typed_variants() {
        // An outputs vec can mix typed + generic entries — simulates
        // a template that emits both a standard WebvhLog and a
        // novel side output.
        let outputs = vec![
            TemplateOutput::WebvhLog {
                did: "did:webvh:mediator.example".into(),
                log: "one\ntwo\n".into(),
            },
            TemplateOutput::Generic {
                kind: "oob-invitation".into(),
                payload: json!({"url": "https://mediator.example/oob?c=abc"}),
            },
        ];
        let wire = serde_json::to_string(&outputs).unwrap();
        let parsed: Vec<TemplateOutput> = serde_json::from_str(&wire).unwrap();
        assert_eq!(parsed.len(), 2);
        assert!(matches!(parsed[0], TemplateOutput::WebvhLog { .. }));
        match &parsed[1] {
            TemplateOutput::Generic { kind, .. } => assert_eq!(kind, "oob-invitation"),
            other => panic!("expected Generic at index 1, got {other:?}"),
        }
    }
}
