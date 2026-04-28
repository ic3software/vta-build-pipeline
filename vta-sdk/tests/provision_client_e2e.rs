//! Mock-based end-to-end smoke test for the online provisioning workflow.
//!
//! Drives the SDK's REST entry point (`provision_via_rest`) against a
//! wiremock-backed fake VTA. The fake decodes the VP nonce from the
//! incoming `ProvisionIntegrationRequest`, seals a synthetic
//! `TemplateBootstrapPayload` to the test's setup-key X25519 pubkey, and
//! returns the armored bundle + matching digest. This exercises the
//! HPKE seal/open + response_to_result chain that the per-runner unit
//! tests can't validate in the success direction (because they don't
//! have a way to mock a valid sealed bundle response).
//!
//! Out of scope for this file: real VTA-side template rendering, ACL
//! state-machine, DID resolution (we feed `provision_via_rest`
//! directly, bypassing `resolve_vta`).

#![cfg(all(feature = "provision-client", feature = "test-support"))]

use std::collections::BTreeMap;

use ed25519_dalek::SigningKey;
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

use vta_sdk::did_key::decode_private_key_multibase;
use vta_sdk::provision_client::ask::ProvisionAsk;
use vta_sdk::provision_client::provision_via_rest;
use vta_sdk::provision_client::result::ProvisionResult;
use vta_sdk::provision_client::setup_key::EphemeralSetupKey;
use vta_sdk::provision_integration::http::{
    ProvisionIntegrationRequest, ProvisionIntegrationResponse, ProvisionSummary,
};
use vta_sdk::provision_integration::payload::{
    DidKeyMaterial, KeyPair, TemplateBootstrapConfig, TemplateBootstrapPayload, TemplateOutput,
    VtaTrustBundle,
};
use vta_sdk::sealed_transfer::{
    AssertionProof, InMemoryNonceStore, ProducerAssertion, SealedPayloadV1, armor, bundle_digest,
    seal_payload,
};

/// Fake VTA bootstrap responder. On every POST, decodes the request VP
/// nonce, seals a synthetic `TemplateBootstrapPayload` to the test's
/// setup-key X25519 pubkey, returns the armored bundle + matching digest.
struct SealResponder {
    /// X25519 public key the bundle is sealed *to*. Derived from the
    /// test's setup `did:key` seed before the test runs.
    recipient_x_pub: [u8; 32],
    /// What the synthetic VTA "rendered" — drives the assertions in the
    /// test bodies.
    integration_did: String,
    admin_did: String,
    template_name: String,
    template_kind: String,
    /// Fixed VTA producer DID for the assertion. PinnedOnly is the
    /// simplest assertion shape; the OOB digest is the integrity anchor.
    producer_did: String,
}

impl Respond for SealResponder {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let req: ProvisionIntegrationRequest =
            serde_json::from_slice(&request.body).expect("decode ProvisionIntegrationRequest body");

        // VP nonce is a base64url-no-pad 16-byte string.
        let nonce: [u8; 16] = {
            use base64::Engine;
            use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
            let raw = B64URL.decode(&req.request.nonce).expect("nonce b64");
            raw.try_into().expect("nonce 16 bytes")
        };

        // Synthetic rendered payload — keys are placeholders; only field
        // shape matters for the open + accessor path.
        let mut secrets = BTreeMap::new();
        secrets.insert(
            self.integration_did.clone(),
            DidKeyMaterial {
                did: self.integration_did.clone(),
                signing_key: KeyPair {
                    key_id: format!("{}#key-1", self.integration_did),
                    public_key_multibase: "z6MkSyntheticIntegrationSig".into(),
                    private_key_multibase: "zSyntheticIntegrationSigPriv".into(),
                },
                ka_key: KeyPair {
                    key_id: format!("{}#key-2", self.integration_did),
                    public_key_multibase: "z6LSSyntheticIntegrationKa".into(),
                    private_key_multibase: "zSyntheticIntegrationKaPriv".into(),
                },
            },
        );
        secrets.insert(
            self.admin_did.clone(),
            DidKeyMaterial {
                did: self.admin_did.clone(),
                signing_key: KeyPair {
                    key_id: format!("{}#key-1", self.admin_did),
                    public_key_multibase: "z6MkSyntheticAdminSig".into(),
                    private_key_multibase: "zSyntheticAdminSigPriv".into(),
                },
                ka_key: KeyPair {
                    key_id: format!("{}#key-2", self.admin_did),
                    public_key_multibase: "z6LSSyntheticAdminKa".into(),
                    private_key_multibase: "zSyntheticAdminKaPriv".into(),
                },
            },
        );

        let template_payload = TemplateBootstrapPayload {
            authorization: json!({
                "type": ["VerifiableCredential", "VtaAuthorizationCredential"],
                "credentialSubject": { "id": self.admin_did }
            }),
            secrets,
            config: TemplateBootstrapConfig {
                template_name: self.template_name.clone(),
                template_kind: self.template_kind.clone(),
                did_document: json!({ "id": self.integration_did }),
                outputs: vec![TemplateOutput::WebvhLog {
                    did: self.integration_did.clone(),
                    log: "{\"versionId\":\"1-fake\"}\n".into(),
                }],
                vta_url: Some("https://vta.example.com".into()),
                vta_trust: VtaTrustBundle {
                    vta_did: self.producer_did.clone(),
                    vta_did_document: json!({ "id": self.producer_did }),
                    vta_did_log: None,
                },
            },
        };
        let sealed_payload = SealedPayloadV1::TemplateBootstrap(Box::new(template_payload));

        let producer = ProducerAssertion {
            producer_did: self.producer_did.clone(),
            proof: AssertionProof::PinnedOnly,
        };

        // seal_payload is async (NonceStore.check_and_record awaits).
        // wiremock's Respond is sync and runs from a context where the
        // current runtime's blocking helpers aren't available, so we
        // cross to a fresh thread + runtime.
        let recipient_x_pub = self.recipient_x_pub;
        let bundle = std::thread::scope(|s| {
            s.spawn(move || {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("build runtime")
                    .block_on(seal_payload(
                        &recipient_x_pub,
                        nonce,
                        producer,
                        &sealed_payload,
                        &InMemoryNonceStore::new(),
                    ))
            })
            .join()
            .expect("seal thread join")
        })
        .expect("seal payload");

        let armored = armor::encode(&bundle);
        let digest = bundle_digest(&bundle);

        let response = ProvisionIntegrationResponse {
            bundle: armored,
            digest,
            summary: ProvisionSummary {
                client_did: req.request.holder.clone(),
                admin_did: self.admin_did.clone(),
                admin_rolled_over: req.request.holder != self.admin_did,
                integration_did: self.integration_did.clone(),
                template_name: self.template_name.clone(),
                template_kind: self.template_kind.clone(),
                admin_template_name: Some("vta-admin".into()),
                bundle_id_hex: hex_lower(&nonce),
                secret_count: 2,
                output_count: 1,
                webvh_server_id: None,
            },
        };

        ResponseTemplate::new(200).set_body_json(response)
    }
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

/// Derive the X25519 pubkey for HPKE seal/open from the setup key's
/// Ed25519 seed. Mirrors what `ed25519_seed_to_x25519_secret` does on
/// the open side; `seal_payload` needs the corresponding pubkey.
fn x25519_pub_from_setup_seed(seed: &[u8; 32]) -> [u8; 32] {
    let sk = SigningKey::from_bytes(seed);
    let ed_pub = sk.verifying_key().to_bytes();
    affinidi_crypto::did_key::ed25519_pub_to_x25519_bytes(&ed_pub)
        .expect("ed25519 → x25519 pubkey conversion")
}

async fn mount_auth_mocks(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/auth/challenge"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "sessionId": "test-session",
            "data": { "challenge": "test-challenge" }
        })))
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(path("/auth/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {
                "accessToken": "test-access-token",
                "accessExpiresAt": 9999999999u64
            }
        })))
        .mount(server)
        .await;
}

/// `did:key` is self-resolving — the auth flow extracts the recipient
/// X25519 from the identifier itself, so no network roundtrip happens.
fn test_vta_did_key() -> String {
    EphemeralSetupKey::generate().unwrap().did
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn provision_via_rest_didcomm_mediator_round_trip() {
    let server = MockServer::start().await;
    mount_auth_mocks(&server).await;

    let key = EphemeralSetupKey::generate().unwrap();
    let seed: [u8; 32] = decode_private_key_multibase(key.private_key_multibase()).unwrap();
    let recipient_x_pub = x25519_pub_from_setup_seed(&seed);

    let integration_did = "did:webvh:mediator.example.com".to_string();
    let admin_did = "did:key:z6MkAdminMediator".to_string();
    Mock::given(method("POST"))
        .and(path("/bootstrap/provision-integration"))
        .respond_with(SealResponder {
            recipient_x_pub,
            integration_did: integration_did.clone(),
            admin_did: admin_did.clone(),
            template_name: "didcomm-mediator".into(),
            template_kind: "mediator".into(),
            producer_did: "did:webvh:vta.example.com".into(),
        })
        .mount(&server)
        .await;

    let ask = ProvisionAsk::didcomm_mediator("prod-mediator", "https://m.example.com");

    let result: ProvisionResult = provision_via_rest(
        &server.uri(),
        &test_vta_did_key(),
        key.did.clone(),
        key.private_key_multibase().to_string(),
        ask,
    )
    .await
    .expect("REST round-trip succeeds");

    assert_eq!(result.integration_did(), integration_did);
    assert_eq!(result.admin_did(), admin_did);
    assert_eq!(result.summary.template_name, "didcomm-mediator");
    assert_eq!(result.summary.template_kind, "mediator");
    assert!(result.summary.admin_rolled_over);
    assert!(result.integration_key().is_some());
    assert!(result.admin_key().is_some());
    assert!(result.webvh_log().is_some());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn provision_via_rest_webvh_server_round_trip() {
    let server = MockServer::start().await;
    mount_auth_mocks(&server).await;

    let key = EphemeralSetupKey::generate().unwrap();
    let seed: [u8; 32] = decode_private_key_multibase(key.private_key_multibase()).unwrap();
    let recipient_x_pub = x25519_pub_from_setup_seed(&seed);

    let integration_did = "did:webvh:service.example.com".to_string();
    let admin_did = "did:key:z6MkAdminWebvhSvc".to_string();
    Mock::given(method("POST"))
        .and(path("/bootstrap/provision-integration"))
        .respond_with(SealResponder {
            recipient_x_pub,
            integration_did: integration_did.clone(),
            admin_did: admin_did.clone(),
            template_name: "webvh-server".into(),
            template_kind: "webvh-server".into(),
            producer_did: "did:webvh:vta.example.com".into(),
        })
        .mount(&server)
        .await;

    let ask = ProvisionAsk::webvh_server("prod-webvh", "did:webvh:m.example.com");

    let result: ProvisionResult = provision_via_rest(
        &server.uri(),
        &test_vta_did_key(),
        key.did.clone(),
        key.private_key_multibase().to_string(),
        ask,
    )
    .await
    .expect("REST round-trip succeeds");

    assert_eq!(result.integration_did(), integration_did);
    assert_eq!(result.admin_did(), admin_did);
    assert_eq!(result.summary.template_name, "webvh-server");
    assert_eq!(result.summary.template_kind, "webvh-server");
}
