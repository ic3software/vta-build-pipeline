//! DID document construction for the did:webvh flow.
//!
//! Pure functions that take derived key material + config and emit a
//! DID document as `serde_json::Value`. No I/O, no keystore access —
//! tested in isolation and reused by both `create_did_webvh` (for the
//! integration's own doc) and the TEE enclave bootstrap path (for the
//! VTA's own doc, which additionally carries `#sealed-transfer-0`).
//!
//! `{DID}` placeholders in the output are substituted by the caller
//! once the webvh log has minted the self-certifying identifier; that
//! final stamping is not this module's concern.

use serde_json::json;

use crate::config::AppConfig;
use crate::keys::{self};

/// Build a DID document with the given keys.
///
/// When `include_ka` is true (default for VTA-derived keys), adds a
/// keyAgreement verification method. When false (signing-only DID),
/// the document contains only authentication/assertion.
pub fn build_did_document(
    derived: &keys::DerivedEntityKeys,
    config: &AppConfig,
    add_mediator_service: bool,
    additional_services: &Option<Vec<serde_json::Value>>,
) -> serde_json::Value {
    build_did_document_inner(
        derived,
        None,
        config,
        true,
        add_mediator_service,
        additional_services,
    )
}

/// Build a DID document for the VTA's own DID, which additionally
/// exposes `#sealed-transfer-0` as a distinct verification method.
///
/// Use this only when minting the VTA's own did:webvh — template-
/// provisioned integration DIDs should use [`build_did_document`].
pub fn build_vta_did_document_with_sealed_transfer(
    derived: &keys::DerivedEntityKeys,
    sealed_transfer: &keys::DerivedSealedTransferKey,
    config: &AppConfig,
    add_mediator_service: bool,
    additional_services: &Option<Vec<serde_json::Value>>,
) -> serde_json::Value {
    build_did_document_inner(
        derived,
        Some(sealed_transfer),
        config,
        true,
        add_mediator_service,
        additional_services,
    )
}

/// Build a DID document with optional keyAgreement support.
pub(crate) fn build_did_document_with_options(
    derived: &keys::DerivedEntityKeys,
    config: &AppConfig,
    include_ka: bool,
    add_mediator_service: bool,
    additional_services: &Option<Vec<serde_json::Value>>,
) -> serde_json::Value {
    build_did_document_inner(
        derived,
        None,
        config,
        include_ka,
        add_mediator_service,
        additional_services,
    )
}

fn build_did_document_inner(
    derived: &keys::DerivedEntityKeys,
    sealed_transfer: Option<&keys::DerivedSealedTransferKey>,
    config: &AppConfig,
    include_ka: bool,
    add_mediator_service: bool,
    additional_services: &Option<Vec<serde_json::Value>>,
) -> serde_json::Value {
    let mut vm = vec![json!({
        "id": "{DID}#key-0",
        "type": "Multikey",
        "controller": "{DID}",
        "publicKeyMultibase": &derived.signing_pub
    })];

    let mut assertion_method = vec![json!("{DID}#key-0")];

    let mut did_document = json!({
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://www.w3.org/ns/cid/v1"
        ],
        "id": "{DID}",
        "authentication": ["{DID}#key-0"]
    });

    if include_ka {
        vm.push(json!({
            "id": "{DID}#key-1",
            "type": "Multikey",
            "controller": "{DID}",
            "publicKeyMultibase": &derived.ka_pub
        }));
        did_document["keyAgreement"] = json!(["{DID}#key-1"]);
    }

    if let Some(st) = sealed_transfer {
        vm.push(json!({
            "id": "{DID}#sealed-transfer-0",
            "type": "Multikey",
            "controller": "{DID}",
            "publicKeyMultibase": &st.public_key
        }));
        // Sealed-transfer signatures are assertion-flavoured (the VTA
        // asserting "I produced this bundle"), so the key appears in
        // assertionMethod alongside `#key-0`.
        assertion_method.push(json!("{DID}#sealed-transfer-0"));
    }

    did_document["assertionMethod"] = json!(assertion_method);
    did_document["verificationMethod"] = json!(vm);

    // Optionally add mediator DIDComm service
    if add_mediator_service && let Some(ref msg) = config.messaging {
        let services = did_document
            .as_object_mut()
            .unwrap()
            .entry("service")
            .or_insert_with(|| json!([]));
        services.as_array_mut().unwrap().push(json!({
            "id": "{DID}#vta-didcomm",
            "type": "DIDCommMessaging",
            "serviceEndpoint": [{
                "accept": ["didcomm/v2"],
                "uri": msg.mediator_did
            }]
        }));
    }

    // Append any additional services
    if let Some(svcs) = additional_services {
        let services = did_document
            .as_object_mut()
            .unwrap()
            .entry("service")
            .or_insert_with(|| json!([]));
        for svc in svcs {
            services.as_array_mut().unwrap().push(svc.clone());
        }
    }

    // Add TeeAttestation service when TEE is active and embed_in_did is enabled
    #[cfg(feature = "tee")]
    if config.tee.embed_in_did
        && let Some(ref public_url) = config.public_url
    {
        let services = did_document
            .as_object_mut()
            .unwrap()
            .entry("service")
            .or_insert_with(|| json!([]));
        services.as_array_mut().unwrap().push(json!({
            "id": "{DID}#tee-attestation",
            "type": "TeeAttestation",
            "serviceEndpoint": format!("{}/attestation/report", public_url.trim_end_matches('/'))
        }));
    }

    did_document
}
