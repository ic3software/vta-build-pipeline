//! Read/replace/remove the DIDComm service entry on a DID document.
//!
//! Pure functions over `serde_json::Value`. No I/O, no keystore access.
//! Identifies the DIDComm service by `id` fragment suffix (matches the
//! fragment the workspace's setup wizard emits — `#vta-didcomm`), so
//! all existing DID documents are recognised without migration.
//!
//! Invariants:
//! - At most one `#vta-didcomm` service entry exists at any time.
//! - `verificationMethod`, `authentication`, `assertionMethod`,
//!   `keyAgreement` are NEVER touched by these helpers.
//! - All other service entries (TeeAttestation, etc.) are preserved
//!   byte-for-byte.

use serde_json::{Value, json};
use thiserror::Error;

/// Fragment used by this workspace for the DIDComm mediator service
/// entry. Matches what
/// `operations::did_webvh::document::build_did_document_inner` emits.
pub const DIDCOMM_SERVICE_FRAGMENT: &str = "#vta-didcomm";

/// A read-only view of the DIDComm service entry on a DID document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DidcommServiceRef {
    /// Full service `id` (e.g. `did:webvh:scid:host:path#vta-didcomm`).
    pub id: String,
    /// The mediator DID this entry advertises (the `uri` field of the
    /// service endpoint object, or the bare endpoint string for legacy
    /// docs).
    pub mediator_did: String,
}

#[derive(Debug, Error)]
pub enum DocumentPatchError {
    #[error("DID document is not a JSON object")]
    NotAnObject,
    #[error("DID document `id` field is missing or not a string")]
    MissingDocumentId,
    #[error("mediator DID must be a non-empty string")]
    EmptyMediatorDid,
}

/// Locate the `#vta-didcomm` service entry on `doc`, if any.
pub fn current_didcomm_service(doc: &Value) -> Option<DidcommServiceRef> {
    let services = doc.get("service")?.as_array()?;
    for svc in services {
        let id = svc.get("id")?.as_str()?;
        if id_matches_didcomm(id) {
            let mediator_did = extract_mediator_did(svc.get("serviceEndpoint")?)?;
            return Some(DidcommServiceRef {
                id: id.to_string(),
                mediator_did,
            });
        }
    }
    None
}

/// Insert or replace the `#vta-didcomm` service entry, returning the
/// updated document. Any other service entries are preserved
/// byte-for-byte; `verificationMethod` and the verification-relation
/// arrays are never touched.
pub fn with_didcomm_service(
    mut doc: Value,
    mediator_did: &str,
) -> Result<Value, DocumentPatchError> {
    if mediator_did.is_empty() {
        return Err(DocumentPatchError::EmptyMediatorDid);
    }
    let did_id = doc
        .get("id")
        .and_then(Value::as_str)
        .ok_or(DocumentPatchError::MissingDocumentId)?
        .to_string();

    let new_entry = json!({
        "id": format!("{did_id}{DIDCOMM_SERVICE_FRAGMENT}"),
        "type": "DIDCommMessaging",
        "serviceEndpoint": [{
            "accept": ["didcomm/v2"],
            "uri": mediator_did,
        }]
    });

    let obj = doc.as_object_mut().ok_or(DocumentPatchError::NotAnObject)?;

    let services = obj
        .entry("service")
        .or_insert_with(|| json!([]))
        .as_array_mut()
        .expect("service field must be an array");

    if let Some(existing) = services.iter_mut().find(|s| {
        s.get("id")
            .and_then(Value::as_str)
            .is_some_and(id_matches_didcomm)
    }) {
        *existing = new_entry;
    } else {
        services.push(new_entry);
    }

    Ok(doc)
}

/// Remove the `#vta-didcomm` service entry, if present. If the
/// resulting service array is empty, the `service` field is removed
/// entirely (matches the pre-DIDComm wizard output for REST-only VTAs
/// with no other services).
pub fn without_didcomm_service(mut doc: Value) -> Value {
    let Some(obj) = doc.as_object_mut() else {
        return doc;
    };
    let Some(services) = obj.get_mut("service").and_then(Value::as_array_mut) else {
        return doc;
    };
    services.retain(|s| {
        !s.get("id")
            .and_then(Value::as_str)
            .is_some_and(id_matches_didcomm)
    });
    if services.is_empty() {
        obj.remove("service");
    }
    doc
}

fn id_matches_didcomm(id: &str) -> bool {
    id.ends_with(DIDCOMM_SERVICE_FRAGMENT)
}

fn extract_mediator_did(endpoint: &Value) -> Option<String> {
    match endpoint {
        Value::String(s) => Some(s.clone()),
        Value::Object(map) => map.get("uri")?.as_str().map(str::to_string),
        Value::Array(arr) => arr.iter().find_map(extract_mediator_did),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vta_did() -> &'static str {
        "did:webvh:abc123:vta.example.com:vta-1"
    }

    fn doc_with_didcomm(mediator: &str) -> Value {
        json!({
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": vta_did(),
            "verificationMethod": [
                { "id": format!("{}#key-0", vta_did()), "type": "Multikey",
                  "controller": vta_did(), "publicKeyMultibase": "zfoo" },
                { "id": format!("{}#key-1", vta_did()), "type": "Multikey",
                  "controller": vta_did(), "publicKeyMultibase": "zbar" }
            ],
            "authentication": [format!("{}#key-0", vta_did())],
            "assertionMethod": [format!("{}#key-0", vta_did())],
            "keyAgreement": [format!("{}#key-1", vta_did())],
            "service": [{
                "id": format!("{}#vta-didcomm", vta_did()),
                "type": "DIDCommMessaging",
                "serviceEndpoint": [{ "accept": ["didcomm/v2"], "uri": mediator }]
            }]
        })
    }

    fn doc_without_service() -> Value {
        json!({
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": vta_did(),
            "verificationMethod": [
                { "id": format!("{}#key-0", vta_did()), "type": "Multikey",
                  "controller": vta_did(), "publicKeyMultibase": "zfoo" }
            ],
            "authentication": [format!("{}#key-0", vta_did())],
            "assertionMethod": [format!("{}#key-0", vta_did())]
        })
    }

    fn doc_with_only_tee() -> Value {
        json!({
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": vta_did(),
            "verificationMethod": [
                { "id": format!("{}#key-0", vta_did()), "type": "Multikey",
                  "controller": vta_did(), "publicKeyMultibase": "zfoo" }
            ],
            "authentication": [format!("{}#key-0", vta_did())],
            "service": [{
                "id": format!("{}#tee-attestation", vta_did()),
                "type": "TeeAttestation",
                "serviceEndpoint": "https://vta.example.com/attestation/report"
            }]
        })
    }

    #[test]
    fn current_finds_didcomm_service() {
        let doc = doc_with_didcomm("did:webvh:mediator-A");
        let svc = current_didcomm_service(&doc).expect("present");
        assert_eq!(svc.id, format!("{}#vta-didcomm", vta_did()));
        assert_eq!(svc.mediator_did, "did:webvh:mediator-A");
    }

    #[test]
    fn current_returns_none_when_absent() {
        assert!(current_didcomm_service(&doc_without_service()).is_none());
        assert!(current_didcomm_service(&doc_with_only_tee()).is_none());
    }

    #[test]
    fn current_tolerates_string_endpoint() {
        let doc = json!({
            "id": vta_did(),
            "service": [{
                "id": format!("{}#vta-didcomm", vta_did()),
                "type": "DIDCommMessaging",
                "serviceEndpoint": "did:webvh:legacy-mediator"
            }]
        });
        let svc = current_didcomm_service(&doc).unwrap();
        assert_eq!(svc.mediator_did, "did:webvh:legacy-mediator");
    }

    #[test]
    fn with_didcomm_replaces_existing_entry() {
        let doc = doc_with_didcomm("did:webvh:mediator-A");
        let patched = with_didcomm_service(doc, "did:webvh:mediator-B").unwrap();
        let svc = current_didcomm_service(&patched).unwrap();
        assert_eq!(svc.mediator_did, "did:webvh:mediator-B");
        // At-most-one invariant: only a single #vta-didcomm entry.
        let count = patched["service"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|s| {
                s["id"]
                    .as_str()
                    .map(|i| i.ends_with("#vta-didcomm"))
                    .unwrap_or(false)
            })
            .count();
        assert_eq!(count, 1);
    }

    #[test]
    fn with_didcomm_inserts_when_missing() {
        let patched = with_didcomm_service(doc_without_service(), "did:webvh:mediator-A").unwrap();
        let svc = current_didcomm_service(&patched).unwrap();
        assert_eq!(svc.mediator_did, "did:webvh:mediator-A");
        assert_eq!(patched["service"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn with_didcomm_preserves_other_services() {
        let patched = with_didcomm_service(doc_with_only_tee(), "did:webvh:mediator-A").unwrap();
        let services = patched["service"].as_array().unwrap();
        assert_eq!(services.len(), 2, "tee + didcomm");
        let tee_present = services
            .iter()
            .any(|s| s["id"].as_str().unwrap().ends_with("#tee-attestation"));
        assert!(tee_present, "TEE attestation service preserved");
    }

    #[test]
    fn with_didcomm_rejects_empty_mediator() {
        let err = with_didcomm_service(doc_without_service(), "").unwrap_err();
        assert!(matches!(err, DocumentPatchError::EmptyMediatorDid));
    }

    #[test]
    fn with_didcomm_rejects_doc_without_id() {
        let bad = json!({ "service": [] });
        let err = with_didcomm_service(bad, "did:webvh:m").unwrap_err();
        assert!(matches!(err, DocumentPatchError::MissingDocumentId));
    }

    #[test]
    fn without_didcomm_removes_only_didcomm_entry() {
        let mut doc = doc_with_didcomm("did:webvh:mediator-A");
        doc["service"].as_array_mut().unwrap().push(json!({
            "id": format!("{}#tee-attestation", vta_did()),
            "type": "TeeAttestation",
            "serviceEndpoint": "https://x"
        }));
        let stripped = without_didcomm_service(doc);
        assert!(current_didcomm_service(&stripped).is_none());
        let services = stripped["service"].as_array().unwrap();
        assert_eq!(services.len(), 1);
        assert!(
            services[0]["id"]
                .as_str()
                .unwrap()
                .ends_with("#tee-attestation")
        );
    }

    #[test]
    fn without_didcomm_drops_empty_service_array() {
        let doc = doc_with_didcomm("did:webvh:mediator-A");
        let stripped = without_didcomm_service(doc);
        assert!(
            stripped.get("service").is_none(),
            "service array removed when last entry was the DIDComm one"
        );
    }

    #[test]
    fn without_didcomm_is_noop_when_absent() {
        let original = doc_with_only_tee();
        let stripped = without_didcomm_service(original.clone());
        assert_eq!(stripped, original);
    }

    #[test]
    fn without_didcomm_handles_no_service_field() {
        let original = doc_without_service();
        let stripped = without_didcomm_service(original.clone());
        assert_eq!(stripped, original);
    }

    #[test]
    fn round_trip_with_then_without_returns_original() {
        let original = doc_without_service();
        let with_d = with_didcomm_service(original.clone(), "did:webvh:m").unwrap();
        let back = without_didcomm_service(with_d);
        assert_eq!(back, original, "round-trip with→without is identity");
    }

    #[test]
    fn verification_method_byte_identical_after_replace() {
        // The spec's load-bearing invariant: verificationMethod is never
        // touched by these helpers. Foreshadows criterion #10.
        let original = doc_with_didcomm("did:webvh:mediator-A");
        let original_vm = original["verificationMethod"].clone();
        let original_auth = original["authentication"].clone();
        let original_ka = original["keyAgreement"].clone();
        let original_assertion = original["assertionMethod"].clone();

        let patched = with_didcomm_service(original, "did:webvh:mediator-B").unwrap();
        assert_eq!(patched["verificationMethod"], original_vm);
        assert_eq!(patched["authentication"], original_auth);
        assert_eq!(patched["keyAgreement"], original_ka);
        assert_eq!(patched["assertionMethod"], original_assertion);
    }

    #[test]
    fn verification_method_byte_identical_after_remove() {
        let original = doc_with_didcomm("did:webvh:mediator-A");
        let original_vm = original["verificationMethod"].clone();
        let original_auth = original["authentication"].clone();
        let original_ka = original["keyAgreement"].clone();
        let original_assertion = original["assertionMethod"].clone();

        let stripped = without_didcomm_service(original);
        assert_eq!(stripped["verificationMethod"], original_vm);
        assert_eq!(stripped["authentication"], original_auth);
        assert_eq!(stripped["keyAgreement"], original_ka);
        assert_eq!(stripped["assertionMethod"], original_assertion);
    }
}
