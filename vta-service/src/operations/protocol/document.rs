//! Read/replace/remove the per-kind transport service entries on a
//! DID document.
//!
//! Pure functions over `serde_json::Value`. No I/O, no keystore access.
//! Identifies each kind by `id` fragment suffix (matching what the
//! workspace's setup wizard emits — `#vta-didcomm` and `#vta-rest`),
//! so all existing DID documents are recognised without migration.
//!
//! ## Invariants
//!
//! - At most one `#vta-didcomm` and one `#vta-rest` entry exists at
//!   any time.
//! - `verificationMethod`, `authentication`, `assertionMethod`,
//!   `keyAgreement` are NEVER touched by these helpers.
//! - All other service entries (TeeAttestation, etc.) are preserved
//!   byte-for-byte.
//!
//! ## REST entry shape (preserved for SDK compat)
//!
//! The REST entry rendered by [`with_rest_service`] matches the
//! shape `setup::build_vta_additional_services` has produced since
//! initial setup —
//! `{ id, type: "VTARest", serviceEndpoint: "<url>" }` with a
//! plain-string `serviceEndpoint`. The SDK's
//! `Resolved::find_service("vta-rest")` (`vta-sdk/src/session.rs:1100`)
//! depends on this; do not reshape. Reading tolerates the
//! object/array forms a future operator might paste in.

use serde_json::{Value, json};
use thiserror::Error;

/// Fragment used by this workspace for the DIDComm mediator service
/// entry. Matches what
/// `operations::did_webvh::document::build_did_document_inner` emits.
pub const DIDCOMM_SERVICE_FRAGMENT: &str = "#vta-didcomm";

/// Fragment used for the VTA's REST service entry. Matches what
/// `setup::build_vta_additional_services` emits and what
/// `vta-sdk/src/session.rs:1100` resolves against — do not change.
pub const REST_SERVICE_FRAGMENT: &str = "#vta-rest";

/// `type` literal for the REST service entry. Stable wire form;
/// renaming would silently break SDK resolution.
pub const REST_SERVICE_TYPE: &str = "VTARest";

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

/// A read-only view of the REST service entry on a DID document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestServiceRef {
    /// Full service `id` (e.g. `did:webvh:scid:host:path#vta-rest`).
    pub id: String,
    /// The URL this entry advertises. Whether the wire form was a
    /// plain string (current convention), an object with `uri`, or
    /// a single-element array, this is the resolved URL the SDK
    /// will route REST traffic to.
    pub url: String,
}

#[derive(Debug, Error)]
pub enum DocumentPatchError {
    #[error("DID document is not a JSON object")]
    NotAnObject,
    #[error("DID document `id` field is missing or not a string")]
    MissingDocumentId,
    #[error("mediator DID must be a non-empty string")]
    EmptyMediatorDid,
    #[error("REST URL must be a non-empty string")]
    EmptyRestUrl,
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

fn id_matches_rest(id: &str) -> bool {
    id.ends_with(REST_SERVICE_FRAGMENT)
}

fn extract_mediator_did(endpoint: &Value) -> Option<String> {
    match endpoint {
        Value::String(s) => Some(s.clone()),
        Value::Object(map) => map.get("uri")?.as_str().map(str::to_string),
        Value::Array(arr) => arr.iter().find_map(extract_mediator_did),
        _ => None,
    }
}

/// Resolve the URL for a REST service entry's `serviceEndpoint`,
/// tolerating the three shapes a DID document might carry it in
/// (plain string — current convention; object with `uri`; or a
/// single-element array of either).
fn extract_rest_url(endpoint: &Value) -> Option<String> {
    match endpoint {
        Value::String(s) => Some(s.clone()),
        Value::Object(map) => map.get("uri")?.as_str().map(str::to_string),
        Value::Array(arr) => arr.iter().find_map(extract_rest_url),
        _ => None,
    }
}

/// Locate the `#vta-rest` service entry on `doc`, if any.
pub fn current_rest_service(doc: &Value) -> Option<RestServiceRef> {
    let services = doc.get("service")?.as_array()?;
    for svc in services {
        let id = svc.get("id")?.as_str()?;
        if id_matches_rest(id) {
            let url = extract_rest_url(svc.get("serviceEndpoint")?)?;
            return Some(RestServiceRef {
                id: id.to_string(),
                url,
            });
        }
    }
    None
}

/// Insert or replace the `#vta-rest` service entry, returning the
/// updated document. Other service entries are preserved
/// byte-for-byte; verification methods are never touched.
///
/// The rendered shape — `type: "VTARest"` (plain string),
/// `serviceEndpoint: "<url>"` (plain string) — matches the wire
/// form `setup::build_vta_additional_services` has produced since
/// initial setup, so SDK consumers
/// (`vta-sdk/src/session.rs:1100`) keep resolving without
/// migration.
pub fn with_rest_service(mut doc: Value, url: &str) -> Result<Value, DocumentPatchError> {
    if url.is_empty() {
        return Err(DocumentPatchError::EmptyRestUrl);
    }
    let did_id = doc
        .get("id")
        .and_then(Value::as_str)
        .ok_or(DocumentPatchError::MissingDocumentId)?
        .to_string();

    let new_entry = json!({
        "id": format!("{did_id}{REST_SERVICE_FRAGMENT}"),
        "type": REST_SERVICE_TYPE,
        "serviceEndpoint": url,
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
            .is_some_and(id_matches_rest)
    }) {
        *existing = new_entry;
    } else {
        services.push(new_entry);
    }

    Ok(doc)
}

/// Remove the `#vta-rest` service entry, if present. If the
/// resulting service array is empty, the `service` field is
/// removed entirely (matches the no-services pre-mutation shape).
pub fn without_rest_service(mut doc: Value) -> Value {
    let Some(obj) = doc.as_object_mut() else {
        return doc;
    };
    let Some(services) = obj.get_mut("service").and_then(Value::as_array_mut) else {
        return doc;
    };
    services.retain(|s| {
        !s.get("id")
            .and_then(Value::as_str)
            .is_some_and(id_matches_rest)
    });
    if services.is_empty() {
        obj.remove("service");
    }
    doc
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

    // ── REST service-entry patcher tests ──────────────────────────

    fn doc_with_rest(url: &str) -> Value {
        json!({
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": vta_did(),
            "verificationMethod": [
                { "id": format!("{}#key-0", vta_did()), "type": "Multikey",
                  "controller": vta_did(), "publicKeyMultibase": "zfoo" }
            ],
            "authentication": [format!("{}#key-0", vta_did())],
            "assertionMethod": [format!("{}#key-0", vta_did())],
            "service": [{
                "id": format!("{}#vta-rest", vta_did()),
                "type": "VTARest",
                "serviceEndpoint": url,
            }]
        })
    }

    #[test]
    fn current_finds_rest_service() {
        let doc = doc_with_rest("https://vta.example.com");
        let svc = current_rest_service(&doc).expect("present");
        assert_eq!(svc.id, format!("{}#vta-rest", vta_did()));
        assert_eq!(svc.url, "https://vta.example.com");
    }

    #[test]
    fn current_rest_returns_none_when_absent() {
        assert!(current_rest_service(&doc_without_service()).is_none());
        assert!(current_rest_service(&doc_with_only_tee()).is_none());
        assert!(current_rest_service(&doc_with_didcomm("did:webvh:m")).is_none());
    }

    /// `serviceEndpoint` may be a plain string (current
    /// convention), an object with `uri`, or a one-element array
    /// of either. The reader accepts all three shapes — operators
    /// who paste DID-Core-compliant object endpoints are handled
    /// the same as those who use the workspace's plain-string
    /// convention.
    #[test]
    fn current_rest_tolerates_object_and_array_endpoints() {
        let object_endpoint = json!({
            "id": vta_did(),
            "service": [{
                "id": format!("{}#vta-rest", vta_did()),
                "type": "VTARest",
                "serviceEndpoint": { "uri": "https://obj.example.com" }
            }]
        });
        assert_eq!(
            current_rest_service(&object_endpoint).unwrap().url,
            "https://obj.example.com",
        );

        let array_endpoint = json!({
            "id": vta_did(),
            "service": [{
                "id": format!("{}#vta-rest", vta_did()),
                "type": "VTARest",
                "serviceEndpoint": ["https://arr.example.com"]
            }]
        });
        assert_eq!(
            current_rest_service(&array_endpoint).unwrap().url,
            "https://arr.example.com",
        );
    }

    #[test]
    fn with_rest_replaces_existing_entry() {
        let doc = doc_with_rest("https://old.example.com");
        let patched = with_rest_service(doc, "https://new.example.com").unwrap();
        let svc = current_rest_service(&patched).unwrap();
        assert_eq!(svc.url, "https://new.example.com");
        // At-most-one invariant.
        let count = patched["service"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|s| {
                s["id"]
                    .as_str()
                    .map(|i| i.ends_with("#vta-rest"))
                    .unwrap_or(false)
            })
            .count();
        assert_eq!(count, 1);
    }

    #[test]
    fn with_rest_inserts_when_missing() {
        let patched = with_rest_service(doc_without_service(), "https://x.example.com").unwrap();
        let svc = current_rest_service(&patched).unwrap();
        assert_eq!(svc.url, "https://x.example.com");
        assert_eq!(patched["service"].as_array().unwrap().len(), 1);
    }

    /// Wire shape preservation — the SDK depends on `type: "VTARest"`
    /// (plain string) and `serviceEndpoint: "<url>"` (plain string).
    /// Pin both.
    #[test]
    fn with_rest_emits_canonical_wire_shape() {
        let patched = with_rest_service(doc_without_service(), "https://vta.example.com").unwrap();
        let entry = &patched["service"].as_array().unwrap()[0];
        assert_eq!(entry["type"], "VTARest");
        assert_eq!(entry["serviceEndpoint"], "https://vta.example.com");
        assert!(
            entry["serviceEndpoint"].is_string(),
            "serviceEndpoint must be a plain string per session.rs:1100",
        );
    }

    #[test]
    fn with_rest_preserves_didcomm_and_tee_entries() {
        let mut doc = doc_with_didcomm("did:webvh:mediator-A");
        doc["service"].as_array_mut().unwrap().push(json!({
            "id": format!("{}#tee-attestation", vta_did()),
            "type": "TeeAttestation",
            "serviceEndpoint": "https://x"
        }));
        let patched = with_rest_service(doc, "https://vta.example.com").unwrap();
        let services = patched["service"].as_array().unwrap();
        assert_eq!(services.len(), 3, "didcomm + tee + rest");
        let didcomm_present = current_didcomm_service(&patched).is_some();
        let rest_present = current_rest_service(&patched).is_some();
        let tee_present = services
            .iter()
            .any(|s| s["id"].as_str().unwrap().ends_with("#tee-attestation"));
        assert!(didcomm_present && rest_present && tee_present);
    }

    #[test]
    fn with_rest_rejects_empty_url() {
        let err = with_rest_service(doc_without_service(), "").unwrap_err();
        assert!(matches!(err, DocumentPatchError::EmptyRestUrl));
    }

    #[test]
    fn with_rest_rejects_doc_without_id() {
        let bad = json!({ "service": [] });
        let err = with_rest_service(bad, "https://x").unwrap_err();
        assert!(matches!(err, DocumentPatchError::MissingDocumentId));
    }

    #[test]
    fn without_rest_removes_only_rest_entry() {
        let mut doc = doc_with_rest("https://x.example.com");
        // Add a didcomm + tee entry so we can verify they survive.
        doc["service"].as_array_mut().unwrap().push(json!({
            "id": format!("{}#vta-didcomm", vta_did()),
            "type": "DIDCommMessaging",
            "serviceEndpoint": [{ "accept": ["didcomm/v2"], "uri": "did:webvh:m" }]
        }));
        doc["service"].as_array_mut().unwrap().push(json!({
            "id": format!("{}#tee-attestation", vta_did()),
            "type": "TeeAttestation",
            "serviceEndpoint": "https://x"
        }));

        let stripped = without_rest_service(doc);
        assert!(current_rest_service(&stripped).is_none());
        assert!(current_didcomm_service(&stripped).is_some());
        let tee_present = stripped["service"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s["id"].as_str().unwrap().ends_with("#tee-attestation"));
        assert!(tee_present);
    }

    #[test]
    fn without_rest_drops_empty_service_array() {
        let doc = doc_with_rest("https://x.example.com");
        let stripped = without_rest_service(doc);
        assert!(stripped.get("service").is_none());
    }

    #[test]
    fn without_rest_is_noop_when_absent() {
        let original = doc_with_didcomm("did:webvh:m");
        let stripped = without_rest_service(original.clone());
        assert_eq!(stripped, original);
    }

    /// REST and DIDComm patchers compose in either order — round
    /// tripping with→without on one kind doesn't disturb the other.
    #[test]
    fn rest_and_didcomm_patchers_compose() {
        let base = doc_without_service();
        let with_d = with_didcomm_service(base.clone(), "did:webvh:m").unwrap();
        let with_both = with_rest_service(with_d, "https://x.example.com").unwrap();

        assert!(current_didcomm_service(&with_both).is_some());
        assert!(current_rest_service(&with_both).is_some());

        let only_didcomm = without_rest_service(with_both.clone());
        assert!(current_didcomm_service(&only_didcomm).is_some());
        assert!(current_rest_service(&only_didcomm).is_none());

        let only_rest = without_didcomm_service(with_both);
        assert!(current_didcomm_service(&only_rest).is_none());
        assert!(current_rest_service(&only_rest).is_some());
    }

    /// `verificationMethod` byte-identical across REST patcher
    /// operations — same load-bearing invariant as the DIDComm
    /// side.
    #[test]
    fn verification_method_byte_identical_after_rest_patches() {
        let original = doc_with_rest("https://old.example.com");
        let original_vm = original["verificationMethod"].clone();
        let original_auth = original["authentication"].clone();

        let patched = with_rest_service(original.clone(), "https://new.example.com").unwrap();
        assert_eq!(patched["verificationMethod"], original_vm);
        assert_eq!(patched["authentication"], original_auth);

        let stripped = without_rest_service(original);
        assert_eq!(stripped["verificationMethod"], original_vm);
        assert_eq!(stripped["authentication"], original_auth);
    }
}
