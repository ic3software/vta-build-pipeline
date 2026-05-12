//! Verifiable-Presentation → policy-`input.vp_claims` extraction
//! (plan §D4).
//!
//! Phase 1 records the raw VP as opaque JSON. Phase 2's policy
//! step needs a structured view it can pass to `join.rego` as
//! `input.vp_claims`. This module pulls a canonical projection
//! out of the VP without doing full cryptographic verification —
//! the holder-binding signature already authenticates the
//! submitter at the route layer, and full VP+VC proof checking is
//! a heavier integration (affinidi-vc, affinidi-data-integrity)
//! that the Phase 2 MVP intentionally defers.
//!
//! The extracted shape is stable wire — operator-uploaded
//! `join.rego` modules read off it:
//!
//! ```text
//! {
//!   "holder":      "<did>" | null,
//!   "credentials": [
//!     {
//!       "issuer":           "<did>" | { "id": "<did>", … },
//!       "type":             [ "VerifiableCredential", … ],
//!       "issuanceDate":     "…",       // when present on the VC
//!       "credentialSubject": { … }     // verbatim from the VC
//!     },
//!     …
//!   ]
//! }
//! ```
//!
//! Missing fields surface as `null` (holder) or empty arrays
//! (credentials, types). Operators write policies that defend
//! against those gracefully — that's the contract the default
//! `join.rego` (which accepts everything) is comfortable with.
//!
//! ## When `vp` isn't a JSON object
//!
//! Some legitimate VPs ship as JWT strings (JSON-encoded
//! compact serialisation). Phase 2 doesn't crack those open
//! — we surface them as `{ "holder": null, "credentials": [] }`
//! and let the operator's policy decide. JWT-format VP support
//! lands alongside the full VP verification milestone (Phase 3
//! or later).

use serde_json::{Map, Value as JsonValue, json};

/// Canonical `vp_claims` projection. Always returns a JSON
/// object; missing optional fields are represented per the
/// module docs.
pub fn extract_vp_claims(vp: &JsonValue) -> JsonValue {
    let vp_obj = match vp.as_object() {
        Some(o) => o,
        None => return empty_claims(),
    };

    let holder = vp_obj
        .get("holder")
        .and_then(|h| match h {
            JsonValue::String(s) => Some(JsonValue::String(s.clone())),
            // VP-1.1 allows `holder` as an object with `id`.
            JsonValue::Object(o) => o.get("id").cloned(),
            _ => None,
        })
        .unwrap_or(JsonValue::Null);

    let credentials = vp_obj
        .get("verifiableCredential")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(extract_credential)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let mut m = Map::new();
    m.insert("holder".into(), holder);
    m.insert("credentials".into(), JsonValue::Array(credentials));
    JsonValue::Object(m)
}

fn empty_claims() -> JsonValue {
    let mut m = Map::new();
    m.insert("holder".into(), JsonValue::Null);
    m.insert("credentials".into(), JsonValue::Array(Vec::new()));
    JsonValue::Object(m)
}

/// Pull the canonical projection out of one VC. Objects only;
/// JWT-encoded VC strings surface as `None` (policy sees a
/// shorter list).
fn extract_credential(vc: &JsonValue) -> Option<JsonValue> {
    let vc_obj = vc.as_object()?;
    let mut out = Map::new();
    if let Some(issuer) = vc_obj.get("issuer") {
        out.insert("issuer".into(), issuer.clone());
    } else {
        out.insert("issuer".into(), JsonValue::Null);
    }
    out.insert(
        "type".into(),
        vc_obj.get("type").cloned().unwrap_or_else(|| json!([])),
    );
    if let Some(date) = vc_obj.get("issuanceDate") {
        out.insert("issuanceDate".into(), date.clone());
    }
    if let Some(date) = vc_obj.get("validFrom") {
        out.insert("validFrom".into(), date.clone());
    }
    out.insert(
        "credentialSubject".into(),
        vc_obj
            .get("credentialSubject")
            .cloned()
            .unwrap_or(JsonValue::Null),
    );
    Some(JsonValue::Object(out))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn empty_vp_yields_empty_claims() {
        let claims = extract_vp_claims(&JsonValue::Null);
        assert_eq!(claims, json!({ "holder": null, "credentials": [] }));

        let claims = extract_vp_claims(&json!("opaque jwt string"));
        assert_eq!(claims, json!({ "holder": null, "credentials": [] }));
    }

    #[test]
    fn holder_is_extracted_from_string_or_object() {
        let s = extract_vp_claims(&json!({ "holder": "did:key:zX" }));
        assert_eq!(s["holder"], json!("did:key:zX"));

        let o = extract_vp_claims(&json!({ "holder": { "id": "did:key:zX", "name": "h" }}));
        assert_eq!(o["holder"], json!("did:key:zX"));
    }

    #[test]
    fn credentials_are_projected_in_order() {
        let vp = json!({
            "holder": "did:key:zHolder",
            "verifiableCredential": [
                {
                    "issuer": "did:key:zIssuerA",
                    "type": ["VerifiableCredential", "EmailCredential"],
                    "issuanceDate": "2026-01-01T00:00:00Z",
                    "credentialSubject": { "email": "a@example.com" }
                },
                {
                    "issuer": { "id": "did:webvh:peer.example" },
                    "type": ["VerifiableCredential", "ProofOfHumanity"],
                    "validFrom": "2026-03-01T00:00:00Z",
                    "credentialSubject": { "level": "L1" }
                }
            ]
        });
        let claims = extract_vp_claims(&vp);
        let creds = claims["credentials"].as_array().unwrap();
        assert_eq!(creds.len(), 2);

        assert_eq!(creds[0]["issuer"], json!("did:key:zIssuerA"));
        assert_eq!(creds[0]["type"][1], "EmailCredential");
        assert_eq!(creds[0]["credentialSubject"]["email"], "a@example.com");
        assert_eq!(creds[0]["issuanceDate"], "2026-01-01T00:00:00Z");

        assert_eq!(creds[1]["issuer"]["id"], "did:webvh:peer.example");
        assert_eq!(creds[1]["validFrom"], "2026-03-01T00:00:00Z");
        // VC without issuanceDate has no such key — operator policies
        // see only the fields actually present.
        assert!(creds[1].get("issuanceDate").is_none());
    }

    #[test]
    fn credentials_array_is_optional() {
        let vp = json!({ "holder": "did:key:zX" });
        let claims = extract_vp_claims(&vp);
        assert_eq!(claims["holder"], "did:key:zX");
        assert_eq!(claims["credentials"], json!([]));
    }

    #[test]
    fn jwt_encoded_vcs_in_array_are_skipped() {
        // A VP might mix JSON-encoded and JWT-encoded VCs.
        // The JWT strings are dropped from the projection until
        // full VP verification arrives.
        let vp = json!({
            "verifiableCredential": [
                "eyJhbGciOi...",
                { "issuer": "did:key:zY", "credentialSubject": {} }
            ]
        });
        let claims = extract_vp_claims(&vp);
        let creds = claims["credentials"].as_array().unwrap();
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0]["issuer"], "did:key:zY");
    }
}
