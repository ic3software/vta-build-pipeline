//! End-to-end tests for template parsing, validation, and rendering.

use serde_json::{Value, json};

use super::*;

fn base_doc() -> Value {
    json!({
        "id": "{DID}",
        "verificationMethod": [{
            "id": "{DID}#key-1",
            "publicKeyMultibase": "{SIGNING_KEY_MB}"
        }]
    })
}

fn base_template(extra: Value) -> Value {
    let mut v = json!({
        "schemaVersion": 1,
        "name": "test-template",
        "kind": "custom",
        "requiredVars": [],
        "optionalVars": {},
        "document": base_doc()
    });
    let obj = v.as_object_mut().unwrap();
    for (k, val) in extra.as_object().unwrap() {
        obj.insert(k.clone(), val.clone());
    }
    v
}

fn ambient_vars() -> TemplateVars {
    let mut v = TemplateVars::new();
    v.insert_string("DID", "did:webvh:example.com:abc");
    v.insert_string("SIGNING_KEY_MB", "z6MkSigning");
    v
}

// ─── validation ──────────────────────────────────────────────────────

#[test]
fn rejects_unsupported_schema_version() {
    let raw = base_template(json!({ "schemaVersion": 99 }));
    let err = DidTemplate::from_json(raw).unwrap_err();
    assert!(matches!(
        err,
        TemplateError::UnsupportedSchema { found: 99, .. }
    ));
}

#[test]
fn rejects_bad_name() {
    let raw = base_template(json!({ "name": "Has Space" }));
    let err = DidTemplate::from_json(raw).unwrap_err();
    assert!(matches!(err, TemplateError::Invalid(_)));
}

#[test]
fn rejects_document_without_did_placeholder() {
    let raw = base_template(json!({
        "document": { "id": "did:example:fixed" }
    }));
    let err = DidTemplate::from_json(raw).unwrap_err();
    assert!(
        matches!(&err, TemplateError::Invalid(msg) if msg.contains("{DID}")),
        "got: {err}"
    );
}

#[test]
fn rejects_reserved_name_in_required_vars() {
    let raw = base_template(json!({ "requiredVars": ["DID"] }));
    let err = DidTemplate::from_json(raw).unwrap_err();
    assert!(matches!(err, TemplateError::ReservedVar(v) if v == "DID"));
}

#[test]
fn rejects_reserved_name_in_optional_vars() {
    let raw = base_template(json!({
        "optionalVars": { "NOW": "x" }
    }));
    let err = DidTemplate::from_json(raw).unwrap_err();
    assert!(matches!(err, TemplateError::ReservedVar(v) if v == "NOW"));
}

#[test]
fn rejects_variable_in_both_lists() {
    let raw = base_template(json!({
        "requiredVars": ["URL"],
        "optionalVars": { "URL": "x" },
        "document": {
            "id": "{DID}",
            "url": "{URL}"
        }
    }));
    let err = DidTemplate::from_json(raw).unwrap_err();
    assert!(
        matches!(&err, TemplateError::Invalid(m) if m.contains("both")),
        "got: {err}"
    );
}

#[test]
fn rejects_undeclared_placeholder() {
    let raw = base_template(json!({
        "document": {
            "id": "{DID}",
            "mystery": "{NOT_DECLARED}"
        }
    }));
    let err = DidTemplate::from_json(raw).unwrap_err();
    assert!(
        matches!(&err, TemplateError::Invalid(m) if m.contains("NOT_DECLARED")),
        "got: {err}"
    );
}

// ─── render ──────────────────────────────────────────────────────────

#[test]
fn renders_embedded_string_placeholder() {
    let raw = base_template(json!({
        "requiredVars": ["URL"],
        "document": {
            "id": "{DID}",
            "uri": "prefix-{URL}-suffix"
        }
    }));
    let tpl = DidTemplate::from_json(raw).unwrap();
    let mut vars = ambient_vars();
    vars.insert_string("URL", "https://m.example.com");

    let out = tpl.render(&vars).unwrap();
    assert_eq!(out["uri"], "prefix-https://m.example.com-suffix");
    assert_eq!(out["id"], "did:webvh:example.com:abc");
}

#[test]
fn whole_string_token_substitutes_native_type() {
    let raw = base_template(json!({
        "optionalVars": {
            "ROUTING_KEYS": ["did:key:fallback"]
        },
        "document": {
            "id": "{DID}",
            "routingKeys": "{ROUTING_KEYS}",
            "accept": "{ACCEPT}"
        },
        "requiredVars": ["ACCEPT"]
    }));
    let tpl = DidTemplate::from_json(raw).unwrap();

    let mut vars = ambient_vars();
    vars.insert("ACCEPT", json!(["didcomm/v2", "didcomm/v1"]));
    vars.insert("ROUTING_KEYS", json!(["did:key:z6Mk1", "did:key:z6Mk2"]));

    let out = tpl.render(&vars).unwrap();
    assert_eq!(
        out["routingKeys"],
        json!(["did:key:z6Mk1", "did:key:z6Mk2"])
    );
    assert_eq!(out["accept"], json!(["didcomm/v2", "didcomm/v1"]));
}

#[test]
fn optional_var_default_used_when_caller_omits() {
    let raw = base_template(json!({
        "optionalVars": {
            "HOSTING_PATH": "/default-path"
        },
        "document": {
            "id": "{DID}",
            "path": "{HOSTING_PATH}"
        }
    }));
    let tpl = DidTemplate::from_json(raw).unwrap();
    let out = tpl.render(&ambient_vars()).unwrap();
    assert_eq!(out["path"], "/default-path");
}

#[test]
fn caller_vars_override_optional_defaults() {
    let raw = base_template(json!({
        "optionalVars": {
            "HOSTING_PATH": "/default-path"
        },
        "document": {
            "id": "{DID}",
            "path": "{HOSTING_PATH}"
        }
    }));
    let tpl = DidTemplate::from_json(raw).unwrap();
    let mut vars = ambient_vars();
    vars.insert_string("HOSTING_PATH", "/custom");
    let out = tpl.render(&vars).unwrap();
    assert_eq!(out["path"], "/custom");
}

#[test]
fn missing_required_var_errors_with_name() {
    let raw = base_template(json!({
        "requiredVars": ["URL"],
        "document": {
            "id": "{DID}",
            "uri": "{URL}"
        }
    }));
    let tpl = DidTemplate::from_json(raw).unwrap();
    let err = tpl.render(&ambient_vars()).unwrap_err();
    assert!(
        matches!(&err, TemplateError::MissingVars(m) if m.contains("URL")),
        "got: {err}"
    );
}

#[test]
fn ambient_var_missing_surfaces_as_unresolved() {
    let raw = base_template(json!({
        "document": {
            "id": "{DID}",
            "vtaDid": "{VTA_DID}"
        }
    }));
    let tpl = DidTemplate::from_json(raw).unwrap();
    // Provide DID + SIGNING_KEY_MB but NOT VTA_DID (both are reserved ambient).
    let err = tpl.render(&ambient_vars()).unwrap_err();
    assert!(
        matches!(&err, TemplateError::Unresolved(m) if m.contains("VTA_DID")),
        "got: {err}"
    );
}

#[test]
fn lowercase_braces_are_not_placeholders() {
    let raw = base_template(json!({
        "document": {
            "id": "{DID}",
            "note": "literal {lowercase} stays"
        }
    }));
    let tpl = DidTemplate::from_json(raw).unwrap();
    let out = tpl.render(&ambient_vars()).unwrap();
    assert_eq!(out["note"], "literal {lowercase} stays");
}

#[test]
fn placeholders_in_nested_arrays_and_objects() {
    let raw = base_template(json!({
        "requiredVars": ["URL"],
        "document": {
            "id": "{DID}",
            "service": [
                {
                    "id": "{DID}#svc",
                    "serviceEndpoint": { "uri": "{URL}" }
                }
            ]
        }
    }));
    let tpl = DidTemplate::from_json(raw).unwrap();
    let mut vars = ambient_vars();
    vars.insert_string("URL", "https://svc.example.com");
    let out = tpl.render(&vars).unwrap();
    assert_eq!(out["service"][0]["id"], "did:webvh:example.com:abc#svc");
    assert_eq!(
        out["service"][0]["serviceEndpoint"]["uri"],
        "https://svc.example.com"
    );
}

#[test]
fn provided_token_may_pass_through_as_sentinel() {
    // A caller supplying `DID = "{DID}"` means "leave this literal alone for
    // a downstream library to resolve" — render must not flag it.
    let raw = base_template(json!({
        "document": {
            "id": "{DID}",
            "verificationMethod": [{
                "id": "{DID}#key-1",
                "publicKeyMultibase": "{SIGNING_KEY_MB}"
            }]
        }
    }));
    let tpl = DidTemplate::from_json(raw).unwrap();

    let mut vars = TemplateVars::new();
    vars.insert_string("DID", "{DID}");
    vars.insert_string("SIGNING_KEY_MB", "z6MkReal");

    let out = tpl.render(&vars).unwrap();
    assert_eq!(out["id"], "{DID}");
    assert_eq!(out["verificationMethod"][0]["id"], "{DID}#key-1");
    assert_eq!(
        out["verificationMethod"][0]["publicKeyMultibase"],
        "z6MkReal"
    );
}

#[test]
fn utf8_strings_survive_substitution() {
    let raw = base_template(json!({
        "requiredVars": ["LABEL"],
        "document": {
            "id": "{DID}",
            "label": "café-{LABEL}-résumé"
        }
    }));
    let tpl = DidTemplate::from_json(raw).unwrap();
    let mut vars = ambient_vars();
    vars.insert_string("LABEL", "naïve");
    let out = tpl.render(&vars).unwrap();
    assert_eq!(out["label"], "café-naïve-résumé");
}

// ─── built-ins ───────────────────────────────────────────────────────

#[test]
fn didcomm_mediator_builtin_renders_end_to_end() {
    let tpl = load_embedded("didcomm-mediator").unwrap();
    let mut vars = TemplateVars::new();
    vars.insert_string("DID", "did:webvh:example.com:mediator");
    vars.insert_string("SIGNING_KEY_MB", "z6MkSign");
    vars.insert_string("KA_KEY_MB", "z6LSKa");
    vars.insert_string("URL", "https://mediator.example.com");

    let doc = tpl.render(&vars).unwrap();
    assert_eq!(doc["id"], "did:webvh:example.com:mediator");
    assert_eq!(doc["service"][0]["type"], "DIDCommMessaging");
    assert_eq!(
        doc["service"][0]["serviceEndpoint"]["uri"],
        "https://mediator.example.com"
    );
    // Optional default flowed through as a native array, not a string.
    assert_eq!(
        doc["service"][0]["serviceEndpoint"]["accept"],
        json!(["didcomm/v2"])
    );
    assert_eq!(
        doc["service"][0]["serviceEndpoint"]["routingKeys"],
        json!([])
    );
}

#[test]
fn vta_admin_builtin_renders_end_to_end() {
    // The vta-admin template is a did:key shape — no required vars beyond
    // the ambient {DID} + {SIGNING_KEY_MB} the renderer / VTA always
    // supplies. No service endpoints, no key-agreement VM (X25519 is
    // derived on demand from the Ed25519 pub by did:key resolvers).
    let tpl = load_embedded("vta-admin").unwrap();
    assert_eq!(tpl.kind, "admin");
    assert!(tpl.required_vars.is_empty());
    assert!(tpl.optional_vars.is_empty());

    let mut vars = TemplateVars::new();
    vars.insert_string("DID", "did:key:z6MkAdminPub");
    vars.insert_string("SIGNING_KEY_MB", "z6MkAdminPub");

    let doc = tpl.render(&vars).unwrap();
    assert_eq!(doc["id"], "did:key:z6MkAdminPub");
    assert_eq!(
        doc["verificationMethod"][0]["id"],
        "did:key:z6MkAdminPub#z6MkAdminPub"
    );
    assert_eq!(
        doc["verificationMethod"][0]["publicKeyMultibase"],
        "z6MkAdminPub"
    );
    assert!(doc.get("service").is_none(), "admin DID has no service");
}

#[test]
fn webvh_hosting_builtin_renders_end_to_end() {
    let tpl = load_embedded("webvh-hosting-server").unwrap();
    let mut vars = TemplateVars::new();
    vars.insert_string("DID", "did:webvh:example.com:host");
    vars.insert_string("SIGNING_KEY_MB", "z6MkSign");
    vars.insert_string("KA_KEY_MB", "z6LSKa");
    vars.insert_string("URL", "https://host.example.com");

    let doc = tpl.render(&vars).unwrap();
    assert_eq!(doc["service"][0]["type"], "WebVHHosting");
    // Default path applied.
    assert_eq!(
        doc["service"][0]["serviceEndpoint"]["hostingPath"],
        "/webvh"
    );
}
