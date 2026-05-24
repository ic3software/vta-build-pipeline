//! Passkey login — DID-VM-resolved WebAuthn assertion verification.
//!
//! Wires the `vti-webauthn` crate into vta-service. Drives the
//! `vta/auth/passkey-login-{start,finish}/1.0` trust-task surface
//! (per `docs/05-design-notes/trust-task-uri-registry.md`).
//!
//! Distinct from [`crate::operations::passkey_vms`], which handles the
//! *enrolment* ceremony (adding a passkey VM to a DID document). This
//! module handles the *assertion* path — verifying that an inbound
//! WebAuthn assertion was produced by the key in a DID-resolved VM.

#![allow(dead_code)] // wired up incrementally; remove once handlers consume the operation.

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use async_trait::async_trait;
use serde_json::Value;

use vti_webauthn::{
    ResolvedVm, ResolverError, VerifierConfig, VerifyError, VmResolver, multikey,
    payload::AssertionPayload, payload::VerifiedAssertion, verify_assertion,
};

/// Adapter that implements [`VmResolver`] over vta-service's existing
/// [`DIDCacheClient`].
///
/// Resolution path:
/// 1. Split `vm_url` into `did` + `#fragment`.
/// 2. Resolve the DID via the cache client.
/// 3. Serialise the DID document to JSON.
/// 4. Locate the VM in `verificationMethod` whose `id` matches the
///    requested URL (accepts either absolute or `#fragment` form).
/// 5. Decode `publicKeyMultibase` via
///    [`vti_webauthn::multikey::decode_multikey`].
/// 6. Return [`ResolvedVm`].
///
/// Only `publicKeyMultibase`-encoded VMs are supported in v0.1.
/// `publicKeyJwk`-only VMs are rejected as malformed — operators can
/// add JWK support in a v0.2 follow-up if a real-world DID method
/// emits them.
pub struct VtaVmResolver {
    did_resolver: DIDCacheClient,
}

impl VtaVmResolver {
    /// Construct a resolver over the supplied DID cache client.
    ///
    /// Typically the caller is `AppState::did_resolver` (Option-stripped
    /// at the call site — passkey login requires DID resolution to work
    /// and should be refused early if the resolver isn't configured).
    pub fn new(did_resolver: DIDCacheClient) -> Self {
        Self { did_resolver }
    }
}

#[async_trait]
impl VmResolver for VtaVmResolver {
    async fn resolve_vm(&self, vm_url: &str) -> Result<ResolvedVm, ResolverError> {
        // 1. Split DID + fragment.
        let (did, _fragment) = vm_url.split_once('#').ok_or_else(|| {
            ResolverError::MalformedVm("verification_method URL must contain '#fragment'".into())
        })?;

        // 2. Resolve the DID.
        let resolved = self
            .did_resolver
            .resolve(did)
            .await
            .map_err(|e| ResolverError::UnresolvableDid(format!("{e}")))?;

        // 3. Serialise to JSON for shape-agnostic navigation. Avoids
        //    coupling this crate to a specific ssi-dids-core type
        //    version — the DID Core JSON shape is the stable contract.
        let doc_value: Value = serde_json::to_value(&resolved.doc).map_err(|e| {
            ResolverError::MalformedVm(format!("DID document serialise failed: {e}"))
        })?;

        // 4. Locate the matching VM. VM ids can be absolute
        //    (`did:webvh:...:alice#passkey-abc`) or relative
        //    (`#passkey-abc`); accept either to keep this code
        //    insensitive to DID-method serialisation choices.
        let vms = doc_value
            .get("verificationMethod")
            .and_then(|v| v.as_array())
            .ok_or(ResolverError::NotFound)?;

        let relative = match vm_url.split_once('#') {
            Some((_, frag)) => format!("#{frag}"),
            None => String::new(),
        };

        let vm = vms
            .iter()
            .find(|vm| {
                let id = vm.get("id").and_then(|v| v.as_str()).unwrap_or("");
                id == vm_url || id == relative
            })
            .ok_or(ResolverError::NotFound)?;

        // 5. Extract publicKeyMultibase and decode.
        let multibase_str = vm
            .get("publicKeyMultibase")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                ResolverError::MalformedVm(
                    "verification method has no publicKeyMultibase \
                     (only Multikey-encoded VMs are supported in v0.1)"
                        .into(),
                )
            })?;

        let (algorithm, public_key_bytes) = multikey::decode_multikey(multibase_str)?;

        // 6. Controller — defaults to the DID itself if not declared
        //    (W3C DID Core §5.1.2 default).
        let controller = vm
            .get("controller")
            .and_then(|v| v.as_str())
            .unwrap_or(did)
            .to_string();

        Ok(ResolvedVm {
            algorithm,
            public_key_bytes,
            controller,
        })
    }
}

/// Verify a passkey-login assertion against a DID-resolved VM and
/// return the authentication outcome.
///
/// The caller (the route handler for
/// `POST /auth/passkey-login/finish`) supplies the assertion bytes
/// (already base64url-decoded), the server-issued challenge nonce,
/// the resolver, and the verifier config. On success, the caller
/// issues a JWT against the verified DID via the existing session
/// machinery.
///
/// Thin pass-through to [`verify_assertion`]. Hosted in vta-service
/// so future policy hooks (audit log, telemetry, scope checks) have
/// a natural home that doesn't pollute the standalone crate.
pub async fn verify_passkey_login(
    payload: &AssertionPayload,
    expected_challenge: &[u8],
    resolver: &VtaVmResolver,
    config: &VerifierConfig,
) -> Result<VerifiedAssertion, VerifyError> {
    verify_assertion(payload, expected_challenge, resolver, config).await
}

/// Enumerate the passkey-eligible verification methods on a DID
/// document. A VM is considered passkey-eligible if its
/// `publicKeyMultibase` decodes via
/// [`vti_webauthn::multikey::decode_multikey`] as a supported
/// algorithm (P-256 in v0.1).
///
/// Returns a list of `(vm_url, credential_id)` pairs suitable for
/// `allow_credentials` in
/// [`vta_sdk::protocols::passkey_login::PasskeyLoginStartResponse`].
/// The `credential_id` is the VM fragment (everything after `#`) —
/// callers responsible for re-encoding as base64url for transmission.
///
/// **v0.1 limitation:** if a DID document stores credential_id bytes
/// separately from the VM, this enumeration misses them and
/// `allow_credentials` ends up empty. Browsers fall back to
/// discoverable credentials in that case, which works. Phase 3
/// hardening: extend the VM schema (or a sibling fjall keyspace) to
/// carry the credential_id bytes alongside the VM URL.
pub async fn enumerate_passkey_vms(
    resolver: &VtaVmResolver,
    did: &str,
) -> Result<Vec<PasskeyVmRef>, ResolverError> {
    // For now, return an empty list — the resolver doesn't expose a
    // "list all VMs on a DID" API. The Phase 3 hardening item will:
    // (a) add `list_vms(did)` to the VmResolver trait, returning
    //     all VMs with `publicKeyMultibase` set; OR
    // (b) thread the DID document through directly (the resolver
    //     already fetches it; pass a richer struct to the caller).
    //
    // For v0.1, returning empty means the browser uses
    // discoverable-credentials mode which works on every modern
    // platform.
    let _ = resolver;
    let _ = did;
    Ok(Vec::new())
}

/// One entry in the passkey-VM enumeration. Matches the shape of
/// `PasskeyLoginStartResponse.allow_credentials` after encoding.
pub struct PasskeyVmRef {
    pub vm_url: String,
    pub credential_id: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use affinidi_did_resolver_cache_sdk::config::DIDCacheConfigBuilder;
    use vti_webauthn::VerificationAlgorithm;

    async fn make_resolver() -> VtaVmResolver {
        // Use the in-process cache resolver with default config — handles
        // did:key locally without any network calls.
        let client = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
            .await
            .expect("did cache client");
        VtaVmResolver::new(client)
    }

    #[tokio::test]
    async fn rejects_vm_url_without_fragment() {
        let resolver = make_resolver().await;
        let err = resolver.resolve_vm("did:example:alice").await.unwrap_err();
        assert!(
            matches!(err, ResolverError::MalformedVm(ref s) if s.contains("fragment")),
            "got {err:?}"
        );
    }

    #[tokio::test]
    async fn surfaces_unresolvable_did() {
        let resolver = make_resolver().await;
        // did:web:nonexistent.invalid — fails DNS or HTTP at resolve time.
        let err = resolver
            .resolve_vm("did:web:nonexistent.invalid#passkey-abc")
            .await
            .unwrap_err();
        // Either UnresolvableDid (network/DID-method failure) or
        // MalformedVm (some resolvers reject before the network call) —
        // both indicate the DID couldn't yield a doc.
        assert!(
            matches!(
                err,
                ResolverError::UnresolvableDid(_) | ResolverError::MalformedVm(_)
            ),
            "got {err:?}"
        );
    }

    #[tokio::test]
    async fn rejects_did_key_without_a_passkey_vm() {
        let resolver = make_resolver().await;
        // did:key DIDs publish a single Ed25519 VM under fragment
        // matching the key. A passkey fragment won't be present.
        let err = resolver
            .resolve_vm(
                "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH#nonexistent-passkey",
            )
            .await
            .unwrap_err();
        assert!(matches!(err, ResolverError::NotFound), "got {err:?}");
    }

    #[tokio::test]
    async fn resolves_did_key_default_vm() {
        // did:key publishes its single VM under the URL `<did>#<key>`.
        let resolver = make_resolver().await;

        // A known did:key for an Ed25519 key (not P-256 — so we expect
        // this to fail at the multikey decode step with "unsupported
        // multicodec" since v0.1 only supports P-256). The point of
        // this test is to confirm we DO reach the multikey decoder
        // (VM found, publicKeyMultibase extracted).
        let did = "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH";
        let vm_url = format!("{did}#{}", &did[8..]);

        let err = resolver.resolve_vm(&vm_url).await.unwrap_err();
        assert!(
            matches!(err, ResolverError::MalformedVm(ref s) if s.contains("unsupported multicodec")),
            "got {err:?}"
        );
    }

    /// Trait-impl smoke: an explicit upcast confirms the type bound
    /// is satisfied. If the trait or method signature drifts in
    /// either crate, this test stops compiling.
    #[allow(clippy::needless_borrow)]
    #[tokio::test]
    async fn implements_vti_webauthn_resolver_trait() {
        let resolver = make_resolver().await;
        let _: &dyn VmResolver = &resolver;
        // Force algorithm enum into scope — guards against the enum
        // being renamed or its P256 variant being moved.
        let _ = VerificationAlgorithm::P256;
    }
}
