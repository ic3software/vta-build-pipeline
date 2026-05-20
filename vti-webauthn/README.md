# vti-webauthn

DID-VM-resolved WebAuthn assertion verifier for the Verifiable Trust
Infrastructure.

This crate verifies WebAuthn (FIDO2 / passkey) assertions where the
credential's public key is resolved from a **DID Document
`verificationMethod`**, not from a server-side credential store.

## When you want this crate

- You have a DID document with one or more passkey VMs (multicodec
  `0x1200` P-256 multikeys).
- A browser produced a WebAuthn assertion claiming to be from one of
  those VMs.
- You want to verify the assertion *without* maintaining a server-side
  passkey registry — the DID document is the source of truth.

If you have a traditional service-managed passkey flow (operator
registers credentials in the service's own database), use
`webauthn-rs` directly.

## Quick usage

```rust,ignore
use vti_webauthn::{
    AssertionPayload, VerifierConfig, verify_assertion,
};

let config = VerifierConfig::from_public_url(
    "https://control.example.com",
    /* require_uv */ true,
)?;

let payload = AssertionPayload {
    credential_id: /* from inbound assertion */,
    authenticator_data: /* … */,
    client_data_json: /* … */,
    signature: /* … */,
    verification_method: "did:webvh:vta.example.com:alice#passkey-abc".into(),
};

let verified = verify_assertion(
    &payload,
    /* expected_challenge */ &challenge_bytes,
    &my_resolver,
    &config,
).await?;

assert!(verified.user_present);
```

## Design notes

See `docs/05-design-notes/vti-webauthn-crate-design.md` in the parent
workspace for the design rationale, verification algorithm, and the
v0.1 ↔ v0.2 scope cut.

## Status

**v0.1 — skeleton.** Public API + module structure landed; verifier
bodies stubbed with `todo!()`. Implementation lands in subsequent PRs
under the trust-task envelope migration initiative.

## License

Apache-2.0
