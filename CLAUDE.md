# CLAUDE.md — Verifiable Trust Infrastructure workspace

Workspace-wide design principles. Each crate also has its own CLAUDE.md for
crate-specific guidance; consult those in addition to this file.

## Default to DIDs wherever we handle public keys

Every public-key surface in operator- or wire-facing APIs is a `did:key`
(Ed25519, multicodec `0xed01`), not a raw base64url pubkey. The HPKE layer
still operates on X25519 bytes internally; those are derived on demand via
`affinidi_crypto::did_key::ed25519_pub_to_x25519_bytes` (public) and
`affinidi_crypto::ed25519::ed25519_private_to_x25519` (secret) and stay
inside the cipher layer.

This applies to both sides of `sealed_transfer` (`client_did`, `producer_did`),
to CLI recipient flags (`--recipient-did`), and to any new protocol we add.
Tests and docs refer to DIDs, not pubkeys.

## Use DID templates, don't hand-roll DID shapes

The workspace has a **DID templates feature** (`docs/did-templates.md`,
`vta-sdk/src/did_templates`, `vta-service/src/routes/did_templates.rs`). A
template is a JSON file describing the **shape** of a DID document with
`{TOKEN}` placeholders; the VTA renders them server-side, filling in keys it
just minted + caller-supplied variables. Built-ins ship with the service
(`didcomm-mediator`, `webvh-hosting-server`); operators can upload more.

**Before inventing a new mint-a-DID path, reach for templates first.**

- When a caller needs a DID (mediator first-boot, webvh host, app identity),
  the right wire shape is "template name + variable bindings", not
  "hand-crafted `MintHints` / `ProvidedDid` / method enum". The template
  already encodes method, service endpoints, key shapes, and required vars.
- The VTA always mints the key material. A caller never ships private keys,
  and we never need a proof-of-possession challenge to verify a caller-
  provided DID — the key generator *is* the VTA.
- Templates are added via their own authed endpoint, not smuggled inline
  through another request. A `BootstrapRequest` referencing template
  `mediator-custom` is only valid if `mediator-custom` is already registered
  on that VTA.
- Variable validation (`requiredVars`, `optionalVars`, unknown-var rejection)
  is the template renderer's job — reuse it, don't re-implement.

The pattern is: operator authors template once → every setup wizard, CLI,
and provisioning surface renders from it → swap the JSON file to change the
DID shape for every consumer, no redeploy.

The noun for "a thing a template provisions" is **integration** (not
"agent" — that word collides with VTA = Verifiable Trust *Agent*). CLI
reads "provision-integration"; docs talk about "integration kinds"
(mediator, webvh-hosting, etc.); each template declares its kind in the
`kind` field.

## Authorization claims between VTA and integrations use VC/VP format

When the VTA attests authorization to a holder (e.g., at bootstrap — "this
DID is admin of context X at this VTA"), the attestation is a **W3C
Verifiable Credential**, not a bespoke signed JSON struct. When a holder
presents something to the VTA signed with their DID (e.g., a bootstrap
request), the envelope is a **W3C Verifiable Presentation**.

Rationale:
- **Standards discipline.** VCs/VPs are the SSI-native envelopes for these
  semantics. Using them means we delegate proof handling to well-tested
  libraries (`affinidi-vc`, `affinidi-data-integrity`) and stay compatible
  with external verifiers that show up later.
- **Scope boundary.** VCs here are bootstrap-transport only — the VTA's
  ACL is the authoritative source of authorization in steady state, not
  the VC. VCs are short-lived (1h default), carry no `credentialStatus`
  (no StatusList machinery), and are never re-verified after first open.
  Revocation is ACL removal, not credential status change.
- **One-shot lifecycle.** The VC is issued once at bootstrap, verified
  once at bundle open, archived for audit. It never participates in
  steady-state operations between VTA and integration.

If you find yourself signing a JSON struct with a VTA key for anything
that resembles an authorization assertion, stop and use a VC. If you find
yourself accepting a signed JSON struct as a holder presentation, use a
VP. Custom JSON-LD contexts for our shapes live under
`https://openvtc.org/contexts/` — baked into crates at compile time via
`include_str!` so verification works offline.

## Typestate discipline for verified wire forms

Wire forms that require cryptographic verification (VPs, VCs, signed
envelopes) expose a `.verify()` method returning a distinct
`Verified*` type. Downstream code only takes the verified form. A call
site that forgets to verify doesn't compile — wrong type.

Pattern:

```rust
// Over-the-wire form: anyone with a byte stream can deserialize this.
pub struct BootstrapRequest { /* ... */ signature: String }

impl BootstrapRequest {
    pub fn verify(self) -> Result<VerifiedBootstrapRequest, ...>;
}

// Post-verification form: only constructable via `.verify()`.
// Every function that takes this is guaranteed to be looking at a
// verified request.
pub struct VerifiedBootstrapRequest { inner: BootstrapRequest }
```

Apply to any wire form where "this came from a trusted source" is a
precondition for subsequent work. Don't paper over with a `verified:
bool` field; use the type system.

## Sealed-transfer is the only secret-bearing wire format

Every credential / key / DID-secrets bundle that moves between tools is
sealed via `vta_sdk::sealed_transfer` — HPKE-encrypted to a consumer-supplied
`client_did`, framed in ASCII armor, with a producer assertion
(`PinnedOnly` / `DidSigned` / `Attested`) + out-of-band SHA-256 digest.

If you find yourself emitting plaintext JSON containing private keys, stop
and wrap it in a `SealedPayloadV1` variant instead. Add a new variant rather
than reshaping an existing one — variants compose cleanly at the consumer;
in-place shape changes break every open path.

## Operator errors should suggest the fix

When the CLI hits a 409 / 404 / 403 and the operator's real intent maps to a
different command, print the corrected command verbatim. Example: `pnm
contexts create --admin-did X --admin-expires 1h` against an existing context
prints the `pnm acl create --did X --role admin --contexts <id> --expires 1h`
the operator should have run. Don't just surface the HTTP error.

This is why the SDK's `VtaError` carries typed variants (not an opaque
`Protocol(String)`) — the CLI layer switches on them to emit friendly
guidance. Preserve the type information through both REST and DIDComm
transports; never collapse a Conflict into a string.

## Versioning & publishing (workspace-specific)

When bumping crate versions in this Rust workspace, always check and bump
dependent sub-crate versions too. Use `major.minor` version pinning (not
`major.minor.patch`) for internal dependencies.

## Commit hygiene

- Run `cargo fmt` before committing.
- All commits must be DCO-signed (`git commit -s`).
- Don't bypass hooks (`--no-verify`), don't skip signatures, don't amend
  published commits.

## General

Before creating new crates or clients, search the workspace and crates.io to
check if the functionality already exists. Prefer existing SDKs over custom
implementations. Before writing any fix, analyze the root cause and explain
the diagnosis. Fix the cause, not the symptom — no workarounds.
