# CLAUDE.md — Verifiable Trust Infrastructure workspace

Workspace-wide design principles, crate map, and integration-flow reference.
Each crate also has its own CLAUDE.md for crate-specific guidance; consult
those in addition to this file.

## Workspace layout

Rust workspace (edition 2024, resolver 3, MSRV 1.91.0). Dependencies flow
strictly downward — no cycles.

```
vti-common  ──┬──► vta-sdk ──┬──► vta-cli-common ──┬──► pnm-cli
              │              │                      └──► cnm-cli
              ├──► vta-service (library + local/dev binary)
              │        └──► vta-enclave (Nitro Enclave binary)
              └──► vtc-service
```

| Crate | Role |
|---|---|
| `vti-common` | Shared foundation: JWT, ACL, `Store`/`KeyspaceHandle` enum (local fjall + vsock), `AppError`, config types |
| `vta-sdk` | Public SDK: types, HTTP + DIDComm client, `sealed_transfer`, `did_templates`, `provision_integration`, attestation |
| `vta-service` | VTA logic (library) + local/dev binary. Exposes routes, operations, setup wizard |
| `vta-enclave` | Nitro Enclave front-end. Depends on `vta-service` as a library, adds TEE bootstrap (KMS, vsock-store, attestation) |
| `vtc-service` | Verifiable Trust Community service (community lifecycle, separate JWT audience) |
| `vta-cli-common` | Shared CLI command implementations — both CLIs are thin wrappers |
| `pnm-cli` | Personal Network Manager (single-VTA operator) |
| `cnm-cli` | Community Network Manager (multi-community operator) |
| `didcomm-test` | Standalone DIDComm connectivity harness (test tool, not shipped) |

Hot spots to know about:
- `vta-service/src/operations/provision_integration.rs` (1.9k lines) —
  orchestrates template render → key mint → ACL wire-up → VC issue → seal.
- `vta-service/src/operations/did_webvh.rs` (1.4k lines) — WebVH DID
  lifecycle + `did.jsonl` publication.
- `vta-service/src/tee/kms_bootstrap.rs` — KMS attest/decrypt, JWT
  fingerprint check, storage-key derivation.
- `vta-sdk/src/sealed_transfer/` — HPKE seal/open, armor, assertions.
- `vti-common/src/store/vsock.rs` — enclave-side store proxy; semantic
  parity with local fjall is asserted but under-tested.

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

The workspace has a **DID templates feature** (`docs/03-integrating/did-templates.md`,
`vta-sdk/src/did_templates`, `vta-service/src/routes/did_templates.rs`). A
template is a JSON file describing the **shape** of a DID document with
`{TOKEN}` placeholders; the VTA renders them server-side, filling in keys it
just minted + caller-supplied variables. Built-ins ship with the service
(`didcomm-mediator`, `vta-admin`, `webvh-hosting-server`, `webvh-service`);
operators can upload more.

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

Known offender (do not emulate): `AttestationResponse.self_verified: bool`
in `vta-service/src/tee/types.rs`. Migrate to a typestate when touched.
`verify_producer_assertion_with_pubkey` returning `Ok(())` for the
`Attested` variant (`vta-sdk/src/sealed_transfer/verify.rs`) has the same
smell — the real verification lives in `vta-sdk::attestation` and callers
must dispatch explicitly; a future refactor should return a
`VerifiedAssertion` typestate.

## Sealed-transfer is the only secret-bearing wire format

Every credential / key / DID-secrets bundle that moves between tools is
sealed via `vta_sdk::sealed_transfer` — HPKE-encrypted to a consumer-supplied
`client_did`, framed in ASCII armor, with a producer assertion
(`PinnedOnly` / `DidSigned` / `Attested`) + out-of-band SHA-256 digest.

Invariants (do not relax):
- HPKE suite is hardcoded: X25519-HKDF-SHA256 KEM, HKDF-SHA256 KDF,
  ChaCha20-Poly1305 AEAD. Not negotiable.
- Info string is domain-bound: `b"vta-sealed-transfer/v1"`. New protocol →
  new info string, not a version parameter.
- `SealedPayloadV1` is tagged with `#[serde(rename_all = "snake_case")]` and
  new variants are **additive**. Never reshape an existing variant — you
  break every existing opener. Add a new variant and let consumers migrate.
- Digest pinning is mandatory at the CLI (`--expect-digest`). `--no-verify-digest`
  exists only as an explicit opt-out with a warning.
- `DID_SIGNED_DOMAIN_TAG = b"vta-sealed-transfer/v1\0"` prefixes the bytes
  that Ed25519 signs. Don't reuse this tag elsewhere.

If you find yourself emitting plaintext JSON containing private keys, stop
and wrap it in a `SealedPayloadV1` variant instead.

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

## Integration flows

This section is a map of the wire-level flows the workspace supports. Each
flow links to the canonical docs + the code entry points. When adding a
new flow, update both this section and the relevant `docs/*.md`.

### VTA first-boot setup
- **What**: Mints master seed, VTA DID, mediator DID, first admin credential.
- **Entry point**: `vta setup` (interactive) or `vta setup --from <file>` (TOML-driven).
- **Code**: `vta-service/src/setup/interactive.rs`, `vta-service/src/setup/from_toml.rs`.
- **Seed**: 24-word BIP-39 mnemonic, stored via `affinidi-secrets-resolver`
  backend (OS keyring by default; AWS/GCP/Azure via feature flags).
- **Docs**: `docs/02-operating/cold-start.md`, `docs/02-operating/non-interactive-setup.md`.

### Admin credential cold-start
- **What**: Bootstrap the first operator without a running VTA.
- **Flow**: PNM mints ephemeral `did:key` locally → operator runs
  `vta import-did --did <temp> --role admin` offline → VTA starts → PNM
  authenticates → on first authenticated call PNM **auto-rotates** to a
  fresh `did:key`, creates the new ACL entry, deletes the temp one.
- **Code**: `pnm-cli/src/setup.rs`, `vta-service/src/main.rs` (`import-did`).
- **Docs**: `docs/02-operating/cold-start.md` §3–6.

### TEE Mode B bootstrap (attested first-boot)
- **What**: One-command admin provisioning against a fresh Nitro-Enclave VTA.
- **Entry point**: `pnm bootstrap connect --vta-url <url>`.
- **Transport**: REST `POST /bootstrap/request` (unauth, rate-limited).
- **Trust anchor**: Nitro attestation quote committing to the client's
  Ed25519 pubkey + bundle_id + producer's Ed25519 pubkey via SHA-256.
- **Carve-out**: Single-use. `BOOTSTRAP_CARVEOUT_CLOSED_KEY` flips on
  first success; subsequent calls return 410.
- **Code**: `vta-service/src/routes/bootstrap.rs`, `vta-service/src/tee/`.
- **Docs**: `sealed-bootstrap.md`, `docs/01-concepts/tee-architecture.md`.

### DIDComm challenge-response auth
- **What**: Session initiation for any authenticated call.
- **Endpoints**: `POST /auth/challenge` → challenge + session_id;
  `POST /auth/` → JWT access token (15m) + refresh token (24h).
- **Wire**: DIDComm v2 (via mediator) **or** direct REST with a JWS.
- **Claims**: `{ aud, sub, session_id, role, contexts, exp }`. Audience
  separates VTA from VTC — cross-audience tokens are rejected.
- **Code**: `vta-service/src/routes/auth.rs`, `vti-common/src/auth/`.

### Context + context-admin bootstrap
- **What**: Application-scoped key hierarchy and role-scoped admin.
- **Endpoint**: `POST /contexts` (super-admin) + `POST /acl` for the admin
  grant. `cnm contexts bootstrap` does both in one call and emits the
  admin credential.
- **Derivation**: `m/26'/2'/<ctx_idx>'/<key_idx>'` — the context's BIP-32
  base path is allocated at creation and is immutable.
- **Code**: `vta-service/src/routes/contexts.rs`,
  `vta-service/src/operations/contexts.rs`.

### Provision-integration (template-driven)
- **What**: The generic path to bootstrap any integration (mediator,
  webvh-host, app, etc.) via a DID template. **This is the canonical flow
  for anything that needs a DID + keys + optional admin credential.**
- **Consumer emits**: VP-framed `BootstrapRequest` signed by an ephemeral
  holder `did:key`. References a template name + variable bindings.
  Seed persisted at `~/.config/{pnm,cnm}/bootstrap-secrets/<bundle_id>.key`
  (0600 + Windows ACL hardening).
- **Producer returns**: HPKE-sealed `TemplateBootstrapPayload` (integration
  DID, private keys, `did.jsonl`, VC-issued admin authorization, VTA trust
  bundle) in armor with SHA-256 digest communicated out-of-band.
- **Transports**:
  - **Offline file**: `vta bootstrap provision-request` / `provision-integration` / `open`.
  - **PNM REST bridge**: `pnm bootstrap provision-request` →
    `pnm bootstrap provision-integration` (authenticated, hits
    `POST /bootstrap/provision-integration`).
  - **DIDComm**: `provision-integration/1.0` protocol (authcrypt; ACL gates).
- **Code**: `vta-service/src/operations/provision_integration.rs`,
  `vta-sdk/src/provision_integration/`,
  `vta-service/src/routes/bootstrap.rs:provision_integration`.
- **Docs**: `docs/03-integrating/provision-integration.md`.

### Sealed-transfer envelope format
- **Inner**: CBOR-serialized `SealedPayloadV1` enum variant.
- **Cipher**: HPKE base mode, X25519-HKDF-SHA256 + ChaCha20-Poly1305.
- **Framing**: OpenPGP-style ASCII armor with Bundle-Id, Chunk, Digest-Algo
  headers (bound to AAD) and CRC24 line checksum.
- **Producer assertion** (one of):
  - `DidSigned` — Ed25519 signature over
    `DID_SIGNED_DOMAIN_TAG || client_x25519_pub || bundle_id`. Default.
  - `Attested` — Nitro attestation quote. Verified via
    `vta_sdk::attestation::verify_nitro_assertion` (feature-gated).
  - `PinnedOnly` — OOB digest is the sole integrity anchor. Dev/test only.
- **Code**: `vta-sdk/src/sealed_transfer/` (bundle, hpke, armor, verify).

### Signing oracle
- **What**: Remote signing without key export.
- **Endpoint**: `POST /keys/{key_id}/sign` — payload + algorithm
  (EdDSA or ES256). Key derived BIP-32 → signature → memory zeroized.
- **DIDComm**: `key-management/1.0/sign-request`.

### Backup / restore
- **What**: Encrypted full-state dump + restore.
- **Endpoints**: `POST /backup/export`, `POST /backup/import`
  (super-admin).
- **Crypto**: Argon2id KDF (≥12-char password) + AES-256-GCM.
- **Watchout**: import currently does not cross-check the backup's
  `vta_did` against the running VTA — restoring a foreign backup
  silently replaces state. Fix before extending this surface.
- **Code**: `vta-service/src/operations/backup.rs`.

### DID template management
- **Offline**: `pnm did-templates init <kind>`, `validate`, `list-builtins`.
- **Online**: `pnm did-templates list/show/create/update/delete` →
  REST `/did-templates` (global) or `/contexts/{id}/did-templates` (scoped).
- **Built-ins**: `didcomm-mediator`, `vta-admin`, `webvh-hosting-server`,
  `webvh-service` (shipped with
  the SDK, always available).
- **Code**: `vta-sdk/src/did_templates/`,
  `vta-service/src/routes/did_templates.rs`, `vta-service/src/operations/did_templates.rs`.
- **Docs**: `docs/03-integrating/did-templates.md`.

## Runtime guards to preserve

These are load-bearing — know they exist before adjusting nearby code.

- **Rate limit** on all unauth routes: `tower-governor` at 5 rps + 10
  burst per source IP (`vta-service/src/routes/mod.rs`). Keep JWT-gated
  routes off the limiter — auth is the gate.
- **Request body cap**: 1 MB globally (`MAX_BODY_SIZE`). Matters in TEE
  where memory is tight.
- **Audience isolation** between VTA and VTC JWTs. Cross-audience tokens
  are rejected. Don't add a "shared" audience.
- **Mnemonic export window** (`MnemonicExportGuard`) — one-shot, timed,
  zeroized on drop. Don't cache the plaintext anywhere.
- **JWT key fingerprint** on TEE boot (`vta-service/src/tee/kms_bootstrap.rs`)
  detects KMS ciphertext tampering or key rotation. Do not widen the
  "first boot after upgrade" silent-store path.
- **Carve-out** (`BOOTSTRAP_CARVEOUT_CLOSED_KEY`) on `/bootstrap/request`
  is single-use. New TEE flows must not provide a back door.

## Versioning & publishing (workspace-specific)

When bumping crate versions in this Rust workspace, always check and bump
dependent sub-crate versions too. Use `major.minor` version pinning (not
`major.minor.patch`) for internal dependencies. Exception: crypto deps
(`ed25519-dalek`, `hpke`, `jsonwebtoken`, `rsa`, `aes-gcm`) should pin to
a minimum patch to avoid silent regressions when a CVE lands.

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
