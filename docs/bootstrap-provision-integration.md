# Design: `provision-integration` — generic template-driven integration bootstrap

Status: design-locked, implementation pending. This doc is the brief for the
implementing agent. It captures what was decided and why.

> **Operator how-to:** for the end-to-end greenfield walkthrough (generate
> request → provision → open + install), see
> [`offline-integration-bootstrap.md`](offline-integration-bootstrap.md).
> This doc covers the wire format and design decisions; that one covers
> how to drive the CLI.

## What this is

A single path for standing up any VTA-managed integration — DIDComm
mediators today, webvh-hosting servers next, whatever template comes later —
against a VTA that may be offline or air-gapped at the integration's first
boot.

The integration's operator ends up with an armored sealed bundle that
contains:
- A VTA-issued VC stating the integration's admin authorization at the VTA.
- Private key material for any DIDs the VTA minted on the integration's
  behalf (rendered from a DID template the operator named).
- Any template-produced side outputs the integration needs to boot (e.g.,
  `did.jsonl` for webvh DIDs, DIDComm service-endpoint config).
- The VTA's own trust material (DID doc + log) so the integration can
  verify the bundle contents offline.

The operator runs `vta bootstrap provision-integration` on the VTA host —
or `pnm bootstrap provision-integration` from an authenticated workstation
bridging to the VTA over HTTPS.

## Preconditions

The provisioning call fails fast (400) if any of these aren't already true
at the VTA:

1. **The target context exists.** `provision-integration` doesn't create
   contexts — that's `vta context provision`'s job. The integration lands
   *inside* an existing context.
2. **The template named in the request is registered.** Error message
   points at the fix: `template '{name}' is not registered on this VTA.
   Register it via 'pnm did-templates upload {name} --file <path>' then
   retry.` (Per the "operator errors should suggest the fix" principle
   in CLAUDE.md.)
3. **The calling operator has admin role in the target context.** ACL
   check is `require_admin` with `allowed_contexts` containing the
   target. Super-admin passes through.

Integrations do not rotate keys on their own. The VTA mints the
integration's signing and key-agreement keys once, at provisioning time,
and the integration uses them for the lifetime of the DID. If a rotation
is ever needed — compromised key, operator policy — it's an admin
operation: revoke the old ACL entry and run `provision-integration`
again with a fresh request. There is no integration-side re-enrollment
flow or scheduled rotation. This keeps the integration code simple (no
refresh-on-schedule machinery) and matches the reality that integrations
are services with long-lived service identity.

## Design decisions, at a glance

| # | Decision | Chosen |
|---|---|---|
| 1 | DID ownership / caller-vs-VTA key custody | **DID templates always; VTA always mints keys** |
| 2 | Payload variant shape | **Generic `SealedPayloadV1::TemplateBootstrap` with typed `TemplateOutput` enum** |
| 3 | Request format | **VP (VC Data Model 2.0, `eddsa-jcs-2022`)** |
| 4 | VC subject (admin authorization) | **`client_did` by default; VTA-minted long-term admin DID when `ask.adminTemplate` is present (admin-DID rollover, §"Admin-DID rollover")** |
| 5 | VC revocation | **Short-lived VC only (1h default); no StatusList; revocation = ACL removal** |
| 6 | VTA issuer DID | **Reuse `vta_did`; template marks an `assertionMethod` key** |
| 7 | VC claim shape | **`adminOf` always, `operatorOf` when template mints an integration DID** |
| 8 | Command name | **`provision-integration`** |
| 9 | HTTP endpoint ACL | **`require_admin` scoped to target context** |
| 10 | `GET /did/{did}/log` auth | **Public, unauthenticated, `tower_governor` rate-limited** |
| 11 | Sealed-transfer producer assertion | **`DidSigned` by `vta_did`; `--expect-digest` mandatory; `--assertion pinned-only` escape hatch** |
| 12 | JSON-LD context hosting | **Bake locally; publishing at canonical URL is operational follow-up** |
| 13 | VP `proofPurpose` | **`authentication`** (VC `proofPurpose` stays `assertionMethod`) |
| 3a | Cryptosuite | **`eddsa-jcs-2022`** (library default for Ed25519; JCS avoids JSON-LD context resolution so offline verification needs no context loader — revised from `eddsa-rdfc-2022` during implementation; `@context` arrays still present but not processed during sign/verify) |
| 14 | Transport for the VP→bundle round-trip | **File + REST + DIDComm** (same VP, same payload, shared library fn; see §"Transports") |
| 15 | DIDComm steady-state auth | **Authcrypt-as-auth, no JWT** (`messaging/auth.rs::auth_from_message` reads `from` + checks ACL — same `AuthClaims` shape REST produces). `SessionStore::ensure_authenticated_didcomm` returns a connected `VtaClient` rather than a token string. |
| 16 | Admin-DID mint method (phase 1) | **`did:key` only** — Ed25519 via BIP-32 under the context base path. Built-in template `vta-admin` (`kind: "admin"`, no required vars). Operator-registered admin templates accepted as long as `methods` contains `"key"` or is empty. |

Full rationale for each is in the transcript of the design conversation.
Short reminders live next to the decisions they shape below.

## Admin-DID rollover (optional)

The VP's `ask.adminTemplate` field is an **optional** second template
reference that promotes the bootstrap from "issue a VC to the
ephemeral `client_did`" to "mint a long-term admin DID under VTA key
custody and bind the VC + ACL row to *that*". The ephemeral
`client_did` keeps its role as the sealing recipient but gains no
steady-state authority — it's purely a transport key.

Motivation: the ephemeral `client_did` is a `did:key` the holder
generated locally to author the VP. Making that DID the long-term
admin principal ties the ACL row to a short-lived private key that
may have been handled outside the VTA's custody. Rolling over to a
VTA-minted admin DID at bootstrap time puts the admin identity under
the same BIP-32 / keystore / audit infrastructure as every other DID
the VTA manages.

How it works:

1. Request includes `"adminTemplate": { "name": "vta-admin", "vars": {} }`
   (built-in) or a custom operator-registered template with
   `kind: "admin"`.
2. VTA's `provision_integration` library fn renders the admin template,
   mints a fresh Ed25519 key via the normal BIP-32 derivation under the
   target context's base path, registers a `KeyRecord` at
   `{admin_did}#{multibase}`, and returns `(admin_did, priv_mb)`.
3. Admin DID is added as a second entry in `payload.secrets`, keyed by
   the admin DID. Both the Ed25519 signing key and the canonical
   X25519 key-agreement derivation are populated so holders that
   DIDComm-authenticate as the admin DID don't need to derive X25519
   themselves.
4. The authorization VC's `credentialSubject.id` is set to the
   VTA-minted admin DID, not `client_did`.
5. The ACL row is written for the VTA-minted admin DID. No transient
   ACL row is created for `client_did` — if bundle open fails, there's
   nothing to clean up.

Absent `adminTemplate`, behaviour is unchanged: VC subject =
`client_did`, ACL row for `client_did`.

Phase 1 only supports `did:key` admin DIDs. Templates that target
other methods are accepted at registration time but rejected by the
mint path until the corresponding mint code lands. Templates with
`methods: []` (no restriction) are accepted.

The holder's install glue (typically an integration setup wizard,
e.g. the mediator tool in `affinidi-tdk-rs`) reads the VC's
`credentialSubject.id`, looks up that DID in `secrets`, installs the
signing + KA keys, and discards `client_did` after the first
successful call to the VTA as the new admin DID.

## Transports

The VP → sealed-bundle exchange is transport-neutral. Three carriers
ship today:

1. **File** (offline / air-gapped). Operator hands the VP JSON to the
   VTA admin via any out-of-band channel; admin runs
   `vta bootstrap provision-integration --request <file>` on the VTA
   host; armored bundle is written to a local path. Use when the VTA
   is not reachable over the network from the integration host.
2. **REST** (PNM-bridged). `pnm bootstrap provision-integration --vta
   <slug>` posts the same VP to `POST /bootstrap/provision-integration`.
   The PNM operator is authenticated via their session token; they
   are relaying a VP that was signed by the integration's `client_did`.
3. **DIDComm** (holder-driven). The integration itself opens an
   authcrypt'd DIDComm session to the VTA via its mediator and calls
   `vta_sdk::provision_integration::didcomm::provision_integration_didcomm`.
   Protocol URI:
   `https://firstperson.network/protocols/provision-integration/1.0/provision-integration`.
   The VTA's DIDComm handler enforces a dual check — `auth_from_message`
   verifies the authcrypt sender + ACL entry, AND the library fn
   verifies the VP's `DataIntegrityProof`. The DIDComm sender DID and
   the VP holder DID must agree; mismatch is rejected as `Forbidden`
   (privilege-laundering guard).

   Precondition for DIDComm: `client_did` must already hold admin role
   in the target context (ACL). This is the expected shape when an
   admin DID from a prior provision-integration rollover is
   provisioning further integrations in the same context over its own
   DIDComm session.

The sealed bundle returned is identical across all three transports —
same CBOR/armor/digest. The only difference is how the bytes move.

## Wire format

### Request: Verifiable Presentation

A JSON file the integration's operator hands to the VTA admin (or submits
via PNM). Signed by the ephemeral key behind `client_did`.

```json
{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://openvtc.org/contexts/bootstrap-v1"
  ],
  "type": ["VerifiablePresentation", "BootstrapRequest"],
  "holder": "did:key:z6Mk...",
  "id": "urn:uuid:...",
  "nonce": "base64url-16-bytes",
  "validUntil": "2026-04-20T12:00:00Z",
  "label": "mediator/conf/mediator.toml",
  "ask": {
    "type": "TemplateBootstrap",
    "template": { "name": "didcomm-mediator", "vars": { "URL": "..." } },
    "adminTemplate": { "name": "vta-admin", "vars": {} },
    "contextHint": "prod-mediator",
    "note": "optional human-readable hint"
  },
  "proof": {
    "type": "DataIntegrityProof",
    "cryptosuite": "eddsa-jcs-2022",
    "verificationMethod": "did:key:z6Mk.../#...",
    "proofPurpose": "authentication",
    "created": "2026-04-20T11:00:00Z",
    "proofValue": "z..."
  }
}
```

Enforcements at `.verify()` time:
- Proof verifies against `holder`'s DID doc (resolve `did:key`, extract
  key, verify signature over JCS-canonicalized bytes). `verificationMethod`
  must reference the same DID as `holder` — forged holder substitution
  rejected.
- `validUntil` is in the future (with ±5 minutes clock-skew tolerance —
  W3C-typical verifier default, applied symmetrically to `validFrom`
  when present).
- Cryptosuite must be `eddsa-jcs-2022` — widens when we intentionally
  accept new suites, not as a side effect.
- `@context` is present but not processed (JCS canonicalizes the JSON
  structure directly, no JSON-LD expansion).
- `proofPurpose == "authentication"`.

### Payload: `SealedPayloadV1::TemplateBootstrap`

```rust
pub enum SealedPayloadV1 {
    AdminCredential(Box<CredentialBundle>),
    ContextProvision(Box<ContextProvisionBundle>),
    DidSecrets(Box<DidSecretsBundle>),
    AdminKeySet(Vec<LabeledKey>),
    RawPrivateKey(RawPrivateKey),
    /// Generic template-driven integration bootstrap.
    TemplateBootstrap(Box<TemplateBootstrapPayload>),
}

pub struct TemplateBootstrapPayload {
    /// VTA-issued VC: "holder is admin of context X at VTA Y, operator
    /// of DID Z". Short-lived (validUntil ~1h), verifiable offline via
    /// the trust bundle below.
    pub authorization: VerifiableCredential,
    /// Private key material for DIDs the VTA minted for the holder.
    /// Keyed by DID. Secrets are `Zeroizing<[u8;32]>` at use.
    pub secrets: BTreeMap<String, DidKeyMaterial>,
    /// Non-credential first-boot config the integration needs.
    pub config: TemplateBootstrapConfig,
}

pub struct DidKeyMaterial {
    pub did: String,
    pub signing_key: KeyPair,   // ed25519
    pub ka_key: KeyPair,        // x25519
}

pub struct KeyPair {
    pub key_id: String,                 // DID URL with fragment
    pub public_key_multibase: String,
    pub private_key_multibase: String,  // Zeroizing at rest
}

pub struct TemplateBootstrapConfig {
    pub template_name: String,
    pub template_kind: String,
    pub did_document: serde_json::Value,
    pub outputs: Vec<TemplateOutput>,
    pub vta_url: Option<String>,
    pub vta_trust: VtaTrustBundle,
}

pub enum TemplateOutput {
    /// webvh `did.jsonl` content. Integration writes to
    /// `/.well-known/did.jsonl` at first boot.
    WebvhLog(String),
    /// DIDComm service-endpoint advertisement.
    DidCommService { url: String, accept: Vec<String>, routing_keys: Vec<String> },
    // Grow here as new template kinds need new side-outputs.
}

pub struct VtaTrustBundle {
    pub vta_did: String,
    pub vta_did_document: serde_json::Value,
    /// For `did:webvh` VTAs — raw `did.jsonl` so the integration can
    /// replay the log and verify the doc independently. None for
    /// self-resolving methods like `did:key`.
    pub vta_did_log: Option<String>,
}
// Cross-VTA / federation trust anchors are not in phase 1. When
// concrete federation scenarios arrive, add them as a typed field
// (e.g. `peer_vtas: Vec<VtaTrustBundle>`) rather than a speculative
// `Vec<TrustAnchor>` whose shape isn't yet informed by a real use case.
```

### VC: `VtaAuthorizationCredential`

```json
{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://openvtc.org/contexts/vta-authorization-v1"
  ],
  "type": ["VerifiableCredential", "VtaAuthorizationCredential"],
  "issuer": "did:webvh:vta.example.com",
  "validFrom": "2026-04-20T11:00:00Z",
  "validUntil": "2026-04-20T12:00:00Z",
  "credentialSubject": {
    "id": "did:key:z6MkVtaMintedAdminDid...",
    "adminOf": {
      "vta": "did:webvh:vta.example.com",
      "context": "prod-mediator",
      "role": "admin"
    },
    "operatorOf": {
      "did": "did:webvh:mediator.example.com",
      "template": "didcomm-mediator"
    }
  },
  "proof": {
    "type": "DataIntegrityProof",
    "cryptosuite": "eddsa-jcs-2022",
    "verificationMethod": "did:webvh:vta.example.com#assertion-key",
    "proofPurpose": "assertionMethod",
    "created": "2026-04-20T11:00:00Z",
    "proofValue": "z..."
  }
}
```

`credentialStatus` is deliberately absent — this VC is not revocable via a
status list. Lifecycle is entirely expiry-based.

`credentialSubject.id` is **the long-term admin DID** — equal to
`client_did` when no rollover was requested, or to the VTA-minted DID
when the request carried `adminTemplate`. The two cases are
distinguishable from the response summary (`admin_rolled_over`,
`admin_did`) but indistinguishable on the VC itself: holders simply
look up `secrets[credentialSubject.id]` to find the matching keys.

## Verification at integration first-boot (offline)

1. Parse the armored bundle, run sealed-transfer integrity checks
   (digest matches `--expect-digest`).
2. Verify sealed-transfer producer assertion: `DidSigned` by `vta_did`.
   Resolve `vta_did` offline via the `VtaTrustBundle` (replay
   `vta_did_log` to verify the shipped doc; extract assertion key;
   verify signature over producer pubkey + bundle digest).
3. Open the HPKE envelope (integration's X25519 secret, derived from
   the Ed25519 seed it kept at request-creation time).
4. Deserialize `TemplateBootstrapPayload`.
5. Verify `authorization` VC: same trust anchor as step 2. Check
   signature, `validUntil`, subject matches `client_did`.
6. Verify `config.did_document` matches the bundled `operatorOf` DID
   (sanity check: "the doc describes the DID the VC says I operate").
7. Write `did.jsonl` if the template emitted one; install keys from
   `secrets` keyed by the DIDs the VC authorizes; write VTA URL +
   trust bundle.
8. VC stashed for audit; never re-verified. ACL is the authority from
   here on.

Everything above happens with no network access. The integration's
subsequent VTA interactions use the installed credentials against the
VTA's native auth, where the VTA's ACL governs.

**Bundle open is not VTA-authoritative.** Bundle verification confirms
the VTA *issued* the authorization — not that it *currently* holds.
Between issuance and open, the VTA's ACL can change (admin revokes the
entry, operator decides not to proceed). A verified bundle install is
tentative until the integration's first successful VTA interaction. If
the ACL has been withdrawn before first call, the VTA returns 403 and
the integration logs the inconsistency and halts. This is working as
intended — the cost of the tentative window is bounded (zero operation
succeeds without ACL approval), so we accept it rather than introduce
a second authoritative channel.

**Clock-skew note.** The VC's `validUntil` check uses the same ±5min
tolerance as the VP's. The VC's `validFrom` is checked with the same
skew. This is a verifier-library default; we rely on
`affinidi-data-integrity`'s defaults rather than overriding.

## CLI + HTTP surface

### VTA host (offline flow)

```
vta bootstrap provision-integration \
    --request    <request.vp.json>       # required
    --context    <id>                    # required if request has no contextHint
    --out        <bundle.armor>          # required
    [--assertion <did-signed|pinned-only>]  # default: did-signed
```

The VTA's admin CLI. Uses `vta_did` (assertion key) to sign both the VC and
the sealed-transfer producer assertion. Mint key material, render template,
write bundle to disk, print digest + summary.

The integration operator generates the request side with:

```
vta bootstrap provision-request \
    --template      <name>               # didcomm-mediator | webvh-hosting-server | …
    --var KEY=VALUE                      # repeat for each template variable
    --context-hint  <id>                 # recommended
    --admin-template vta-admin           # recommended (long-term admin rollover)
    --validity-hours 168                 # default: 7 days
    --out           <request.vp.json>
```

Also available as `pnm bootstrap provision-request …` with identical
flags. Integration wizards built in Rust can call
[`vta_sdk::provision_integration::ProvisionRequestBuilder`] directly
instead of shelling out.

`--assertion pinned-only` is a dev/test-only escape hatch for
environments where `vta_did` is not yet configured (early integration
testing, scratch instances). Production flows must use `did-signed`.
The flag exists because hard-failing in dev environments slows iteration;
the default (`did-signed`) is what operators should always use when a
VTA identity is provisioned.

### PNM bridge (online flow)

```
pnm bootstrap provision-integration \
    --request    <request.vp.json>
    --vta        <slug>                  # which VTA (from PNM config)
    --context    <id>
    --out        <bundle.armor>
    [--assertion <did-signed|pinned-only>]
```

Thin HTTP client around `POST /bootstrap/provision-integration`. PNM
authenticates to the VTA with the operator's session; VTA does the
provisioning server-side using the same library function the offline CLI
uses.

### HTTP endpoint

```
POST /bootstrap/provision-integration
Authorization: <PNM session token>
Body:  { request: <VP JSON>, context: <id>, assertion: <variant> }
Response: { bundle: <armor string>, digest: <sha256 hex>, summary: {...} }
```

ACL: `require_admin` scoped to the target context. Super-admin passes
through. If the caller is context-admin but the request's `context_hint`
disagrees with `context`, reject (don't silently normalize).

### did.jsonl retrieval

```
vta did log --did <did> [--out <file>]
pnm did log --did <did> --vta <slug> [--out <file>]

GET /did/{did}/log      # public, unauthenticated, rate-limited
```

Returns raw `did.jsonl` bytes. 404 if the VTA doesn't know the DID. Public
because webvh logs are world-readable by design — security is cryptographic
(signatures, SCID anchoring), not access-gated.

**Snapshot semantics.** The VTA's copy of an integration's `did.jsonl`
is the provisioning-time snapshot. Once the integration boots and
publishes the log at its own webvh host, the integration becomes the
live source of truth and may extend the log (key rotation, service
updates) without re-syncing to the VTA. Use this endpoint for audit
("what did the VTA issue at provisioning?") and as a bootstrap/recovery
fallback when the integration's webvh host is unreachable. Don't treat
it as a live resolver — live resolution goes to the integration's own
host per standard webvh semantics.

## Shared library surface

Both CLI and HTTP handler route through:

```rust
// vta-service core library
pub async fn provision_integration(
    state: &AppState,
    auth: &AuthClaims,  // from PNM session or CLI local auth
    request: VerifiedBootstrapRequest,
    context: ContextId,
    assertion_mode: AssertionMode,
) -> Result<ProvisionIntegrationOutput, AppError>;

pub struct ProvisionIntegrationOutput {
    pub armored: String,       // sealed bundle, armored
    pub digest: String,        // sha256 of ciphertext
    pub summary: ProvisionSummary,  // admin did, integration did, log bytes, vta did
}
```

Inside:
1. Auth / ACL check (`require_admin` + `allowed_contexts`).
2. Resolve `context` — must already exist.
3. Resolve template (reject if template references an unregistered name).
4. Render template (existing `did_templates::render` path). Mint signing
   + KA keys. Capture `did.jsonl` for webvh, service endpoint for DIDComm,
   etc. as `TemplateOutput` values.
5. Mint admin credential for `client_did` in `context` (existing
   `operations::acl::create_acl` — role=admin, contexts=[context]).
6. Build + sign `VtaAuthorizationCredential` with `vta_did`'s assertion
   key. Set `validUntil` per operator config (default 1h).
7. Assemble `TemplateBootstrapPayload`. Secrets map keyed by integration
   DIDs. Config includes `VtaTrustBundle`.
8. Seal payload to `client_did`'s X25519 pubkey (derived from Ed25519 via
   `affinidi_crypto::did_key`). `ProducerAssertion` = `DidSigned` by
   `vta_did`. Fresh `bundle_id`, persistent nonce store to prevent replay.
9. Armor, digest, return.

Persistence: admin ACL row written atomically with the seal (same pattern
as `vta context provision`). Integration DID + log cached in the VTA's
webvh store (existing schema) so `GET /did/{did}/log` can serve it later.

### Security note on signing-key reuse

`vta_did`'s assertion key signs both the VC (Data Integrity proof over
URDNA2015-canonical VC bytes, `proofPurpose = "assertionMethod"`) and
the sealed-transfer producer assertion (Ed25519 signature over
`producer_pubkey || bundle_digest` in a framed context). This reuse is
safe: the two signed targets are structurally disjoint — different
canonicalization, different byte prefixes, different framing — so a
signature produced for one cannot be verified as valid in the other's
verifier. Standard cross-protocol replay analysis applies. No separate
issuer key is needed.

If at any point we introduce a third signed-by-`vta_did` artifact, the
same disjointness analysis must be re-run. The DID doc explicitly marks
the reused key as `assertionMethod`; anything claiming `authentication`
or other purposes should use a distinct verification method on the same
DID, not conflate purposes on one key.

## JSON-LD context files

Ship in `vta-sdk/src/sealed_transfer/contexts/`:
- `bootstrap-v1.jsonld` — defines `BootstrapRequest` type, `nonce`, `ask`,
  `label`, `validUntil` terms.
- `vta-authorization-v1.jsonld` — defines `VtaAuthorizationCredential`
  type, `adminOf`, `operatorOf` terms with their sub-properties.

Both marked `@protected: true`. Baked at compile time via `include_str!`
and registered with `ssi-json-ld`'s context loader. Tests include an
offline-verification sanity check that fails if the loader touches the
network.

Publishing at `https://openvtc.org/contexts/...` is an operational
follow-up. No code change required when it happens.

## Implementation sequencing

Original PR order. All landed on `sealed-bootstrap`; the
implementation diverged from the rough plan as the existing
infrastructure was understood — annotated below.

1. **`vta-sdk`: types + verify logic.** ✅ Landed.
2. **`vta-service`: shared `provision_integration` library fn.** ✅
   Landed. Took `&AppState` initially; refactored to
   `ProvisionIntegrationDeps` (with `From<&AppState>` and
   `From<&VtaState>`) when the DIDComm handler arrived in step 9.
3. **`vta-service`: CLI command.** ✅ Landed.
4. **`vta-service`: HTTP endpoint.** ✅ Landed.
5. **`vta-service`: `vta did log` CLI + `GET /did/{did}/log` endpoint.**
   ✅ Landed (REST). DIDComm equivalent fulfilled by the existing
   `did_management::GET_DID_WEBVH_LOG` protocol — see "DIDComm
   transport" notes below.
6. **`pnm-cli`: bridge commands.** ✅ Landed.
7. **Docs.** ✅ This file.

Follow-up work landed alongside (admin-DID rollover + DIDComm carrier):

8. **`vta-sdk`: `adminTemplate` field + `vta-admin` builtin.** ✅
   Optional second template ref on `TemplateBootstrapAsk`; backward-
   compatible (omitting it preserves pre-rollover behaviour).
9. **`vta-service`: ACL handoff for VTA-minted admin DID.** ✅
   `mint_admin_via_template` helper, ACL row written for the minted
   admin DID, VC subject set to the minted DID, both keys (Ed25519
   signing + canonical X25519 KA) populated in `payload.secrets`.
10. **`vta-sdk`: `SessionStore::ensure_authenticated_didcomm`.** ✅
    Returns a connected `VtaClient` (no JWT — DIDComm authcrypt is
    the auth). Mirrors REST `rotate_key` over DIDComm for sessions
    flagged `needs_rotation`.
11. **`vta-service`: DIDComm provision-integration handler.** ✅
    New protocol `firstperson.network/protocols/provision-integration/1.0`,
    handler in `messaging/handlers.rs`, wired through
    `messaging/router.rs`. Dual-check: authcrypt sender + VP holder
    must agree.
12. **`vta-sdk`: `provision_integration_didcomm` SDK helper.** ✅
    Holder-side wrapper over `DIDCommSession::send_and_wait`. No
    standalone CLI in this workspace — integration setup wizards
    (e.g. `affinidi-tdk-rs` mediator tool) consume the SDK directly.

DIDComm steady-state auth (`messaging/auth.rs::auth_from_message`)
was already in place before this work — no new code needed for the
"DIDComm auth handler" PR; the existing router already authcrypt-
authenticates every inbound message and ACL-gates by `from`.

## Non-goals (out of scope for this PR)

- **VC for other `SealedPayloadV1` variants.** `AdminCredential`,
  `ContextProvision`, `DidSecrets`, etc. stay as bespoke structs. Their
  VC migration is a separate design conversation.
- **Inline template JSON in requests.** Templates must be registered on
  the VTA via the existing authed endpoint first.
- **Federation / cross-VTA trust.** `VtaTrustBundle` is single-VTA in
  phase 1; federation is future work.
- **Integration key rotation.** The integration uses its minted keys for
  the lifetime of the DID. Rotation, if ever needed, is an admin
  operation (revoke + reprovision), not a built-in feature.
- **StatusList2021 or any VC revocation infrastructure.** Revocation is
  ACL removal.
- **VC-v2 post-rotation on the admin side.** Admin auth rotation updates
  the ACL entry's DID; no new VC issued. The admin-DID rollover at
  bootstrap time (§"Admin-DID rollover") is a single VC issuance with
  the rolled DID as subject — not a post-rotation re-issuance.
- **`webvh` admin-DID templates in phase 1.** The admin mint path
  rejects templates whose `methods` list excludes `"key"`. Adding
  webvh-hosted admin DIDs is a follow-up (the template authoring is
  already supported; the mint-path branch needs to be wired).
- **Custom `TemplateOutput` variants without a workspace PR.** Phase 1 has
  `WebvhLog` and `DidCommService` only; new variants require core change.

## Open questions (after review)

None blocking. The design is ready for implementation.

Notes-for-later (not decisions to make, just things to revisit when the
trigger arrives):

- **Operator-facing walkthrough.** A worked end-to-end example (request
  → provision → open → first VTA call) belongs in
  `docs/cold-start-guide.md` when step 7 of the sequencing lands. Not in
  this design brief — this doc is implementer-facing.
- **Federation trust anchors.** When cross-VTA scenarios become
  concrete, add a typed `peer_vtas: Vec<VtaTrustBundle>` to
  `VtaTrustBundle`. Deferred from phase 1 to avoid speculative shape.
- **VC for other `SealedPayloadV1` variants.** Separate design
  conversation when we need it — `AdminCredential`, `ContextProvision`,
  `DidSecrets` are all candidates but each has its own semantic fit
  question.
