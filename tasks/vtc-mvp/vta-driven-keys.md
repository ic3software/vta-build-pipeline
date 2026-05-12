# VTA-driven keys — Phase 0 design amendment

> **Status:** approved 2026-05-12. Open questions §9 resolved.
> **Drives:** M0.9.2 (wizard rewrite), M0.10 rework (emergency
> bootstrap), partial init_auth refactor in `vtc-service`, new
> `did:webvh` publication route on the VTC daemon.
> **Supersedes:** the M0.9.1 mapping doc's BIP-39 mnemonic step in
> the wizard call graph; M0.10's mnemonic-based recovery.

## 1. Problem statement

Two milestones already merged inside Phase 0 commit to incompatible
seed models:

- **M0.10 (PR #69, merged)** — `vtc admin emergency-bootstrap`
  verifies the operator's 24-word BIP-39 mnemonic by deriving 64
  bytes via `bip39::Mnemonic::to_seed("")` and constant-time
  comparing against the secret store contents. The check
  *presumes* the stored 64 bytes are BIP-39-derived.
- **M0.9.2 (acceptance)** — `vtc setup` calls VTA
  `POST /bootstrap/provision-integration` with the `vtc-host`
  template; the sealed bundle is the canonical source of the
  VTC's DID + key material.

The conflict: VTA-bundle keys are random integration keys minted
inside the VTA. There is no BIP-39 mnemonic that decodes to those
bytes. Adopting the M0.9.2 path breaks M0.10's recovery loop;
adopting M0.10's recovery model contradicts M0.9.2's stated
acceptance criteria and the "VTA is key authority" stance from
the project lead's response to the M0.9.2 design question.

Both `init_auth` (`vtc-service/src/server.rs:547-714`) and
`emergency.rs` (`vtc-service/src/emergency.rs:114-227`) assume a
single 64-byte secret-store value with mnemonic-recoverable
semantics. The rework touches both.

## 2. Revised seed model

**One source of truth.** The VTA is the sole authority for the
VTC's DID + key material. The VTC stores what the VTA gives it
and nothing else — no locally-generated BIP-39 mnemonic, no
locally-minted master seed.

### 2.1 What `vtc-service` stores

Where today's `secret_store.get() → Vec<u8>` returns 64 raw bytes
(`[Ed25519:32 || X25519:32]`), the post-rework layout is:

```
secret_store.get_bundle() → VtcKeyBundle {
    integration_did: String,                       // VTC's DID
    ed25519_signing_key_multibase: Zeroizing<String>,
    x25519_key_agreement_multibase: Zeroizing<String>,
    // optional: extra assertionMethod / authentication keys per
    // vtc-host template; see §6 open questions.
}
```

The bundle is the deserialized
`TemplateBootstrapPayload::secrets[<vtc_did>]` from the VTA. The
secret store wire format becomes a serialized `VtcKeyBundle`
(JSON or bincode — TBD in §6), not 64 raw bytes.

### 2.2 What `vtc-service` no longer stores

- No BIP-39 mnemonic anywhere.
- No HKDF-derived install-token signing key or audit key. These
  derive from the **VTA-provisioned Ed25519 signing key**
  instead, using the same HKDF info-string namespacing
  (`vtc-install-jwt-key/v1`, `vtc-audit-key/v1`). The signing
  key is still the operator-controllable secret; only its
  origin changes (VTA-minted, not BIP-39-derived).

### 2.3 Why this works

The Ed25519 signing key is high-entropy random bytes regardless
of whether it came from BIP-39 entropy or from the VTA's
provisioning RNG. HKDF is content-agnostic — install token
signing + audit-key HMAC work identically against either.

The breakage is purely on the **recovery** path: there is no
mnemonic to retype on a stopped daemon to prove "I'm the
legitimate operator." §4 specifies the replacement.

## 3. New wizard call graph (`vtc setup`)

```text
vtc setup
  └─ vtc_service::setup::wizard::run()
       │
       ├─ banner + intro
       │
       ├─ ask:                                         // 5 prompts
       │     ├─ config path
       │     ├─ vtc_url        : https://vtc.example.com
       │     ├─ admin_ux_url   : https://admin.vtc.example.com
       │     ├─ vta_url        : https://vta.example.com
       │     ├─ vta_did        : did:webvh:vta.example.com:dids:vta
       │     └─ context        : default
       │
       ├─ generate ephemeral Ed25519 keypair → ephemeral_did_key
       │     (one-shot — used for VTA auth + as VP holder key;
       │      discarded after this run)
       │
       ├─ print:
       │     "Authorize the temporary DID at the VTA, then continue:
       │
       │        pnm acl create --did <ephemeral_did_key> \
       │          --role admin --contexts <context>
       │
       │      Press <enter> once that completes."
       │
       ├─ wait for confirmation
       │
       ├─ vti_common::setup::secrets_prompt::configure_secrets()
       │     → SecretsConfig (keyring|aws|gcp|azure|env|toml)
       │     // promoted from vta-service in this PR-track
       │
       ├─ vta_sdk::provision_client::runner::run_provision(
       │     intent = VtaIntent::FullSetup,
       │     vta_did,
       │     setup_did       = ephemeral_did_key,
       │     setup_privkey_mb = ephemeral_priv_mb,
       │     ask = ProvisionAsk::for_template(
       │              "vtc-host",
       │              { URL, COMMUNITY_NAME, ADMIN_UX_URL },
       │              context,
       │           ),
       │     ...
       │   )
       │     → VtaReply::Full(FullSetupResult { admin_did,
       │         integration_did, payload, ... })
       │
       ├─ build VtcKeyBundle from payload.secrets[<integration_did>]
       │
       ├─ secrets_store.put(serialize(VtcKeyBundle))
       │
       ├─ write vtc-service/config.toml
       │     vtc_did = integration_did
       │     vta_did = <operator-supplied>
       │     public_url = vtc_url
       │     store.data_dir, secrets.*, auth.jwt_signing_key, …
       │
       ├─ vti_common::store::Store::open(&cfg.store)
       │     for ks in [sessions, acl, community, config,
       │                passkey, install, audit, audit_key]:
       │         store.keyspace(ks)?
       │
       ├─ derive install signer from bundle's Ed25519 key via HKDF
       │     mint_install_token(&signer, integration_did, ttl=15min)
       │     install_store.record_issued(jti, cnonce, eph_key, exp)
       │
       ├─ print install URL:  "{vtc_url}/install?token={jwt}"
       │
       └─ footer:  "Run `vtc` to start the daemon."
```

Three deviations from M0.9.1's mapping doc:

- **5 prompts**, not 3. The mapping's three-question list is
  insufficient — the wizard needs `vta_did` + `context` to drive
  challenge-response auth + ACL placement.
- **No BIP-39 mnemonic generation prompt.** Removed entirely —
  there is no operator-held secret to confirm. Recovery is the
  VTA path (§4), not a written mnemonic.
- **Operator-driven ACL step in the middle.** The wizard pauses
  while the operator runs `pnm acl create` to authorize the
  ephemeral DID. This is the same pattern PNM uses for `pnm
  setup` against a deferred-VTA-DID flow (workspace CLAUDE.md
  §"Deferred VTA-DID setup"). The wizard's "wait for confirmation"
  is what closes the loop.

## 4. New emergency-bootstrap flow

Mnemonic verification disappears. The new recovery flow:

```text
vtc admin emergency-bootstrap
  └─ open store (fjall lock = daemon stopped)
  └─ read existing VtcKeyBundle from secret store
  └─ if no bundle: AppError::Config "VTC was never set up"
  └─ read vtc_did + vta_did + vta_url from config.toml
  │
  ├─ banner: "EMERGENCY BOOTSTRAP — destructive recovery"
  ├─ Confirm prompt (skippable with --yes)
  │
  ├─ generate ephemeral Ed25519 keypair → ephemeral_did_key
  │     // ephemeral DID for the recovery round-trip
  │
  ├─ print:
  │     "Authorize this recovery DID at the VTA, then continue:
  │
  │        pnm acl create --did <ephemeral_did_key> \
  │          --role admin --contexts <vtc-context>
  │
  │      Press <enter> once that completes."
  │
  ├─ wait for confirmation
  │
  ├─ vta_sdk::provision_client::runner::run_provision(
  │     intent = VtaIntent::AdminRotated,
  │     vta_did, ephemeral_did, ephemeral_priv,
  │     ask = ProvisionAsk::vta_admin_rotated(context),
  │   )
  │     → VtaReply::AdminRotated(result)
  │     // VTA verifies the operator is genuinely an admin at the
  │     // target context (challenge-response succeeds only if the
  │     // ephemeral DID was just authorized) and confirms the
  │     // existing VTC integration DID is unchanged.
  │
  ├─ destructive local cleanup (same as today):
  │     - clear every Role::Admin ACL entry
  │     - remove every admin:<did> sister record
  │     - drop PasskeyUser + pk_cred:* + pk_did:* rows
  │     - clear install:carveout:closed
  │
  ├─ derive install signer from existing bundle's Ed25519 key
  │     mint_install_token + install_store.record_issued
  │
  ├─ persist install:emergency_pending marker
  │     (same as today — server::run consumes on next boot)
  │
  └─ print install URL + footer
```

Key shifts vs today's M0.10:

- **Authority** is the VTA's ACL, not a mnemonic the operator
  wrote down. The check is "can this operator currently get a
  fresh admin grant at the VTA for this context?"
- **The VTC's integration DID + keys are not rotated.** The
  bundle stays in the secret store; only the admin ACL state
  resets.
- **Trust boundary moves to PNM.** The operator must still
  control their PNM admin credential at the VTA. Losing both
  the VTC's admin passkey *and* PNM admin access at the VTA
  means losing the community — but that's a stronger trust
  posture than "anyone with the mnemonic can reset the VTC."
- **`vta_did` becomes required config.** Today's
  `config.vta_did` is optional / informational; after this
  rework it's load-bearing for recovery.

## 5. Code refactor surface

### 5.1 `vti-common::config::SecretsConfig`

Today: `inline_secret: Option<String>` carries a hex-encoded 64-
byte buffer. Post-rework: same field, but contents are now a
serialized `VtcKeyBundle` (JSON, base64url-wrapped). VTA's usage
is unchanged — only VTC reinterprets the field's contents.

### 5.2 `vtc-service/src/server.rs::init_auth`

Today (`server.rs:547-714`):
```rust
let key_material = secret_store.get().await?;     // 64 bytes
let ed25519_bytes = &key_material[..32];
let x25519_bytes  = &key_material[32..];
let install_signer = InstallTokenSigner::from_master_seed(&key_material)?;
let audit_writer   = AuditKeyStore::ensure_initial(&key_material).await?;
let signing_secret = Secret::generate_ed25519(None, Some(ed25519_bytes));
let ka_secret      = Secret::generate_x25519(None, Some(x25519_bytes))?;
```

Post-rework:
```rust
let bundle = secret_store.get_bundle().await?;    // VtcKeyBundle
let ed25519_bytes = decode_multibase(&bundle.ed25519_signing_key_multibase)?;
let x25519_bytes  = decode_multibase(&bundle.x25519_key_agreement_multibase)?;
let install_signer = InstallTokenSigner::from_signing_key(&ed25519_bytes)?;
let audit_writer   = AuditKeyStore::ensure_initial_from_signing_key(&ed25519_bytes).await?;
let signing_secret = Secret::generate_ed25519(None, Some(&ed25519_bytes));
let ka_secret      = Secret::generate_x25519(None, Some(&x25519_bytes))?;
```

Roughly the same wiring; the source of the bytes changes. The
HKDF input shifts from 64 bytes to 32 (the Ed25519 half only);
HKDF accepts variable-length IKM so the construction is fine. We
must rename the `info` string to a `/v2` form
(`vtc-install-jwt-key/v2`, `vtc-audit-key/v2`) so any pre-rework
deployment with v1-derived keys fails loud instead of silently
treating different bytes as the same key.

### 5.3 `vtc-service/src/emergency.rs`

Today (~330 lines): mnemonic prompt, BIP-39 derivation,
constant-time compare, destructive cleanup, install token mint.

Post-rework: drop the mnemonic prompt + verification entirely.
Replace with the ephemeral did:key + `run_provision`
`AdminRotated` flow described in §4. Roughly the same line count
— the BIP-39 surface goes away, the VTA roundtrip surface comes
in.

### 5.4 `vtc-service/src/install/state_machine.rs`

No changes. `reopen_carveout` / `mark_emergency_pending` /
`take_pending_emergency` are recovery-flow-agnostic.

### 5.5 New module: `vtc-service/src/setup/`

```
vtc-service/src/setup/
├── mod.rs                pub use wizard::run_setup_wizard;
├── wizard.rs             interactive wizard (§3)
└── bundle.rs             VtcKeyBundle (de)serialization, store I/O
```

### 5.6 `vti-common::setup::*` (new feature-gated submodule)

```
vti-common/src/setup/
├── mod.rs
└── secrets_prompt.rs     promoted from vta-service::setup::interactive
```

Behind a `setup` feature flag (`dialoguer` is heavy). Only the
**secrets-prompt** moves — the mnemonic-with-confirmation helper
disappears from the codebase entirely (no more BIP-39 in either
service).

### 5.7 `vtc-service/src/main.rs`

`Commands::Setup` re-dispatches to `setup::wizard::run_setup_wizard`.
`Commands::Admin::EmergencyBootstrap` keeps its clap surface but
no longer accepts `--mnemonic`; gains `--context` and reads
`vta_url` / `vta_did` from config.

## 6. Test refactor surface

### 6.1 `vtc-service/tests/emergency_bootstrap.rs`

All 6 tests need rewriting:

| Today's test | Post-rework |
|---|---|
| `happy_path_clears_admin_reopens_carveout_and_audits_on_restart` | Same shape; replace mnemonic input with a mocked VtaClient that returns a successful `AdminRotated` reply. |
| `wrong_mnemonic_is_refused_and_state_unchanged` | Replaced by `vta_rejects_unauthorized_recovery_did_and_state_unchanged` — the mocked VtaClient returns 401 (ephemeral DID not in ACL); local state untouched. |
| `malformed_mnemonic_is_rejected_as_validation_error` | Drop — no mnemonic input. |
| `fresh_install_url_works_for_claim_start_after_emergency_bootstrap` | Unchanged (the install URL handoff is the same). |
| `no_secret_in_store_yields_clean_config_error` | Same — bundle absent. |
| `outcome_install_url_falls_back_to_vtc_scheme_when_public_url_missing` | Unchanged. |

Net: 5 tests, all driving against a `MockVtaClient` trait the
wizard + emergency-bootstrap take through their constructor (the
existing `run_emergency_bootstrap_with_store` already follows the
"driver split for tests" pattern; same shape).

### 6.2 `vtc-service/tests/install_flow.rs`

Today's M0.12.1 install-flow gate test pre-stages a 64-byte
master seed directly into the secret store
(`install_flow.rs::seed_secret_store`). It needs reshaping to
stage a `VtcKeyBundle` instead. Behaviour assertions stay the
same.

### 6.3 vtc-service test helpers

Every integration test (`tests/admin_bootstrap.rs`,
`tests/admin_passkeys.rs`, `tests/install_claim.rs`, etc.)
constructs an AppState today via a `seed_secret_store` helper
that calls `secret_store.put(&[u8; 64])`. The helper moves to
`seed_secret_store(&VtcKeyBundle)`. One central change; every
test consumes it.

## 7. PR slice proposal (superseded by §11)

> §11 supersedes this section after Q3 was answered "no
> compat shim." Kept here for traceability — the original
> three-PR plan assumed a shim window.

Three PRs, dependency-ordered:

### PR A — VtcKeyBundle + init_auth refactor

- Introduce `VtcKeyBundle` (`vtc-service/src/setup/bundle.rs`).
- Refactor `init_auth` to consume a bundle, deriving install
  signer + audit key from the Ed25519 signing key only.
- Bump HKDF info strings to `/v2`.
- Rewrite every test helper that stages secret-store contents
  to stage a bundle.
- Existing CLI flows (`vtc setup` legacy wizard, `vtc admin
  emergency-bootstrap`) keep working — they still produce 64
  raw bytes today; PR A keeps a temporary compatibility shim
  that converts legacy 64-byte buffers into a synthetic bundle
  so the integration tests stay green during the slice.
- ~700 lines, mostly test plumbing.

### PR B — New wizard + secrets-prompt promotion

- Add `vti-common::setup::secrets_prompt` behind `setup` feature.
- Write `vtc-service::setup::wizard::run_setup_wizard` per §3.
- Swap `main.rs::Commands::Setup` dispatch.
- Delete legacy `vtc-service/src/{setup.rs, did_webvh.rs,
  import_did.rs, acl_cli.rs}` and prune from `lib.rs` + `main.rs`.
- Remove the compatibility shim from PR A — every test fixture
  now stages a real VtcKeyBundle.
- `#[ignore]`d integration test against a live VTA fixture
  documenting the env-var contract (`VTC_SETUP_TEST_VTA_URL`,
  `VTC_SETUP_TEST_VTA_DID`).
- ~800 lines added + ~1100 lines deleted.

### PR C — Emergency-bootstrap rework

- Rewrite `vtc-service/src/emergency.rs` per §4.
- Rewrite `tests/emergency_bootstrap.rs` per §6.1.
- Update `main.rs::run_emergency_bootstrap_cli` (drop `--mnemonic`,
  add `--context`).
- Update spec `docs/05-design-notes/vtc-mvp.md` §4.5.
- ~600 lines net.

After PR C: M0.9.2 + M0.9.3 + M0.10-rework + the relevant
M0.12.x updates land together. Phase 0 gate (M0.12.3) follows.

## 8. Spec amendments

### 8.1 `docs/05-design-notes/vtc-mvp.md` §4.1 (Install token + setup wizard)

Three-question prompt → 5-question prompt; add the
"VTA-driven keys" subsection that pins the bundle source.

### 8.2 §4.5 (Emergency bootstrap)

Rewrite the "mnemonic gate" section. New language:

> Emergency bootstrap is authorized by the operator's ability
> to authenticate as an admin against the VTA for the
> community's context. The check is delegated to the VTA's
> `provision-integration` flow with `VtaIntent::AdminRotated`:
> if the operator can mint a fresh admin authorization at the
> VTA (i.e., they hold a PNM admin credential and can ACL-add
> a temporary recovery DID), the VTC accepts the recovery.

> No locally-held mnemonic is involved. Losing PNM admin
> access at the VTA means losing the community; this is by
> design — there is one trust root, not two.

### 8.3 `tasks/vtc-mvp/setup-mapping.md`

Mark superseded: insert a header pointing at this doc. The
3-question call graph is wrong; the mnemonic step is dropped.

## 9. Open questions — resolutions

Decided 2026-05-12.

- **Q1 (key shape).** Collapse to two keys. One Ed25519
  serves both `assertionMethod` and `authentication`; one
  X25519 serves `keyAgreement`. Matches `DidKeyMaterial`'s
  shape and how VTA DIDs already work. **Spec
  implication:** M0.2.1's vtc-host template needs amendment
  — the three-key description in `tasks/vtc-mvp/todo.md`
  M0.2.1 ("mints three keys: assertionMethod Ed25519,
  authentication Ed25519, keyAgreement X25519") and in
  the spec drops to two. The amendment lands in PR A as
  part of the bundle slice.
- **Q2 (serialization).** JSON. Forward-compat (extra fields
  decode-skip) wins over the size saving.
- **Q3 (compat shim).** No shim. The codebase hasn't shipped
  to operators; we get a clean break. PR slicing in §7 is
  revised accordingly — every test fixture flips in lockstep
  with the producer change.
- **Q4 (VTA connection topology).** VTC connects directly to
  the VTA — no PNM IPC anywhere in the daemon's wire path.
  PNM stays a human-facing tool. The operator still uses PNM
  to ACL-add the ephemeral DID at the VTA (a human action),
  but the VTC's wizard authenticates to the VTA in-process
  via challenge-response using the same ephemeral key. No
  new dependency from `vtc-service` on PNM.
- **Q5 (VTC DID method).** VTC's DID is always `did:webvh`,
  never `did:key`. The VTC must host its own `did.jsonl`.
  **Spec implication:** the VTC daemon gains a route
  (`GET /<scid>/did.jsonl` or `GET /.well-known/did.jsonl`
  — choice §10) that serves the DID log produced by the
  VTA's `vtc-host` template render. The log content is
  delivered to the VTC inside
  `TemplateBootstrapPayload.config.outputs`; the wizard
  writes it to disk at setup time. Subsequent log entries
  (e.g., key rotation) flow through the same bundle-open
  path — for Phase 0 there are none.

## 10. Did-log publication on the VTC

Forced into scope by Q5. The VTC needs a route that serves
the canonical `did.jsonl` for its own DID.

**Route shape**: `GET /{scid}/did.jsonl` mounted under the
`api.mount` prefix (default `/v1` → `/v1/{scid}/did.jsonl`).
The scid is parsed out of the VTC's `did:webvh:<host>:<scid>`
identifier and matched against the URL parameter; mismatch
returns 404. Trust-Task-exempt (it's a DID-resolver fetch,
not an authenticated operation). No rate limiting beyond
the global unauthed-route limiter.

**Storage**: the `did.jsonl` content is one of two equivalent
sources — either a file at `<store.data_dir>/did/<scid>.jsonl`
written by the wizard, or a row in a new `did_logs` keyspace.
Proposal: file on disk; matches `affinidi-secrets-resolver`'s
existing keyring artefact pattern and lets `cat` work for
debugging. The handler `tokio::fs::read`s on every request
(cheap; the log is < 4 KiB for a fresh DID).

**Trust-Task ID**: `did/webvh/log/1.0`. Exempt from header
enforcement (same logic as `/health` — DID resolvers won't
attach our private extension header).

**Setup wizard responsibility**: after opening the bundle,
extract `payload.config.outputs[i].content` where
`outputs[i].name == "did.jsonl"` and write to disk.

**Rotation in steady state**: out of scope for Phase 0.
Phase 1+ adds a routed update path (probably reusing
`provision-integration` with a rotate variant). For now the
log is write-once at setup; emergency-bootstrap leaves it
intact (§4: "VTC's integration DID is not rotated").

## 11. Revised PR slicing (replaces §7's three-PR proposal)

With no compat shim and no operator deployment to preserve,
the slicing tightens. Two PRs, with the boundary shifted
from the doc's original plan based on what actually surfaced
during PR A's implementation:

### PR A — Plumbing + legacy delete (this PR)

- Introduce `VtcKeyBundle` (`vtc-service/src/setup/bundle.rs`).
- Refactor `init_auth` to consume a bundle, deriving install
  signer + audit key from the Ed25519 signing key only.
  - Accepts both bundle JSON and the legacy 64-byte
    `[Ed25519:32 || X25519:32]` shape so every existing
    integration-test fixture keeps working unchanged.
- Bump HKDF info strings to `/v2`
  (`vtc-install-jwt-key/v2`, `vtc-audit-key/v2`).
- Delete legacy `vtc-service/src/{setup.rs, did_webvh.rs,
  import_did.rs, acl_cli.rs}` and the
  `create-did-webvh` / `import-did` / `acl` subcommands.
- Stub the new `vtc-service/src/setup/wizard.rs` with a
  "feature being reworked" error so `vtc setup` returns a
  clear message instead of running the old throw-away
  wizard.
- Stub `vtc-service/src/emergency.rs` with a matching
  error and delete `tests/emergency_bootstrap.rs` (PR B
  rewrites both).
- Note: M0.2.1 already ships the 2-key shape; only the
  todo.md description needed correction.

Boundary shift vs the original doc: did-log publication
route, secrets-prompt promotion, and the live wizard impl
move to PR B because they're consumers of the bundle, not
producers of it. PR A focuses on the producer interface
+ legacy delete.

### PR B — Live wizard + emergency-bootstrap rework

- Promote `vti-common::setup::secrets_prompt` behind
  `setup` feature flag.
- Add did-log publication route (§10).
- Implement `vtc-service/src/setup/wizard.rs` per §3 (5
  prompts → ephemeral DID → operator ACL step →
  `run_provision` → bundle open → config write + did.jsonl
  write + install URL).
- Rewrite `vtc-service/src/emergency.rs` per §4 (VTA
  `AdminRotated` flow, no BIP-39 anywhere).
- Write `vtc-service/tests/emergency_bootstrap.rs` per
  §6.1 (5 tests, MockVtaClient).
- Update `main.rs::Commands::Admin::EmergencyBootstrap`
  clap surface (drop `--mnemonic`, add `--context`).
- Spec amendments: `docs/05-design-notes/vtc-mvp.md` §4.5
  rewritten; `tasks/vtc-mvp/setup-mapping.md` marked
  superseded with pointer to this doc.
- `#[ignore]`d end-to-end test against a live VTA fixture
  documenting the env-var contract.

After PR B: M0.9.2, M0.9.3, M0.10-rework all land. Phase 0
gate M0.12.3 follows.
