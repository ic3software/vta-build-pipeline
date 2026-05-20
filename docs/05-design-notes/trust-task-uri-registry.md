# Trust-task URI registry — VTA + webvh-service migration

**Status:** Draft (Phase 0.2 of the trust-task envelope migration initiative).
**Updated:** 2026-05-19; revised 2026-05-20 (cryptosuite dropped; passkey-login-{start,finish} URIs added).
**Scope:** Both services + all dependent consumers.

This document is the authoritative catalogue of trust-task URIs across
the VTA (`verifiable-trust-infrastructure`) and the WebVH services
(`affinidi-webvh-service`) for the duration of the trust-task envelope
migration. Each URI corresponds to one operation on the wire and is the
target both REST handlers and DIDComm dispatchers route on.

Once the migration ships, the source-of-truth for each URI lives in the
service's own const registry (`vta-sdk::trust_tasks::specs` for VTA,
`did-hosting-common::did_hosting_tasks` for WebVH). This document
catalogues them once for design review.

## Naming convention

```
https://trusttasks.org/{namespace}/{op-path}/{maj}.{min}
```

| Slot | Rule |
|---|---|
| **scheme + host** | Always `https://trusttasks.org/`. Identifier only, not resolvable. |
| **namespace** | One of `vta`, `did-hosting`, `webvh`. See namespace table below. |
| **op-path** | Lowercase kebab-case. Hierarchical (`auth/challenge`, `services/didcomm/enable`). |
| **version** | `{major}.{minor}` only. No patch component. A new minor or major requires registering a new URI; the old URI keeps routing to the old handler until removed in a future release. |

The router does NOT do version-family matching. `1.0` and `1.1` are
completely separate identifiers and may have completely different
payload shapes.

## Namespaces

| Namespace | Owner service | Scope |
|---|---|---|
| `vta` | VTA (`vta-service`, `vta-enclave`) | All VTA operations — auth, keys, contexts, ACL, bootstrap, services management, templates, audit, backup |
| `did-hosting` | webvh-service (`did-hosting-control`, `did-hosting-server`, `did-hosting-daemon`) | DID-method-agnostic hosting operations — auth, DID lifecycle, server registration, domain management, registry |
| `webvh` | webvh-service | WebVH-protocol-specific operations — witness publish/confirm, log sync. Other DID methods (`webs`, `webplus`) would get sibling namespaces. |

The boundary between `vta/webvh/*` (VTA-controlled WebVH operations) and
`did-hosting/*` is explicitly resolved below — see "Boundary between VTA
and WebVH".

## VTA URIs (new — all to be added)

VTA has no trust-task URIs registered yet. The full surface migrates in
Phase 3 slices; this section enumerates the target URIs by slice.

### Auth slice (`vta/auth/*`)

| URI | Today's surface | Direction | Payload sketch |
|---|---|---|---|
| `vta/auth/challenge/1.0` | `POST /auth/challenge` | request | `{ did }` → returns `{ session_id, challenge }` as generic OK-response (no separate URI; follows webvh-service convention) |
| `vta/auth/authenticate/1.0` | `POST /auth/` | request | `{ session_id, challenge, session_pubkey_b58btc? }` (+ `eddsa-jcs-2022` proof on trust-task). **Note:** legacy DID-key-JWS auth path. Passkey-based authentication uses `vta/auth/passkey-login-{start,finish}/1.0` instead — see Passkey login slice below. |
| `vta/auth/passkey-login-start/1.0` | **NEW** (mirrors webvh `did-hosting/auth/passkey-login-start/1.0`) | request | `{ did }` → returns `{ session_id, challenge, allowCredentials[] }` |
| `vta/auth/passkey-login-finish/1.0` | **NEW** (mirrors webvh `did-hosting/auth/passkey-login-finish/1.0`) | request | `{ session_id, authenticatorData, clientDataJSON, signature, credential_id, session_pubkey_b58btc? }`. WebAuthn assertion verified via webauthn-rs against DID-resolved VM. `clientData.challenge` MUST equal `SHA-256(canonical trust-task body)` (document binding). |
| `vta/auth/authenticate-response/1.0` | response of `/auth/` | response | `{ access_token, refresh_token, access_expires_at, refresh_expires_at, session_id }` |
| `vta/auth/refresh/1.0` | `POST /auth/refresh` | request | `{ refresh_token }` (+ proof from session key) |
| `vta/auth/refresh-response/1.0` | response of `/auth/refresh` | response | same shape as authenticate-response |
| `vta/auth/revoke-session/1.0` | `DELETE /auth/sessions/{id}` | request | `{ session_id }` |

### Bootstrap slice (`vta/bootstrap/*`)

| URI | Today's surface | Notes |
|---|---|---|
| `vta/bootstrap/request/1.0` | `POST /bootstrap/request` (TEE Mode B carve-out) | Carries Nitro attestation in the trust-task `proof` block; single-use, MODE_B_LOCK still applies |
| `vta/bootstrap/request-response/1.0` | response | sealed admin VP bundle (HPKE), CRC24-armored |
| `vta/bootstrap/provision-integration/1.0` | `POST /bootstrap/provision-integration` | Body is the template-bootstrap VP; sealed reply unchanged |
| `vta/bootstrap/provision-integration-response/1.0` | response | sealed `TemplateBootstrapPayload` |

### Keys slice (`vta/keys/*`)

| URI | Today's surface | Notes |
|---|---|---|
| `vta/keys/list/1.0` | `GET /keys` + `key-management/1.0/list-keys` | |
| `vta/keys/create/1.0` | `POST /keys` + `key-management/1.0/create-key` | |
| `vta/keys/get/1.0` | `GET /keys/{key_id}` + DIDComm equivalent | |
| `vta/keys/rename/1.0` | DIDComm `rename-key` (no REST today) | |
| `vta/keys/revoke/1.0` | DIDComm `revoke-key` + REST equivalent | |
| `vta/keys/sign/1.0` | `POST /keys/{key_id}/sign` + `key-management/1.0/sign-request` | Raw-bytes signing oracle |
| `vta/keys/sign-trust-task-proof/1.0` | **NEW** (Phase 2 task 2.1) | Returns a ready-to-splice trust-task `proof` block; cryptosuites `eddsa-jcs-2022` and `ecdsa-jcs-2019` |
| `vta/keys/import-wrapping-key/1.0` | `GET /keys/import/wrapping-key` | |
| `vta/keys/import/1.0` | `POST /keys/import` | |

**Note:** the legacy `GET /keys/{key_id}/secret` mnemonic-export
endpoint moves to the seeds slice (it was per-seed, not per-key — the
URL was misleading). See `vta/seeds/export-mnemonic/1.0`.

### Seeds slice (`vta/seeds/*`)

| URI | Today's surface | Notes |
|---|---|---|
| `vta/seeds/list/1.0` | `GET /keys/seeds` + DIDComm `list-seeds` | |
| `vta/seeds/rotate/1.0` | `POST /keys/seeds/rotate` + DIDComm `rotate-seed` | |
| `vta/seeds/export-mnemonic/1.0` | `GET /keys/{key_id}/secret` (formerly under keys) | One-shot BIP-39 mnemonic export under `MnemonicExportGuard`. Super-admin only. Zeroized on drop. Audit event renames `keys.get-secret` → `seeds.export-mnemonic`. |

### Contexts slice (`vta/contexts/*`)

| URI | Today's surface |
|---|---|
| `vta/contexts/list/1.0` | `GET /contexts` + DIDComm `list-contexts` |
| `vta/contexts/create/1.0` | `POST /contexts` + DIDComm `create-context` |
| `vta/contexts/get/1.0` | `GET /contexts/{id}` + DIDComm `get-context` |
| `vta/contexts/update/1.0` | `PATCH /contexts/{id}` + DIDComm `update-context` |
| `vta/contexts/update-did/1.0` | DIDComm `update-context-did` (and REST equivalent) |
| `vta/contexts/preview-delete/1.0` | DIDComm `preview-delete-context` + REST |
| `vta/contexts/delete/1.0` | `DELETE /contexts/{id}` + DIDComm `delete-context` |

### ACL slice (`vta/acl/*`)

| URI | Today's surface |
|---|---|
| `vta/acl/list/1.0` | `GET /acl` + DIDComm `list-acl` |
| `vta/acl/create/1.0` | `POST /acl` + DIDComm `create-acl` |
| `vta/acl/get/1.0` | `GET /acl/{did}` + DIDComm `get-acl` |
| `vta/acl/update/1.0` | `PATCH /acl/{did}` + DIDComm `update-acl` |
| `vta/acl/delete/1.0` | `DELETE /acl/{did}` + DIDComm `delete-acl` |

### Audit slice (`vta/audit/*`)

| URI | Today's surface |
|---|---|
| `vta/audit/list-logs/1.0` | `GET /audit/logs` + DIDComm `list-logs` |
| `vta/audit/get-retention/1.0` | DIDComm `get-retention` + REST |
| `vta/audit/update-retention/1.0` | DIDComm `update-retention` + REST |

### Attestation slice (`vta/attestation/*`)

| URI | Today's surface |
|---|---|
| `vta/attestation/status/1.0` | `GET /attestation/status` |
| `vta/attestation/did-log/1.0` | `GET /attestation/did-log` |

### Services management slice (`vta/services/*`)

This is the runtime service-management surface (REST + DIDComm
transports, drain windows, mediator reports). All eleven ops migrate.

| URI | Today's surface |
|---|---|
| `vta/services/list/1.0` | `GET /services` + DIDComm `services/list` |
| `vta/services/rest/enable/1.0` | `POST /services/rest/enable` |
| `vta/services/rest/update/1.0` | `POST /services/rest/update` |
| `vta/services/rest/disable/1.0` | `POST /services/rest/disable` |
| `vta/services/rest/rollback/1.0` | `POST /services/rest/rollback` |
| `vta/services/didcomm/enable/1.0` | `POST /services/didcomm/enable` (REST-only by construction) |
| `vta/services/didcomm/update/1.0` | `POST /services/didcomm/update` |
| `vta/services/didcomm/disable/1.0` | `POST /services/didcomm/disable` |
| `vta/services/didcomm/rollback/1.0` | `POST /services/didcomm/rollback` |
| `vta/services/didcomm/drain/list/1.0` | `GET /services/didcomm/drain` |
| `vta/services/didcomm/drain/cancel/1.0` | `POST /services/didcomm/drain/cancel` |
| `vta/services/mediators/report/1.0` | `GET /mediators/report` |

### WebVH-DID-lifecycle slice (`vta/webvh/*`)

Operations VTA performs on WebVH DIDs it owns — distinct from the
WebVH host's own DID lifecycle ops under `did-hosting/did/*`. See
boundary discussion below.

| URI | Today's surface |
|---|---|
| `vta/webvh/servers/list/1.0` | webvh server CRUD on VTA side |
| `vta/webvh/servers/add/1.0` | (REST `POST /webvh/servers`) |
| `vta/webvh/servers/update/1.0` | |
| `vta/webvh/servers/remove/1.0` | |
| `vta/webvh/dids/list/1.0` | DIDs hosted/known to this VTA |
| `vta/webvh/dids/create/1.0` | Mint new DID via template + register with host |
| `vta/webvh/dids/get/1.0` | |
| `vta/webvh/dids/get-log/1.0` | `GET /webvh/dids/{did}/log` (authed) |
| `vta/webvh/dids/get-log-public/1.0` | `GET /did/{did}/log` (unauthed mirror — keep REST-only) |
| `vta/webvh/dids/delete/1.0` | |
| `vta/webvh/dids/update/1.0` | DID-doc patch |
| `vta/webvh/dids/rotate-keys/1.0` | |
| `vta/webvh/dids/register-with-server/1.0` | Promote serverless → server-managed (one-way) |

### DID templates slice (`vta/did-templates/*`)

Global + context-scoped CRUD. Same operations under both scopes; URIs
distinguish by namespace.

**Global (super-admin):**

| URI | Today's surface |
|---|---|
| `vta/did-templates/list/1.0` | `GET /did-templates` |
| `vta/did-templates/create/1.0` | `POST /did-templates` |
| `vta/did-templates/get/1.0` | `GET /did-templates/{name}` |
| `vta/did-templates/update/1.0` | `PATCH /did-templates/{name}` |
| `vta/did-templates/delete/1.0` | `DELETE /did-templates/{name}` |
| `vta/did-templates/render/1.0` | `POST /did-templates/{name}/render` |

**Context-scoped (context-admin):**

| URI | Today's surface |
|---|---|
| `vta/contexts/did-templates/list/1.0` | `GET /contexts/{id}/did-templates` |
| `vta/contexts/did-templates/create/1.0` | `POST /contexts/{id}/did-templates` |
| `vta/contexts/did-templates/get/1.0` | `GET /contexts/{id}/did-templates/{name}` |
| `vta/contexts/did-templates/update/1.0` | `PATCH /contexts/{id}/did-templates/{name}` |
| `vta/contexts/did-templates/delete/1.0` | `DELETE /contexts/{id}/did-templates/{name}` |
| `vta/contexts/did-templates/render/1.0` | `POST /contexts/{id}/did-templates/{name}/render` |

### Passkey VM slice (`vta/passkey-vms/*`)

**Scope clarification:** this slice is **DID-level passkey VM enrolment** —
adding a passkey as a `verificationMethod` in a DID document that this VTA
controls. Once enrolled, the passkey is usable across *any* RP that resolves
the DID. Distinct from webvh-service's `did-hosting/auth/passkey-*` URIs,
which are *service-level* credentials (direct passkey login to webvh-service
for users who don't have a VTA). Both can coexist; our initiative uses the
DID-level path.

| URI | Today's surface |
|---|---|
| `vta/passkey-vms/enroll-challenge/1.0` | `POST /did/verification-methods/passkey/challenge` |
| `vta/passkey-vms/enroll-submit/1.0` | `POST /did/verification-methods/passkey` |
| `vta/passkey-vms/list/1.0` | `GET /did/verification-methods/passkey?did=…` |
| `vta/passkey-vms/revoke/1.0` | `DELETE /did/verification-methods/passkey/{fragment}` |

### Backup slice (`vta/backup/*`)

Three-phase descriptor pattern (initiate → transport → finalize) — bulk
bytes flow out-of-band so the trust-task framework's 1MB cap is never
hit, and the transport can be swapped (VTA-streamed in v1, S3-presigned
later) without changing clients. Modelled on OCI image distribution +
Sigstore + Git LFS.

| URI | Purpose |
|---|---|
| `vta/backup/initiate-export/1.0` | Request export. Returns `BundleDescriptor { bundle_id, transport_url, transport_token, expected_sha256, expected_size_bytes, algorithm, expires_at }`. Authed + audit-logged. |
| `vta/backup/complete-export/1.0` | Optional client ack of successful download. Closes the audit loop. |
| `vta/backup/initiate-import/1.0` | Request import. Returns upload BundleDescriptor with POST target. |
| `vta/backup/finalize-import/1.0` | Apply uploaded bytes; returns `{ status, dids_loaded, contexts_loaded }`. |
| `vta/backup/abort/1.0` | Cancel an in-flight bundle by `bundle_id`. |

**Plus one REST endpoint that stays REST (excluded from migration):**
`GET /backup/blob/{bundle_id}` with `X-Export-Token` header. Streams
encrypted bytes (chunked transfer-encoding). Token is one-shot, 5-minute
TTL. Analogous to `GET /did/{did}/log` — bulk transport is wrong on top
of a JSON envelope.

Algorithms supported initially: `stream` (this VTA serves the bytes).
Future: `s3-presigned`, `chunked-trust-task` (for DIDComm-only deployments
with no HTTPS transport).

### Config slice (`vta/config/*`)

| URI | Today's surface |
|---|---|
| `vta/config/get/1.0` | DIDComm `get-config` |
| `vta/config/update/1.0` | DIDComm `update-config` |

### Discovery slice (`vta/discovery/*`)

| URI | Today's surface |
|---|---|
| `vta/discovery/capabilities/1.0` | `GET /capabilities` |

### VTA management slice (`vta/management/*`)

| URI | Today's surface | Notes |
|---|---|---|
| `vta/management/reload-services/1.0` | `POST /vta/restart` (current implementation does soft reload, not process restart) | Tears down and re-initializes REST, DIDComm, storage threads with current config. Does NOT restart the process. Use after `vta/config/update/1.0` to apply changes. Super-admin only. URI renamed from `restart` to `reload-services` to match actual semantics. |

Metrics is excluded from migration entirely — see "Excluded from
migration" below.

### Join requests (`vta/join-requests/*`)

VTC↔VTA bridge — currently DIDComm-only.

| URI | Today's surface |
|---|---|
| `vta/join-requests/request/1.0` | DIDComm `join-requests/request` |
| `vta/join-requests/decision/1.0` | DIDComm `join-requests/decision` |
| `vta/join-requests/list/1.0` | DIDComm `join-requests/list` |

**VTA URI count:** ~79 (precise count after slice-by-slice spec lockdown). VTC ops excluded from this initiative.

## WebVH URIs (already registered, plus additions for this initiative)

The complete set lives in `did-hosting-common::did_hosting_tasks`
(61 URIs as of 2026-05-19) and is authoritative. Highlights:

### Existing — auth (relevant to first-light)

| URI | Status |
|---|---|
| `did-hosting/auth/authenticate/1.0` | registered; handler still uses legacy `affinidi.com/webvh/1.0/authenticate` (Phase 4.4 work) |
| `did-hosting/auth/authenticate-response/1.0` | registered |
| `did-hosting/auth/challenge/1.0` | registered |
| `did-hosting/auth/refresh/1.0` | registered |
| `did-hosting/auth/passkey-{enroll,login}-{start,finish}/1.0` | registered — passkey flow already specced |
| `did-hosting/auth/passkey-invite/1.0` | registered |

### Existing — ACL, DID lifecycle, server registration, domain management, registry, observability

All registered. See `did_hosting_tasks.rs` for the full list. No new URIs
required for these in this initiative.

### Existing — WebVH-protocol-specific (`webvh/*`)

| URI | Status |
|---|---|
| `webvh/did/witness-publish/1.0` | registered |
| `webvh/did/witness-confirm/1.0` | registered |
| `webvh/did/sync-update/1.0` | registered |
| `webvh/did/sync-update-ack/1.0` | registered |
| `webvh/did/sync-delete/1.0` | registered |
| `webvh/did/sync-delete-ack/1.0` | registered |

### Net-new for this initiative

| URI | Purpose | Slice |
|---|---|---|
| `did-hosting/admin/swap-did/1.0` | DID swap ceremony (cold-start finalisation per `[[project-browser-plugin-rp-login]]`). **Payload shape:** `{ new_did, new_did_proof: <embedded DataIntegrityProof by new DID's authentication VM> }`. Outer trust-task proof is by the OLD DID's session key (`eddsa-jcs-2022`); inner `new_did_proof` proves control of the new DID via any standard cryptosuite (`eddsa-jcs-2022` for VTA-managed Ed25519 `#key-1`, or `ecdsa-jcs-2019` for P-256). | Phase 4.2 (mega-project: Phase 2.2) |
| `did-hosting/admin/swap-did-response/1.0` | response with fresh capability JWT | Phase 4.2 |

That's it for webvh side — two new URIs.

## Boundary between `vta/webvh/*` and `did-hosting/*`

Both services touch WebVH DIDs. Disambiguation:

| Operation lives in | Means |
|---|---|
| `vta/webvh/*` | VTA-side: VTA mints the DID and its keys, owns the local `did.jsonl`, decides when to update or rotate. VTA pushes updates to the WebVH host. |
| `did-hosting/*` | Host-side: receives DID-doc updates from controllers, publishes WebVH log entries, runs witness/watcher, serves resolution requests. Doesn't own the keys. |
| `webvh/*` | Protocol-mechanical ops on WebVH's append-only log (witness publish/confirm, sync). Host runs these but they're protocol-level, not host-admin-level. |

Concrete examples:
- VTA wants to rotate a key on a DID it controls → `vta/webvh/dids/rotate-keys/1.0` to the VTA, which then sends `webvh/did/sync-update/1.0` to the host. Two different URIs, two different actions, on two different services.
- Operator wants to add a host to their VTA's known-hosts list → `vta/webvh/servers/add/1.0`. Adding a controller authorisation to the host itself → `did-hosting/acl/create/1.0`.

## Excluded from migration

These wire surfaces do NOT become trust-task envelopes:

| Surface | Reason |
|---|---|
| `GET /health/details` | Operator/infra observability. Health checks must be cheap and proxy-friendly; trust-task overhead is wrong here. |
| `GET /metrics` | Prometheus scrape format. Standard exporter contract; not application-level. |
| `GET /did/{did}/log` (public, unauthed) | **LOAD-BEARING**: failover path for WebVH log resolution. When a WebVH hosting service drops a LogEntry, any DID resolver in the world must be able to fetch the canonical copy from the minting VTA. Wrapping it in a trust-task envelope makes it useless for that purpose. Stays plain REST + public-unauthed forever. (The authed admin equivalent `GET /webvh/dids/{did}/log` DOES migrate to `vta/webvh/dids/get-log/1.0`.) |
| Mediator pickup (DIDComm transport infrastructure) | Mediator protocol is its own DIDComm spec (`coordinate-mediation/2.0`, `messagepickup/3.0`); not application-level. |
| Internal server-push from server → control plane (webvh stats sync over HTTP) | Already trust-task in webvh-service (`did-hosting/server/stats-sync/1.0`); no VTA equivalent needed. |
| KMS attest/unwrap (TEE startup-time only) | Pre-bootstrap; no JWT, no client, no envelope. |

## Migration mapping (legacy → trust-task URI)

For each VTA wire-surface element, what it becomes. The format is:
`<today's surface> → <trust-task URI>`. This is the table the migration
PRs work from in Phase 3.

```
REST:
  POST /auth/challenge                              → vta/auth/challenge/1.0
  POST /auth/                                       → vta/auth/authenticate/1.0
  POST /auth/refresh                                → vta/auth/refresh/1.0
  DELETE /auth/sessions/{session_id}                → vta/auth/revoke-session/1.0
  POST /bootstrap/request                           → vta/bootstrap/request/1.0
  POST /bootstrap/provision-integration             → vta/bootstrap/provision-integration/1.0
  GET    /keys                                      → vta/keys/list/1.0
  POST   /keys                                      → vta/keys/create/1.0
  GET    /keys/{id}                                 → vta/keys/get/1.0
  DELETE /keys/{id}                                 → vta/keys/revoke/1.0
  GET    /keys/{id}/secret                          → vta/keys/get-secret/1.0
  POST   /keys/{id}/sign                            → vta/keys/sign/1.0
  GET    /keys/{id}/secret                          → vta/seeds/export-mnemonic/1.0  (relocated from keys to seeds)
  GET    /keys/import/wrapping-key                  → vta/keys/import-wrapping-key/1.0
  POST   /keys/import                               → vta/keys/import/1.0
  GET    /keys/seeds                                → vta/seeds/list/1.0
  POST   /keys/seeds/rotate                         → vta/seeds/rotate/1.0
  GET    /contexts                                  → vta/contexts/list/1.0
  POST   /contexts                                  → vta/contexts/create/1.0
  GET    /contexts/{id}                             → vta/contexts/get/1.0
  PATCH  /contexts/{id}                             → vta/contexts/update/1.0
  DELETE /contexts/{id}                             → vta/contexts/delete/1.0
  GET    /acl                                       → vta/acl/list/1.0
  POST   /acl                                       → vta/acl/create/1.0
  PATCH  /acl/{did}                                 → vta/acl/update/1.0
  DELETE /acl/{did}                                 → vta/acl/delete/1.0
  GET    /audit/logs                                → vta/audit/list-logs/1.0
  GET    /attestation/status                        → vta/attestation/status/1.0
  GET    /attestation/did-log                       → vta/attestation/did-log/1.0
  GET    /services                                  → vta/services/list/1.0
  POST   /services/rest/enable                      → vta/services/rest/enable/1.0
  POST   /services/rest/update                      → vta/services/rest/update/1.0
  POST   /services/rest/disable                     → vta/services/rest/disable/1.0
  POST   /services/rest/rollback                    → vta/services/rest/rollback/1.0
  POST   /services/didcomm/enable                   → vta/services/didcomm/enable/1.0
  POST   /services/didcomm/update                   → vta/services/didcomm/update/1.0
  POST   /services/didcomm/disable                  → vta/services/didcomm/disable/1.0
  POST   /services/didcomm/rollback                 → vta/services/didcomm/rollback/1.0
  GET    /services/didcomm/drain                    → vta/services/didcomm/drain/list/1.0
  POST   /services/didcomm/drain/cancel             → vta/services/didcomm/drain/cancel/1.0
  GET    /mediators/report                          → vta/services/mediators/report/1.0
  POST   /webvh/servers                             → vta/webvh/servers/add/1.0
  GET    /webvh/servers                             → vta/webvh/servers/list/1.0
  …(see WebVH-DID-lifecycle slice for the rest)…
  GET    /did-templates                             → vta/did-templates/list/1.0
  POST   /did-templates                             → vta/did-templates/create/1.0
  …(see DID templates slice)…
  POST   /did/verification-methods/passkey/challenge → vta/passkey-vms/enroll-challenge/1.0
  POST   /did/verification-methods/passkey          → vta/passkey-vms/enroll-submit/1.0
  GET    /did/verification-methods/passkey          → vta/passkey-vms/list/1.0
  DELETE /did/verification-methods/passkey/{fragment} → vta/passkey-vms/revoke/1.0
  POST   /backup/export                             → vta/backup/initiate-export/1.0 + GET /backup/blob/{id}
                                                       + vta/backup/complete-export/1.0
  POST   /backup/import                             → vta/backup/initiate-import/1.0 + POST /backup/blob/{id}
                                                       + vta/backup/finalize-import/1.0
  POST   /vta/restart                               → vta/management/reload-services/1.0
  GET    /capabilities                              → vta/discovery/capabilities/1.0

  GET /health/details, GET /metrics,
  GET /did/{did}/log (public),
  GET/POST /backup/blob/{id} (token-gated bulk transport) — EXCLUDED, stay REST.

DIDComm protocols:
  key-management/1.0/{create,get,list,rename,revoke,sign,get-secret}-key/-request
                                                    → vta/keys/{create,get,list,rename,revoke,sign,get-secret}/1.0
  seed-management/1.0/{list-seeds,rotate-seed}       → vta/seeds/{list,rotate}/1.0
  context-management/1.0/{create,get,list,update,update-did,preview-delete,delete}
                                                    → vta/contexts/{create,get,list,update,update-did,preview-delete,delete}/1.0
  acl-management/1.0/{create,get,list,update,delete} → vta/acl/{create,get,list,update,delete}/1.0
  audit-management/1.0/{list-logs,get-retention,update-retention}
                                                    → vta/audit/{list-logs,get-retention,update-retention}/1.0
  attestation-management/1.0/*                      → vta/attestation/*/1.0
  backup-management/1.0/{export,import}             → vta/backup/{export,import}/1.0
  did-management/1.0/*                              → vta/webvh/*/1.0 (server + did sub-ops)
  did-template-management/1.0/*                     → vta/did-templates/*/1.0 + vta/contexts/did-templates/*/1.0
  discovery/1.0/capabilities                        → vta/discovery/capabilities/1.0
  join-requests/1.0/*                               → vta/join-requests/*/1.0
  protocol-management/services-management/1.0/*     → vta/services/*/1.0
  provision-integration/1.0/*                       → vta/bootstrap/provision-integration/1.0 (single op now)
  vta-management/1.0/restart                        → vta/management/restart/1.0
```

Total VTA: ~79 URIs. Total WebVH (existing + new): 63.

## Cross-cutting design notes

### Cryptosuite use

| Cryptosuite | Where used |
|---|---|
| **WebAuthn (no cryptosuite)** | Browser-side passkey assertions carried as **trust-task payload data** (NOT a Data Integrity proof on the trust-task itself). Verified via webauthn-rs against DID-resolved VMs. Used by `vta/auth/passkey-login-finish/1.0`, `did-hosting/auth/passkey-login-finish/1.0`, and any task that needs step-up user-presence (e.g. `vta/backup/initiate-export/1.0` for sensitive exports). |
| `eddsa-jcs-2022` | Per-call proofs by session keys (Ed25519, `did:key:z6Mk…`), cold-start `did:key` direct signing |
| `ecdsa-jcs-2019` | When the user's primary VM is P-256 and they sign with it directly (rare; passkey path is normal) |

### Proof-policy stance during migration

webvh-service `enforce_proofs` flag defaults to false today. During
this initiative it stays default-false until each service is fully on
trust-task envelopes; flipping to true is a hardening step in Phase 7.

### Session-pubkey binding stays uniform

Both services bind a session pubkey at auth time and require subsequent
trust-task proofs to use `did:key:{session-pk}#{session-pk}` as
`verificationMethod`. The mechanism is identical across VTA and
webvh-service. The plugin maintains one session key per authenticated
service.

### Versioning policy

- New URI for every breaking change to a payload shape.
- A service may accept multiple versions concurrently during deprecation; clients send the highest version they understand.
- We do NOT plan any `1.1`/`2.0` URIs for the initial migration — all ops launch at `1.0`. The first `*/1.1` happens only when a real schema-breaking refinement lands.

## Architectural questions for Phase 2/3

These are NOT spec/naming decisions — they're implementation patterns that
should be decided once and applied uniformly across all slices. Surfaced
here so they're not relitigated per-slice.

1. **Single dispatcher endpoint vs per-resource routes.** webvh-service uses
   one `POST /api/trust-tasks` that dispatches by URI. VTA could do the same
   (single endpoint, simpler routing, one body cap, one auth middleware) or
   keep per-resource routes (cleaner Prometheus path metrics, easier
   per-resource rate limiting). **Recommendation:** follow webvh's
   single-endpoint pattern for consistency. Resolve in Phase 3.1.

2. **DIDComm-side dispatch.** Same question for the DIDComm transport — one
   inbound message type that carries any trust-task envelope, or per-protocol
   dispatch on the outer DIDComm `type`? webvh uses the former. **Recommendation:**
   same as above.

3. **Cross-crate parity harness.** webvh-service has a T9 test invariant that
   pins every URL const byte-for-byte against the client crate. VTA needs the
   same: `vta-sdk::trust_tasks::specs` consts and any client mirror must agree.
   Land alongside Phase 3.1.

## Resolved decisions (2026-05-19 review)

1. **`vta/management/reload-services/1.0`** — keep, renamed from `restart`. The current implementation does an in-process soft reload, not a binary restart, and the URI now reflects that.
2. **`vta/keys/get-secret/1.0`** → **`vta/seeds/export-mnemonic/1.0`** — relocated to the seeds slice and renamed. Misleading "per-key" semantics fixed; same guard machinery (`MnemonicExportGuard`).
3. **`GET /did/{did}/log`** — excluded from migration. Load-bearing failover path for public WebVH resolution. Marked in "Excluded from migration" with a `LOAD-BEARING` comment that should appear on the route itself in code.
4. **VTC** — out of scope. `vtc-service` stays on bespoke DIDComm/REST until a follow-on initiative.
5. **Sealed-armor envelopes** — payload-of. The trust-task envelope holds metadata; the armor blob IS the payload value (a string). No double-wrapping. Applies to `vta/bootstrap/request-response/1.0` and `vta/bootstrap/provision-integration-response/1.0`.
6. **Large backup payloads** — three-phase descriptor pattern (initiate → out-of-band transport → finalize). Bulk bytes flow over a token-gated streaming REST endpoint that's excluded from the trust-task migration; the descriptor in the trust-task carries hash + size + transport URL + token, so integrity is verified end-to-end against signed metadata. Pluggable transport (stream-from-VTA in v1, S3-presigned later) without breaking clients. See revised `vta/backup/*` slice and Excluded list.

## Action items

- [ ] **0.2g** — review the boundary section ("VTA vs WebVH") and the migration mapping; confirm no URI is in the wrong namespace.
- [ ] **0.2h** — propagate URI consts into `vta-sdk::trust_tasks::specs` (mirrors the `did_hosting_tasks.rs` pattern); add the cross-crate parity harness referenced as T9 in webvh-service.
- [ ] **0.2i** — add `LOAD-BEARING` comment on the public `/did/{did}/log` route handler explaining the WebVH resolver failover invariant (so a future "tidy-up" PR doesn't quietly remove it).
- [ ] **0.2j** — pin `BundleDescriptor` schema (Phase 3.7 design item; not blocking lighthouse).
