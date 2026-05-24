# Trust-task envelope migration — release sequencing runbook

**Status:** Draft (Phase 0.5 of the trust-task envelope migration initiative).
**Date:** 2026-05-20.
**Audience:** operators upgrading deployed VTAs, webvh-services, and PNM/CNM
clients across the mega-project's release window.

## What this document is for

The mega-project migrates **four repos** to a new wire envelope in a
**hard-cutover** model (no compat shim — see
`project_browser_plugin_rp_login.md` decision #3). Releases must land
in a specific order to avoid breaking deployed operators mid-flight.
This runbook is the canonical ordering.

## Repos in the dance

| Symbol | Repo | What changes |
|---|---|---|
| **TT-RS** | `dtgwg-trust-tasks-tf` | New cryptosuite-free path (no work after Phase 0.1 drop). |
| **VTA** | `verifiable-trust-infrastructure` (workspace) | Wire surface migrates to trust-tasks; passkey-login surface added. |
| **WEBVH** | `affinidi-webvh-service` | Legacy `affinidi.com/webvh/1.0/*` URLs replaced by canonical `trusttasks.org/did-hosting/*`; `swap-did` added. |
| **PLUGIN** | `pnm-browser-plugin` | New trust-task client; passkey login flow; session-key DPoP signing. |

## Versioning convention

All four repos move in lockstep on this initiative:

| Phase | Version bump |
|---|---|
| Phase 1 (`vti-webauthn` crate ships) | TT-RS unchanged. VTA: `0.X.0` minor — adds the new crate as a workspace member but no consumer change. |
| Phase 2 (first-light: passkey login + swap-did) | VTA: minor. WEBVH: minor. PLUGIN: minor. New surfaces are additive; legacy paths still live. |
| Phase 3 (VTA slice migration) | VTA: minor per slice batch (auth, ACL, contexts, keys, etc.). New URIs additive; legacy routes coexist. |
| Phase 4 (client migration) | PLUGIN, PNM, CNM: minor each. SDK consumes new surfaces. |
| Phase 5 (TEE parity) | VTA: minor. Enclave attestation flow migrates. |
| Phase 6 (legacy deletion) | **All four: MAJOR.** Breaking change. Legacy URLs / routes removed atomically across the fleet. |
| Phase 7 (hardening) | Minor releases as fixes land. |

Operators upgrade at the major bump in Phase 6. Before that point, every
release is backwards-compatible — operators can roll forward at their own
pace and only need to coordinate at the breaking release.

## Release ordering (per phase)

Within each phase, releases ship server-side first, then client-side.
This means new clients can talk to upgraded servers immediately; old
clients keep working until they're upgraded.

### Phase 1 (this week's work)

```
1. VTA — vti-webauthn 0.1.0 lands as new workspace member. No consumer
   change yet. Other VTA crates unaffected.

   Operator action: none. (Library landing only.)
```

### Phase 2 (first-light: ~3 weeks)

```
1. TT-RS — no change.
2. VTA — adds vti-webauthn dependency to vta-service.
        adds VtaVmResolver implementing vti_webauthn::VmResolver.
        adds passkey_login operation (off the wire; library-callable only
        in this release).
3. WEBVH — adds did-hosting/admin/swap-did/1.0 trust-task handler.
        adds passkey-login-{start,finish} support against DID-resolved VMs
        (alongside existing server-store passkeys).
        legacy auth URL still routed.
4. PLUGIN — adds trust-task TS client (@pnm/core/trust-task/*).
        adds WebAuthn get() + passkey-login client.
        adds session-key generation (WebCrypto Ed25519).
5. VTA — wires passkey_login operation to a new REST surface
        (POST /api/trust-tasks) accepting the trust-task envelope.

   Operator action: upgrade VTA + webvh-service first, then PNM/plugin.
                    Old PNM clients keep working against legacy auth.
```

### Phase 3 (VTA slice migration: ~5 weeks)

Ten slices land independently. Each is additive — new URIs alongside
existing routes — so each operator upgrade adds capability without
removing any.

```
Per slice (auth → ACL → contexts → keys → seeds → provision-integration
→ DID templates → backup → services → audit + passkey-VMs):
  1. VTA — slice handlers added under POST /api/trust-tasks.
           legacy REST + DIDComm routes still active.
  2. PLUGIN / PNM-CLI / CNM-CLI — clients migrate per slice as ready.
           legacy paths still usable.

   Operator action per slice: optional. Clients on old surface still work.
                              Recommended: upgrade VTA, then upgrade PNM
                              when convenient.
```

### Phase 4 (client migration: ~3 weeks, overlaps Phase 3 tail)

```
1. SDK (vta-sdk) — VtaClient method-set replaced with trust-task transport.
                   Old method signatures kept as deprecated wrappers
                   that call into the new ones; consumer code can migrate
                   incrementally.
2. PNM-CLI / CNM-CLI — internal callers point at the new SDK methods.
3. PLUGIN — universal trust-task client (used for both VTA + webvh-service).
4. didcomm-test — test harness updated.
5. VTC-service — out of scope this initiative (memory decision #4).

   Operator action: upgrade CLI/plugin when desired. Old SDK consumers
                    still build and run.
```

### Phase 5 (TEE parity: ~2 weeks)

```
1. VTA — Mode B bootstrap becomes vta/bootstrap/request/1.0 trust-task;
         Nitro attestation payload moves into the trust-task proof block;
         carve-out (BOOTSTRAP_CARVEOUT_CLOSED_KEY) still applies.
         Sealed-transfer wraps trust-task envelopes as payload bytes.
2. ENCLAVE (`vta-enclave`) — receives the new bootstrap shape;
         backwards-compat with the old POST /bootstrap/request retained.

   Operator action: rebuild enclave image only if upgrading from a
                    pre-Phase-5 VTA. Existing enclaves keep accepting
                    legacy bootstrap until Phase 6.
```

### Phase 6 (legacy deletion: **BREAKING — coordinate fleet upgrade**)

```
At this point the fleet upgrade is a coordinated event. Operators MUST
upgrade all four components (VTA, webvh-service, PLUGIN, CLIs) before
attempting any operation against the new release. There is no compat
shim.

1. Release notes ship 4 weeks before this release tagged
   "BREAKING RELEASE — legacy wire surface removed." Operators get
   advance notice + a runbook (this document, updated for the
   specific release).

2. Tagged release lands:
   - VTA — deletes legacy /auth/*, /keys/*, /contexts/* etc. REST routes;
           deletes legacy DIDComm protocol message types.
   - WEBVH — deletes legacy /api/auth/, /api/auth/refresh routes;
             deletes affinidi.com/webvh/1.0/* DIDComm constants.
   - SDK — removes legacy method signatures.
   - PLUGIN — removes legacy wire support.

3. Operator upgrade sequence (single maintenance window):
   - Drain DIDComm mediators if applicable.
   - Stop PNM/CNM CLI usage briefly.
   - Upgrade webvh-service (so it accepts the new shape).
   - Upgrade VTA (so it accepts the new shape from PNM).
   - Upgrade PNM/CNM clients.
   - Upgrade browser plugins (PWA auto-updates; extension store push).
   - Resume operations; confirm health.

4. Rollback strategy:
   - VTA + webvh-service downgrade is supported for 30 days post-release
     (the legacy code paths are preserved in a tagged branch).
   - PNM/CNM CLI downgrade is supported (binaries are immutable releases).
   - Browser plugin downgrade requires manual extension reinstall.
```

### Phase 7 (hardening: ongoing)

```
Telemetry, negative-test sweep, operator runbook updates, ADR. Patch
releases as needed.
```

## Pre-flight checklist (Phase 6 day)

- [ ] All four repos tagged to the matching MAJOR version.
- [ ] Operator advance notice sent ≥4 weeks before tagged release.
- [ ] Rollback branches exist for VTA + WEBVH at the previous MAJOR.
- [ ] All in-tree consumers (CLIs, plugin, test harnesses) tested against
      the new release in staging.
- [ ] No external operators on the fleet have pinned to a legacy version
      that won't be upgraded in time (survey before tag).
- [ ] Migration doc (this file) updated with the exact release tags.

## Per-component upgrade quick reference

```
WEBVH:  systemctl restart did-hosting-control (or did-hosting-daemon)
        after replacing the binary. Storage on-disk format unchanged
        through Phase 6.

VTA:    Same — restart the service (or trigger
        vta/management/reload-services/1.0 from Phase 3 onward).
        TEE enclaves: re-attest after image rebuild.

PNM:    Replace ~/.local/bin/pnm. No state migration needed.
CNM:    Same.

PLUGIN: PWA — auto-updates on next page load.
        Extension — Chrome/Firefox store push; operators on managed
        deployments need MDM rollout.
```

## Failure modes & responses

| Failure | Likely cause | Response |
|---|---|---|
| Old PNM CLI → new VTA returns 404 on /auth/ | Operator skipped Phase 6 notice | Direct operator to upgrade CLI; old PNM cannot recover without upgrade |
| New PNM CLI → old VTA times out | Operator skipped server upgrade | Direct operator to upgrade VTA before CLI |
| New PLUGIN → old webvh-service rejects trust-task envelope | Operator skipped server upgrade | Upgrade webvh-service to ≥ Phase-6 release |
| TEE enclave fails to boot after Phase 6 | Image not rebuilt | Rebuild enclave image against new VTA crate; re-deploy via KMS-provisioned bootstrap |
| Sealed bundle from old VTA fails to open on new client | Wrong shape in transit | Bundle holders upgrade client to ≥ Phase-6 release; sealed-payload format is forward-compatible |

## Open follow-ups

- Specific release tags + dates land here once the major-bump release is
  scheduled.
- A short "client-version-required" header / capability negotiation could
  reduce mis-upgrade pain (Phase 7+ idea — not in scope today).
- Whether to extend the 30-day rollback window for VTA / webvh-service is
  an operator-policy decision; current default 30 days.
