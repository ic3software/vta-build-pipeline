# Trust-task dispatcher — feature-gating convention

**Status:** Design (decided 2026-05-20).
**Scope:** `vta-service::routes::trust_tasks` and `vta-sdk::trust_tasks`.
**Audience:** anyone adding a new trust-task URI that depends on a
specific `vta-service` feature flag (e.g. `webvh`, `didcomm`, `tee`).

## The problem

`vta-sdk::trust_tasks::ALL_URIS` is the canonical catalogue of every
operation the VTA exposes — consumed by:
- Clients (PNM, CNM, plugin) probing what a server supports.
- The dispatcher's cross-crate URI parity harness, which asserts every
  URI is wired into the dispatcher OR routed via dedicated REST.

But several upcoming slices depend on `vta-service` feature flags:

| Slice | Features required | URIs |
|---|---|---|
| Passkey-VM enrolment | `webvh` + `didcomm` | 4 |
| WebVH lifecycle | `webvh` | ~13 |
| Services management | `webvh` + `didcomm` | ~12 |
| Provision-integration | `provision-integration` | ~2 |
| Join requests | `didcomm` | ~3 |
| Bootstrap (TEE Mode B) | `tee` | ~4 |

Without a convention:
- When a feature is off, the slice's handler module isn't compiled.
- The dispatcher's match arms for that slice aren't compiled.
- The URIs are still in `ALL_URIS` (vta-sdk is feature-agnostic).
- The parity harness fails: "URI declared but not wired."

We need a way for the harness to know "this URI is *gated* — being
unwired in this build is OK, because the corresponding feature is off."

## Rejected approaches

### A. cfg-gate the URI consts in vta-sdk

Add `vta-sdk` features mirroring `vta-service`'s (`webvh`, `didcomm`,
`tee`). Each `TASK_*` const is `#[cfg(feature = "X")]`. `ALL_URIS`
shrinks when features are off.

**Why rejected:**
- vta-sdk gains a feature surface coupling it to vta-service's
  deployment topology. Other consumers (CLIs, plugin) probe servers and
  legitimately want to see *all possible* URIs regardless of which
  features the consumer's binary enables.
- `ALL_URIS` becoming dynamic across builds breaks the "single source
  of truth for the wire surface" property the doc-comment promises.

### B. Move parity harness to runtime introspection

Have the dispatcher publish its known URIs via a runtime
`KNOWN_URIS: Lazy<HashSet<&str>>` populated from per-arm calls.
Harness compares to `ALL_URIS`.

**Why rejected:**
- Requires the dispatcher to wrap each match arm in something that also
  registers the URI — boilerplate, easy to forget.
- Loses the compile-time correlation between match arms and URI consts.

### C. Weaken the parity check to "every dispatched URI must be declared"

Only check the reverse direction. Stop checking that declared URIs are
dispatched.

**Why rejected:**
- Drops the protection that catches "forgot to wire this URI" — which
  is the harness's whole reason for existing.

## Chosen design

**Two-level URI ownership:**

1. Each handler module exports its own `pub(super) const DISPATCHED_URIS: &[&str]`
   listing the URIs it handles. Feature-gated modules are cfg-gated
   in their entirety, so their `DISPATCHED_URIS` is implicitly cfg-gated.
2. The dispatcher's `mod.rs` aggregates `DISPATCHED_URIS` from all
   slice modules into a single list at test time, using `cfg!` to
   include feature-gated modules' contributions only when their features
   are on.

**Explicit allowlist for feature-gated URIs:**

3. `mod.rs` declares a `KNOWN_FEATURE_GATED_URIS: &[&str]` const listing
   URIs that vta-sdk declares but the dispatcher may not wire in every
   build. The list is unconditional; entries don't change with features.

**Parity harness logic:**

```rust
for uri in ALL_URIS {
    let dispatched = aggregate_dispatched_uris().contains(uri);  // cfg-aware
    let rest_routed = REST_ROUTED.contains(uri);
    let feature_gated = KNOWN_FEATURE_GATED_URIS.contains(uri);

    assert!(
        dispatched || rest_routed || feature_gated,
        "URI {uri} is declared in vta-sdk but is not tracked in this \
         dispatcher — add it to a slice's DISPATCHED_URIS const, the \
         REST_ROUTED list, or KNOWN_FEATURE_GATED_URIS (with a comment \
         explaining the gating)"
    );
}
```

When a feature is **off**:
- The slice's handler module isn't compiled → its `DISPATCHED_URIS`
  isn't aggregated → URIs aren't in `dispatched`.
- The URIs ARE in `KNOWN_FEATURE_GATED_URIS` → harness passes.

When a feature is **on**:
- The slice's `DISPATCHED_URIS` IS aggregated → URIs are in `dispatched`.
- They're also in `KNOWN_FEATURE_GATED_URIS` (redundant but harmless).
- Harness passes.

## What the convention guarantees + doesn't guarantee

**Guaranteed:**
- ✓ Every URI declared in `vta-sdk::trust_tasks::ALL_URIS` is tracked
  in the dispatcher's catalogue (DISPATCHED_URIS or REST_ROUTED or
  KNOWN_FEATURE_GATED_URIS).
- ✓ A URI added to `ALL_URIS` without any other change fails the parity
  test loudly.
- ✓ Per-slice ownership: changing a slice's handler doesn't require
  touching mod.rs's master list.

**Not guaranteed (acceptable trade-offs):**
- ✗ A URI listed in `KNOWN_FEATURE_GATED_URIS` is *actually* wired
  when its feature is on. If a slice's handler module forgets to add
  a match arm matching the URI, the dispatcher silently falls through
  to `unsupported_type`. Mitigation: when the feature is on, the
  URI IS in the slice's `DISPATCHED_URIS`, so the parity check covers
  it. If the slice author forgets to update `DISPATCHED_URIS` after
  adding a URI to vta-sdk, the harness catches the discrepancy at
  test time.
- ✗ The match-arm-vs-DISPATCHED_URIS pairing within a slice file is
  not automatically verified. Authors must keep them in sync — same
  failure mode as before, but localised to one file.

## Workflow when adding a new feature-gated slice

1. **Declare URIs in vta-sdk** (unconditional):
   ```rust
   // vta-sdk/src/trust_tasks.rs
   pub const TASK_PASSKEY_VMS_ENROLL_CHALLENGE_1_0: &str =
       "https://trusttasks.org/spec/vta/passkey-vms/enroll-challenge/1.0";
   // ...

   pub const ALL_URIS: &[&str] = &[
       // ...
       TASK_PASSKEY_VMS_ENROLL_CHALLENGE_1_0,
       // ...
   ];
   ```

2. **Create the cfg-gated handler module**:
   ```rust
   // vta-service/src/routes/trust_tasks/passkey_vms.rs
   #![cfg(all(feature = "webvh", feature = "didcomm"))]

   pub(super) const DISPATCHED_URIS: &[&str] = &[
       vta_sdk::trust_tasks::TASK_PASSKEY_VMS_ENROLL_CHALLENGE_1_0,
       // ...
   ];

   pub(super) async fn handle_enroll_challenge(...) -> Response {
       // ...
   }
   ```

3. **Wire into mod.rs** with cfg gating:
   ```rust
   #[cfg(all(feature = "webvh", feature = "didcomm"))]
   mod passkey_vms;

   // In dispatch_typed():
   match type_uri.as_str() {
       // ... existing arms ...
       #[cfg(all(feature = "webvh", feature = "didcomm"))]
       vta_sdk::trust_tasks::TASK_PASSKEY_VMS_ENROLL_CHALLENGE_1_0 => {
           passkey_vms::handle_enroll_challenge(state, auth, doc).await
       }
       // ...
   }
   ```

4. **Add to `KNOWN_FEATURE_GATED_URIS`**:
   ```rust
   const KNOWN_FEATURE_GATED_URIS: &[&str] = &[
       // ... existing ...
       // webvh + didcomm:
       vta_sdk::trust_tasks::TASK_PASSKEY_VMS_ENROLL_CHALLENGE_1_0,
       // ...
   ];
   ```

5. **Add slice's `DISPATCHED_URIS` to the aggregator** in `mod.rs`'s
   `aggregate_dispatched_uris()`:
   ```rust
   fn aggregate_dispatched_uris() -> Vec<&'static str> {
       let mut v: Vec<&'static str> = Vec::new();
       v.extend(acl::DISPATCHED_URIS);
       // ...
       #[cfg(all(feature = "webvh", feature = "didcomm"))]
       v.extend(passkey_vms::DISPATCHED_URIS);
       // ...
       v
   }
   ```

That's the entire convention. Steps 1, 2, 3 are needed regardless; 4
and 5 are the feature-gating additions.

## REST-routed URIs

`REST_ROUTED` is a flat list in `mod.rs` because the corresponding
operations live in `routes/auth.rs` etc. — not in slice modules under
`trust_tasks/`. No change needed; it stays a flat list.

Feature-gated REST routes (e.g. TEE attestation) live in
`KNOWN_FEATURE_GATED_URIS` until the underlying routes are themselves
restructured (out of scope for this design).

## Migration of existing slices

The existing 9 slice modules (auth, acl, contexts, keys, seeds, audit,
discovery, config, management) are all unconditional. They get
per-slice `DISPATCHED_URIS` consts as part of this design's rollout,
even though feature-gating doesn't apply to them yet. Reasons:
- Consistent pattern across all slices makes adding new ones mechanical.
- Removes the master `dispatched` array from `mod.rs` (~30 lines today,
  ~78 at full Phase 3) — that array's been a manual-maintenance hotspot.
- Future "split a slice into multiple modules" or "rename a URI" is
  contained to the slice's own file.

## Alternative considered: macro-based registration

A `dispatch!` proc-macro could auto-generate match arms + DISPATCHED_URIS
from a single declaration. Rejected for v1:
- Adds a proc-macro crate dependency.
- Obscures the dispatcher's behaviour from a code reader.
- The current pattern is mechanical enough that a proc-macro doesn't
  earn its complexity.

Revisit if Phase 3 hits ~100+ URIs and the per-arm duplication becomes
painful.
