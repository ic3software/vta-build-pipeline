# DIDComm Protocol Management

Enable, disable, and migrate DIDComm support on a running VTA
without rebuilding it, re-issuing admin credentials, or rotating
the VTA's verification keys. Every protocol change is published as
a new WebVH LogEntry on the VTA's DID, so external resolvers see
each change as an authentic, signed update.

Spec: `docs/05-design-notes/didcomm-protocol-management.md`.

## Operations at a glance

| Task | Command |
|---|---|
| Enable DIDComm on a REST-only VTA | `pnm services enable didcomm --mediator-did <did>` |
| Disable DIDComm (drain, then tear down) | `pnm services disable didcomm [--drain-ttl <secs>]` |
| Move to a different mediator | `pnm mediator migrate --to <did> [--drain-ttl <secs>]` |
| Roll back to a previous mediator | `pnm mediator rollback --to <did> [--drain-ttl <secs>]` |
| Cancel an in-flight drain early | `pnm mediator drain cancel --mediator-did <did>` |
| See per-mediator inbound traffic | `pnm mediator report [--since <rfc3339>] [--format table]` |

All commands require **super-admin** privileges on the target VTA.

## How it changes the DID document

Every protocol change is a new WebVH LogEntry. The operations
patch a single field — the `#vta-didcomm` service entry — and
republish the document. The patcher guarantees:

- **At most one `#vta-didcomm` service entry** at any time.
- **`verificationMethod` is byte-identical** before and after.
  Only the WebVH **control keys** (the `update_keys` and
  pre-rotation commitments that authorize log mutations) rotate.
  Application/identity keys are untouched.
- **Other service entries** (e.g. TEE attestation) are preserved
  byte-for-byte.

External resolvers see one new LogEntry per protocol change.
Public-key consumers (anyone who already verified your VTA's DID)
are not affected.

## Drain semantics

When DIDComm is disabled or a mediator is replaced, the prior
mediator's listener does **not** drop immediately by default.
Instead, it enters **drain state**:

- The prior mediator is removed from the `service` array of the
  VTA's DID document immediately.
- The VTA's WebSocket listener to the prior mediator stays up
  for `drain-ttl` seconds. In-flight messages from senders who
  resolved a stale copy of the DID document continue to land
  through the prior mediator until the deadline.
- Once the deadline passes (or the operator runs `drain cancel`),
  the listener is torn down. Messages arriving via the prior
  mediator after that point are not delivered — the sender's DID
  cache will eventually refresh.

You can have **multiple drains coexist** — overlapping migrations
are permitted. Each drain has its own TTL and is tracked
independently. The drain set survives VTA restarts (persisted in
fjall + replayed at boot).

**Defaults:** `drain-ttl` = 1 hour for `services disable didcomm`,
`mediator migrate`, and `mediator rollback`. Use `--drain-ttl 0` to
tear the listener down immediately, or any value up to **30 days**
(the spec's hard upper bound).

## Walkthrough: enable DIDComm on a REST-only VTA

```bash
# 1. Provision a mediator separately. (Mediator is its own VTA.)
#    Use the `didcomm-mediator` template on a different VTA host.
#    See docs/03-integrating/provision-integration.md.

# 2. Get the mediator's DID — typically did:webvh:scid:mediator.example.com:m1
mediator_did=did:webvh:abcd1234:mediator.example.com:m1

# 3. Enable DIDComm on the consuming VTA.
pnm services enable didcomm --mediator-did "$mediator_did"
```

Expected output:

```
DIDComm enabled.
  Mediator DID:   did:webvh:abcd1234:mediator.example.com:m1
  Mediator URL:   wss://mediator.example.com/v2/ws
  New version ID: 5-z6Mk...

  Note: First-enable runs only handshake step 1 (DID resolution).
  The connection is validated when the DIDComm runtime starts after
  the next service restart. To validate end-to-end pre-publish, run
  `pnm mediator migrate --to <same>` once DIDComm is up.
```

After this command:
- The VTA's DID document advertises the mediator (`#vta-didcomm`
  service entry).
- `services.didcomm = true` is persisted to the on-disk config.
- The mediator is recorded as the active mediator in the
  in-memory registry.

A service restart picks up the new config and starts the DIDComm
runtime against the mediator. Until then, REST traffic is
unaffected and DIDComm is queued for next boot.

### Errors and what to do

| Error | Meaning | Fix |
|---|---|---|
| `409 didcomm_already_enabled` | DIDComm is already on; you wanted `migrate`. | `pnm mediator migrate --to <new>` |
| `409 vta_did_not_configured` | The VTA hasn't completed setup. | `vta setup` |
| `502 mediator_handshake_failed` (`stage: resolve`) | The mediator DID didn't resolve. | Check the DID is correct and your VTA can reach it. |

## Walkthrough: migrate to a new mediator

```bash
new_mediator=did:webvh:efgh5678:mediator-prod-2.example.com:m1

pnm mediator migrate --to "$new_mediator" --drain-ttl 7200
```

Expected output:

```
Mediator migrated.
  Prior mediator:  did:webvh:abcd1234:mediator.example.com:m1
  Active mediator: did:webvh:efgh5678:mediator-prod-2.example.com:m1
  Active endpoint: wss://mediator-prod-2.example.com/v2/ws
  New version ID:  6-z6Mk...
  Drain deadline:  2026-04-29T17:00:00+00:00 (prior listener stays up until then)
```

After this:
- The DID document's `#vta-didcomm` now points at the new mediator.
- The prior mediator is in drain state for 2 hours.
- Inbound DIDComm messages may arrive on either mediator during
  the drain window — they're handled identically and tagged in
  telemetry with their source mediator.

While the drain is active, run the report to see who's still
arriving via the old mediator:

```bash
pnm mediator report --since 2026-04-29T15:00:00Z --format table
```

```
Mediator report
  Window: 2026-04-29T15:00:00Z → 2026-04-29T16:30:00Z

  Per-mediator inbound counts (most recent first):
    MEDIATOR DID                                                  INBOUND  LAST SEEN
    did:webvh:efgh5678:mediator-prod-2.example.com:m1                  47  2026-04-29T16:29:51Z
    did:webvh:abcd1234:mediator.example.com:m1                          3  2026-04-29T16:24:12Z

  Senders by last-seen mediator:
    did:peer:alice          → did:webvh:efgh...prod-2 (at 2026-04-29T16:29:51Z)
    did:peer:bob            → did:webvh:abcd...m1     (at 2026-04-29T16:24:12Z)
```

Bob is still routing through the old mediator — nudge him to
refresh his cached copy of your DID document if you want him on
the new one.

## Walkthrough: rollback

If the new mediator turns out to misbehave, roll back:

```bash
pnm mediator rollback --to "$prior_mediator" --drain-ttl 1800
```

Mechanically identical to `migrate`, but tagged in telemetry as
a rollback so the report's audit kind distinguishes forward and
reverse moves.

## Walkthrough: disable DIDComm

Confirm REST is enabled (otherwise the operation refuses), then:

```bash
pnm services disable didcomm --drain-ttl 3600
```

Expected output:

```
DIDComm disabled.
  Prior mediator: did:webvh:efgh5678:mediator-prod-2.example.com:m1
  New version ID: 8-z6Mk...
  Drain deadline: 2026-04-29T18:30:00+00:00

  The listener stays up until the deadline so in-flight messages can
  arrive. Cancel early with `pnm mediator drain cancel --mediator-did <did>`.
```

If you want immediate teardown (no drain):

```bash
pnm services disable didcomm --drain-ttl 0
```

Note: `--drain-ttl 0` is **only** permitted over REST transport.
Over DIDComm transport, the operation enforces a **1-hour
minimum** to avoid the race where the response itself drops
mid-flight as the listener tears down.

## Walkthrough: cancel a drain early

```bash
pnm mediator drain cancel --mediator-did "$old_mediator"
```

The named mediator's listener drops immediately. Refuses if the
named DID is the active mediator (use `services disable didcomm`
instead).

## Reading the report programmatically

The `--format json` output is stable:

```json
{
  "since": "2026-04-29T15:00:00Z",
  "until": "2026-04-29T16:30:00Z",
  "mediators": [
    {
      "mediator_did": "did:webvh:...",
      "inbound_count": 47,
      "first_seen": "2026-04-29T15:01:08Z",
      "last_seen": "2026-04-29T16:29:51Z"
    }
  ],
  "senders": [
    {
      "sender_did": "did:peer:alice",
      "last_seen_mediator": "did:webvh:...",
      "last_seen_at": "2026-04-29T16:29:51Z"
    }
  ]
}
```

`mediators` is sorted by inbound count, descending. `senders` is
sorted by `last_seen_at`, newest first.

## Telemetry events

Every protocol change emits a structured telemetry event into
the VTA's telemetry sink (default: in-memory ring buffer of
10,000 events; pluggable via the `TelemetrySink` trait):

| Event | When |
|---|---|
| `services.didcomm.enable` | After `services enable didcomm` succeeds |
| `services.didcomm.disable` | After `services disable didcomm` succeeds |
| `mediator.migrate.start` | After `mediator migrate` or `rollback` succeeds |
| `mediator.drain.start` | A mediator entered drain state |
| `mediator.drain.cancel` | A drain was cancelled by the operator |
| `mediator.drain.expire` | A drain hit its TTL deadline |
| `mediator.handshake.ok` | Pre-promotion handshake succeeded |
| `mediator.handshake.failed` | Pre-promotion handshake failed |
| `mediator.handshake.bypassed` | `--force` skipped handshake steps 2-5 |
| `didcomm.message.inbound` | An inbound DIDComm message arrived (drives `mediator report`) |
| `didcomm.response.dropped` | An outbound response was dropped (drain expired or buffer full) |

## Known limitations

These are the v1 cuts that reduce scope without reducing
correctness. Each is tracked for a focused follow-up.

1. **First-enable handshake is partial.** `pnm services enable
   didcomm` runs only step 1 of the handshake (DID resolution +
   `DIDCommMessaging` service check + `keyAgreement` presence)
   because there's no live DIDComm runtime yet at first-enable
   time. The connection is validated implicitly when the
   DIDComm runtime starts up after the next service restart. To
   end-to-end validate a mediator pre-publish, run
   `pnm services enable didcomm` followed by
   `pnm mediator migrate --to <same>` — the migrate path runs
   the full handshake.
2. **Live `DIDCommService`-backed handshake is a follow-up.**
   All routes currently use a placeholder prover that satisfies
   handshake steps 2-5 with a noop. Step 1 (DID resolve) still
   runs. Wiring the live prover requires an in-process mock
   mediator for end-to-end test coverage; tracked separately.
3. **DIDComm transport for these admin calls.** REST is the
   only available transport today. The operations layer's
   1-hour-min-TTL guard (when `disable` is called over DIDComm)
   is wired and tested but has no DIDComm route handler invoking
   it yet.
4. **Listener teardown signal.** `disable` and drain expiry
   signal upstream listener teardown via an mpsc channel. The
   bootstrap-side consumer that translates the signal into
   `DIDCommService::remove_listener` calls hasn't been wired in
   `server.rs` yet — same scope rationale as #2.

None of these change the on-disk state model or the DID-document
semantics. They're places where the wire-shape is in place but
the live runtime hasn't been hooked up.

## Cross-references

- Spec: `docs/05-design-notes/didcomm-protocol-management.md`
- Update primitive: `docs/03-integrating/did-webvh-update.md`
- Provisioning a mediator: `docs/03-integrating/provision-integration.md`
- Setup: `docs/02-operating/cold-start.md`
