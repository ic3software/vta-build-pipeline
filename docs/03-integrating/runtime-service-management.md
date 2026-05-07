# Runtime Service Management

Operator guide for the unified `pnm services …` command surface
that manages the VTA's advertised transport services (REST and
DIDComm) at runtime, without rebuilding the VTA, re-issuing admin
credentials, or rotating verification keys. Every service change
publishes a new WebVH LogEntry; external resolvers see each
change as an authentic, signed update.

Spec: `docs/05-design-notes/runtime-service-management.md`.

This page replaces the older `didcomm-protocol-management.md`
guide. The DIDComm-specific surface is now part of a unified
`services {kind} {verb}` tree alongside REST.

## Migration from the legacy `pnm mediator …` surface

If you have scripts targeting the pre-P5 commands, here's the
direct mapping. Old commands have been **retired** (no aliases).
Calling `pnm mediator …` prints a friendly redirect with the
equivalent `pnm services didcomm …` command and exits 2 — the
clap-default "unknown subcommand" message is intercepted in
`pnm-cli/src/main.rs` so operators with stale scripts get a
copy-pasteable suggestion instead of a generic parse error.

| Old | New |
|---|---|
| `pnm services enable didcomm --mediator-did X` | `pnm services didcomm enable --mediator-did X` |
| `pnm services disable didcomm --drain-ttl 3600` | `pnm services didcomm disable --drain-ttl 86400` |
| `pnm mediator migrate --to X --drain-ttl 3600` | `pnm services didcomm update --mediator-did X --drain-ttl 86400` |
| `pnm mediator rollback --to X` | `pnm services didcomm rollback` |
| `pnm mediator drain cancel --mediator-did X` | `pnm services didcomm drain cancel --mediator-did X` |
| `pnm mediator report` | `pnm services report` |
| (no equivalent) | `pnm services list` |
| (no equivalent) | `pnm services didcomm drain list` |
| (no equivalent) | `pnm services rest {enable,update,disable,rollback}` |

**Default `--drain-ttl` is now 24h** (was 1h). The 1h floor for
DIDComm-transport delivery is unchanged.

**Rollback semantics changed.** The old `pnm mediator rollback
--to <did>` took an explicit target DID. The new `pnm services
didcomm rollback` is **snapshot-driven** — it reads the per-kind
snapshot store and fail-forwards into whichever forward operation
re-applies the prior config. No `--to` argument; the rollback
target is whatever was in effect before the most recent forward
mutation.

The `--to` muscle memory is partially preserved on `update`:
`pnm services didcomm update --to <did>` works (clap
`visible_alias` on `--mediator-did`).

## Operations at a glance

All commands require **super-admin** privileges on the target VTA.
All twelve operations are reachable over both REST and DIDComm
transports, except `services didcomm enable` which is REST-only by
nature (DIDComm isn't running yet at first-enable).

### Inspect

| Task | Command |
|---|---|
| Show currently-advertised services | `pnm services list` |
| Show in-flight drain entries | `pnm services didcomm drain list` |
| Per-mediator traffic + sender attribution | `pnm services report [--since <rfc3339>] [--until <rfc3339>] [--format json|table]` |

### Mutate REST

| Task | Command |
|---|---|
| Add `#vta-rest` service entry | `pnm services rest enable --url <https-url>` |
| Change the URL on the existing entry | `pnm services rest update --url <https-url>` |
| Remove the `#vta-rest` entry | `pnm services rest disable` |
| Roll back the most recent REST mutation | `pnm services rest rollback` |

### Mutate DIDComm

| Task | Command |
|---|---|
| Enable DIDComm on a REST-only VTA | `pnm services didcomm enable --mediator-did <did>` |
| Update the active mediator | `pnm services didcomm update --mediator-did <did> [--drain-ttl 86400]` |
| Disable DIDComm (drain, then tear down) | `pnm services didcomm disable [--drain-ttl 86400]` |
| Roll back the most recent DIDComm mutation | `pnm services didcomm rollback [--drain-ttl 86400]` |
| Cancel an in-flight drain early | `pnm services didcomm drain cancel --mediator-did <did>` |

## How service changes touch the DID document

Every mutation is a new WebVH LogEntry. The operation layer
patches a single field — the `service[]` array — and republishes
the document. The patcher guarantees:

- **At most one entry per kind** (`#vta-didcomm`, `#vta-rest`).
- **DIDComm comes before REST** in the array when both are
  advertised. DID-Core resolvers walking the array pick DIDComm
  first.
- **`verificationMethod` is byte-identical** before and after.
  Only the WebVH **control keys** (the `update_keys` and
  pre-rotation commitments that authorize log mutations) rotate.
  Application/identity keys are untouched.
- **Other service entries** (TEE attestation, custom `additional_
  services` from setup) are preserved byte-for-byte.

External resolvers see one new LogEntry per change. Public-key
consumers (anyone who already verified your VTA's DID) are not
affected.

## Brick-prevention

**At least one transport service must remain advertised at all
times.** This is enforced at the operation layer by a single
helper (`would_violate_last_service`) that disable / rollback
paths consult before any I/O.

There is **no `--force` escape hatch.** If you genuinely want a
totally unreachable VTA you can rotate it out and replace it via
setup; the CLI will not provide a foot-gun.

The relevant typed errors:

- `LastServiceRefused` — the operation would leave the VTA with
  no advertised services. CLI prints "Run `pnm services <other>
  enable …` first, then retry."
- `ServiceNotPresent` — the operation targets a kind that's
  already off (e.g. `services rest update` when REST is
  disabled).
- `ServiceAlreadyEnabled` — the operation would add a kind that's
  already on.

## Fail-forward rollback

WebVH is an append-only ledger. **Rollback never rewinds the
chain** — it appends a new LogEntry whose `service[]` matches the
snapshotted prior state.

Each successful mutation persists a per-kind snapshot of the
**prior state** before applying the runtime mutation. `pnm services
{kind} rollback` reads the snapshot, computes the equivalent
forward operation, and dispatches into it:

| snapshot               | current state         | dispatched op                |
|------------------------|-----------------------|------------------------------|
| `Disabled`             | enabled               | `disable` (re-disable)       |
| `Enabled { config }`   | disabled              | `enable` with the prior config |
| `Enabled { X }`        | enabled with Y        | `update` from Y to X         |
| snapshot ≡ current     | -                     | no-op (`kind == no_op`)      |

Two scenarios produce no-op rollbacks:

1. A previous mutation crashed between snapshot persist and
   runtime mutation — the snapshot describes the current state,
   so re-applying it is a no-op.
2. The operator runs rollback twice in a row — a "rollback the
   rollback" cycle. The second rollback finds snapshot ≡ current.

Both are returned with `kind: "no_op"` and an empty
`log_entry_version_id`. The CLI prints "rollback: no change
required."

**Rollback is single-step per kind.** Each kind tracks its own
"previous-config" pointer; rollback consumes it. After rollback,
the snapshot reflects the state from *before* the rollback, so a
second consecutive rollback would reverse the rollback (a no-op
cycle the operator can avoid by running `services list` first).

REST and DIDComm rollback are independent. Rolling back REST does
not affect DIDComm state and vice versa.

## Drain semantics (DIDComm only)

When DIDComm is disabled or the active mediator is replaced, the
prior mediator's listener does **not** drop immediately by
default. Instead, it enters **drain state**:

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

Multiple drains can coexist — overlapping migrations are
permitted. Each drain has its own TTL and is tracked
independently. The drain set survives VTA restarts (persisted in
fjall + replayed at boot).

**Defaults and bounds:**
- `--drain-ttl` default: **24 hours** (spec §3.6).
- Use `--drain-ttl 0` to tear the listener down immediately. This
  is **REST-transport only**; over DIDComm the server enforces a
  1h minimum so the response can land before the listener drops.
- Hard upper bound: 30 days.

Both bounds are enforced at the operation layer — `disable`,
`update`, and `rollback` all reject out-of-range values with the
typed `DrainTtlOutOfBounds` error before any I/O. Spec §7a.4
matrix cells (`--drain-ttl 30s` over DIDComm, `--drain-ttl 31d`)
are pinned by unit tests.

**Rollback handshake.** When `services didcomm rollback` dispatches
into `update_didcomm` to re-promote a previously-active mediator,
it runs the same live mediator handshake as a forward update.
Re-promoting a mediator that has since gone offline fails fast
with `MediatorHandshakeFailed` rather than silently bricking the
VTA — the rollback is rejected and the operator can pick a
different recovery action.

REST has no drain semantics — there's nothing to keep listening
for after the URL is unadvertised. The Axum process keeps running
(it's a process-level binding); only the *advertisement* is
removed.

## Walkthrough: enable DIDComm on a REST-only VTA

```bash
# 1. Provision a mediator separately. The mediator is its own VTA.
#    Use the `didcomm-mediator` template on a different VTA host.
#    See docs/03-integrating/provision-integration.md.

# 2. Get the mediator's DID — typically did:webvh:scid:mediator.example.com:m1
mediator_did=did:webvh:abcd1234:mediator.example.com:m1

# 3. Enable DIDComm on the consuming VTA.
pnm services didcomm enable --mediator-did "$mediator_did"
# DIDComm enabled.
#   Mediator DID:   did:webvh:abcd1234:mediator.example.com:m1
#   Mediator URL:   wss://mediator.example.com/ws
#   New version ID: 1-zQm…

# 4. Verify the published service[] array.
pnm services list
# Services advertised on this VTA's DID document:
#   DIDComm:  on
#     Mediator: did:webvh:abcd1234:mediator.example.com:m1
#   REST:     on
#     URL:      https://vta.example.com
```

**Note on first-enable:** the live mediator handshake (steps 2-5)
requires a running `DIDCommService`, which doesn't exist yet at
first-enable. The route uses `AlwaysOkProver`, so steps 2-5 are
bypassed; the connection is validated implicitly when the DIDComm
runtime starts up after the next service restart. To validate
end-to-end pre-publish, run `pnm services didcomm update
--mediator-did <same>` once DIDComm is up — the update path runs
the full handshake.

## Walkthrough: change the active mediator

```bash
# A new mediator host has come online and you want to migrate.
new_mediator=did:webvh:wxyz9876:m2.example.com:mediator

pnm services didcomm update --mediator-did "$new_mediator"
# DIDComm mediator updated.
#   Prior mediator:  did:webvh:abcd1234:mediator.example.com:m1
#   Active mediator: did:webvh:wxyz9876:m2.example.com:mediator
#   Active endpoint: wss://m2.example.com/ws
#   New version ID:  2-zQm…
#   Drain deadline:  2026-05-08T13:14:15Z (prior listener stays up until then)

# Inspect the drain state any time during the 24h window:
pnm services didcomm drain list
# Drain set (1 mediator(s)):
#   MEDIATOR DID                                                  DRAIN UNTIL
#   did:webvh:abcd1234:mediator.example.com:m1                    2026-05-08T13:14:15Z

# If you decide to revert before the drain expires, rollback is
# snapshot-driven (no --to argument):
pnm services didcomm rollback
# DIDComm rolled back.
#   Action:         updated
#   New version ID: 3-zQm…
#   Effective at:   2026-05-07T15:00:00Z
#   Drain deadline: 2026-05-08T15:00:00Z
#   Draining:       did:webvh:wxyz9876:m2.example.com:mediator
```

## Walkthrough: change the published REST URL

```bash
# Domain migration. The new URL takes effect on the next
# resolver refresh — no restart needed.
pnm services rest update --url https://vta-new.example.com
# REST URL updated.
#   New version ID: 4-zQm…
#   Effective at:   2026-05-07T15:30:00Z

# If the new URL turns out to be wrong, rollback restores the
# prior URL:
pnm services rest rollback
# REST rolled back.
#   Action:         updated
#   New version ID: 5-zQm…
#   Effective at:   2026-05-07T15:31:00Z
```

## Walkthrough: register a serverless DID with a webvh host

Use case: the VTA was set up serverless (no webvh host configured
at setup time), so it has a complete `did.jsonl` locally but
nothing is publishing it. A webvh hosting server has now come
online and you want the VTA's DID to be served by it without
re-issuing the DID identifier.

```bash
# 1. Register the host with the VTA. This validates the host's DID
#    resolves and advertises a `WebVHHostingService` or
#    `DIDCommMessaging` endpoint.
pnm webvh add-server \
  --id primary \
  --did did:web:webvh.example.com \
  --label "primary host"

# 2. Promote the VTA's DID. Pushes the local did.jsonl to the host
#    and flips `server_id` from "serverless" to "primary".
pnm webvh register-did \
  --did did:webvh:abcd1234:webvh.example.com:vta \
  --server primary
# DID registered with WebVH server.
#   DID:        did:webvh:abcd1234:webvh.example.com:vta
#   Server:     primary
#   Log entries: 4
#
# Future `pnm services …` mutations will auto-publish to `primary`.

# 3. Verify by running any subsequent `services` change — it now
#    publishes to the host as part of the same operation.
pnm services rest update --url https://vta.example.com
# REST URL updated.
#   New version ID: 5-zQm…
#   Effective at:   2026-05-07T17:14:00Z
```

**Refused if already server-managed.** Re-pointing a hosted DID at
a different host is a separate operation (would need coordinated
teardown on the old host) and is out of scope for this command.

**Offline equivalent.** When the VTA daemon is stopped, the same
operation is available on the local binary:

```bash
vta webvh register-did \
  --did did:webvh:abcd1234:webvh.example.com:vta \
  --server primary
```

The fjall lock applies — fails fast if the daemon is running. TEE
deployments must use `pnm webvh register-did` against the running
enclave (the offline path can't reach the vsock store on the
parent host).

## Walkthrough: edit an existing DID document

Use case: you want to add or remove a service entry, change a
verification method's controller, or otherwise hand-edit the DID
document, then publish the change as a new LogEntry.

### Interactive (the common case)

```bash
pnm webvh edit-did --did did:webvh:abcd1234:vta.example.com:vta
```

What happens:

1. The CLI fetches the latest published DID document and opens it
   in `$EDITOR` (uses `dialoguer::Editor` — `vi` by default,
   honours your `$EDITOR` / `$VISUAL`).
2. Make your edits, save, exit. Quitting without saving aborts
   the operation cleanly.
3. The CLI prints a one-line diff summary (`added: …`,
   `changed: …`, `removed: …`) so you can sanity-check what
   you touched.
4. A `Confirm` chain asks whether to change any webvh parameters:
   - Override pre-rotation count?
   - Replace watcher URLs?
   - Set a new TTL?
   - Add an audit label?
   Each defaults to **No** — hit Enter to skip and just publish
   the document edit.
5. Final confirmation lists what's in the body
   (`document, watchers, label`, etc.) and asks "Publish?".
6. The CLI calls `update_did_webvh`, which appends a new
   LogEntry, rotates control keys, and (if the DID is server-managed)
   pushes the new log line to the host.

**The DID `id` is locked.** If you edit the top-level `id` field,
the publish is rejected with `DidIdChanged` and the
operation aborts. The DID identifier is a permanent commitment
from the first LogEntry; mutating it would break every existing
reference. To mint a new DID instead, use `pnm webvh create-did`.

### Non-interactive (scripted)

```bash
# Just publish a new document, no parameter changes:
pnm webvh edit-did \
  --did did:webvh:abcd:vta.example.com:vta \
  --document new-doc.json \
  --no-confirm

# Document + parameter overrides:
pnm webvh edit-did \
  --did did:webvh:abcd:vta.example.com:vta \
  --document new-doc.json \
  --pre-rotation 2 \
  --ttl 86400 \
  --watcher https://watcher.example.com \
  --label "post-audit rotation" \
  --no-confirm

# Disable watchers entirely:
pnm webvh edit-did \
  --did did:webvh:abcd:vta.example.com:vta \
  --no-watchers \
  --no-confirm
```

`--no-confirm` skips the final "Publish?" prompt — required for
unattended runs.

For witness changes, use `--options-file <path>` pointing at a
JSON file with the full
[`UpdateDidWebvhBody`](https://github.com/OpenVTC/verifiable-trust-infrastructure/blob/main/vta-sdk/src/protocols/did_management/update.rs)
shape. The witness wire form uses multibase ids and a threshold
field that's awkward to express on the command line; a JSON file
is friendlier.

### Offline equivalent

```bash
# VTA daemon must be stopped — fjall lock applies.
vta webvh edit-did --did did:webvh:abcd:vta.example.com:vta
```

Same flag surface and same security boundary as the other
offline `vta` commands: filesystem access to the data directory
is the boundary, no operator authentication ceremony, not
available in TEE deployments.

## Walkthrough: brick-prevention in action

```bash
# Try to disable both transports — the second one refuses.
pnm services didcomm disable
# DIDComm disabled.
#   Prior mediator: did:webvh:wxyz9876:m2.example.com:mediator
#   New version ID: 6-zQm…
#   Drain deadline: 2026-05-08T16:00:00Z

pnm services rest disable
# Error: refusing to disable REST — DIDComm is also off, so the
# VTA would have no advertised services.
# Suggested fix: Run `pnm services didcomm enable --mediator-did <did>`
# first, then retry.
```

## Telemetry events

Every mutation emits a `service.<kind>.<verb>` event via the
`vti_common::telemetry::TelemetrySink` plug-in. Direct operations
emit no `triggered_by` field; rollback-dispatched operations emit
`triggered_by: "rollback"`.

Event names (kebab-case in the wire form):
- `services_rest_enable` / `services_rest_update` /
  `services_rest_disable`
- `services_didcomm_enable` / `services_didcomm_update` /
  `services_didcomm_disable`
- `mediator_drain_start` / `mediator_drain_cancel` /
  `mediator_drain_expire` (drain bookkeeping events; not part of
  the rename surface)

Each event carries the new LogEntry's `version_id`, channel
(`rest` / `didcomm`), and kind-specific fields (URL for REST,
mediator DID for DIDComm).

`pnm services report` queries the same telemetry sink and renders
per-mediator inbound counts plus per-sender last-seen attribution.

## Wire-form details

These are the on-the-wire shapes the SDK exposes. Most operators
won't need them; the `pnm` CLI is the canonical interface.

**REST endpoints** (super-admin auth):
- `GET /services` — list services
- `POST /services/rest/{enable,update,disable,rollback}`
- `POST /services/didcomm/{enable,update,disable,rollback}`
- `GET /services/didcomm/drain` — list drain entries
- `POST /mediators/drain/cancel` — cancel one drain entry

**DIDComm message types** (services-management/1.0):
- `rest-{enable,update,disable,rollback}` and matching
  `*-result`
- `didcomm-{disable,update,rollback}` and matching `*-result`
  (`didcomm-enable` is REST-only by nature)
- `list`, `didcomm-drain-list`, and matching `*-result`

The `mediator-management/1.0` namespace is retained for
`drain-cancel` and `report` — these operate on the drain set, not
the active mediator advertisement, so the original naming is still
accurate.

## Failure modes

The CLI's error renderer surfaces the typed `VtaError` variant
along with a suggested-fix string per CLAUDE.md "operator errors
should suggest the fix":

| Error | Status | Suggested fix |
|---|---|---|
| `ServiceAlreadyEnabled` | 409 | "Use `services <kind> update …` to change the configuration." |
| `ServiceNotPresent` | 409 | "Run `services <kind> enable …` first." |
| `LastServiceRefused` | 409 | "Enable the other transport first via `services <other> enable …`." |
| `MediatorHandshakeFailed` | 502 | "Confirm the mediator DID is correct and the mediator is reachable." |
| `DrainTtlOutOfBounds` | 400 | "Pick a value within [3600s, 30 days]." |
| `NoPriorMutation` | 409 | "No prior mutation to roll back; use the direct command instead." |

## Offline `vta services …` — operator-host alternative

Every command above has an offline counterpart on the local
`vta` binary. The shape is identical (`vta services list`,
`vta services rest enable --url …`, `vta services didcomm
update --to <did>`, etc.) but the execution model differs:

- **No HTTP**, no operator authentication ceremony.
- **Direct fjall access** — opens the local data directory and
  calls the operation functions in-process.
- **Filesystem access is the security boundary** — same model
  as `vta acl …`, `vta keys …`, `vta contexts …`. Anyone with
  read/write access to the data dir can run these.

### Don't run while the VTA daemon is running

fjall takes an exclusive file lock when the running VTA opens
its data directory. Offline `vta services` will fail to open
the store with a clear error pointing the operator at `pnm
services` against the live VTA. This protects against
split-brain corruption on disk; the cost is that `vta services`
mutations require stopping the daemon first (which most
operators won't want to do — `pnm services` is the canonical
path for live-VTA changes).

### Not for TEE deployments

Inside a Nitro Enclave the VTA's fjall store lives behind a
vsock proxy; the offline `vta` binary on the parent host has no
access to it. Same constraint applies to every other `vta`
offline command (acl, keys, contexts, webvh) — operators
running TEE always use `pnm services …` against the VTA's
HTTPS endpoint.

### When `vta services` is useful

- Cold-start setup before the daemon ever runs (e.g. publishing
  a REST URL for an air-gapped VTA before it boots).
- Recovery / forensics on a stopped VTA.
- Test environments where spinning up the full daemon is
  overkill.

For day-to-day service management against a running VTA, prefer
`pnm services …`.

## Spec references

- §3.2 — at-least-one-service brick-prevention invariant
- §3.3 — DIDComm-preferred ordering in the `service[]` array
- §3.4 — REST-specific operations and the `#vta-rest` shape
- §3.5 — DIDComm-specific operations and the drain machinery
- §3.5a — fail-forward rollback semantics
- §3.6 — 24h default drain TTL
- §5.1 — final CLI surface (this guide is the operator-facing
  rendering of that section)
- §7a — end-to-end test matrix

## See also

- `docs/05-design-notes/runtime-service-management.md` — the
  approved spec
- `docs/05-design-notes/runtime-service-management-plan.md` —
  the dependency-ordered implementation plan
- `docs/05-design-notes/runtime-service-management-tasks.md` —
  the 33-task breakdown
- `docs/03-integrating/didcomm-protocol-management.md` —
  redirects here (legacy DIDComm-only guide superseded in P5)
