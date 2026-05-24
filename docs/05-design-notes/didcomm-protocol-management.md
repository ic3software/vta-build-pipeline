# Spec: DIDComm Protocol Management (post-setup) — SUPERSEDED

> **Status:** Superseded by
> `docs/05-design-notes/runtime-service-management.md`. This
> document remains as historical context for the DIDComm-only
> precursor that shipped on the `sealed-bootstrap` branch
> (commits up to 88dab00). The follow-on runtime
> service-management feature generalised the same machinery
> (per-kind snapshot store, drain-set, brick-prevention helper,
> WebVH LogEntry per mutation) to cover REST as well, with
> fail-forward rollback and a unified `services {kind} {verb}`
> CLI.
>
> See:
> - `docs/05-design-notes/runtime-service-management.md` (the
>   active spec)
> - `docs/02-vta/runtime-service-management.md` (the
>   active operator guide)

Status: ~~Draft — awaiting human review before implementation~~ — Superseded
Owner: Glenn Gore
Related: `docs/02-vta/did-webvh-update.md`, `docs/05-design-notes/pnm-setup-deferred-vta-did.md`

## Objective

Allow a VTA operator to **enable, disable, and migrate DIDComm support
after initial setup**, without rebuilding the VTA, re-issuing admin
credentials, or rotating the VTA's verification keys. Every protocol
change is reflected in the VTA's WebVH DID document via a new LogEntry,
so external resolvers see the change as an authentic, signed update.

User stories:

1. *I set up my VTA REST-only and now want DIDComm.* One CLI command
   binds the VTA to a mediator, publishes a new LogEntry advertising the
   `#didcomm` service, opens the listener, and starts accepting DIDComm
   traffic.
2. *I no longer want DIDComm on this VTA.* One CLI command removes the
   `#didcomm` service from the DID doc, schedules the listener to drop
   after a configurable drain window, and refuses if REST is also
   disabled (otherwise the VTA has no protocol surface left).
3. *I'm moving from mediator A to mediator B.* One CLI command swaps the
   `#didcomm` service in the DID doc to point at B, places A in
   *drain* state with an operator-defined TTL, and keeps a parallel
   listener on A so in-flight messages from senders who still resolve
   the cached DID doc continue to land. Reporting shows which senders
   are still arriving via A so the operator can nudge them.
4. *I need to roll back a migration.* One CLI command swaps `#didcomm`
   back to A and pushes B into drain — symmetric with step 3.
5. *I need to know who's still using the old mediator.* A query/report
   surfaces per-mediator inbound counts and per-sender last-seen, so
   the operator can decide when to let a drain expire.

This spec covers **only** the consuming VTA's protocol surface and
mediator-binding state. It does not change how mediators themselves are
provisioned (`didcomm-mediator` template, unchanged) or how DIDComm
sessions authenticate (challenge/response, unchanged).

## Tech Stack

No new dependencies. Touches:

- `vti-common` — `MessagingConfig`, `Store`/`KeyspaceHandle` for drain state
- `vta-service` — operations, routes, didcomm bridge, listener lifecycle
- `vta-sdk` — REST/DIDComm client surface for new endpoints
- `vta-cli-common` — new commands (`pnm services …`, `pnm mediator …`)
- `pnm-cli` — wire the new command groups (CNM is out of scope for v1)
- `audit!` macro / existing tracing — telemetry for inbound mediator attribution

## Commands

CLI surface (PNM only for v1):

```
# Enable DIDComm on a REST-only VTA. Mediator must already exist as
# a reachable DID (separate deployment). VTA does NOT mint a new
# mediator — operator either provides an existing DID or first runs
# `pnm bootstrap provision-integration --template didcomm-mediator`.
pnm services enable didcomm \
    --mediator-did did:webvh:<...> \
    [--mediator-url https://<host>]      # optional override; otherwise resolved from DID doc

# Disable DIDComm. Refuses if REST is also disabled. Removes the
# #didcomm service from the DID doc immediately; the listener stays
# up until drain-ttl elapses.
pnm services disable didcomm \
    --drain-ttl <duration>               # 0s = immediate; e.g. 24h, 7d

# Show current protocol surface + active/draining mediators.
pnm services list

# Migrate the active mediator. Publishes a new LogEntry pointing at
# the new mediator; old mediator enters drain state with the given TTL.
# Multiple drains may coexist (overlapping migrations are permitted).
pnm mediator migrate \
    --to did:webvh:<...> \
    --drain-ttl <duration>

# Cancel an in-progress drain (immediate disconnect from the named mediator).
pnm mediator drain cancel --mediator-did did:webvh:<...>

# Rollback: swap #didcomm back to a previously-active mediator that is
# still in drain (or fully expired). Mechanically identical to migrate
# with --to set to the prior mediator.
pnm mediator rollback --to did:webvh:<...> --drain-ttl <duration>

# Reporting. Returns per-mediator inbound counts and per-sender
# last-seen mediator over a time window.
pnm mediator report [--since <duration>] [--format json|table]
```

Build / test / lint commands are unchanged — workspace-wide:
`cargo build --workspace`, `cargo test --workspace`, `cargo fmt`,
`cargo clippy --workspace --all-targets`.

## Project Structure

New code, in order of dependency:

```
vti-common/src/config.rs
    + DrainState, MediatorBinding (active vs draining + TTL)

vta-service/src/operations/protocol/
    mod.rs              ← orchestrator: lock + state transitions
    enable_didcomm.rs   ← REST-only → DIDComm
    disable_didcomm.rs  ← DIDComm → REST-only (or schedule drain-then-disable)
    migrate_mediator.rs ← swap #didcomm service, push old into drain
    drain.rs            ← drain set persistence + TTL expiry sweeper
    document.rs         ← read-modify-write of `service` array on existing DID doc

vta-service/src/routes/protocol.rs        ← REST handlers
    POST /services/didcomm/enable
    POST /services/didcomm/disable
    GET  /services
    POST /mediators/migrate
    POST /mediators/drain/cancel
    GET  /mediators/report

vta-service/src/didcomm/protocol/services_management.rs
    https://openvtc.org/protocols/services-management/1.0
    messages: list, disable
    (note: enable is REST-only — no DIDComm surface exists yet)
vta-service/src/didcomm/protocol/mediator_management.rs
    https://openvtc.org/protocols/mediator-management/1.0
    messages: migrate, drain-cancel, report

vta-service/src/didcomm_bridge.rs       ← extended: multi-listener registry,
                                          reconnect-with-backoff, sticky
                                          outbound routing
vta-service/src/operations/protocol/handshake.rs
                                        ← preflight: connect → auth → register
                                          → trust-ping → pong (or --force bypass)

vti-common/src/telemetry/mod.rs         ← TelemetrySink trait + TelemetryEvent
vti-common/src/telemetry/ring.rs        ← RingBufferTelemetry default impl

vta-sdk/src/protocol/                   ← typed client + request/response shapes
                                          including `--transport` selection
vta-cli-common/src/commands/services.rs ← new command group
vta-cli-common/src/commands/mediator.rs ← new command group

vta-service/src/operations/audit.rs     ← extended: drain ttl events,
                                          handshake events, force-bypass events
```

Tests:

```
vta-service/tests/protocol_enable.rs
vta-service/tests/protocol_disable.rs
vta-service/tests/protocol_migrate.rs
vta-service/tests/protocol_drain_expiry.rs
vta-service/tests/protocol_telemetry.rs
vta-sdk/tests/protocol_client.rs
```

## Code Style

Existing patterns are load-bearing — emulate them rather than inventing
new ones.

**Typestate for verified wire forms** (per CLAUDE.md): every request
that mutates protocol state is a JWT-authenticated REST or DIDComm
message; the route handler's first job is producing a `Verified*` value
and passing only that into the operation layer. New SDK request shapes
follow the `BootstrapRequest` / `VerifiedBootstrapRequest` split.

**Operations layer is where the work happens, routes stay thin.** The
operation function takes keyspace handles + verified params + an audit
channel, returns a typed result. Routes deserialize, verify, call op,
serialize.

**Reuse `update_did_webvh`** (`vta-service/src/operations/did_webvh/update.rs:699`)
as the only path that produces a new LogEntry. Do not bypass it. The
existing semantics are exactly right for this feature: when `document`
is `Some`, the WebVH **control keys** (`update_keys`,
`pre_rotation_commitments`) rotate, while `verificationMethod` keys are
preserved. We are explicitly opting into control-key rotation on every
protocol change — that's the intended cost and matches the user
guidance.

**Audit through the existing macro.** Protocol changes emit
`audit!(channel, action = …, …)` events with the same shape used in
`auth.rs`. New event kinds: `services.didcomm.enable`,
`services.didcomm.disable`, `mediator.migrate.start`,
`mediator.drain.start`, `mediator.drain.cancel`, `mediator.drain.expire`,
`didcomm.message.inbound{mediator_did, sender_did, msg_type}`.

**Operator errors suggest the fix** (CLAUDE.md). Examples:

```
$ pnm services disable didcomm
Error: cannot disable DIDComm — REST is also disabled.
   The VTA would have no protocol surface left.
   Run `pnm services enable rest` first, or use
        `pnm services disable didcomm --drain-ttl 0s` after enabling REST.

$ pnm mediator migrate --to did:webvh:<B>
Error: mediator B is currently in drain state (expires in 4h).
   Use `pnm mediator drain cancel --mediator-did did:webvh:<B>` first,
        or use `pnm mediator rollback --to did:webvh:<B>` to make it active again.
```

These map from typed `VtaError` variants, not opaque protocol strings.

**Sealed-transfer is unchanged.** This feature emits no new
secret-bearing wire data. No bundle, no HPKE.

Indicative snippet (sketch of the migrate operation; NOT prescriptive):

```rust
// vta-service/src/operations/protocol/migrate_mediator.rs

#[tracing::instrument(skip_all, fields(channel = %channel, new_mediator = %req.new_mediator_did))]
pub async fn migrate_mediator(
    keys_ks: KeyspaceHandle,
    contexts_ks: KeyspaceHandle,
    webvh_ks: KeyspaceHandle,
    drain_ks: KeyspaceHandle,
    seed_store: &SeedStore,
    auth: AuthContext,         // super-admin only
    req: VerifiedMigrateMediatorRequest,
    listeners: &MediatorListenerRegistry,
    channel: AuditChannel,
) -> Result<MigrateMediatorResponse, AppError> {
    // 0. Single global lock to serialize protocol-state mutations.
    let _guard = PROTOCOL_LOCK.lock().await;

    // 1. Load current DID doc, locate #didcomm service.
    let current = load_current_document(&webvh_ks).await?;
    let prior_mediator = current
        .didcomm_service()
        .ok_or(AppError::Conflict("DIDComm not enabled — use `services enable didcomm` instead".into()))?;

    if prior_mediator.did == req.new_mediator_did {
        return Err(AppError::Conflict("new mediator is already active".into()));
    }

    // 2. Resolve new mediator DID -> serviceEndpoint, validate reachability.
    let new_endpoint = resolve_mediator_endpoint(&req.new_mediator_did, &req.url_override).await?;

    // 3. Build the patched DID doc (single #didcomm entry → new mediator).
    let patched = current.with_didcomm_service(&req.new_mediator_did, &new_endpoint);

    // 4. Publish via existing update_did_webvh (rotates control keys, preserves verificationMethod).
    let result = update_did_webvh(/* … */, UpdateDidWebvhOptions {
        document: Some(patched),
        ..Default::default()
    }, /* … */).await?;

    // 5. Open listener on new mediator, push prior into drain.
    listeners.activate(&req.new_mediator_did, &new_endpoint).await?;
    listeners.drain(&prior_mediator.did, req.drain_ttl, &drain_ks).await?;

    audit!(channel, action = "mediator.migrate.start",
        from = %prior_mediator.did, to = %req.new_mediator_did, drain_ttl = ?req.drain_ttl);

    Ok(MigrateMediatorResponse {
        new_version_id: result.new_version_id,
        prior_mediator: prior_mediator.did,
        active_mediator: req.new_mediator_did,
        drain_until: now() + req.drain_ttl,
    })
}
```

## Testing Strategy

Framework: existing `cargo test` workspace setup; `tokio::test` for
async; `tempfile` + ephemeral fjall for keyspace-backed tests.

Coverage targets per concern:

- **Document patching.** Unit tests on `with_didcomm_service` / read+modify
  of the `service` array — input doc with no DIDComm, with DIDComm,
  with multiple service entries (e.g. WebVH service); confirm only the
  `#didcomm` fragment is touched.
- **State transitions.** Property-style tests that walk the
  state machine (REST-only → +DIDComm → migrate → migrate again →
  cancel drain → disable). Assert: at most one `#didcomm` service in
  the DID doc at all times; drain set is monotonic in operations
  (no listener disappears before TTL); LogEntry count increments by
  exactly 1 per state-changing call.
- **Concurrency.** Two `migrate` calls racing — both must serialize
  via `PROTOCOL_LOCK`; the second observes the first's state. Modeled
  on `MODE_B_LOCK` (`vta-service/src/main.rs`).
- **Drain TTL expiry.** Time-mocked: drain registered with TTL 1h,
  advance clock past TTL, sweeper drops listener and emits audit
  event.
- **Rollback equivalence.** `rollback --to A` after `migrate --to B`
  produces a DID doc identical to pre-migrate (modulo the bumped
  `versionId` and rotated control keys), and B ends up in drain.
- **Disable guardrail.** `disable didcomm` while REST is off must
  return a `Conflict` carrying the suggested-fix string; assert the
  error variant, not the message text.
- **Telemetry.** Inject a fake DIDComm message tagged with mediator A
  while drain on A is active, and a message tagged with B; assert
  the report endpoint returns counts grouped by mediator + per-sender
  last-seen mediator.
- **Multi-listener bridge.** Stand up two in-process mock mediators,
  send a request via each, confirm responses flow back through the
  same mediator the request arrived on (response routing is
  symmetric with inbound).

Integration coverage at the route level mirrors existing
`vta-service/tests/*.rs` style — full process boot, real fjall, real
HTTP client.

## Boundaries

**Always do**
- **Use DIDComm as the transport when it is available; fall back to
  REST only when DIDComm is not (yet) up.** Every admin call in this
  feature MUST ship with both a REST route and a DIDComm protocol
  message handler, and the CLI MUST prefer DIDComm by default
  (controlled by `--transport rest|didcomm|auto`, default `auto`).
  Exception: `services enable didcomm` is REST-only by nature — at
  call time the VTA has no DIDComm surface.
- Serialize every protocol-state mutation through `PROTOCOL_LOCK`
  (a single process-wide async mutex). Modelled on `MODE_B_LOCK`.
- Persist drain state in fjall (`drain_ks`) so it survives restart.
  On boot, replay drain set → re-open listeners → re-arm TTL timers.
- Run `cargo fmt && cargo clippy --workspace --all-targets` before
  commit; `git commit -s` (DCO).
- Audit every state transition.
- Run the full mediator handshake (resolve → connect → auth →
  register → trust-ping → pong) **before** publishing the LogEntry.
  See *Mediator handshake before promotion*. `--force` skips
  steps 2–5 only and emits a loud audit event.
- Tag every inbound DIDComm message with the mediator it arrived
  through, propagate that tag through to outbound reply routing.
- Refuse `services disable didcomm` if REST is also disabled —
  super-admin must opt-in to a no-protocol VTA via a separate
  `--allow-no-protocol` escape hatch (not in v1).

**Ask first**
- Whether `mediator report` needs persistence beyond an in-memory
  ring buffer (default: ring buffer of N=10000 events; persisted only
  via `audit!`).
- Whether the drain-TTL sweeper should be a single global tokio task
  per VTA, or a `tokio::time::sleep_until` per drain entry. Default:
  one `JoinSet` keyed by mediator DID, since drain count is small.

**Never do**
- Rotate `verificationMethod` keys on a protocol-state change. Only
  the WebVH control keys rotate (the existing semantics of
  `update_did_webvh` when `document` is `Some`).
- Allow more than one `#vta-didcomm` service entry in the DID document
  at once. Drain mediators are a runtime listener concern, not a
  resolution concern. (Note: the workspace's existing setup wizard
  emits the fragment `#vta-didcomm`; this spec uses `#didcomm` as a
  shorthand throughout, but the implementation matches the existing
  wizard fragment for backwards compatibility with already-published
  DID documents.)
- Mint or provision a mediator from inside this feature — the
  operator brings a mediator DID. Mediator provisioning continues to
  go through `pnm bootstrap provision-integration --template didcomm-mediator`.
- Forward in-flight messages from a draining mediator to the active
  mediator. Stragglers stay where they land; the report names them.
- Re-route an outbound response onto a different mediator if the
  inbound mediator is momentarily disconnected. Wait, retry, drop
  with audit — never silently switch transports.
- Persist outbound DIDComm response buffers to disk in v1.
- Bypass `update_did_webvh` to write a hand-crafted LogEntry.
- Publish a LogEntry advertising a mediator that has not completed
  the handshake (unless `--force`).

## Success Criteria

A reviewer can confirm completion by running each of these in a fresh
test environment:

1. **Enable from REST-only.** Set up a VTA REST-only via the wizard.
   Provision a mediator on a separate VTA via the existing template
   path. Run `pnm services enable didcomm --mediator-did <M>`. Assert:
   `did.jsonl` has one new LogEntry, the new entry's document carries
   exactly one `#didcomm` service entry pointing at `M`, the listener
   is up, an inbound DIDComm challenge succeeds.
2. **Disable with drain.** From the state above, run `pnm services
   disable didcomm --drain-ttl 60s`. Assert: the new LogEntry's
   document has no `#didcomm` service; listener is still active.
   After 60s, listener is closed, `mediator.drain.expire` event is
   audited, and a fresh inbound attempt fails to connect.
3. **Disable refused.** Disable REST first via `pnm services rest disable`,
   then run `pnm services disable didcomm` — must fail with the
   suggested-fix error. (Hand-editing the legacy `config.toml [services]`
   block is no longer effective at runtime — runtime state lives in the
   `service_state` fjall keyspace.)
4. **Migrate.** With mediator A active, run `pnm mediator migrate --to
   <B> --drain-ttl 1h`. Assert: DID doc's `#didcomm` is now B; both
   listeners are connected; inbound messages from senders that still
   resolve A's endpoint land and are tagged with A in the report;
   inbound from B-aware senders land and are tagged B; responses to
   each go back via the inbound mediator.
5. **Overlapping drains.** With A→B migration in flight (drain on A
   for 1h), run `pnm mediator migrate --to <C> --drain-ttl 30m`.
   Assert: DID doc's `#didcomm` is now C; A is in drain (≤ 1h
   remaining); B is in drain (≤ 30m remaining); three listeners up.
6. **Rollback.** From A→B migration in drain, run `pnm mediator
   rollback --to <A> --drain-ttl 30m`. Assert: DID doc's `#didcomm`
   is now A; B is in drain.
7. **Cancel drain.** Run `pnm mediator drain cancel --mediator-did
   <X>`. Assert: listener for X drops immediately; no further
   inbound from X.
8. **Restart resilience.** Mid-drain, kill the VTA process. Restart.
   Assert: drain set is restored, listeners come back up, TTL
   countdown resumes from the persisted deadline.
9. **Reporting.** After a few minutes of mixed traffic across A and
   B, run `pnm mediator report --since 1h --format json`. Assert:
   per-mediator counts are correct; per-sender `last_seen_mediator`
   matches the most recent inbound source for each sender DID.
10. **Verification keys preserved.** Across all the above, the DID
    doc's `verificationMethod` array MUST be byte-identical to its
    state at VTA setup. Only `service[]`, `versionId`, and the WebVH
    control-key fields change.
11. **DIDComm transport parity.** Repeat steps 4 (migrate), 7 (drain
    cancel), and 9 (report) over DIDComm transport (`pnm … --transport
    didcomm`) and assert identical outcomes. Also: invoke `services
    disable didcomm --drain-ttl 60s` over DIDComm — the response MUST
    arrive at the CLI before the listener tear-down (via the inbound
    mediator, which is now in drain).
12. **Disable-over-DIDComm response routing.** When `disable didcomm`
    is sent over DIDComm, the response is delivered through the same
    mediator the request arrived on, before that mediator's drain
    expires. (No race where the listener drops while the response is
    in flight.) `--drain-ttl 0s` over DIDComm is refused with a
    suggested-fix error.
13. **Handshake aborts publish.** Run `pnm mediator migrate --to <B>`
    where B does not exist (or B's listener auth fails, or trust-ping
    times out). Assert: no new LogEntry is appended to `did.jsonl`,
    no listener is opened, the active mediator is unchanged, and the
    operator gets a typed `MediatorHandshakeFailed` error pointing at
    the failing stage.
14. **`--force` bypass is auditable.** Run `pnm mediator migrate --to
    <B> --force` against an unreachable B. Assert: LogEntry IS
    published, no listener for B, and a
    `mediator.handshake.bypassed` telemetry event is recorded.
15. **Reconnect under transient drop.** With B active, kill B's
    websocket from the mediator side. Assert: VTA reconnects with
    backoff (≤ 60s cap), the active state is unchanged, no LogEntry
    is published.
16. **Sticky outbound routing.** Send a request via mediator A while
    A is in drain. Disconnect A's session momentarily. Generate the
    response while A is reconnecting. Assert: the response is queued,
    delivered via A on reconnect, and is NOT re-routed via the
    active mediator. If A's drain expires before reconnect, the
    response is dropped with a `didcomm.response.dropped` telemetry
    event.
17. **Telemetry sink swappability.** Run the test suite with the
    default `RingBufferTelemetry` and again with a stub
    `Vec<Mutex<…>>` in-test impl. Same assertions pass against
    both — proves the trait boundary holds.

## Decisions locked in

The following defaults are confirmed and become the implementation
target (no longer open):

- **Drain TTL upper bound: 30 days.** Operator may renew via `migrate
  --to <same>` if a longer drain is needed.
- **Drained mediator listener stays authenticated.** Session token is
  re-issued via the standard challenge/response flow up to the drain
  deadline; then the listener drops.
- **Drain-TTL sweeper:** one `JoinSet` keyed by mediator DID.
- **Minimum drain TTL when `disable didcomm` is invoked over DIDComm
  transport: 1h.** REST transport allows `0s`. Operation refuses
  `0s` over DIDComm with a suggested-fix error.
- **Promotion preflight is mandatory** (see *Mediator handshake* below).
  `--force` is the only escape hatch and emits a loud audit event.

## Mediator handshake before promotion

`pnm mediator migrate --to <B>` and `pnm services enable didcomm
--mediator-did <B>` both run a handshake against `B` **before** the
new LogEntry is published. The DID document is the source of truth
seen by the world, so we do not advertise a mediator we have not
proven we can use.

```
1. Resolve B from its DID. Read keyAgreement + DIDCommMessaging
   serviceEndpoint. Reject if either is missing.
2. Open the listener connection to B and authenticate the VTA's DID
   to B using the standard DIDComm challenge/response flow.
3. Register the listener with B so B will route messages addressed
   to the VTA's DID to this socket.
4. Send a `https://didcomm.org/trust-ping/2.0/ping` message addressed
   to the VTA's own DID, routed via B (round-trip via B's queue).
5. Wait for the pong, with a bounded timeout (default 10s, configurable
   via `--handshake-timeout`).
6. Only then publish the new LogEntry.
7. On any failure in steps 1–5: do not publish; return a typed error
   (`MediatorHandshakeFailed { stage, cause }`) with a suggested fix.
```

`--force` skips steps 2–5. `--force` does *not* skip step 1 —
malformed DID resolution is always a hard error. Every `--force`
publish emits `audit(action = "mediator.handshake.bypassed", …)` so
the choice is auditable.

By the time the LogEntry is published, B's listener is already up and
authenticated; there is no window where the DID doc advertises B but
the VTA cannot receive on B.

## Listener resilience and message retry

The drain primitive only protects against DNS/cache lag. The lower
layer must also be resilient to transient transport failures while a
mediator is in either *active* or *draining* state. Required
behaviour:

- **Reconnect with backoff.** If a listener loses its websocket to a
  mediator (any state), reconnect with exponential backoff
  (initial 1s, factor 2.0, cap 60s). Stop reconnecting when the
  mediator's drain deadline passes (active mediators have no
  deadline; reconnect indefinitely).
- **Outbound response routing is sticky.** A response is bound at the
  time the request arrives to the inbound mediator. If that
  mediator's listener is momentarily disconnected when the response
  is ready, queue the response and retry on reconnect, **bounded by
  the mediator's drain deadline**. Do not silently fall back to a
  different mediator — that breaks the symmetric-routing invariant.
  If retry exhausts (drain deadline reached with response still
  buffered), drop the response and emit
  `audit(action = "didcomm.response.dropped", reason = "mediator-drained", …)`.
- **No outbound buffering across restart.** Buffered outbound
  responses are in-memory only. A VTA restart drops them; the sender
  must retry. Persisting outbound responses is a separate
  reliability feature (out of scope here).

## Telemetry sink trait

The mediator-attribution telemetry that drives `pnm mediator report`
is emitted through a `TelemetrySink` trait, not hard-coded to a ring
buffer. The default impl is a bounded in-memory ring buffer; future
impls (fjall keyspace, file rotation, append-only log, blockchain
anchor) plug in without touching the call sites. **Only the trait and
the ring-buffer default ship in v1.**

Sketch (not prescriptive — final shape settled in planning):

```rust
// vti-common/src/telemetry/mod.rs

#[async_trait::async_trait]
pub trait TelemetrySink: Send + Sync {
    async fn record(&self, event: TelemetryEvent) -> Result<(), TelemetryError>;
    async fn query(&self, filter: &TelemetryFilter)
        -> Result<Vec<TelemetryEvent>, TelemetryError>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryEvent {
    pub at: SystemTime,
    pub kind: TelemetryKind,            // strongly typed, not free-string
    pub mediator_did: Option<String>,
    pub sender_did:   Option<String>,
    pub message_type: Option<String>,
    pub fields: serde_json::Map<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TelemetryKind {
    DidcommInbound,
    DidcommResponseDropped,
    MediatorHandshakeOk,
    MediatorHandshakeFailed,
    MediatorHandshakeBypassed,
    MediatorMigrateStart,
    MediatorDrainStart,
    MediatorDrainCancel,
    MediatorDrainExpire,
    ServicesDidcommEnable,
    ServicesDidcommDisable,
}

pub struct RingBufferTelemetry { /* bounded VecDeque + RwLock */ }

#[async_trait::async_trait]
impl TelemetrySink for RingBufferTelemetry { /* … */ }
```

The existing `audit!` macro continues to operate on its current sink
for security-audit semantics (auth events, key operations). The
`TelemetrySink` is a parallel surface for the higher-volume, query-
oriented mediator telemetry. They are not unified in v1; doing so is
a follow-up refactor. This split is intentional — it lets the audit
log stay simple/append-only while the telemetry surface gains
backends.

## Open questions

None blocking. All material design decisions are above. Anything
remaining is implementation detail to be settled during planning
(`agent-skills:plan`).
