# Trust-registry integration

How the VTC publishes its membership to an external trust registry,
how the `MembershipSyncer` keeps the published view in step with
the local ACL, and how cross-community recognition lets one VTC
mint a session for a member of a peer community.

## Why a trust registry?

A trust registry answers the question **"is `did:key:zFoo...` an
active member of community X right now?"** for verifiers who don't
have direct access to the community's ACL. The VTC writes to it;
external verifiers read from it.

```mermaid
graph LR
    subgraph VTC["VTC (us)"]
        ACL[ACL + member roster]
        SYNC[MembershipSyncer]
        ACL --> SYNC
    end

    TR[Trust Registry<br/>TRQP v2.0]

    SYNC -->|publish + update + delete| TR

    subgraph PeerVTC["Peer VTC"]
        REC[POST /v1/auth/recognise]
    end

    PeerVTC -->|recognise our member| TR
    TR -->|membership lookup| PeerVTC

    External[External verifier]
    External -->|verify foreign VMC| TR
```

The VTC uses **TRQP v2.0** (Trust Registry Query Protocol) via the
`affinidi-trust-registry-rs` client (or any TRQP-compatible
backend).

## Publication

```mermaid
sequenceDiagram
    participant App as Daemon code
    participant Aud as Audit log
    participant SS as MembershipSyncer
    participant TR as Trust Registry

    App->>Aud: write(MemberAdded / MemberRemoved / RoleChanged)
    Note over Aud,SS: Syncer reads the audit tail<br/>(no separate event bus)
    SS->>SS: Enqueue SyncJob<br/>in sync_queue keyspace
    loop until success or max retries
        SS->>TR: POST /registry/v2/membership
        alt success
            TR-->>SS: 200 OK
            SS->>SS: Update local mirror<br/>(registry_records keyspace)
            SS->>Aud: write(RegistrySyncSucceeded)
        else failure
            TR-->>SS: 5xx / timeout
            SS->>SS: Exponential backoff<br/>retry
            SS->>Aud: write(RegistrySyncFailed)<br/>after final attempt
        end
    end
```

The syncer:

- Subscribes to audit-tail events (`MemberAdded` / `MemberRemoved`
  / `RoleChanged`) — the audit log is the source of truth for
  triggers, not a separate event bus.
- Persists each pending job in a `sync_queue` fjall keyspace so
  pending work survives restarts. At boot, the syncer replays
  outstanding jobs.
- Uses exponential backoff on failure (default starts at 30s,
  doubles, caps at 1h).
- Surfaces health on `GET /v1/health/diagnostics`:
  - `registry_status: "active" | "degraded"`
  - `sync_queue_depth: <u32>`
  - `last_sync_at: <iso8601>`
  - `last_failure_reason: <string>`

`registry_status` flips to `degraded` when the queue is ≥1h behind
(configurable via `registry.degraded_threshold_seconds`).

## RTBF batching

A self-initiated `Purge` (right-to-be-forgotten) is timing-sensitive:
if a single member purges and the registry record disappears within
seconds, a malicious observer can correlate the audit event with the
specific member.

The VTC defends with **batched RTBF deletes**:

```mermaid
graph LR
    purge1[Purge req<br/>11:00] --> batch[(RTBF batch<br/>window)]
    purge2[Purge req<br/>14:30] --> batch
    purge3[Purge req<br/>23:45] --> batch
    timer[Daily timer<br/>or boot replay] --> flush[Flush all<br/>at once]
    batch --> flush
    flush --> TR[Trust registry<br/>multi-delete]
```

`registry.rtbf_batch_window_hours` (default 24) coalesces every
RTBF deletion into one daily batch. The batch trigger fires on a
periodic timer AND at boot (so a daemon restart doesn't leak
batched purges that haven't yet flushed).

## Cross-community recognition

A peer community's member presents their VMC to our VTC and asks
for a session. Our VTC verifies the foreign credential, checks the
peer registry, runs our `cross_community_roles.rego` to map their
role to ours, and (on success) mints a session.

```mermaid
sequenceDiagram
    participant M as Foreign member
    participant US as Our VTC
    participant FOREIGN as Their VTC
    participant TR as Trust Registry

    M->>US: POST /v1/auth/recognise<br/>(foreign VMC envelope)
    US->>US: Verify VMC signature<br/>against foreign issuer's resolved DID
    US->>FOREIGN: GET /v1/status-lists/revocation
    FOREIGN-->>US: Status list
    US->>US: Check bit at credentialStatus.statusListIndex
    alt slot revoked
        US-->>M: 403 ForeignCredentialRevoked
    else slot clear
        US->>TR: GET /registry/v2/membership/<foreign-issuer>
        TR-->>US: Active / not-active
        alt foreign issuer not in registry
            US-->>M: 403 IssuerNotRecognised
        else recognised
            US->>US: Evaluate cross_community_roles.rego
            US->>US: Mint session<br/>TTL = min(JWT-default, VMC.validUntil)
            US-->>M: { access_token, refresh_token }
        end
    end
```

**Session-mint hardening invariants** (every one is load-bearing):

- Foreign VMC must pass **live** status-list revocation check.
- Foreign issuer must be in the trust-registry recognition graph
  **at mint time**.
- Minted session TTL = `min(JWT-audience-default,
  foreign-VEC.validUntil, foreign-VMC.validUntil)`.
- **No caching** — every mint re-runs policy + status-list + registry
  checks. A peer community removed mid-session doesn't retain
  access on refresh.

## Configuration

```toml
# config.toml
[registry]
url = "https://trust-registry.example.org"
http_timeout_seconds = 30
health_probe_interval_seconds = 300       # 5 minutes; 0 disables
rtbf_batch_window_hours = 24              # daily flush
degraded_threshold_seconds = 3600         # status flips to degraded after 1h lag
```

Setting `registry.url = ""` (or omitting it) disables registry
features entirely — the daemon runs in "no-registry" mode,
`registry_status` reports `degraded`, and `cross_community_roles`
short-circuits to deny-all.

## CLI quick reference

```sh
# Registry health
cnm registry health
cnm registry profile show     # community's registry record

# Sync queue inspection
cnm registry queue list
cnm registry queue retry --id <job-id>
cnm registry queue cancel --id <job-id>

# Force a re-publish
cnm registry refresh
```

## See also

- [VTC MVP spec §8](../05-design-notes/vtc-mvp.md) — full TRQP
  binding + reconciliation details.
- [Community lifecycle](community-lifecycle.md) — what events
  trigger registry sync (`MemberAdded`, etc.).
- [Credentials](credentials.md) — status-list mechanics that
  recognition relies on.
