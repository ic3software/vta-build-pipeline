# Offline Integration Bootstrap

An operator-facing walkthrough for standing up an integration (DIDComm
mediator, webvh hosting server, future template-driven services) against
a VTA where **no infrastructure exists yet** — no running VTA, no
mediator, no hosting server, no network between the hosts. Everything
moves between hosts as files the operator shuttles by hand.

For the wire-format design brief, see
[`bootstrap-provision-integration.md`](bootstrap-provision-integration.md).
This doc is the how-to.

## When to use this

| Scenario | Use this flow |
|---|---|
| First-time setup of a brand-new VTA + first mediator on isolated hosts | ✅ |
| Adding a webvh hosting server to an existing VTA, operator prefers offline transfer | ✅ |
| Adding a second/third mediator to an already-running VTA, ops pipeline is file-based | ✅ |
| VTA and integration operator both have network access to a live VTA REST endpoint | Use `pnm bootstrap provision-integration` (online bridge) instead |

The offline flow and the online flow go through the same shared library
function in the VTA. The only difference is the transport. This doc
covers the offline path end-to-end.

## The principle

- `vta setup` stands up a VTA with no integrations. Done in isolation, no
  network, no dependencies.
- `vta bootstrap provision-integration` runs as a **local CLI** against
  the VTA's own keystore on disk — no HTTP server, no DIDComm, no live
  mediator. Same shared library function that backs the REST route; only
  the I/O differs.
- The integration emits a signed VP request, the VTA produces a sealed
  bundle, the integration opens it. Three files move between the two
  hosts.

Once both endpoints are running and the operator has a hosting server
live, every DID's `did.jsonl` can be published there. Until then, both
DIDs self-host their own logs. No circular dependency.

## The flow

```
┌──────────────────────────┐            ┌──────────────────────────┐
│  Integration host        │            │  VTA host                │
│  (future mediator /      │            │  (already `vta setup`)   │
│   webvh server)          │            │                          │
└──────────────────────────┘            └──────────────────────────┘
            │                                        │
  ┌─────────▼─────────┐                              │
  │ 1. generate VP    │                              │
  │  request.vp.json  │                              │
  │  (signs with      │                              │
  │   ephemeral       │                              │
  │   did:key)        │                              │
  └─────────┬─────────┘                              │
            │     request.vp.json                    │
            └──────────────────────────► ┌───────────▼───────────┐
                                         │ 2. provision-         │
                                         │    integration:       │
                                         │    mint keys, render  │
                                         │    template, issue    │
                                         │    VC, seal bundle    │
                                         └───────────┬───────────┘
            ┌──────────────────────────────── bundle.armor + digest
            │
  ┌─────────▼─────────┐
  │ 3. open bundle    │
  │  verify digest,   │
  │  unseal, install  │
  │  keys + trust     │
  │  bundle + log     │
  └───────────────────┘
```

## Phase 1 — Generate the request (integration host)

On the host that will run the mediator (or webvh server, or whatever).
No VTA contact, no network.

### Mediator example

```bash
vta bootstrap provision-request \
    --template      didcomm-mediator \
    --var           URL=https://mediator.example.com \
    --context-hint  mediator-prod \
    --admin-template vta-admin \
    --validity-hours 168 \
    --label         mediator-prod-bootstrap \
    --out           mediator-request.vp.json
```

### Webvh-hosting-server example

```bash
vta bootstrap provision-request \
    --template      webvh-hosting-server \
    --var           URL=https://webvh.example.com \
    --context-hint  webvh-host-prod \
    --admin-template vta-admin \
    --validity-hours 168 \
    --out           webvh-host-request.vp.json
```

### What this does

1. Mints a fresh ephemeral Ed25519 keypair — this is the VP's `holder`
   DID. Scoped to this one bootstrap round-trip; the long-term admin DID
   you end up with is minted by the VTA in Phase 2 if you pass
   `--admin-template vta-admin` (recommended).
2. Persists the seed under
   `~/.config/vta/bootstrap-secrets/<bundle_id>.key` (mode 0600 on
   Unix). You'll need it in Phase 3 to decrypt the returned bundle.
3. Signs a VP (W3C Verifiable Presentation) carrying the template name,
   variables, and context hint. The VP is valid for 168 hours (7 days)
   by default — widen or narrow with `--validity-hours`.
4. Writes the VP to `--out` as JSON.

Also available as `pnm bootstrap provision-request ...` — same shape,
different binary, different default seed directory
(`~/.config/pnm/bootstrap-secrets/`).

### Flags

| Flag | Required | Notes |
|---|---|---|
| `--template` | yes | Built-in (`didcomm-mediator`, `webvh-hosting-server`) or operator-uploaded template name. |
| `--var KEY=VALUE` | varies | Template-specific. Values are parsed as JSON when possible (`true`, numbers, arrays, objects, quoted strings); unquoted values are treated as strings. |
| `--context-hint` | recommended | The VTA context the integration will live in. The VTA operator confirms; mismatch is rejected, not silently normalized. |
| `--admin-template` | recommended | Typically `vta-admin`. The VTA mints a long-term admin DID under its own key custody and binds authorization to it — the ephemeral key stays throwaway. Omit only if you intentionally want the ephemeral `client_did` to remain the admin. |
| `--validity-hours` | default 168 | 7 days. Setup-file shuffling is slow; don't set too low. |
| `--label` | optional | Shows up in the VTA's audit log. |
| `--seed-dir` | optional | Override the default `~/.config/vta/bootstrap-secrets/` for CI or sealed images where `$HOME` isn't writable. |
| `--out` | yes | Path to write the signed VP. |

### Hand off

Copy `mediator-request.vp.json` (or equivalent) to the VTA host. Any
transport is fine — `scp`, USB, carrier pigeon. The VP is not secret;
its value is operator-signed intent.

## Phase 2 — Provision (VTA host)

On the VTA host. The VTA process does **not** need to be running; this
command operates directly on the store on disk.

```bash
vta bootstrap provision-integration \
    --request  mediator-request.vp.json \
    --context  mediator-prod \
    --out      mediator-bundle.armor
```

(Omit `--context` if the request's `contextHint` is authoritative.)

What it does:

1. Loads the VTA's config + opens the store.
2. Verifies the VP: signature (against the ephemeral `holder`), types,
   freshness (`validUntil`), context agreement.
3. Creates the target context if needed (`--context` must match either
   the explicit flag or the `contextHint`).
4. Mints the integration's DID + keys via the named template. In
   greenfield setup — no webvh hosting server exists yet — this runs in
   **serverless mode**: the VTA writes `did.jsonl` to its own store and
   the operator publishes it wherever (S3, nginx, GitHub Pages) later.
5. Mints the long-term admin DID if `adminTemplate` is set.
6. Writes the admin ACL row.
7. Issues a `VtaAuthorizationCredential` signed with the VTA's key.
8. HPKE-seals a `TemplateBootstrapPayload` (integration keys, admin
   keys, webvh log, VTA trust bundle, VC) to the VP holder's X25519
   derivation.
9. Writes the armored bundle to `--out` and prints the SHA-256 digest
   + provisioning summary.

### Preconditions

The call fails fast if:

- The calling operator isn't admin of the target context (on the
  CLI path this is synthesised as super-admin — the operator running
  the CLI has root access to the keyspace; ACL gating is enforced on
  the REST endpoint where it actually matters).
- The template isn't registered or known as a built-in.
- The request has expired (`validUntil` past, ±5 min skew).
- The request's signature doesn't verify against the holder DID.

### Hand off

Copy `mediator-bundle.armor` to the integration host. Communicate the
printed SHA-256 digest **out-of-band** — different channel than the
bundle file itself. Examples:

- Print the digest on the VTA-host terminal, type it into a Signal
  message to the integration operator.
- Drop the bundle on shared storage, text the digest.

The digest is the trust anchor. Without it, a bundle tampered in flight
is undetectable.

### Publish the VTA's and the integration's `did.jsonl`

Both DIDs are in serverless mode at this point. The VTA wrote:
- `data/vta/...<vta_did>.../did.jsonl` — the VTA's own log. Publish at
  the URL in `[vta_did] url` from `setup.toml`.
- The integration's `did.jsonl` is inside the sealed bundle as a
  `WebvhLog` output. Phase 3 installs it; the integration operator
  publishes at the URL they supplied in `--var URL=...`.

## Phase 3 — Open the bundle (integration host)

Back on the integration host. Verify and install.

```bash
vta bootstrap open \
    --bundle         mediator-bundle.armor \
    --expect-digest  <digest-from-OOB-channel>
```

(Or `pnm bootstrap open` if you used the `pnm` side in Phase 1.)

What it does:

1. Verifies the OOB digest matches the armored bundle's hash. Aborts
   loudly on mismatch; there is no silent TOFU.
2. Looks up the stashed seed by `bundle_id`
   (`~/.config/vta/bootstrap-secrets/<bundle_id>.key`).
3. Derives the X25519 HPKE secret from the Ed25519 seed.
4. Decrypts the sealed bundle.
5. Prints the payload summary — template name, kind, secret count,
   outputs, VTA URL.

`vta bootstrap open` today **prints** the payload contents; it does
not automatically install them into the integration's keystore. That
install step is integration-specific and lives in the integration's
own setup wizard (mediator repo, webvh-hosting-server repo, etc.).
Those wizards use the same library APIs described in the next section.

### What the integration installs

From the opened `TemplateBootstrapPayload`:

| Field | Install into |
|---|---|
| `secrets[integration_did]` | Integration's signing + key-agreement keys — persist into its own keystore (keyring, file, TEE). |
| `secrets[admin_did]` (if admin rollover) | Long-term admin DID keys — persist as the integration's admin identity. |
| `outputs: [WebvhLog { did, log_content }]` | Save `log_content` to disk; operator publishes at the URL from Phase 1's `--var URL=`. |
| `vta_trust_bundle` | VTA DID + root key + context id. Persist so the integration trusts incoming DIDComm from that VTA. |
| The inner VC | Archive for audit. The VTA's ACL is the authoritative authorization source in steady state — this VC is bootstrap-transport only and never re-verified after first open. |

## SDK surface (for integration-side wizards)

Integration setup wizards (the mediator binary's own setup, the webvh
server's own setup, any custom operator glue) should import the SDK
directly rather than shelling out to the CLI.

### Generate a request

```rust
use chrono::Duration;
use vta_sdk::provision_integration::ProvisionRequestBuilder;

let signed = ProvisionRequestBuilder::new("didcomm-mediator")
    .var("URL", "https://mediator.example.com")
    .context_hint("mediator-prod")
    .admin_template("vta-admin")
    .validity(Duration::days(7))
    .label("mediator-prod-bootstrap")
    .sign_ephemeral()
    .await?;

// Persist signed.seed under signed.bundle_id (hex) wherever your
// integration stores secrets. Serialize signed.request as JSON and
// hand to the VTA operator.
```

For integrations that already have a long-lived keypair they want to
reuse as the bootstrap identity, use `sign_with(&seed, &client_did)`
instead of `sign_ephemeral()`.

### Open a bundle

```rust
use vta_sdk::sealed_transfer::{armor, open_bundle, ed25519_seed_to_x25519_secret};

let armored = std::fs::read_to_string(&bundle_path)?;
let bundles = armor::decode(&armored)?;
let bundle = &bundles[0];

// Re-load the seed you persisted in Phase 1 (look up by bundle.bundle_id).
let x_secret = ed25519_seed_to_x25519_secret(&ed_seed);
let opened = open_bundle(&x_secret, bundle, Some(&oob_digest_hex))?;

// opened.payload is a SealedPayloadV1::TemplateBootstrap(...). Install
// its secrets, outputs, and vta_trust_bundle per your integration's
// keystore layout.
```

The CLI-common layer (`vta_cli_common::sealed_consumer`) wraps these
calls with the `~/.config/<tool>/bootstrap-secrets/` persistence
convention. Integrations with their own secret-storage strategy
(keyring, TEE, custom dir) should call the SDK directly and persist
wherever they already store keys.

## Exporting existing context state (offline admin handoff)

The flow above provisions a **new** integration from a template. A
second offline scenario: the operator has an **already-provisioned**
context and wants to hand its admin identity + DID material to a new
or backup admin host. Same sealed-transfer envelope, different payload
shape — [`SealedPayloadV1::ContextProvision`] or
[`SealedPayloadV1::DidSecrets`] instead of `TemplateBootstrap`.

Two commands, direct parallels of their `pnm` counterparts but
reading the local on-disk keystore (no running VTA, no network):

```bash
# Export a context's admin credential + all DID keys + DID document +
# log. Consumer imports the bundle and is set up as admin of that
# context. The DID's operational keys (signing, KA, pre-rotation) are
# auto-included — the operator doesn't name them.
vta context reprovision \
    --id             mediator-prod \
    --recipient      new-admin-request.json \
    --out            mediator-prod-handoff.armor

# Export all active keys in a context as a portable DID secrets bundle
# (DID + keys only, no admin credential).
vta keys bundle \
    --context        mediator-prod \
    --recipient      backup-admin-request.json \
    --out            mediator-prod-keys.armor
```

The consumer generates their bootstrap request with `vta bootstrap
request` (v1 shape — any recipient keypair, not the VP-framed one the
`provision-*` flow uses), hands the JSON to the VTA-host operator, and
decrypts the returned armored bundle with `vta bootstrap open`.

Same flags work with `pnm context reprovision` / `pnm keys bundle` on
an admin workstation that can reach the VTA over REST — the wire
shapes and sealing logic are shared via `vta-cli-common`. Pick the
binary that matches your transport: `vta` on the VTA host when the
admin has shell access and the VTA is air-gapped; `pnm` on an
authenticated workstation when the VTA is reachable over HTTPS.

`vta context reprovision`'s `--admin-key` is optional. When omitted
(recommended default), the VTA mints a fresh Ed25519 key scoped to
the context, derives its `did:key`, writes an admin ACL row for it,
and packs the resulting `CredentialBundle` into the sealed output.
The consumer installs the new admin identity and can immediately
authenticate to the VTA. Pass `--admin-key <existing-key-id>` only
when reusing a specific already-stored identity — rotation, backup
recovery, or a deliberate multi-admin setup. `--key` is accepted as a
deprecated alias of `--admin-key`. `pnm context reprovision` uses the
same flag name and accepts the same alias.

The DID's operational keys (signing, KA, any pre-rotation) are
always included in the bundle regardless — the operator never has to
enumerate them. `--admin-key` only affects the separate admin
credential slot.

The ACL entry for the derived admin DID is written on the VTA side
automatically if it doesn't already exist, so the consumer can
authenticate once they come online.

## Trust model

- **In-flight integrity**: SHA-256 digest communicated out-of-band. The
  bundle armor is public; the digest is the anchor.
- **Producer assertion**: `did-signed` (default) — the VTA signs the
  sealed-transfer envelope with its `{vta_did}#key-0` key. The
  integration can verify once the VTA DID is resolvable (may require
  both `did.jsonl` files to be published first).
- **VC verification**: the inner `VtaAuthorizationCredential` is
  verified at first open if the VTA DID is resolvable. In greenfield
  setup neither DID is published yet — use `--assertion pinned-only`
  on the provision-integration side, or defer VC verification until
  first live handshake.
- **Steady state**: the VC is bootstrap-only. After first open, the
  VTA's ACL is the authoritative authorization source. Revocation is
  ACL removal, not VC status change.

## Repeat for additional integrations

Every integration goes through the same three phases with the same
CLI. Different `--template`, different `--var` values, different
`--context-hint`. Provision a second mediator in another context, add
a webvh hosting server, then a custom integration from an
operator-uploaded template — all one flow.

Once a hosting server is live and both the VTA's and earlier
integrations' `did.jsonl` files are published there, subsequent
integrations can use `--var WEBVH_SERVER=<registered-id>` (and
optionally `--var WEBVH_PATH=<path>`) to have the VTA publish the new
integration's log directly to that server instead of self-hosting.

## See also

- [`bootstrap-provision-integration.md`](bootstrap-provision-integration.md) —
  wire-format design brief (VP shape, VC shape, sealed payload shape).
- [`non-interactive-setup.md`](non-interactive-setup.md) — `vta setup
  --from <file>` for the pre-provision VTA-stand-up step.
- [`cold-start-guide.md`](cold-start-guide.md) — interactive VTA setup
  walkthrough and admin seeding.
- [`did-templates.md`](did-templates.md) — how templates are authored,
  uploaded, resolved (context → global → built-in).
