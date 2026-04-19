# Cold-Start Guide: Non-TEE VTA + PNM

This guide walks through bootstrapping a working **non-TEE Verifiable Trust
Agent** and connecting a PNM CLI to it. Everything runs on one machine
(or across two — operator workstation + VTA host); no external services
(mediator, WebVH hosting, Redis) are required.

For enclave-hosted (TEE) deployments and the full multi-service trust
network (VTA + mediator + WebVH DID hosting), see the follow-up sections
at the end.

## Prerequisites

- **Rust 1.94.0+** (`rustup update stable`)
- **OS keyring support** (macOS Keychain, GNOME Keyring, Windows Credential
  Manager) — the default seed storage backend
- **git** and **curl**

## The flow in one diagram

```
   ┌────────────────────┐             ┌────────────────────┐
   │  Operator laptop   │             │      VTA host      │
   │      (pnm-cli)     │             │     (vta server)   │
   └────────────────────┘             └────────────────────┘
              │                                  │
              │                                  │
              │ 1. vta setup (offline)           │
              │    (config + seed + VTA DID)     │
              │                                  │
              │ 2. pnm setup ──────────┐         │
              │    mint temp did:key   │         │
              │    print `vta import-did`────────▶
              │                        │         │ 3. vta import-did
              │                        │         │    (offline, writes ACL)
              │                        │         │
              │                                  │ 4. vta --config ...
              │                                  │    (VTA process starts)
              │ 5. pnm health  ─────────────────▶│
              │    auto-rotate did:key           │ (auth + rotate)
              │    done                          │
```

The temp did:key lives only long enough for PNM's first authenticated
request; auto-rotation mints a fresh long-lived did:key and drops the
temp from the ACL.

## Phase 1: Build

```bash
cd ~/devel/fpp/verifiable-trust-infrastructure
cargo build --workspace
```

Verify the two binaries used in this guide:

```bash
cargo run --package vta-service -- --help
cargo run --package pnm-cli    -- --help
```

## Phase 2: Run the VTA Setup Wizard (Offline)

The setup wizard runs with **no services needed**. It generates a BIP-39
seed, configures the server, optionally creates a VTA did:webvh, and
writes `config.toml`.

```bash
cd ~/devel/fpp/verifiable-trust-infrastructure
cargo run --package vta-service --features setup -- setup
```

### 2.1 Server configuration

```
Config file path [config.toml]: config.toml
VTA name: My Trust Network
Services to enable: [x] REST API   [ ] DIDComm Messaging
Public URL for this VTA: http://localhost:8100
Server host [0.0.0.0]: 0.0.0.0
Server port [8100]: 8100
Log level [info]: info
Log format: text
Data directory [data/vta]: data/vta
```

(For a REST-only setup, uncheck DIDComm. DIDComm requires a mediator —
see "Adding DIDComm messaging" at the end.)

### 2.2 BIP-39 mnemonic

Choose **Generate new 24-word mnemonic**. Write down and store the
mnemonic securely — it is the root of every key in the VTA's BIP-32
hierarchy.

### 2.3 Seed storage

Choose **OS keyring** for local development. The seed is stored in your
platform's credential manager (macOS Keychain, GNOME Keyring, etc.).
For headless / server deployments see the built-in alternatives
(AWS Secrets Manager, GCP Secret Manager, Azure Key Vault, config-seed
in `config.toml`).

### 2.4 VTA DID (optional but recommended)

If you want a resolvable VTA DID:

```
VTA DID:
  > Create a new did:webvh DID
```

Point it at wherever you plan to host the `did.jsonl` (a WebVH server,
static host, or a `did:web`-style URL). Choose **Simple** mode.

If you skip this, the VTA will use `did:key` as its identity; clients
still resolve it fine, but there's no stable DID log.

### 2.5 What to do next

At the end, the wizard prints instructions tailored for your config.
They look roughly like:

```
── What to do next ──

  1. On your operator workstation (with the VTA still stopped),
     run `pnm setup` and choose "Connect to an existing non-TEE
     VTA". When it asks for the VTA DID, enter:

       did:webvh:Qm...:localhost%3A8000:dids:vta

     `pnm setup` mints a temp did:key and prints an
     `vta import-did` command.

  2. Back on this host, run the `vta import-did` command pnm
     printed. This grants admin access to the temp did:key by
     writing to the local store — no network call, no running VTA
     required.

  3. Start the VTA:
       vta --config config.toml

     On the operator workstation's first authenticated command
     (e.g. `pnm health`), PNM rotates to a fresh long-lived
     did:key and removes the temp from the ACL.
```

## Phase 3: Run `pnm setup` on the operator workstation

With the VTA still stopped (so `vta import-did` can take the store lock
next), run:

```bash
cd ~/devel/fpp/verifiable-trust-infrastructure
cargo run --package pnm-cli -- setup
```

```
What would you like to do?
  > Connect to an existing non-TEE VTA

VTA DID (see `vta config show` on the VTA host): did:webvh:...:dids:vta
Name for this VTA [vta]: my-trust-network
```

PNM mints a did:key locally, stores a rotation-pending session in the
OS keyring, and prints:

```
Temp admin identity created.

  VTA slug:  my-trust-network
  VTA DID:   did:webvh:...:dids:vta
  Temp DID:  did:key:z6Mk...

Ask your VTA admin to grant this identity admin access. On the VTA host,
they should run:

  vta import-did --did did:key:z6Mk... --role admin
```

Copy the `vta import-did` command — you'll run it in Phase 4.

> **Tip:** if you forget the VTA DID, run `vta config show` on the VTA
> host. It prints everything `pnm setup` asks for.

## Phase 4: Grant admin access on the VTA host

Still with the VTA **stopped** (the `vta import-did` CLI takes the
store lock), run the command pnm printed:

```bash
vta import-did --did did:key:z6Mk... --role admin
```

This writes a single `AclEntry` directly to the fjall store. No
network call, no server required.

## Phase 5: Start the VTA

```bash
cd ~/devel/fpp/verifiable-trust-infrastructure
cargo run --package vta-service
```

## Phase 6: Verify + auto-rotate

On the operator workstation, run any authenticated command:

```bash
cargo run --package pnm-cli -- health
```

What happens internally:

1. PNM loads its session, sees `needs_rotation = true`.
2. Authenticates as the temp did:key (challenge-response).
3. Mints a fresh Ed25519 did:key from CSPRNG.
4. `GET /acl/<temp-did>` — reads the role + contexts the admin granted.
5. `POST /acl` with the new DID, same role + contexts.
6. Challenge-responds as the new DID to verify the grant is live.
7. `DELETE /acl/<temp-did>` — removes the temp from the ACL.
8. Saves the session with the new DID, clears the rotation flag.
9. Finishes the original `pnm health` request.

If the delete fails, PNM logs a warning and continues — the old temp
is stale anyway. Re-running `pnm health` is a no-op after rotation.

## That's it

A fresh VTA with a rotated admin identity on the operator's workstation.
No admin credentials ever crossed the wire; the temp did:key that briefly
existed in `pnm setup`'s output is gone from the ACL after step 6.

---

## Reference: `vta` offline CLI commands used here

All of these operate on the fjall store directly and require the VTA
process to be stopped (they take a store-level lock).

```bash
# Inspect config.toml — works while the VTA is running (doesn't open the store)
vta config show

# Check status (opens the store; requires VTA stopped)
vta status

# Add a DID to the ACL
vta import-did --did <did> --role admin [--label <text>] [--context <id>]...

# List / update / delete ACL entries
vta acl list [--context <id>] [--role <role>]
vta acl get <did>
vta acl update <did> [--role <role>] [--label <text>] [--contexts <id,...>]
vta acl delete <did>

# Manage keys offline
vta keys list [--context <id>] [--status active|revoked]
vta keys secrets <key-id...> [--context <id>]
vta keys seeds
vta keys rotate-seed [--mnemonic <phrase>]

# DID creation (offline, no server required)
vta create-did-key    --context <id> [--admin] [--label <text>]
vta create-did-webvh  --context <id> [--label <text>]
```

`vta bootstrap seal` is a producer-side command for sealing a payload
to a complex client's bootstrap request — used in the "Provisioning
complex clients" section below.

---

## Adding DIDComm messaging (mediator)

DIDComm is optional. Without a mediator, PNM authenticates via HTTP
challenge-response. To add mediator-routed DIDComm you need:

- A running DIDComm mediator (e.g. `affinidi-messaging-mediator`).
- A mediator DID published somewhere PNM can resolve (WebVH, did:web).
- Mediator setup knows about the VTA (it fetches its keys from the VTA
  at startup).

When bootstrapping a mediator against this VTA the same temp-did:key
flow applies:

1. On the mediator host, run the mediator's setup to mint the mediator's
   identity DID + produce a `BootstrapRequest` for its admin credential.
2. On a workstation with `pnm-cli`, run:
   ```
   pnm bootstrap request --out mediator-request.json
   ```
   and ship `mediator-request.json` to the VTA host.
3. On the VTA host (VTA **stopped**):
   ```
   vta bootstrap seal \
       --request mediator-request.json \
       --payload mediator-payload.json \
       --out     mediator.armor
   ```
   The payload is a `SealedPayloadV1::ContextProvision` produced by
   `vta context provision --recipient mediator-request.json` on a PNM-
   authenticated operator workstation (see [`sealed-bootstrap.md`] for
   the wire format).
4. Ship `mediator.armor` (and the printed SHA-256 digest) back to the
   mediator host; it opens the bundle, reads its VTA-admin credential,
   and rotates on first connect.

The full mediator + WebVH cold-start is out of scope for this guide —
those services live in separate repositories with their own setup docs.

---

## Adding WebVH DID hosting

Same shape as the mediator: provision the WebVH server's VTA-admin
credential via `pnm bootstrap request` + `vta context provision
--recipient`, and run the WebVH server's own bootstrap to import its
signing / KA keys.

See the `affinidi-webvh-service` repository's cold-start docs.

---

## Provisioning complex clients (sealed offline flow)

For services that need a full identity (DID + signing key + KA key +
VTA DID/URL) *before* they can contact the VTA — typically mediators
and webvh servers — the VTA admin uses the sealed-transfer flow:

**On the client's host** (1-time):

```bash
pnm bootstrap request --out request.json [--label "my-mediator"]
# → writes request.json; persists the ephemeral X25519 secret under
#   ~/.config/pnm/bootstrap-secrets/
```

**On a PNM-authenticated workstation** (admin):

```bash
pnm contexts provision \
    --id myservice \
    --name "My service" \
    --did-url "http://webvh.example.com/dids/myservice" \
    --mediator-service \
    --recipient request.json
# → prints an armored VTA SEALED BUNDLE + SHA-256 digest
```

**Back on the client's host**:

```bash
pnm bootstrap open --bundle myservice.armor --expect-digest <hex>
# → decrypts the bundle, surfaces DID + keys + VTA info for the client
#   to install
```

The complex client rotates its VTA-admin credential on first successful
VTA connect using the same `needs_rotation` flag the PNM flow uses
(see `vta-sdk::session::SessionStore::rotate_key`).

---

## Troubleshooting

### `pnm setup` can't resolve the VTA DID

PNM's interactive prompt only stores the DID — endpoints are resolved
at runtime from the DID document (`#vta-rest` service endpoint, or
did:web / did:webvh domain parsing). If resolution fails:

- Check the DID document is actually hosted where the DID claims
  (for did:webvh: `<domain>/<path>/did.jsonl`).
- Override the URL explicitly per-command: `pnm --url http://... health`.

### `vta import-did` fails with "could not open store"

The VTA process is running and holding the fjall lock. Stop the VTA
first (Ctrl+C / systemctl stop), run `vta import-did`, then restart.

### `pnm health` fails with 401 / 403 after setup

The admin hasn't run `vta import-did` for the temp did:key yet. Re-run
it on the VTA host (VTA stopped) using the command `pnm setup` printed.

### Rotation succeeded but old temp DID lingers in ACL

The new DID is live; the delete-old step failed (e.g. transient
network). Run:

```bash
pnm acl delete <temp-did>   # after authenticating — new did is active
```

or on the VTA host (stopped):

```bash
vta acl delete <temp-did>
```

### "Keyring not available" errors

Common in headless / SSH sessions. Use `config-seed` for the VTA seed
and a keyring-less PNM session:

```bash
# VTA: pick "Config file (hex in TOML)" during setup
cargo run --package vta-service \
    --no-default-features \
    --features setup,config-seed,rest -- setup
```

---

## Version / MSRV

- Rust workspace MSRV: **1.94.0** (see `Cargo.toml`).
- VTA / PNM binaries: **0.5.0**.

## Further reading

- [`sealed-bootstrap.md`](../sealed-bootstrap.md) — design doc for the
  sealed-transfer primitive used by complex-client provisioning.
- [`phase5-cutover.md`](../phase5-cutover.md) — removal of the
  plaintext base64 `encode/decode` path; the new `needs_rotation` +
  local keygen flow replaces Mode A token bootstrap.
- [`bip32_paths.md`](bip32_paths.md) — how contexts map to BIP-32
  derivation paths.
- [`feature-flags.md`](feature-flags.md) — compile-time feature matrix
  (TEE mode, secret backends, REST vs DIDComm, etc.).
