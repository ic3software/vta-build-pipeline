# Non-Interactive VTA Setup

`vta setup --from <file>` provisions a VTA end-to-end from a single TOML
inputs file — no prompts, no terminal needed. Use it for CI pipelines,
immutable images, sealed-image redeploys, or any unattended bootstrap.

For the prompted walkthrough, see
[`cold-start-guide.md`](cold-start-guide.md). Both paths produce
identical state on disk.

## When to use which

| Scenario | Command |
|---|---|
| First time, you want to be guided through choices | `vta setup` |
| You already know what you want, want it scripted | `vta setup --from setup.toml` |
| CI pipeline, sealed image, headless host | `vta setup --from setup.toml` |
| You want to seed the first admin and seal the VTA in one step | `vta setup --from setup.toml` (with `admin_did` set) |

## Quick start

A minimum viable setup file:

```toml
config_path = "/srv/vta/config.toml"
data_dir    = "/srv/vta/data"

[secrets]
backend = "keyring"
service = "vta-prod"
```

Run it:

```bash
vta setup --from setup.toml
```

This generates a fresh seed, writes `config.toml`, initialises the store,
and prints next-step guidance. The VTA's ACL starts empty — seed an
admin separately:

```bash
vta bootstrap-admin --did did:key:z6Mk... --label ops
```

## Full example with admin seeding and DID minting

```toml
config_path = "/srv/vta/config.toml"
data_dir    = "/srv/vta/data"
vta_name    = "trust-prod-1"
public_url  = "https://trust.example.com"

# Seed the first super-admin and seal the VTA atomically with the rest of
# setup. Skip this if you'd rather seed admin(s) later via `pnm setup`.
admin_did   = "did:key:z6MkABCDEFGHIJKLMNOPQRSTUVWXYZ"
admin_label = "ops-bootstrap"

[secrets]
backend     = "aws"
region      = "us-east-1"
secret_name = "vta/prod/seed"

[messaging]
kind    = "create_mediator"
context = "mediator"
url     = "https://mediator.example.com"

[vta_did]
kind               = "create_webvh"
url                = "https://trust.example.com/dids/vta"
portable           = true
pre_rotation_count = 2
```

A complete annotated reference is at
[`examples/vta-setup.example.toml`](examples/vta-setup.example.toml).

## Schema

The schema is defined in Rust by `vta_service::setup::WizardInputs`
(vta-service/src/setup.rs). Field-level rustdoc on that struct is the
authoritative source — the snippets below are the operator-facing
summary.

### Top-level fields

| Field | Required | Default | Notes |
|---|---|---|---|
| `config_path` | yes | — | Where to write `config.toml`. Refuses to overwrite an existing file. |
| `data_dir` | yes | — | On-disk fjall store location. |
| `vta_name` | no | `null` | Human-readable name. |
| `public_url` | no | `null` | Used as the `VTARest` service endpoint when minting a DID. |
| `data_dir_exists` | no | `"error"` | What to do if `data_dir` already exists. `"delete"` for CI re-runs. |
| `admin_did` | no | `null` | If set, seeds a super-admin and seals the VTA atomically. Must start with `did:`. |
| `admin_label` | no | `null` | Label on the seeded admin's ACL row. |

### Sections

- **`[services]`** — `rest = true` and `didcomm = true` by default.
- **`[server]`** — `host = "0.0.0.0"`, `port = 8100`.
- **`[log]`** — `level = "info"`, `format = "text"`.
- **`[secrets]`** — required; tagged enum on `backend`. See below.
- **`[messaging]`** — optional; tagged enum on `kind`. Default `"skip"`.
- **`[vta_did]`** — optional; tagged enum on `kind`. Default `"skip"`.

### Seed-store backends

`backend` selects the variant; per-variant fields are required.

| Backend | Fields |
|---|---|
| `"keyring"` | `service` (default `"vta"`) |
| `"aws"` | `secret_name`, optional `region` |
| `"gcp"` | `project`, `secret_name` |
| `"azure"` | `vault_url`, `secret_name` |
| `"config_seed"` | none — hex seed embedded in `config.toml`. **Not recommended.** |
| `"plaintext"` | none — plaintext file under `data_dir`. **Dev only.** |

Cloud backends require the matching feature at compile time
(`aws-secrets`, `gcp-secrets`, `azure-secrets`) — the wizard refuses to
proceed with a clear error if the feature isn't compiled in.

### Messaging

| `kind` | Fields | Use when |
|---|---|---|
| `"skip"` | — | No DIDComm. |
| `"existing"` | `did` | You already have a mediator DID. |
| `"create_mediator"` | `url`, `context` (default `"mediator"`) | Mint a new mediator using the built-in `didcomm-mediator` template. |

### VTA DID

| `kind` | Fields | Use when |
|---|---|---|
| `"skip"` | — | No VTA DID. REST works; DIDComm/VC issuance doesn't. |
| `"existing"` | `did` | You already have a VTA DID. |
| `"create_webvh"` | `url`, `portable` (default `true`), `pre_rotation_count` (default `1`) | Mint a new did:webvh in "simple mode". |

`create_webvh` writes the DID's `did.jsonl` to
`<data_dir>/did-logs/<label>-did.jsonl` for re-publishing or audit.
Operators who need advanced DID options (template-from-file, pre-signed
log import, user-specified key IDs) should use interactive setup.

## Mnemonic policy

Setup **always generates** a fresh 24-word BIP-39 mnemonic. There is no
way to provide your own at setup time — pasting a mnemonic into a
terminal exposes it to shell history, scrollback, and clipboard, and
that risk isn't worth the convenience.

If you need a known seed (disaster-recovery import, controlled key
ceremony), run after setup:

```bash
vta keys rotate-seed --mnemonic "<your 24 words>"
```

If you want a backup of the generated seed, run after the first admin
connects:

```bash
pnm backup export --output vta-backup.vtabak
```

The backup is password-encrypted and contains the seed plus the rest of
the VTA's persistent state.

## CI re-run pattern

For pipelines that re-run setup against a clean state each time:

```toml
config_path     = "/srv/vta/config.toml"
data_dir        = "/srv/vta/data"
data_dir_exists = "delete"     # wipe on re-run
admin_did       = "did:key:..."

[secrets]
backend = "aws"
secret_name = "vta/ci/seed"
```

Then in your pipeline:

```bash
rm -f /srv/vta/config.toml             # config_path overwrite is also blocked
vta setup --from setup.toml
vta --config /srv/vta/config.toml &    # ready to serve
```

The seed is generated fresh on each run, so the AWS secret value
changes each time — fine for CI, not what you want in production.

## Validation and errors

The wizard validates the file in two phases:

1. **TOML parse + schema** — happens at deserialization. Unknown fields,
   missing required fields, wrong types, and unknown enum variants all
   fail here with serde-quality messages.
2. **Cross-field rules** — happens before any state is mutated. All
   errors are collected and reported in a single message:

```
Setup failed: setup file has 2 validation error(s):
  - messaging.kind = "create_mediator" requires services.didcomm = true
  - admin_did = "not-a-did" must be a DID (starts with `did:`)
```

If validation passes, the wizard makes incremental changes (open store,
write seed, mint DIDs, seal). A failure mid-flight leaves whatever was
written on disk; the safest recovery is to delete `config_path` and
`data_dir` and re-run.

## What you get afterwards

```bash
# Inspect what was written
vta --config /srv/vta/config.toml config show

# Confirm the admin row landed
vta --config /srv/vta/config.toml acl list

# Start serving
vta --config /srv/vta/config.toml
```

If you set `admin_did`, the VTA is sealed and ready for production
management via the authenticated REST API or DIDComm. If you didn't,
follow the
[interactive admin-grant flow in `cold-start-guide.md`](cold-start-guide.md)
(`pnm setup` → `vta import-did` → start VTA → first authenticated
command auto-rotates).
