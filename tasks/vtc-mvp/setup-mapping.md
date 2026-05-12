# `vtc setup` rewrite — mapping doc

> Output of **M0.9.1**. Drives the implementation of M0.9.2 (new
> wizard) and M0.9.3 (legacy deletion).

The plan calls (D5) the existing `vtc-service/src/setup.rs` (930
lines) "throw-away" and points at `vta-service`'s `src/setup/`
(~3000 lines across `interactive.rs` + `from_toml.rs`) as the
latest working reference. This doc enumerates the helpers worth
keeping, the ones that should move into `vti-common`, and the
ones that should stay per-service.

## Decision table

Each row pairs a `vta-service` helper with our intended treatment
for `vtc setup` (M0.9.2). "Reimplement thin" means VTC's wizard
gets a short, VTC-specific version rather than depending on the
VTA crate cross-tree.

| `vta-service` helper / concern                                     | Decision                            | Target location                              |
|--------------------------------------------------------------------|-------------------------------------|----------------------------------------------|
| **Banner + prompt UX** (clap, dialoguer, colours)                  | Reimplement thin                    | `vtc-service/src/setup/wizard.rs`            |
| `configure_secrets` + per-backend prompts (`keyring`, `aws`, `gcp`, `azure`, `vault`) | Promote to `vti-common`             | `vti-common/src/setup/secrets_prompt.rs` (new). VTC + VTA share the dialoguer flow + `SecretsConfig` shape — divergence would be a footgun. |
| `affinidi-secrets-resolver` integration / `SecretStore` traits     | Already shared                      | `vti-common::secrets` (no change)            |
| BIP-39 mnemonic generation + confirmation prompt                   | Promote to `vti-common`             | `vti-common/src/setup/mnemonic.rs` (new). The confirmation re-display + `MnemonicExportGuard` are load-bearing security primitives; one canonical impl. |
| Master-seed → keyring write                                        | Reimplement thin                    | `vtc-service/src/setup/wizard.rs`. VTA stores 64 bytes (Ed25519+X25519); VTC matches that shape (see `server.rs::init_auth`) — the call site differs by one constant. |
| `build_wizard_did` / `create_vta_did`                              | Don't reuse                         | (legacy). The new VTC flow doesn't mint its own DID — it calls VTA's `POST /bootstrap/provision-integration` with the `vtc-host` template and accepts whatever DID the VTA renders. The VTA-side analogue stays in `vta-service`. |
| `configure_messaging` (DIDComm endpoint prompts)                   | Reimplement thin                    | `vtc-service/src/setup/wizard.rs`. VTC's DIDComm story is "optional, add later via runtime-service-management" — the wizard's prompt can be minimal. |
| Keyspace init (open every keyspace once so the fjall files exist)  | Reimplement thin                    | `vtc-service/src/setup/wizard.rs`. VTC's keyspace catalogue differs (`sessions`, `acl`, `community`, `config`, `passkey`, `install`, `audit`, `audit_key`); VTA's catalogue is its own. |
| TOML config file emission                                          | Reimplement thin                    | `vtc-service/src/setup/wizard.rs`. Each service has its own `AppConfig` shape; `toml::to_string_pretty(&cfg)` is one-liner. |
| **NEW**: VTA `POST /bootstrap/provision-integration` call          | Use `vta-sdk` as-is                 | `vta_sdk::client::VtaClient::provision_integration` already covers REST. Wizard builds a `ProvisionIntegrationRequest` for the `vtc-host` template, signs the VP with an ephemeral key, opens the returned sealed bundle, and writes the VTC's DID + key seeds. |
| **NEW**: Install token mint + URL print                            | Already shipped                     | `vtc_service::install::token::mint_install_token` (M0.4) + `record_issued`. Wizard calls these at the end. |
| `setup --from <toml>` non-interactive driver                       | Defer to Phase 1+                   | The plan only asks for the three-question interactive flow in M0.9.2. Non-interactive can land later. |
| Mnemonic export window (`MnemonicExportGuard`)                     | Already shared                      | `vti_common::secrets::MnemonicExportGuard` (already used by VTA setup). |

## Call graph — new `vtc setup`

```text
vtc setup
  └─ vtc_service::setup::wizard::run()                            // M0.9.2
       │
       ├─ banner + intro (vtc-service)
       │
       ├─ ask 3 questions (dialoguer)
       │     ├─ vtc_url        : https://vtc.example.com
       │     ├─ admin_ux_url   : https://admin.vtc.example.com   (placeholder until Phase 5)
       │     └─ vta_url        : https://vta.example.com
       │
       ├─ vti_common::setup::secrets_prompt::configure_secrets()  // promoted from vta-service
       │     → SecretsConfig (keyring|aws|gcp|azure|env|toml)
       │
       ├─ vti_common::setup::mnemonic::generate_with_confirmation()  // promoted
       │     → 24-word mnemonic
       │     → 64-byte derived key material (Ed25519+X25519)
       │
       ├─ secrets_store.put(key_material)                          // vti_common::secrets
       │
       ├─ vta_sdk::client::VtaClient::new(vta_url)                 // already shared
       │     │
       │     ├─ build ProvisionIntegrationRequest for "vtc-host" template
       │     │     ├─ ephemeral did:key + Ed25519 keypair
       │     │     ├─ template vars: { vtc_url, admin_ux_url }
       │     │     └─ ask: BootstrapAsk::TemplateBootstrap { template: "vtc-host" }
       │     │
       │     └─ POST /bootstrap/provision-integration
       │           → ProvisionIntegrationResponse { bundle, digest, summary }
       │
       ├─ open sealed bundle → vtc_did, integration key seeds
       │     (uses vta_sdk::sealed_transfer / template_verify)
       │
       ├─ write vtc-service/config.toml
       │     vtc_did, vta_did, public_url, store.data_dir,
       │     auth.jwt_signing_key, secrets.* …
       │
       ├─ vti_common::store::Store::open(&cfg.store)
       │     for ks in ["sessions","acl","community","config",
       │                "passkey","install","audit","audit_key"]:
       │         store.keyspace(ks)?    // creates the partition
       │
       ├─ vtc_service::install::token::InstallTokenSigner::from_master_seed(&key_material)
       │     vtc_service::install::token::mint_install_token(&signer, &vtc_did, ttl=15min)
       │     install_store.record_issued(&jti, cnonce, ephemeral_key, exp)
       │
       ├─ print install URL ("{vtc_url}/install?token={jwt}")
       │
       └─ optionally spawn daemon  (or print "now run `vtc` to start the daemon")
```

## What gets deleted (M0.9.3)

After M0.9.2 lands, these legacy modules can be removed in
isolation — every reference in `main.rs` / `lib.rs` is replaceable
or stale:

| Module                                | Reason                                                                                      |
|---------------------------------------|---------------------------------------------------------------------------------------------|
| `vtc-service/src/setup.rs`            | Replaced by `setup/wizard.rs`. The legacy file hand-rolls the VTC DID locally; the new flow calls the VTA template path instead. |
| `vtc-service/src/did_webvh.rs`        | Local `did:webvh` stamping is replaced by VTA-side template rendering. The CLI subcommand (`vtc create-did-webvh`) loses its rationale and gets dropped. |
| `vtc-service/src/import_did.rs`       | The old `vtc import-did` CLI is the legacy cold-start path. The new install carve-out (M0.5/M0.6) is the supported way to bootstrap an admin DID — `import-did` is now misleading and goes away. |
| `vtc-service/src/acl_cli.rs`          | CLI-side ACL CRUD predates the web UX. Phase 0 endpoints (`/v1/acl/*` + admin/passkeys) supersede; admin UX is the canonical surface in Phase 0+. |

Order of operations in M0.9.3:

1. Confirm `main.rs` no longer needs any of the deleted modules
   (the new wizard replaces every meaningful path).
2. `git rm` the four files.
3. Strip module declarations from `vtc-service/src/lib.rs` +
   `src/main.rs`.
4. Drop the `create-did-webvh`, `import-did`, and `acl`
   subcommands from the clap `Commands` enum.
5. `cargo build` + `cargo clippy --workspace -- -D warnings` clean.

The `create-did-key` subcommand (`vtc-service/src/did_key.rs`) is
**not** in scope for deletion — it stays as a useful offline
utility for minting did:key pairs against a configured VTC
(handy for tests + the emergency-bootstrap flow in M0.10).

## Promoted-to-`vti-common` surface (new files)

Both are thin reusable layers, both used by VTA setup today and by
VTC setup after M0.9.2:

```text
vti-common/src/setup/
├── mod.rs
├── mnemonic.rs            // generate_with_confirmation() -> Mnemonic
├── secrets_prompt.rs      // configure_secrets() -> SecretsConfig (interactive)
└── ...
```

Behind a new `setup` feature flag so non-setup consumers (e.g.,
`vta-service` running headless in TEE) don't pull in `dialoguer`.

## Open questions surfaced by the mapping

These are not blockers — they have default answers but want a
sanity check in the M0.9.2 PR review:

- **Q1.** Should the new wizard tolerate `--from <toml>` non-
  interactive driving? The plan only asks for interactive; defer.
- **Q2.** What happens when the VTA's `provision-integration` call
  fails mid-flight (network blip, VTA rejects)? Default: surface
  the error verbatim and roll back any local writes (`config.toml`
  not written until provisioning succeeds). Keyring entry is also
  not written until provisioning succeeds — keeps the
  fresh-install-no-half-state invariant.
- **Q3.** Should the wizard auto-spawn the daemon after printing
  the install URL? Default: print the URL + a "now run `vtc`"
  hint. Auto-spawn confuses operator-facing logs and complicates
  shutdown semantics; leaving the daemon-launch step explicit is
  the boring choice.
