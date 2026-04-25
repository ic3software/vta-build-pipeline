# Verifiable Trust Infrastructure — Documentation

A guided tour of the VTI workspace: what it is, how to operate it,
how to integrate with it, and where the design decisions live.

## If you're trying to…

| Task | Start here |
|---|---|
| Understand what VTI is | [Overview](01-concepts/overview.md) |
| Stand up a VTA from scratch | [Cold-start guide](02-operating/cold-start.md) |
| Pick a place to store the master seed | [Secret-storage backends](02-operating/secret-backends.md) |
| Run a VTA on Kubernetes | [Secret-storage backends — HashiCorp Vault](02-operating/secret-backends.md#hashicorp-vault) |
| Deploy the VTA inside a Nitro Enclave | [TEE architecture](01-concepts/tee-architecture.md) |
| Build an application that uses a VTA | [Integration guide](03-integrating/integration-guide.md) |
| Provision a mediator / webvh-host / custom integration | [Provision-integration](03-integrating/provision-integration.md) |
| Add a new front-end binary to the workspace | [Architecture — Adding a new front-end](01-concepts/architecture.md#adding-a-new-front-end) |
| Look up an API endpoint or BIP-32 path | [Architecture — API surface](01-concepts/architecture.md#api-surface), [BIP-32 paths](04-reference/bip32-paths.md) |
| Read the threat model | [Security model](01-concepts/security-model.md) |

## Table of contents

### Part I — Concepts

- **[Overview](01-concepts/overview.md)** — what VTI is, the core
  concepts (contexts, DIDs, roles, sealed-transfer envelopes), the
  technology stack, the request flow.
- **[Architecture](01-concepts/architecture.md)** — workspace shape,
  crate map, `vta-service` module layout, API surface, storage
  layout, VTA CLI reference, how to add a new front-end binary.
- **[Security model](01-concepts/security-model.md)** —
  defense-in-depth layers, key lifecycle, threat model, attack
  trees, cryptographic inventory, deployment security checklist.
- **[TEE architecture](01-concepts/tee-architecture.md)** — Nitro
  Enclave deployment, KMS bootstrap, vsock store, attestation chain.

### Part II — Operating a VTA

- **[Cold-start guide](02-operating/cold-start.md)** — bootstrap a
  VTA + WebVH + mediator from scratch, the interactive way.
- **[Non-interactive setup](02-operating/non-interactive-setup.md)** —
  scripted VTA provisioning via `vta setup --from <file>` for CI,
  sealed images, and unattended bootstrap.
- **[Secret-storage backends](02-operating/secret-backends.md)** —
  AWS Secrets Manager, GCP Secret Manager, Azure Key Vault,
  HashiCorp Vault (with Kubernetes / token / AppRole auth),
  KMS-TEE, OS keyring, config-seed, plaintext. Picking, configuring,
  migrating.
- **[Feature flags](02-operating/feature-flags.md)** — Cargo
  feature reference, deployment profiles, dependency graph.
- **[Setup example](02-operating/examples/vta-setup.example.toml)** —
  worked TOML for `vta setup --from`.

### Part III — Integrating with a VTA

- **[Integration guide](03-integrating/integration-guide.md)** —
  building a third-party application that consumes VTA-managed keys
  and DIDs.
- **[DIDComm protocol](03-integrating/didcomm-protocol.md)** —
  message types, schemas, authorization, on-the-wire shapes.
- **[DID templates](03-integrating/did-templates.md)** — how
  templates are authored, uploaded, resolved (context → global →
  built-in).
- **[Provision-integration](03-integrating/provision-integration.md)** —
  the canonical flow for standing up an integration (mediator,
  webvh-host, custom service) via DID templates and sealed-transfer.
  Operator how-to + wire-format reference.

### Part IV — Reference

- **[BIP-32 paths](04-reference/bip32-paths.md)** — the
  hierarchical-key derivation specification: which paths the VTA
  uses, how indices are allocated, how P-256 fits in.
- **[CLI style](04-reference/cli-style.md)** — conventions for
  flags, output, errors, and JSON modes across the `vta`, `pnm`,
  and `cnm` binaries.

### Part V — Design notes

In-flight or historical design documents kept for context. These are
implementer-facing rather than operator-facing.

- **[Store migration](05-design-notes/store-migration.md)** — the
  enum-to-trait migration path for storage backends.
- **[PNM setup with deferred VTA DID](05-design-notes/pnm-setup-deferred-vta-did.md)** —
  the design behind the two-phase PNM setup that allows the VTA DID
  to be bound after initial wallet provisioning.

## Conventions

- Cross-references use relative links so the docs work both on
  GitHub and in any local Markdown viewer.
- Code references in prose use the form `path/to/file.rs:line` so
  IDEs can jump to them directly.
- Wire-format snippets are JSON for narrative clarity; the actual
  on-the-wire format is whatever the linked Rust types serialize to
  (CBOR for sealed payloads, JSON for VPs/VCs).

## Contributing to the docs

This tree was reorganized into chapters in April 2026. If you're
adding a new document:

- **Operator-facing how-to?** Add to `02-operating/` or
  `03-integrating/`.
- **Architectural / "what is this and why"?** Add to `01-concepts/`.
- **Pure reference (tables, paths, formats)?** Add to
  `04-reference/`.
- **Implementation-detail design brief?** Add to `05-design-notes/`.

Update this index when you add or rename a chapter. Cross-references
in the workspace `README.md` and `CLAUDE.md` may also need updating.
