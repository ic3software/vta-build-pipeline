# Secret-Storage Backends

The VTA's master seed is the root of every key it manages. This
chapter is the single reference for where that seed can live, how to
wire each backend up, and which one to pick for a given deployment.

If you just want to get going, the answer for most cases is:

| Deployment | Backend |
|---|---|
| Local development on a workstation | OS keyring (default) |
| AWS Nitro Enclave | KMS-TEE (automatic via `vta-enclave`) |
| EKS / GKE / AKS / on-prem Kubernetes | HashiCorp Vault with Kubernetes auth |
| Single EC2 / GCE / Azure VM, no TEE | AWS Secrets Manager / GCP Secret Manager / Azure Key Vault |
| CI / sealed images / unattended bootstrap | Config-seed (with the seed coming in via a sealed channel) |

Read [Picking a backend](#picking-a-backend) below if you want the
trade-offs rather than the cheat-sheet.

---

## How backend selection works

`vti_common::seed_store::SeedStore` is a small async trait
(`get` / `set` / `delete`). Every backend implements it. At startup
`vta-service::keys::seed_store::create_seed_store(&config)` walks
the configured backends in priority order and returns the first one
whose feature is compiled in **and** whose config is populated:

| Priority | Backend | Cargo feature | Activates when… |
|---|---|---|---|
| 1 | AWS Secrets Manager | `aws-secrets` | `secrets.aws_secret_name` is set |
| 2 | GCP Secret Manager | `gcp-secrets` | `secrets.gcp_secret_name` is set |
| 3 | Azure Key Vault | `azure-secrets` | `secrets.azure_vault_url` is set |
| 4 | HashiCorp Vault | `vault-secrets` | `secrets.vault_addr` is set |
| 5 | Config-seed | `config-seed` | `secrets.seed` is set |
| 6 | OS keyring | `keyring` | always (the default) |
| 7 | Plaintext file | always available | unconditional fallback |

If no secure-backend feature is compiled and no config is set, the
service falls back to a plaintext file in the data directory and
**logs a warning**. The plaintext backend exists for first-boot
testing only — never use it in production.

In TEE mode (`vta-enclave`), the KMS-backed bootstrap path provides
the seed directly via attested decryption; the table above is
bypassed entirely. See
[`../01-concepts/tee-architecture.md`](../01-concepts/tee-architecture.md).

## Encoding

Every backend stores the master seed as a **hex-encoded string** of
the BIP-39 entropy bytes (32 bytes for 24-word mnemonics, 16 for
12-word). This is consistent across AWS / GCP / Azure / Vault /
keyring / config-seed / plaintext. Mismatched encodings are the
single most common foot-gun when migrating between backends — they
are otherwise wire-compatible.

---

## Backends

### AWS Secrets Manager

Cargo feature: `aws-secrets` · File: `vta-service/src/keys/seed_store/aws.rs`

Stores the seed in a named AWS Secrets Manager secret in the VTA's
deployment region. AWS credentials resolve from the standard SDK
chain: IAM role on EC2/EKS, env vars, `~/.aws/credentials`, etc.

```toml
[secrets]
aws_secret_name = "vta/master-seed"
aws_region      = "us-east-1"   # optional; falls back to AWS_REGION env / IMDS
```

Equivalent env vars:

```bash
VTA_SECRETS_AWS_SECRET_NAME=vta/master-seed
VTA_SECRETS_AWS_REGION=us-east-1
```

IAM policy on the secret:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "secretsmanager:GetSecretValue",
        "secretsmanager:PutSecretValue",
        "secretsmanager:CreateSecret"
      ],
      "Resource": "arn:aws:secretsmanager:us-east-1:*:secret:vta/master-seed-*"
    }
  ]
}
```

`CreateSecret` is needed only on the very first `vta setup`. Drop it
from the policy after first-boot if you'd like the principle of
least privilege.

### GCP Secret Manager

Cargo feature: `gcp-secrets` · File: `vta-service/src/keys/seed_store/gcp.rs`

Stores the seed as a Secret Manager secret version. Authentication
uses Application Default Credentials — service-account JSON, GCE
metadata server, or Workload Identity in GKE.

```toml
[secrets]
gcp_project     = "my-project-id"
gcp_secret_name = "vta-master-seed"
```

Equivalent env vars:

```bash
VTA_SECRETS_GCP_PROJECT=my-project-id
VTA_SECRETS_GCP_SECRET_NAME=vta-master-seed
```

IAM role on the secret resource (or project, broader): `roles/secretmanager.secretVersionManager`
covers reads + writes of new versions; downgrade to
`roles/secretmanager.secretAccessor` after first-boot.

### Azure Key Vault

Cargo feature: `azure-secrets` · File: `vta-service/src/keys/seed_store/azure.rs`

Stores the seed as a Key Vault secret. Authentication uses the
DefaultAzureCredential chain — Managed Identity, az CLI session,
service principal, etc.

```toml
[secrets]
azure_vault_url    = "https://my-vault.vault.azure.net"
azure_secret_name  = "vta-master-seed"   # default if omitted
```

Equivalent env vars:

```bash
VTA_SECRETS_AZURE_VAULT_URL=https://my-vault.vault.azure.net
VTA_SECRETS_AZURE_SECRET_NAME=vta-master-seed
```

The principal needs `Get` and `Set` permissions on secrets in the
target vault. After first-boot the `Set` permission can be revoked.

### HashiCorp Vault

Cargo feature: `vault-secrets` · File: `vta-service/src/keys/seed_store/vault.rs`

Stores the seed as a field within a Vault KV v2 secret. Designed for
in-cluster Kubernetes deployments but works anywhere. Three auth
methods are supported, picked by `secrets.vault_auth_method`:
`kubernetes` (default), `token`, or `approle`.

The Vault token is **auto-renewed** in the background: a tokio task
renews at half the lease duration and re-authenticates from scratch
when the lease can no longer be extended. SA JWTs are re-read from
the kubelet-mounted projected-volume path on every authentication so
kubelet rotations are picked up transparently.

#### Kubernetes auth (default — pod talks to Vault directly)

```toml
[secrets]
vault_addr         = "https://vault.svc.cluster.local:8200"
vault_secret_path  = "vta/master-seed"
vault_kv_mount     = "secret"      # default
vault_secret_key   = "seed"        # default
vault_auth_method  = "kubernetes"  # default
vault_k8s_role     = "vta"
vault_k8s_mount    = "kubernetes"  # default
# vault_k8s_jwt_path defaults to /var/run/secrets/kubernetes.io/serviceaccount/token
```

Equivalent env vars (canonical Vault names work too):

```bash
VAULT_ADDR=https://vault.svc.cluster.local:8200
VAULT_NAMESPACE=engineering            # Vault Enterprise only
VTA_SECRETS_VAULT_SECRET_PATH=vta/master-seed
VTA_SECRETS_VAULT_K8S_ROLE=vta
```

Vault server-side configuration (one-time):

```bash
# Enable the K8s auth method
vault auth enable kubernetes

# Tell Vault how to reach the cluster's API
vault write auth/kubernetes/config \
    kubernetes_host="https://kubernetes.default.svc"

# Bind the VTA's ServiceAccount to a policy that grants KV read/write
vault policy write vta-policy - <<EOF
path "secret/data/vta/master-seed" {
  capabilities = ["read", "create", "update"]
}
EOF

vault write auth/kubernetes/role/vta \
    bound_service_account_names="vta" \
    bound_service_account_namespaces="vta-prod" \
    policies="vta-policy" \
    ttl="1h"
```

The pod runs with a ServiceAccount named `vta` in the `vta-prod`
namespace; the kubelet-mounted SA JWT presents that identity to
Vault.

#### Static-token auth

```toml
[secrets]
vault_addr        = "https://vault.example.com"
vault_secret_path = "vta/master-seed"
vault_auth_method = "token"
# Don't put the token in the config file — pass via env:
```

```bash
VAULT_TOKEN=hvs.xxx...
```

Suited to local development and CI. Renewal is best-effort — static
tokens have no auth-time lease, so the renewal task polls every 5
minutes and re-authenticates on token rotation.

#### AppRole auth

```toml
[secrets]
vault_addr               = "https://vault.example.com"
vault_secret_path        = "vta/master-seed"
vault_auth_method        = "approle"
vault_approle_mount      = "approle"   # default
vault_approle_role_id    = "abc-123-..."
vault_approle_secret_id  = "def-456-..."
```

Equivalent env vars:

```bash
VTA_SECRETS_VAULT_APPROLE_ROLE_ID=abc-123-...
VTA_SECRETS_VAULT_APPROLE_SECRET_ID=def-456-...
```

Useful for non-K8s machines where you still want short-lived,
auto-renewable Vault tokens (Nomad, plain VMs with a sidecar that
provisions the secret-id, etc.).

#### TLS

`vault_skip_verify = true` (or `VAULT_SKIP_VERIFY=1`) disables TLS
certificate verification. **Dev/test only.** Production deployments
should run a Vault that presents a CA-trusted certificate; the VTA
uses the system trust store to validate.

#### Common pitfalls

- **`vault_kv_mount` vs Vault path notation.** In the Vault CLI you
  write `vault kv put secret/vta/master-seed seed=<hex>` (the `/data/`
  segment is implicit). In our config you set `vault_kv_mount =
  "secret"` and `vault_secret_path = "vta/master-seed"` — also no
  `/data/`. The vaultrs library injects it for KV v2.
- **Field name.** The seed lives at `data.seed` by default. If you
  put it under a different key (e.g. `bip39_seed`), set
  `vault_secret_key = "bip39_seed"` to match.
- **Pod restarts on token expiry.** Don't rely on it. The renewal
  task is in-process; pod restarts will re-authenticate cleanly.
- **CrashLoopBackOff with `kubernetes auth` errors.** The most
  common cause is the ServiceAccount name/namespace not matching the
  Vault role's `bound_service_account_*` lists. Run
  `vault read auth/kubernetes/role/vta` and double-check.

### KMS-TEE (Nitro Enclave)

Cargo feature: `tee` · File: `vta-service/src/keys/seed_store/kms_tee.rs`

In `vta-enclave` deployments the seed never enters the file system.
Instead, the enclave performs an **attested decryption** at boot:

1. Generate an attestation document (PCR0/1/2 measurements, optional
   nonce, ephemeral RSA pubkey).
2. Send it to KMS via `kms:Decrypt` with the encrypted seed
   ciphertext.
3. KMS verifies the attestation against a Condition policy on the
   key, then encrypts the plaintext seed back to the enclave's
   ephemeral pubkey.
4. The enclave decrypts using its in-memory private key. The seed
   lives in `Zeroizing<[u8; 64]>` for the rest of the process
   lifetime.

There is no operator-visible config for this backend beyond the
upstream KMS key and the encrypted-seed ciphertext (provided via
`vta-enclave`'s parent-instance bootstrap). See
[`../01-concepts/tee-architecture.md`](../01-concepts/tee-architecture.md)
for the full design.

### OS keyring

Cargo feature: `keyring` (default) · File: `vta-service/src/keys/seed_store/keyring.rs`

The default for local development. Stores the seed under
`service = "vta"`, `username = "master_seed"` in the OS-native
credential store: macOS Keychain, GNOME Keyring / KWallet via
libsecret on Linux, Windows Credential Manager on Windows.

```toml
[secrets]
keyring_service = "vta"   # default
```

Set `keyring_service` to a different value to run multiple VTA
instances on the same workstation (e.g. `"vta-dev"`, `"vta-staging"`).

The keyring is **interactive** on macOS — a Keychain unlock prompt
may appear when `vta` first reads the seed in a fresh terminal
session. CI / headless environments should use a different backend.

### Config-seed

Cargo feature: `config-seed` · File: `vta-service/src/keys/seed_store/config.rs`

Reads the hex-encoded seed directly from the config file:

```toml
[secrets]
seed = "abcdef0123456789..."   # 32 or 64 hex chars
```

Designed for **CI / sealed images / unattended bootstrap** where
the seed arrives via an out-of-band sealed channel
(`vta bootstrap open …` writes the unsealed seed material into the
config). Not appropriate for long-running production deployments —
the seed sits on disk in plaintext.

If you find yourself reaching for this in production, use Vault or a
cloud secret manager instead.

### Plaintext file (fallback only)

File: `vta-service/src/keys/seed_store/plaintext.rs`

Always available, no Cargo feature required. Stores the seed as a
hex string in `<data_dir>/seed.hex`. The service emits a `WARN` log
line at startup when this backend is selected:

```
WARN no secure seed store backend available — falling back to plaintext file storage
```

Use only when first-boot-bringing-up a VTA in a sandbox where you
plan to migrate to a real backend before any production traffic hits
the system. Or when you are deliberately testing failure modes.

---

## Picking a backend

### Decision flowchart

```
Are you running inside an AWS Nitro Enclave?
├── Yes → KMS-TEE (automatic, no config)
└── No  ↓

Are you running inside a Kubernetes cluster?
├── Yes → HashiCorp Vault, kubernetes auth
└── No  ↓

Do you have a managed cloud secret store you already trust?
├── AWS  → AWS Secrets Manager
├── GCP  → GCP Secret Manager
├── Azure → Azure Key Vault
└── No  ↓

Do you have HashiCorp Vault deployed (any auth method)?
├── Yes → HashiCorp Vault
└── No  ↓

Is this a developer workstation?
├── Yes → OS keyring
└── No  → Stand up Vault before going to production. Use config-seed
         only as a sealed-image / CI bridge.
```

### Trade-offs

| | AWS SM | GCP SM | Azure KV | Vault | KMS-TEE | Keyring | Config | Plaintext |
|---|---|---|---|---|---|---|---|---|
| Encrypted at rest | ✅ | ✅ | ✅ | ✅ (Vault internal) | ✅ (KMS) | ✅ (OS) | ❌ | ❌ |
| Auto rotation friendly | ✅ | ✅ | ✅ | ✅ | n/a | ❌ | ❌ | ❌ |
| Works in TEE | via parent | via parent | via parent | via parent | ✅ native | ❌ | ❌ | ❌ |
| Works headless / CI | ✅ | ✅ | ✅ | ✅ | n/a | ⚠️ macOS prompts | ✅ | ✅ |
| In-process auto-renewal | implicit (IAM) | implicit (ADC) | implicit (MI) | ✅ explicit | implicit (KMS) | n/a | n/a | n/a |
| Production-ready | ✅ | ✅ | ✅ | ✅ | ✅ | dev only | dev only | never |

## Migrating between backends

The seed is hex-encoded everywhere, so migration is a read-from-old,
write-to-new operation. Two options:

1. **Plan it from setup.** `vta setup --from setup.toml` accepts the
   destination backend's config; the wizard mints a fresh seed
   directly into that backend.
2. **Migrate post-hoc.** Stop the VTA. Read the old seed
   (`vta keys seeds export`), update `[secrets]` in `config.toml`
   to the new backend, restart. The first call to
   `seed_store.get()` returns `None`; the wizard / first-write path
   stashes the imported seed in the new backend.

Treat seed migration the same way you treat key rotation: scheduled
maintenance, with a backup of the prior backend retained until the
new one is verified.

## See also

- [`feature-flags.md`](feature-flags.md) — Cargo-level feature
  reference (build profiles, dependency graph).
- [`cold-start.md`](cold-start.md) — first-boot setup walkthrough,
  including how the wizard interacts with the chosen backend.
- [`non-interactive-setup.md`](non-interactive-setup.md) —
  `vta setup --from <file>` with a TOML config that pre-selects the
  backend.
- [`../01-concepts/tee-architecture.md`](../01-concepts/tee-architecture.md) —
  Nitro Enclave / KMS bootstrap design, including the parent-side
  seed-encryption procedure.
