//! Vault entries — third-party credentials the holder has stored on the
//! VTA, used by Companions and Services to authenticate against external
//! sites and apps. M1 ships the metadata view + read-only store helpers;
//! upsert, delete, sync, proxy-login, and release land in later milestones.
//!
//! Wire format mirrors the canonical Trust Task spec
//! `https://trusttasks.org/spec/vault/_shared/0.1/vault-entry` field-for-field
//! — `#[serde(rename_all = "camelCase")]` lines the JSON up with the
//! schema's camelCase wire form. Timestamps are RFC 3339 strings rather
//! than Unix epoch (unlike [`crate::acl::AclEntry`]); this matches the spec
//! directly and avoids a separate wire/domain conversion. The slight
//! ergonomic loss versus `u64` is fine for v0.1.
//!
//! **No secret material lives in this module.** [`VaultEntry`] is the
//! metadata projection — the `secret_kind` discriminator is present, but
//! the bytes only ever transit through HPKE-sealed envelopes carried by
//! the vault/release/0.1 task (which lands in M2).

use serde::{Deserialize, Serialize};

use crate::error::AppError;
use crate::store::KeyspaceHandle;

/// Public metadata view of a single vault entry. Direct wire-form match for
/// the `VaultEntry` `$def` in the canonical Trust Task shared schema.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultEntry {
    /// Opaque maintainer-assigned id (ULID recommended).
    pub id: String,
    /// Trust context (persona) this entry belongs to.
    pub context_id: String,
    /// Binding targets. A request from any matching target uses this entry.
    pub targets: Vec<SiteTarget>,
    /// User-facing display name.
    pub label: String,
    /// Discriminator for the kind of secret bytes; never the bytes themselves.
    pub secret_kind: SecretKind,
    /// User-defined tags for filtering.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// Non-sensitive notes (sensitive notes live inside the secret payload).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    /// Optional icon URI.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub favicon: Option<String>,
    /// Opaque policy-engine selector strings.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub selectors: Vec<String>,
    /// Names of custom fields (values live in the secret payload).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub custom_field_names: Vec<String>,
    /// References to encrypted blobs (recovery codes, key files, etc.).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attachments: Vec<AttachmentRef>,
    /// Expected expiry (e.g. OAuth refresh-token expiry, time-limited tokens).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    /// Set when HIBP (or equivalent) detects this credential in a breach.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub breached_at: Option<String>,
    /// Last password rotation timestamp (for password-kind entries).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password_changed_at: Option<String>,
    /// RFC 3339 creation timestamp.
    pub created_at: String,
    /// DID of the consumer that created the entry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_by: Option<String>,
    /// RFC 3339 last-modification timestamp.
    pub updated_at: String,
    /// DID of the consumer that last modified the entry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<String>,
    /// Most recent use (proxy-login or release).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<String>,
    /// Monotonic version for optimistic concurrency + sync seq baseline.
    pub version: u32,
}

/// Binding target for a vault entry. Tagged union over the discriminator
/// `kind`. Wire form (kebab-case discriminator) matches the canonical
/// `SiteTarget` shared schema.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum SiteTarget {
    WebOrigin {
        origin: String,
    },
    Did {
        did: String,
    },
    #[serde(rename_all = "camelCase")]
    IosApp {
        bundle_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        team_id: Option<String>,
    },
    #[serde(rename_all = "camelCase")]
    AndroidApp {
        package_name: String,
        sha256_cert_fingerprints: Vec<String>,
    },
}

/// Discriminator for the kind of secret stored. Wire values are kebab-case
/// (`oauth-tokens`, `did-self-issued`, etc.) per the canonical schema.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum SecretKind {
    Password,
    Passkey,
    OauthTokens,
    DidSelfIssued,
    DidcommPeer,
    BearerToken,
    SshKey,
    Custom,
}

/// Descriptor for an encrypted blob associated with a vault entry. The blob
/// itself is fetched via a separate mechanism; this struct carries only the
/// metadata projection.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AttachmentRef {
    pub id: String,
    pub name: String,
    pub size_bytes: u64,
    /// Hex-encoded SHA-256 of the encrypted blob bytes.
    pub sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
}

/// Filter criteria for [`list_vault_entries`]. All populated fields are
/// AND-combined. Matches the `payload.schema.json` of `vault/list/0.1`
/// minus pagination (`cursor` / `page_size`), which is applied in the
/// route layer rather than the store helper.
#[derive(Debug, Default)]
pub struct VaultListFilter<'a> {
    pub context_id: Option<&'a str>,
    pub target_origin_prefix: Option<&'a str>,
    pub target_did: Option<&'a str>,
    pub target_ios_bundle_id: Option<&'a str>,
    pub target_android_package: Option<&'a str>,
    pub secret_kind: Option<SecretKind>,
    pub tag: Option<&'a str>,
    pub used_since: Option<&'a str>,
    /// When `Some(true)`, return only entries with no `lastUsedAt`. Mutually
    /// exclusive with `used_since` at the caller level.
    pub never_used: Option<bool>,
    pub expires_before: Option<&'a str>,
    pub breached: Option<bool>,
}

/// Storage key for a vault entry — `"vault:<id>"`. Prefix scans on
/// `"vault:"` enumerate every entry in this VTA's keyspace.
fn vault_key(id: &str) -> String {
    format!("vault:{id}")
}

/// Read a single vault entry by id. Returns `Ok(None)` for absent ids so
/// callers can map to a not_found / permission_denied response per their
/// enumeration-resistance policy.
pub async fn get_vault_entry(
    vault: &KeyspaceHandle,
    id: &str,
) -> Result<Option<VaultEntry>, AppError> {
    vault.get(vault_key(id)).await
}

/// Store (create or overwrite) a vault entry. Unconditional write — version
/// checks are the caller's responsibility (the upsert handler will gain a
/// `If-Match`-style ETag in M2).
pub async fn put_vault_entry(vault: &KeyspaceHandle, entry: &VaultEntry) -> Result<(), AppError> {
    vault.insert(vault_key(&entry.id), entry).await
}

/// Delete a vault entry by id. Use the upcoming `vault/delete/0.1` handler
/// (M2) for the tombstone-aware path; this helper exists for tests and
/// administrative scripts.
pub async fn delete_vault_entry(vault: &KeyspaceHandle, id: &str) -> Result<(), AppError> {
    vault.remove(vault_key(id)).await
}

/// List vault entries matching `filter`, ordered by `last_used_at`
/// descending (entries without `last_used_at` sort last). Pagination is
/// caller-applied; this helper returns the full filtered set.
pub async fn list_vault_entries(
    vault: &KeyspaceHandle,
    filter: &VaultListFilter<'_>,
) -> Result<Vec<VaultEntry>, AppError> {
    let raw = vault.prefix_iter_raw("vault:").await?;
    let mut out = Vec::with_capacity(raw.len());
    for (_, bytes) in raw {
        let entry: VaultEntry = serde_json::from_slice(&bytes)?;
        if !matches_filter(&entry, filter) {
            continue;
        }
        out.push(entry);
    }
    out.sort_by(|a, b| {
        // Most-recently-used first; absent last_used_at sorts last.
        match (b.last_used_at.as_deref(), a.last_used_at.as_deref()) {
            (Some(x), Some(y)) => x.cmp(y),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => std::cmp::Ordering::Equal,
        }
    });
    Ok(out)
}

fn matches_filter(entry: &VaultEntry, filter: &VaultListFilter<'_>) -> bool {
    if let Some(ctx) = filter.context_id {
        if entry.context_id != ctx {
            return false;
        }
    }
    if let Some(kind) = filter.secret_kind {
        if entry.secret_kind != kind {
            return false;
        }
    }
    if let Some(tag) = filter.tag {
        if !entry.tags.iter().any(|t| t == tag) {
            return false;
        }
    }
    if let Some(since) = filter.used_since {
        match entry.last_used_at.as_deref() {
            Some(last) if last >= since => {}
            _ => return false,
        }
    }
    if filter.never_used == Some(true) && entry.last_used_at.is_some() {
        return false;
    }
    if let Some(before) = filter.expires_before {
        match entry.expires_at.as_deref() {
            Some(ts) if ts < before => {}
            _ => return false,
        }
    }
    if let Some(want_breached) = filter.breached {
        let is_breached = entry.breached_at.is_some();
        if is_breached != want_breached {
            return false;
        }
    }
    // Target filters: an entry matches when AT LEAST ONE target satisfies the
    // criterion. Each target filter is independent — passing multiple narrows
    // the result to entries that have a target matching every criterion (a
    // single target need not satisfy all of them).
    if let Some(prefix) = filter.target_origin_prefix {
        let ok = entry.targets.iter().any(|t| match t {
            SiteTarget::WebOrigin { origin } => origin.starts_with(prefix),
            _ => false,
        });
        if !ok {
            return false;
        }
    }
    if let Some(did) = filter.target_did {
        let ok = entry.targets.iter().any(|t| match t {
            SiteTarget::Did { did: d } => d == did,
            _ => false,
        });
        if !ok {
            return false;
        }
    }
    if let Some(bid) = filter.target_ios_bundle_id {
        let ok = entry.targets.iter().any(|t| match t {
            SiteTarget::IosApp { bundle_id, .. } => bundle_id == bid,
            _ => false,
        });
        if !ok {
            return false;
        }
    }
    if let Some(pkg) = filter.target_android_package {
        let ok = entry.targets.iter().any(|t| match t {
            SiteTarget::AndroidApp { package_name, .. } => package_name == pkg,
            _ => false,
        });
        if !ok {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(id: &str, ctx: &str, last_used: Option<&str>) -> VaultEntry {
        VaultEntry {
            id: id.to_string(),
            context_id: ctx.to_string(),
            targets: vec![SiteTarget::WebOrigin {
                origin: "https://github.com".to_string(),
            }],
            label: format!("entry {id}"),
            secret_kind: SecretKind::Password,
            tags: vec!["work".to_string()],
            notes: None,
            favicon: None,
            selectors: vec![],
            custom_field_names: vec![],
            attachments: vec![],
            expires_at: None,
            breached_at: None,
            password_changed_at: None,
            created_at: "2026-05-26T10:00:00Z".to_string(),
            created_by: None,
            updated_at: "2026-05-26T10:00:00Z".to_string(),
            updated_by: None,
            last_used_at: last_used.map(String::from),
            version: 1,
        }
    }

    #[test]
    fn site_target_round_trip_matches_canonical_wire_form() {
        let cases = vec![
            (
                SiteTarget::WebOrigin {
                    origin: "https://github.com".to_string(),
                },
                r#"{"kind":"web-origin","origin":"https://github.com"}"#,
            ),
            (
                SiteTarget::Did {
                    did: "did:web:rp.example".to_string(),
                },
                r#"{"kind":"did","did":"did:web:rp.example"}"#,
            ),
            (
                SiteTarget::IosApp {
                    bundle_id: "com.example.app".to_string(),
                    team_id: Some("ABCD123456".to_string()),
                },
                r#"{"kind":"ios-app","bundleId":"com.example.app","teamId":"ABCD123456"}"#,
            ),
            (
                SiteTarget::AndroidApp {
                    package_name: "com.example.app".to_string(),
                    sha256_cert_fingerprints: vec!["AA:BB".to_string()],
                },
                r#"{"kind":"android-app","packageName":"com.example.app","sha256CertFingerprints":["AA:BB"]}"#,
            ),
        ];
        for (val, expected) in cases {
            let json = serde_json::to_string(&val).unwrap();
            assert_eq!(json, expected, "encode {val:?}");
            let back: SiteTarget = serde_json::from_str(expected).unwrap();
            assert_eq!(back, val, "round-trip {expected}");
        }
    }

    #[test]
    fn secret_kind_serialises_to_canonical_kebab_case() {
        let cases = vec![
            (SecretKind::Password, "\"password\""),
            (SecretKind::OauthTokens, "\"oauth-tokens\""),
            (SecretKind::DidSelfIssued, "\"did-self-issued\""),
            (SecretKind::DidcommPeer, "\"didcomm-peer\""),
            (SecretKind::BearerToken, "\"bearer-token\""),
            (SecretKind::SshKey, "\"ssh-key\""),
        ];
        for (val, expected) in cases {
            assert_eq!(serde_json::to_string(&val).unwrap(), expected);
            let back: SecretKind = serde_json::from_str(expected).unwrap();
            assert_eq!(back, val);
        }
    }

    #[test]
    fn filter_matches_intersection_of_criteria() {
        let entry = sample("v1", "ctx_a", Some("2026-05-20T00:00:00Z"));

        // Match-all empty filter
        assert!(matches_filter(&entry, &VaultListFilter::default()));

        // Single criterion that matches
        assert!(matches_filter(
            &entry,
            &VaultListFilter {
                context_id: Some("ctx_a"),
                ..Default::default()
            }
        ));

        // Single criterion that misses
        assert!(!matches_filter(
            &entry,
            &VaultListFilter {
                context_id: Some("ctx_b"),
                ..Default::default()
            }
        ));

        // never_used excludes used entries
        assert!(!matches_filter(
            &entry,
            &VaultListFilter {
                never_used: Some(true),
                ..Default::default()
            }
        ));

        // used_since accepts a timestamp at or before last_used_at
        assert!(matches_filter(
            &entry,
            &VaultListFilter {
                used_since: Some("2026-05-19T00:00:00Z"),
                ..Default::default()
            }
        ));
        assert!(!matches_filter(
            &entry,
            &VaultListFilter {
                used_since: Some("2026-05-21T00:00:00Z"),
                ..Default::default()
            }
        ));

        // Origin prefix matches any web-origin target
        assert!(matches_filter(
            &entry,
            &VaultListFilter {
                target_origin_prefix: Some("https://github."),
                ..Default::default()
            }
        ));
        assert!(!matches_filter(
            &entry,
            &VaultListFilter {
                target_origin_prefix: Some("https://gitlab."),
                ..Default::default()
            }
        ));
    }
}
