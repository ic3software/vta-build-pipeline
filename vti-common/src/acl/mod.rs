use std::fmt;

use serde::{Deserialize, Serialize};

use crate::auth::extractor::AuthClaims;
use crate::error::AppError;
use crate::store::KeyspaceHandle;

/// Roles that determine endpoint access permissions.
///
/// Hierarchy (most to least privileged):
/// - **Admin** — full management access, can assign any role
/// - **Initiator** — can manage ACL entries and application contexts
/// - **Application** — standard API access (sign, cache write) within allowed contexts
/// - **Reader** — read-only access to keys, contexts, DIDs within allowed contexts
/// - **Monitor** — infrastructure-only: metrics and health endpoints
#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Admin,
    Initiator,
    Application,
    Reader,
    /// `Monitor` is the least-privileged role and the natural default
    /// for a `Default::default()` `AuthClaims` (typically used in tests
    /// or pre-authentication scaffolding). A test fixture that leaks
    /// past its expected reach now lands on the most-restricted role
    /// rather than the most-privileged.
    #[default]
    Monitor,
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Role::Admin => write!(f, "admin"),
            Role::Initiator => write!(f, "initiator"),
            Role::Application => write!(f, "application"),
            Role::Reader => write!(f, "reader"),
            Role::Monitor => write!(f, "monitor"),
        }
    }
}

impl Role {
    /// Parse a role from its string representation.
    pub fn parse(s: &str) -> Result<Self, AppError> {
        match s {
            "admin" => Ok(Role::Admin),
            "initiator" => Ok(Role::Initiator),
            "application" => Ok(Role::Application),
            "reader" => Ok(Role::Reader),
            "monitor" => Ok(Role::Monitor),
            _ => Err(AppError::Internal(format!("unknown role: {s}"))),
        }
    }
}

/// An entry in the Access Control List.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AclEntry {
    pub did: String,
    pub role: Role,
    pub label: Option<String>,
    #[serde(default)]
    pub allowed_contexts: Vec<String>,
    pub created_at: u64,
    pub created_by: String,
    /// Unix-epoch seconds at which this entry expires and should be pruned by
    /// the background sweeper. `None` is permanent (existing pre-Phase-2
    /// behavior; entries serialized before this field existed deserialize with
    /// this default).
    #[serde(default)]
    pub expires_at: Option<u64>,
}

impl AclEntry {
    /// Returns true if this entry has passed its configured `expires_at`.
    /// Permanent entries (no `expires_at`) never expire.
    pub fn is_expired(&self, now_unix: u64) -> bool {
        match self.expires_at {
            Some(deadline) => now_unix >= deadline,
            None => false,
        }
    }
}

fn acl_key(did: &str) -> String {
    format!("acl:{did}")
}

/// Retrieve an ACL entry by DID.
pub async fn get_acl_entry(acl: &KeyspaceHandle, did: &str) -> Result<Option<AclEntry>, AppError> {
    acl.get(acl_key(did)).await
}

/// Store (create or overwrite) an ACL entry.
pub async fn store_acl_entry(acl: &KeyspaceHandle, entry: &AclEntry) -> Result<(), AppError> {
    acl.insert(acl_key(&entry.did), entry).await
}

/// Delete an ACL entry by DID.
pub async fn delete_acl_entry(acl: &KeyspaceHandle, did: &str) -> Result<(), AppError> {
    acl.remove(acl_key(did)).await
}

/// List all ACL entries.
pub async fn list_acl_entries(acl: &KeyspaceHandle) -> Result<Vec<AclEntry>, AppError> {
    let raw = acl.prefix_iter_raw("acl:").await?;
    let mut entries = Vec::with_capacity(raw.len());
    for (_key, value) in raw {
        let entry: AclEntry = serde_json::from_slice(&value)?;
        entries.push(entry);
    }
    Ok(entries)
}

fn now_epoch() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Check whether a DID is in the ACL and return its role.
///
/// Returns `Forbidden` if the DID is not found or if its entry has expired.
pub async fn check_acl(acl: &KeyspaceHandle, did: &str) -> Result<Role, AppError> {
    match get_acl_entry(acl, did).await? {
        Some(entry) if entry.is_expired(now_epoch()) => {
            Err(AppError::Forbidden(format!("ACL entry expired: {did}")))
        }
        Some(entry) => Ok(entry.role),
        None => Err(AppError::Forbidden(format!("DID not in ACL: {did}"))),
    }
}

/// Check whether a DID is in the ACL and return its role and allowed contexts.
///
/// Returns `Forbidden` under the same conditions as [`check_acl`].
pub async fn check_acl_full(
    acl: &KeyspaceHandle,
    did: &str,
) -> Result<(Role, Vec<String>), AppError> {
    match get_acl_entry(acl, did).await? {
        Some(entry) if entry.is_expired(now_epoch()) => {
            Err(AppError::Forbidden(format!("ACL entry expired: {did}")))
        }
        Some(entry) => Ok((entry.role, entry.allowed_contexts)),
        None => Err(AppError::Forbidden(format!("DID not in ACL: {did}"))),
    }
}

/// Validate that the caller is allowed to assign the given role.
///
/// - Only Admins can assign the Admin role.
/// - Reader, Application, and Monitor roles cannot assign any role.
pub fn validate_role_assignment(caller: &AuthClaims, target_role: &Role) -> Result<(), AppError> {
    if matches!(
        caller.role,
        Role::Monitor | Role::Reader | Role::Application
    ) {
        return Err(AppError::Forbidden(
            "insufficient role to assign roles".into(),
        ));
    }
    if *target_role == Role::Admin && caller.role != Role::Admin {
        return Err(AppError::Forbidden(
            "only admins can assign the admin role".into(),
        ));
    }
    Ok(())
}

/// Validate that the caller is allowed to create or modify an ACL entry
/// with the given `target_contexts`.
///
/// - Super admins can do anything.
/// - Context admins cannot create entries with empty `allowed_contexts`
///   (that would grant super admin access) and can only assign contexts
///   they themselves have access to.
pub fn validate_acl_modification(
    caller: &AuthClaims,
    target_contexts: &[String],
) -> Result<(), AppError> {
    if caller.is_super_admin() {
        return Ok(());
    }
    if target_contexts.is_empty() {
        return Err(AppError::Forbidden(
            "only super admin can create unrestricted accounts".into(),
        ));
    }
    for ctx in target_contexts {
        caller.require_context(ctx)?;
    }
    Ok(())
}

/// Check whether an ACL entry is visible to the caller.
///
/// Super admins see all entries. Context admins only see entries whose
/// `allowed_contexts` overlap with their own.
pub fn is_acl_entry_visible(caller: &AuthClaims, entry: &AclEntry) -> bool {
    if caller.is_super_admin() {
        return true;
    }
    entry
        .allowed_contexts
        .iter()
        .any(|ctx| caller.has_context_access(ctx))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::StoreConfig;
    use crate::store::Store;

    // ── Test fixtures ───────────────────────────────────────────────

    fn temp_store() -> (Store, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = StoreConfig {
            data_dir: dir.path().to_path_buf(),
        };
        let store = Store::open(&config).expect("open store");
        (store, dir)
    }

    fn sample_entry(did: &str, role: Role) -> AclEntry {
        AclEntry {
            did: did.to_string(),
            role,
            label: Some(format!("test-{did}")),
            allowed_contexts: vec![],
            created_at: now_epoch(),
            created_by: "did:key:zSetup".into(),
            expires_at: None,
        }
    }

    fn scoped_entry(did: &str, role: Role, contexts: &[&str]) -> AclEntry {
        AclEntry {
            did: did.to_string(),
            role,
            label: None,
            allowed_contexts: contexts.iter().map(|s| s.to_string()).collect(),
            created_at: now_epoch(),
            created_by: "did:key:zSetup".into(),
            expires_at: None,
        }
    }

    fn super_admin_claims() -> AuthClaims {
        AuthClaims {
            did: "did:key:zSuperAdmin".into(),
            role: Role::Admin,
            allowed_contexts: vec![],
            session_id: "test-session".into(),
            access_expires_at: 0,
            amr: Vec::new(),
            acr: String::new(),
        }
    }

    fn context_admin_claims(contexts: &[&str]) -> AuthClaims {
        AuthClaims {
            did: "did:key:zCtxAdmin".into(),
            role: Role::Admin,
            allowed_contexts: contexts.iter().map(|s| s.to_string()).collect(),
            session_id: "test-session".into(),
            access_expires_at: 0,
            amr: Vec::new(),
            acr: String::new(),
        }
    }

    // ── Role parsing ────────────────────────────────────────────────

    #[test]
    fn role_parse_accepts_canonical_lowercase() {
        assert_eq!(Role::parse("admin").unwrap(), Role::Admin);
        assert_eq!(Role::parse("initiator").unwrap(), Role::Initiator);
        assert_eq!(Role::parse("application").unwrap(), Role::Application);
        assert_eq!(Role::parse("reader").unwrap(), Role::Reader);
        assert_eq!(Role::parse("monitor").unwrap(), Role::Monitor);
    }

    #[test]
    fn role_parse_rejects_unknown() {
        let err = Role::parse("godmode").expect_err("unknown role must error");
        assert!(format!("{err:?}").contains("godmode"), "got {err:?}");
    }

    #[test]
    fn role_parse_rejects_case_variation() {
        // Serde rename_all="lowercase" means Admin != Admin on the wire.
        // parse() mirrors that contract.
        assert!(Role::parse("Admin").is_err(), "case-sensitive parse");
        assert!(Role::parse("ADMIN").is_err());
    }

    #[test]
    fn role_display_round_trips_with_parse() {
        for role in [
            Role::Admin,
            Role::Initiator,
            Role::Application,
            Role::Reader,
            Role::Monitor,
        ] {
            let s = format!("{role}");
            assert_eq!(Role::parse(&s).unwrap(), role, "display->parse cycle");
        }
    }

    // ── Expiration ──────────────────────────────────────────────────

    #[test]
    fn entry_without_expiry_never_expires() {
        let entry = sample_entry("did:key:zA", Role::Admin);
        assert!(entry.expires_at.is_none());
        assert!(
            !entry.is_expired(u64::MAX),
            "permanent entries never expire"
        );
    }

    #[test]
    fn entry_with_future_expiry_is_not_expired() {
        let mut entry = sample_entry("did:key:zA", Role::Admin);
        entry.expires_at = Some(now_epoch() + 3600);
        assert!(!entry.is_expired(now_epoch()));
    }

    #[test]
    fn entry_with_past_expiry_is_expired() {
        let mut entry = sample_entry("did:key:zA", Role::Admin);
        entry.expires_at = Some(now_epoch().saturating_sub(1));
        assert!(entry.is_expired(now_epoch()));
    }

    #[test]
    fn entry_with_exact_expiry_boundary_is_expired() {
        // Guard choice: `now >= deadline` is expired. The boundary at
        // equal seconds counts as past — callers don't get a free
        // extra second of access.
        let mut entry = sample_entry("did:key:zA", Role::Admin);
        let now = now_epoch();
        entry.expires_at = Some(now);
        assert!(entry.is_expired(now), "now == deadline counts as expired");
    }

    // ── Store CRUD ──────────────────────────────────────────────────

    #[tokio::test]
    async fn crud_round_trip() {
        let (store, _dir) = temp_store();
        let acl = store.keyspace("acl").unwrap();

        let entry = sample_entry("did:key:zAbc", Role::Admin);
        store_acl_entry(&acl, &entry).await.unwrap();

        let got = get_acl_entry(&acl, "did:key:zAbc")
            .await
            .unwrap()
            .expect("entry should exist");
        assert_eq!(got.did, entry.did);
        assert_eq!(got.role, Role::Admin);

        delete_acl_entry(&acl, "did:key:zAbc").await.unwrap();
        let gone = get_acl_entry(&acl, "did:key:zAbc").await.unwrap();
        assert!(gone.is_none(), "deleted entry must be gone");
    }

    #[tokio::test]
    async fn list_returns_every_entry() {
        let (store, _dir) = temp_store();
        let acl = store.keyspace("acl").unwrap();

        for did in ["did:key:zA", "did:key:zB", "did:key:zC"] {
            store_acl_entry(&acl, &sample_entry(did, Role::Reader))
                .await
                .unwrap();
        }

        let entries = list_acl_entries(&acl).await.unwrap();
        assert_eq!(entries.len(), 3);
        let dids: std::collections::HashSet<_> = entries.iter().map(|e| e.did.as_str()).collect();
        assert!(dids.contains("did:key:zA"));
        assert!(dids.contains("did:key:zB"));
        assert!(dids.contains("did:key:zC"));
    }

    // ── check_acl ───────────────────────────────────────────────────

    #[tokio::test]
    async fn check_acl_returns_role_for_present_did() {
        let (store, _dir) = temp_store();
        let acl = store.keyspace("acl").unwrap();
        store_acl_entry(&acl, &sample_entry("did:key:zA", Role::Initiator))
            .await
            .unwrap();

        let role = check_acl(&acl, "did:key:zA").await.unwrap();
        assert_eq!(role, Role::Initiator);
    }

    #[tokio::test]
    async fn check_acl_rejects_missing_did_as_forbidden() {
        let (store, _dir) = temp_store();
        let acl = store.keyspace("acl").unwrap();

        let err = check_acl(&acl, "did:key:zUnknown")
            .await
            .expect_err("missing DID must be rejected");
        assert!(
            matches!(err, AppError::Forbidden(_)),
            "got {err:?}; expected Forbidden so the handler emits 403"
        );
    }

    #[tokio::test]
    async fn check_acl_rejects_expired_entry() {
        let (store, _dir) = temp_store();
        let acl = store.keyspace("acl").unwrap();

        let mut entry = sample_entry("did:key:zExpired", Role::Admin);
        entry.expires_at = Some(now_epoch().saturating_sub(10));
        store_acl_entry(&acl, &entry).await.unwrap();

        let err = check_acl(&acl, "did:key:zExpired")
            .await
            .expect_err("expired entry must be rejected");
        let msg = format!("{err:?}");
        assert!(
            matches!(err, AppError::Forbidden(_)) && msg.contains("expired"),
            "got {err:?}"
        );
    }

    #[tokio::test]
    async fn check_acl_full_returns_role_and_contexts() {
        let (store, _dir) = temp_store();
        let acl = store.keyspace("acl").unwrap();
        store_acl_entry(
            &acl,
            &scoped_entry("did:key:zCtx", Role::Admin, &["ctx1", "ctx2"]),
        )
        .await
        .unwrap();

        let (role, contexts) = check_acl_full(&acl, "did:key:zCtx").await.unwrap();
        assert_eq!(role, Role::Admin);
        assert_eq!(contexts, vec!["ctx1".to_string(), "ctx2".to_string()]);
    }

    // ── validate_role_assignment ────────────────────────────────────

    #[test]
    fn role_assignment_super_admin_can_assign_admin() {
        validate_role_assignment(&super_admin_claims(), &Role::Admin)
            .expect("super admin assigns admin");
    }

    #[test]
    fn role_assignment_context_admin_can_assign_admin_role_itself() {
        // A context admin (Role::Admin with non-empty allowed_contexts)
        // passes validate_role_assignment for the Admin role — the
        // role-level check only gates `caller.role != Role::Admin`.
        // The actual escape-prevention is in validate_acl_modification,
        // which confines the new entry to the caller's own contexts.
        validate_role_assignment(&context_admin_claims(&["ctx1"]), &Role::Admin)
            .expect("context admin CAN assign Admin role; scope is enforced separately");
    }

    #[test]
    fn role_assignment_non_admin_cannot_assign_admin() {
        // Initiator, Reader, Application, Monitor cannot mint admins
        // regardless of scope. Only callers with Role::Admin can
        // assign Role::Admin.
        let initiator = AuthClaims {
            did: "did:key:zIni".into(),
            role: Role::Initiator,
            allowed_contexts: vec!["ctx1".into()],
            session_id: "test-session".into(),
            access_expires_at: 0,
            amr: Vec::new(),
            acr: String::new(),
        };
        let err = validate_role_assignment(&initiator, &Role::Admin)
            .expect_err("non-admin must not assign admin");
        assert!(matches!(err, AppError::Forbidden(_)), "got {err:?}");
    }

    #[test]
    fn role_assignment_readers_cannot_assign_any_role() {
        let reader = AuthClaims {
            did: "did:key:zReader".into(),
            role: Role::Reader,
            allowed_contexts: vec!["ctx1".into()],
            session_id: "test-session".into(),
            access_expires_at: 0,
            amr: Vec::new(),
            acr: String::new(),
        };
        for target in [
            Role::Admin,
            Role::Initiator,
            Role::Application,
            Role::Reader,
            Role::Monitor,
        ] {
            let err = validate_role_assignment(&reader, &target)
                .expect_err(&format!("reader must not assign {target}"));
            assert!(matches!(err, AppError::Forbidden(_)), "got {err:?}");
        }
    }

    #[test]
    fn role_assignment_initiator_can_assign_non_admin_roles() {
        let initiator = AuthClaims {
            did: "did:key:zIni".into(),
            role: Role::Initiator,
            allowed_contexts: vec!["ctx1".into()],
            session_id: "test-session".into(),
            access_expires_at: 0,
            amr: Vec::new(),
            acr: String::new(),
        };
        validate_role_assignment(&initiator, &Role::Reader).expect("initiator can assign reader");
        validate_role_assignment(&initiator, &Role::Application)
            .expect("initiator can assign application");
    }

    // ── validate_acl_modification ───────────────────────────────────

    #[test]
    fn acl_modification_super_admin_can_create_unrestricted() {
        validate_acl_modification(&super_admin_claims(), &[]).expect("super admin unrestricted");
        validate_acl_modification(&super_admin_claims(), &["any-ctx".into()])
            .expect("super admin any-context");
    }

    #[test]
    fn acl_modification_context_admin_cannot_create_unrestricted() {
        // Empty allowed_contexts on a new entry = super admin. A scoped
        // admin trying to create one would escape their scope.
        let err = validate_acl_modification(&context_admin_claims(&["ctx1"]), &[])
            .expect_err("context admin must not create unrestricted");
        assert!(matches!(err, AppError::Forbidden(_)), "got {err:?}");
    }

    #[test]
    fn acl_modification_context_admin_confined_to_own_contexts() {
        let caller = context_admin_claims(&["ctx1", "ctx2"]);
        validate_acl_modification(&caller, &["ctx1".into()]).expect("own context ok");
        validate_acl_modification(&caller, &["ctx1".into(), "ctx2".into()])
            .expect("all-own contexts ok");

        let err = validate_acl_modification(&caller, &["ctx3".into()])
            .expect_err("foreign context must be rejected");
        assert!(matches!(err, AppError::Forbidden(_)), "got {err:?}");

        let err = validate_acl_modification(&caller, &["ctx1".into(), "ctx3".into()])
            .expect_err("mixed own+foreign must be rejected");
        assert!(matches!(err, AppError::Forbidden(_)), "got {err:?}");
    }

    // ── is_acl_entry_visible ────────────────────────────────────────

    #[test]
    fn visibility_super_admin_sees_everything() {
        let caller = super_admin_claims();
        assert!(is_acl_entry_visible(
            &caller,
            &sample_entry("did:key:zA", Role::Admin)
        ));
        assert!(is_acl_entry_visible(
            &caller,
            &scoped_entry("did:key:zB", Role::Admin, &["private"])
        ));
    }

    #[test]
    fn visibility_context_admin_sees_overlapping_entries_only() {
        let caller = context_admin_claims(&["ctx1", "ctx2"]);

        // Entry scoped to ctx1 — visible (overlaps)
        assert!(is_acl_entry_visible(
            &caller,
            &scoped_entry("did:key:zA", Role::Reader, &["ctx1"])
        ));

        // Entry scoped to ctx3 — not visible (no overlap)
        assert!(!is_acl_entry_visible(
            &caller,
            &scoped_entry("did:key:zB", Role::Reader, &["ctx3"])
        ));

        // Super-admin entry (empty contexts) — not visible to scoped admin
        // so they can't enumerate holders of the higher privilege.
        assert!(!is_acl_entry_visible(
            &caller,
            &sample_entry("did:key:zSuper", Role::Admin)
        ));

        // Entry with mixed contexts — visible if any overlap
        assert!(is_acl_entry_visible(
            &caller,
            &scoped_entry("did:key:zC", Role::Reader, &["ctx2", "ctx99"])
        ));
    }

    // ── Serialization compatibility ─────────────────────────────────

    #[test]
    fn acl_entry_without_expires_at_deserializes() {
        // Pre-Phase-2 entries were serialized without expires_at; they
        // must continue to load with expires_at=None (permanent). If
        // this test breaks, operators with older stores lose their
        // ACL data on upgrade.
        let legacy = r#"{
            "did": "did:key:zLegacy",
            "role": "admin",
            "label": "old admin",
            "allowed_contexts": [],
            "created_at": 1700000000,
            "created_by": "did:key:zSetup"
        }"#;
        let entry: AclEntry = serde_json::from_str(legacy).expect("legacy shape must deserialize");
        assert_eq!(entry.did, "did:key:zLegacy");
        assert!(entry.expires_at.is_none(), "default to permanent");
    }

    #[test]
    fn acl_entry_with_missing_allowed_contexts_defaults_to_empty() {
        // Pre-ACL-scoping entries also omitted allowed_contexts.
        let legacy = r#"{
            "did": "did:key:zLegacy",
            "role": "admin",
            "label": null,
            "created_at": 1700000000,
            "created_by": "did:key:zSetup"
        }"#;
        let entry: AclEntry = serde_json::from_str(legacy).expect("legacy shape must deserialize");
        assert!(entry.allowed_contexts.is_empty());
    }
}
