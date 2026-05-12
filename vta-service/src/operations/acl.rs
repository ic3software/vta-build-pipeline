use tracing::info;

use crate::audit::{self, audit};
use vta_sdk::protocols::acl_management::{
    create::CreateAclResultBody, delete::DeleteAclResultBody, list::ListAclResultBody,
};

use crate::acl::{
    AclEntry, Role, delete_acl_entry, get_acl_entry, is_acl_entry_visible, list_acl_entries,
    store_acl_entry, validate_acl_modification, validate_role_assignment,
};
use crate::auth::AuthClaims;
use crate::auth::session::now_epoch;
use crate::error::AppError;
use crate::store::KeyspaceHandle;

pub struct UpdateAclParams {
    pub role: Option<Role>,
    pub label: Option<String>,
    pub allowed_contexts: Option<Vec<String>>,
}

/// Compute the symmetric difference of two context lists — every
/// element that appears in one but not the other. Used by `update_acl`
/// to enforce that a context-admin can only add or remove contexts
/// they themselves admin: removing a context the caller has no scope
/// over would otherwise silently evict the target from a context the
/// caller can't see.
///
/// Order doesn't matter; duplicates within a list are ignored. The
/// resulting Vec is deduped but unordered (a HashSet would do, but
/// the caller wants to iterate + format errors, so Vec is friendlier).
fn symmetric_difference_contexts(old: &[String], new: &[String]) -> Vec<String> {
    use std::collections::HashSet;
    let old_set: HashSet<&str> = old.iter().map(String::as_str).collect();
    let new_set: HashSet<&str> = new.iter().map(String::as_str).collect();
    old_set
        .symmetric_difference(&new_set)
        .map(|s| (*s).to_string())
        .collect()
}

fn to_result_body(e: &AclEntry) -> CreateAclResultBody {
    CreateAclResultBody {
        did: e.did.clone(),
        role: e.role.to_string(),
        label: e.label.clone(),
        allowed_contexts: e.allowed_contexts.clone(),
        created_at: e.created_at,
        created_by: e.created_by.clone(),
        expires_at: e.expires_at,
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn create_acl(
    acl_ks: &KeyspaceHandle,
    audit_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    did: &str,
    role: Role,
    label: Option<String>,
    allowed_contexts: Vec<String>,
    expires_at: Option<u64>,
    channel: &str,
) -> Result<CreateAclResultBody, AppError> {
    auth.require_manage()?;
    validate_role_assignment(auth, &role)?;
    validate_acl_modification(auth, &allowed_contexts)?;

    if get_acl_entry(acl_ks, did).await?.is_some() {
        return Err(AppError::Conflict(format!(
            "ACL entry already exists for DID: {did}"
        )));
    }

    let entry = AclEntry {
        did: did.to_string(),
        role,
        label,
        allowed_contexts,
        created_at: now_epoch(),
        created_by: auth.did.clone(),
        expires_at,
    };

    store_acl_entry(acl_ks, &entry).await?;

    info!(channel, caller = %auth.did, did = %entry.did, role = %entry.role, "ACL entry created");
    audit!(
        "acl.create",
        actor = &auth.did,
        resource = did,
        outcome = "success"
    );
    let _ = audit::record(
        audit_ks,
        "acl.create",
        &auth.did,
        Some(did),
        "success",
        Some(channel),
        None,
    )
    .await;
    Ok(to_result_body(&entry))
}

pub async fn get_acl(
    acl_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    did: &str,
    channel: &str,
) -> Result<CreateAclResultBody, AppError> {
    auth.require_manage()?;

    let entry = get_acl_entry(acl_ks, did)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("ACL entry not found for DID: {did}")))?;
    if !is_acl_entry_visible(auth, &entry) {
        return Err(AppError::NotFound(format!(
            "ACL entry not found for DID: {did}"
        )));
    }
    info!(channel, did = %did, "ACL entry retrieved");
    Ok(to_result_body(&entry))
}

pub async fn list_acl(
    acl_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    context_filter: Option<&str>,
    channel: &str,
) -> Result<ListAclResultBody, AppError> {
    auth.require_manage()?;

    let all_entries = list_acl_entries(acl_ks).await?;
    let entries: Vec<CreateAclResultBody> = all_entries
        .iter()
        .filter(|e| is_acl_entry_visible(auth, e))
        .filter(|e| match context_filter {
            Some(ctx) => e.allowed_contexts.contains(&ctx.to_string()),
            None => true,
        })
        .map(to_result_body)
        .collect();
    info!(channel, caller = %auth.did, count = entries.len(), "ACL listed");
    Ok(ListAclResultBody { entries })
}

pub async fn update_acl(
    acl_ks: &KeyspaceHandle,
    audit_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    did: &str,
    params: UpdateAclParams,
    channel: &str,
) -> Result<CreateAclResultBody, AppError> {
    // Modifying an ACL entry can downgrade an existing admin's role or
    // shrink their `allowed_contexts`. That's a privilege-tamper surface
    // — narrow it to Admin callers (creation still accepts Initiator via
    // `require_manage` so operators can grant Reader/Application access).
    auth.require_admin()?;

    let mut entry = get_acl_entry(acl_ks, did)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("ACL entry not found for DID: {did}")))?;

    if !is_acl_entry_visible(auth, &entry) {
        return Err(AppError::NotFound(format!(
            "ACL entry not found for DID: {did}"
        )));
    }

    if let Some(ref role) = params.role {
        validate_role_assignment(auth, role)?;
        entry.role = role.clone();
    }
    if let Some(label) = params.label {
        entry.label = Some(label);
    }
    if let Some(allowed_contexts) = params.allowed_contexts {
        // Validate the *symmetric difference* of (old, new), not just
        // the new set. A ctx-A-admin updating an entry whose existing
        // `allowed_contexts` is `[ctx-A, ctx-B]` would otherwise be
        // allowed to PATCH it down to `[ctx-A]` — silently evicting
        // the target from ctx-B, which the caller has no admin over.
        // Validating only the new set treats removal as a free
        // operation; symmetric difference forces every context being
        // added *or* removed to be in caller scope. Super admins
        // short-circuit inside `validate_acl_modification`, so they
        // remain unaffected.
        let changes = symmetric_difference_contexts(&entry.allowed_contexts, &allowed_contexts);
        if !changes.is_empty() {
            // Validate the *changes* against caller scope. The
            // empty-target carve-out in `validate_acl_modification`
            // (which forbids non-super-admins from creating
            // unrestricted entries) doesn't apply here — we're
            // validating a delta, not a final shape — so call
            // `require_context` directly per changed context.
            if !auth.is_super_admin() {
                for ctx in &changes {
                    auth.require_context(ctx)?;
                }
            }
        }
        // Also keep the original full-shape check so the
        // empty-`allowed_contexts` super-admin-only invariant is
        // preserved on the *resulting* entry (a context admin can't
        // produce an unrestricted entry by edit any more than by
        // create).
        validate_acl_modification(auth, &allowed_contexts)?;
        entry.allowed_contexts = allowed_contexts;
    }

    store_acl_entry(acl_ks, &entry).await?;

    info!(channel, did = %did, "ACL entry updated");
    audit!(
        "acl.update",
        actor = &auth.did,
        resource = did,
        outcome = "success"
    );
    let _ = audit::record(
        audit_ks,
        "acl.update",
        &auth.did,
        Some(did),
        "success",
        Some(channel),
        None,
    )
    .await;
    Ok(to_result_body(&entry))
}

pub async fn delete_acl(
    acl_ks: &KeyspaceHandle,
    audit_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    did: &str,
    channel: &str,
) -> Result<DeleteAclResultBody, AppError> {
    auth.require_manage()?;

    if auth.did == did {
        return Err(AppError::Conflict(
            "cannot delete your own ACL entry".into(),
        ));
    }

    let entry = get_acl_entry(acl_ks, did)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("ACL entry not found for DID: {did}")))?;
    if !is_acl_entry_visible(auth, &entry) {
        return Err(AppError::NotFound(format!(
            "ACL entry not found for DID: {did}"
        )));
    }

    delete_acl_entry(acl_ks, did).await?;

    info!(channel, caller = %auth.did, did = %did, "ACL entry deleted");
    audit!(
        "acl.delete",
        actor = &auth.did,
        resource = did,
        outcome = "success"
    );
    let _ = audit::record(
        audit_ks,
        "acl.delete",
        &auth.did,
        Some(did),
        "success",
        Some(channel),
        None,
    )
    .await;
    Ok(DeleteAclResultBody {
        did: did.to_string(),
        deleted: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acl::{AclEntry, store_acl_entry};
    use crate::auth::session::now_epoch;
    use crate::store::Store;
    use vti_common::config::StoreConfig;

    async fn fresh_store() -> (Store, KeyspaceHandle, KeyspaceHandle, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().into(),
        })
        .unwrap();
        let acl_ks = store.keyspace("acl").unwrap();
        let audit_ks = store.keyspace("audit").unwrap();
        (store, acl_ks, audit_ks, dir)
    }

    fn ctx_admin(did: &str, contexts: &[&str]) -> AuthClaims {
        AuthClaims {
            did: did.into(),
            role: Role::Admin,
            allowed_contexts: contexts.iter().map(|s| s.to_string()).collect(),
        }
    }

    async fn seed_target(acl_ks: &KeyspaceHandle, did: &str, contexts: &[&str]) {
        store_acl_entry(
            acl_ks,
            &AclEntry {
                did: did.into(),
                role: Role::Admin,
                label: None,
                allowed_contexts: contexts.iter().map(|s| s.to_string()).collect(),
                created_at: now_epoch(),
                created_by: "seed".into(),
                expires_at: None,
            },
        )
        .await
        .unwrap();
    }

    #[test]
    fn symmetric_difference_handles_typical_cases() {
        let s = symmetric_difference_contexts(&["a".into(), "b".into()], &["a".into(), "c".into()]);
        let mut s = s;
        s.sort();
        assert_eq!(s, vec!["b".to_string(), "c".to_string()]);

        // Identity: empty diff.
        assert!(
            symmetric_difference_contexts(&["a".into(), "b".into()], &["b".into(), "a".into()])
                .is_empty()
        );

        // All adds, no removes.
        let s = symmetric_difference_contexts(&[], &["x".into()]);
        assert_eq!(s, vec!["x".to_string()]);

        // All removes, no adds.
        let s = symmetric_difference_contexts(&["x".into()], &[]);
        assert_eq!(s, vec!["x".to_string()]);
    }

    /// Regression test for the eviction-via-shrink bug.
    ///
    /// A context-A admin must NOT be able to PATCH a target whose
    /// existing scope is `[ctx-A, ctx-B]` down to `[ctx-A]` — that
    /// removes the target from ctx-B silently, even though the caller
    /// has no admin rights over ctx-B. Pre-fix `update_acl` accepted
    /// this because it only validated the *new* set against caller
    /// scope; the new symmetric-diff check rejects it.
    #[tokio::test]
    async fn update_acl_rejects_shrink_across_caller_scope() {
        let (_store, acl_ks, audit_ks, _dir) = fresh_store().await;
        let target = "did:key:zTarget";
        seed_target(&acl_ks, target, &["ctx-a", "ctx-b"]).await;

        let caller = ctx_admin("did:key:zCallerA", &["ctx-a"]);
        let err = update_acl(
            &acl_ks,
            &audit_ks,
            &caller,
            target,
            UpdateAclParams {
                role: None,
                label: None,
                allowed_contexts: Some(vec!["ctx-a".into()]),
            },
            "test",
        )
        .await
        .unwrap_err();
        assert!(matches!(err, AppError::Forbidden(_)), "got {err:?}");
    }

    /// A context-admin shrinking *within their own scope* must still
    /// succeed — e.g. ctx-A-admin removing ctx-A from a target that
    /// has both ctx-A and ctx-B is the natural "I'm done with this
    /// integration in my context" operation, and the admin of ctx-B
    /// retains their independent grant.
    #[tokio::test]
    async fn update_acl_allows_remove_within_caller_scope() {
        let (_store, acl_ks, audit_ks, _dir) = fresh_store().await;
        let target = "did:key:zTarget2";
        seed_target(&acl_ks, target, &["ctx-a", "ctx-b"]).await;

        // Caller admins both ctx-a and ctx-b → the symmetric diff
        // (just `ctx-b`) is in scope, so the shrink is allowed.
        let caller = ctx_admin("did:key:zCallerAB", &["ctx-a", "ctx-b"]);
        let body = update_acl(
            &acl_ks,
            &audit_ks,
            &caller,
            target,
            UpdateAclParams {
                role: None,
                label: None,
                allowed_contexts: Some(vec!["ctx-a".into()]),
            },
            "test",
        )
        .await
        .unwrap();
        assert_eq!(body.allowed_contexts, vec!["ctx-a".to_string()]);
    }

    /// Adding a new context the caller doesn't admin is also rejected
    /// (this case the pre-fix code already caught via the full-shape
    /// `validate_acl_modification` call — pin it so the symmetric-diff
    /// refactor doesn't accidentally regress it).
    #[tokio::test]
    async fn update_acl_rejects_add_outside_caller_scope() {
        let (_store, acl_ks, audit_ks, _dir) = fresh_store().await;
        let target = "did:key:zTarget3";
        seed_target(&acl_ks, target, &["ctx-a"]).await;

        let caller = ctx_admin("did:key:zCallerA", &["ctx-a"]);
        let err = update_acl(
            &acl_ks,
            &audit_ks,
            &caller,
            target,
            UpdateAclParams {
                role: None,
                label: None,
                allowed_contexts: Some(vec!["ctx-a".into(), "ctx-b".into()]),
            },
            "test",
        )
        .await
        .unwrap_err();
        assert!(matches!(err, AppError::Forbidden(_)), "got {err:?}");
    }
}
