//! Member domain model — spec §5.2.
//!
//! ## Why a separate keyspace from `acl:`
//!
//! Plan §D3: `acl:<did>` (auth-gate) and `members:<did>`
//! (community-membership metadata) are 1:1 by DID but logically
//! distinct. The auth path reads ACL rows on every request and
//! shouldn't pay the cost of loading the richer Member metadata.
//! Lifecycle is matched — creating a Member is always atomic with
//! writing the ACL row, and removal is similarly paired — so the
//! per-DID consistency invariant is upheld inside the same fjall
//! transaction.
//!
//! ## What's deferred to Phase 2+
//!
//! Spec §5.2's `status_list_index`, `current_vmc_id`, and
//! `current_role_vec_id` are credential pointers populated by
//! Phase 2's VTA-oracle issuance flow. They ship as `Option<T>`
//! slots from day one so Phase 2 can populate them without a
//! migration; Phase 1 always writes `None`.
//!
//! Spec §10.1's `Disposition` enum carries
//! `PolicyDefault` which (per plan §D6) resolves to `Tombstone`
//! in Phase 1 until `removal.rego` lands in Phase 2. The
//! `Disposition` enum is defined here so the value is on the wire
//! from day one; the resolver indirection lives at the removal
//! call site.

pub mod storage;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

pub use storage::{
    DEFAULT_DEPARTURE_PREFERENCE, MEMBER_EXTENSIONS_MAX_BYTES, delete_member, get_member,
    list_members, list_members_paginated, store_member,
};

/// One community member. 1:1 with a [`crate::acl::VtcAclEntry`]
/// row by DID.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Member {
    pub did: String,
    pub joined_at: DateTime<Utc>,
    /// Random-with-decoys status-list slot (spec §6.2). Populated by
    /// Phase 2's issuance flow; `None` until then.
    #[serde(default)]
    pub status_list_index: Option<u32>,
    /// Operator-controlled flag: when `true`, the community may
    /// publish the member's DID via the trust-registry sync path
    /// (spec §8.2). Default `false` until the member opts in.
    #[serde(default)]
    pub publish_consent: bool,
    /// Member-controlled preference for `DELETE /v1/members/me`
    /// disposition handling (spec §10.2).
    #[serde(default = "Disposition::default_preference")]
    pub departure_preference: Disposition,
    /// ID of the currently-active VMC for this member (spec §6.1).
    /// Populated by Phase 2's issuance flow.
    #[serde(default)]
    pub current_vmc_id: Option<String>,
    /// ID of the currently-active role VEC (spec §6.1).
    /// Populated by Phase 2's issuance flow.
    #[serde(default)]
    pub current_role_vec_id: Option<String>,
    /// Community-defined extensions slot (spec §3-M). Bounded by
    /// [`MEMBER_EXTENSIONS_MAX_BYTES`] = 16 KiB at the route
    /// layer.
    #[serde(default)]
    pub extensions: JsonValue,
}

impl Member {
    /// Construct a new member with the conventional defaults the
    /// join-approval flow writes (M1.10):
    ///
    /// - `joined_at` = now
    /// - `publish_consent` = false (opt-in)
    /// - `departure_preference` = `PolicyDefault` (resolves to
    ///   `Tombstone` until the policy engine ships in Phase 2)
    /// - credential pointers + extensions absent
    pub fn fresh(did: impl Into<String>) -> Self {
        Self {
            did: did.into(),
            joined_at: Utc::now(),
            status_list_index: None,
            publish_consent: false,
            departure_preference: Disposition::default_preference(),
            current_vmc_id: None,
            current_role_vec_id: None,
            extensions: JsonValue::Null,
        }
    }
}

/// Spec §5.5 disposition for a removal. Determines what happens to
/// the Member record + status-list slot on member departure.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Disposition {
    /// Hard delete — Member row removed entirely. RTBF default.
    Purge,
    /// Member row anonymised (DID retained, profile fields
    /// blanked). Default for `PolicyDefault` in Phase 1 (plan §D6).
    Tombstone,
    /// Member row retained verbatim, marked departed. For
    /// audit-significant communities.
    Historical,
    /// Defer to `removal.rego`'s `min_disposition`. In Phase 1
    /// resolves to `Tombstone`; Phase 2 swaps the resolver.
    PolicyDefault,
}

impl Disposition {
    fn default_preference() -> Self {
        Disposition::PolicyDefault
    }

    /// Resolve `PolicyDefault` to a concrete disposition. In
    /// Phase 1 this always returns [`Disposition::Tombstone`];
    /// Phase 2 reads the active `removal.rego` policy.
    pub fn resolve(self) -> Disposition {
        match self {
            Disposition::PolicyDefault => Disposition::Tombstone,
            other => other,
        }
    }
}
