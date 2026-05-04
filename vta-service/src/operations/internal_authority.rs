//! Sealed marker type representing operations-layer internal authority.
//!
//! Some operations need to load the VTA's own signing material (e.g. the
//! provision-integration flow needs `{vta_did}#key-0` and
//! `{vta_did}#sealed-transfer-0` to issue VCs and sign producer
//! assertions). The user-facing caller has already been authorised
//! upstream as a context admin; loading the VTA's own keys is a
//! server-internal step, not an action attributable to the user.
//!
//! Historically this was expressed by synthesising a fake "super admin"
//! `AuthClaims` via `AuthClaims::server_internal_super_admin`. That had
//! two problems:
//!
//! 1. The synthesised claim was *byte-indistinguishable* from a genuine
//!    super-admin claim except for a `did: "internal:..."` prefix, which
//!    is a naming convention not a type-system guarantee.
//! 2. Any future call site — including a route handler introduced by an
//!    unrelated refactor — could call `server_internal_super_admin` and
//!    fully bypass the JWT/session/ACL pipeline. Auditors had to grep
//!    every `_super_admin` call to confirm intent.
//!
//! [`InternalAuthority`] replaces that pattern with a sealed marker
//! type. The constructor `InternalAuthority::new` is `pub(super)`, so
//! only sibling modules under `crate::operations::*` can construct one.
//! Route handlers (`crate::routes::*`) cannot. Operations that previously
//! took `&AuthClaims` and synthesised a super-admin claim now take an
//! `InternalAuthority` by value, making the elevation explicit at the
//! call site and unforgeable from outside the operations layer.

/// Marker type proving the caller is an operations-layer internal step.
///
/// Construct via `InternalAuthority::new`, which is `pub(super)` so
/// only `crate::operations::*` siblings can instantiate. Carries a
/// purpose tag for audit logging.
///
/// `Debug` is hand-implemented so the purpose surfaces in audit logs
/// without leaking any other field. `Clone` is intentionally **not**
/// derived — passing the authority by value once forces the call site
/// to be intentional about each elevation.
pub struct InternalAuthority {
    purpose: &'static str,
}

impl InternalAuthority {
    /// Construct an internal-authority token tagged with the operation
    /// that's elevating. `pub(super)` so only sibling modules under
    /// `crate::operations::*` can call this — route handlers cannot.
    ///
    /// `purpose` is used for audit logging (`actor = "internal:<purpose>"`)
    /// so an auditor can grep operation names from access logs.
    #[must_use]
    pub(super) fn new(purpose: &'static str) -> Self {
        Self { purpose }
    }

    /// The purpose tag passed at construction. Used by callers to render
    /// an audit-log actor field in the form `internal:<purpose>`.
    #[must_use]
    pub fn purpose(&self) -> &'static str {
        self.purpose
    }

    /// Render the audit-log actor string for this authority.
    /// Mirrors the `did: "internal:..."` shape of the legacy
    /// `server_internal_super_admin` so existing log queries still match.
    #[must_use]
    pub fn audit_actor(&self) -> String {
        format!("internal:{}", self.purpose)
    }
}

impl std::fmt::Debug for InternalAuthority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InternalAuthority")
            .field("purpose", &self.purpose)
            .finish()
    }
}
