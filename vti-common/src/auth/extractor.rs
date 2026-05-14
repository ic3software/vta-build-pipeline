use std::sync::Arc;

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum_extra::TypedHeader;
use axum_extra::headers::Authorization;
use axum_extra::headers::authorization::Bearer;
use tracing::warn;

use crate::acl::Role;
use crate::auth::jwt::JwtKeys;
use crate::auth::session::{SessionState, get_session};
use crate::error::AppError;
use crate::store::KeyspaceHandle;

/// Trait that each service's `AppState` implements to provide the data
/// needed by the auth extractors.
pub trait AuthState: Clone + Send + Sync + 'static {
    fn jwt_keys(&self) -> Option<&Arc<JwtKeys>>;
    fn sessions_ks(&self) -> &KeyspaceHandle;
}

/// Extracted from a valid JWT Bearer token on protected routes.
///
/// Add this as a handler parameter to require authentication:
/// ```ignore
/// async fn handler(_auth: AuthClaims, ...) { }
/// ```
#[derive(Debug, Clone)]
pub struct AuthClaims {
    pub did: String,
    pub role: Role,
    pub allowed_contexts: Vec<String>,
}

/// Name of the admin UX session cookie set by the VTC's
/// `POST /v1/auth/admin-login` flow (Phase 5 M5.2.3). When the
/// `Authorization: Bearer` header is absent, [`AuthClaims`]
/// falls back to reading a JWT out of this cookie. The cookie
/// is set with `Path=/admin; SameSite=Strict; Secure; HttpOnly`
/// so the public-website origin can't read it.
pub const ADMIN_SESSION_COOKIE: &str = "vtc_admin_session";

impl<S: AuthState> FromRequestParts<S> for AuthClaims {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        // Try `Authorization: Bearer <jwt>` first. Programmatic
        // clients (cnm-cli, DIDComm bridges, the existing
        // `/v1/auth/` flow) all use this path.
        let bearer_token = TypedHeader::<Authorization<Bearer>>::from_request_parts(parts, state)
            .await
            .ok()
            .map(|TypedHeader(auth)| auth.token().to_string());

        // Fall back to the admin session cookie (Phase 5 M5.2.3).
        // Set by `POST /v1/auth/admin-login`; carries the same JWT
        // as the bearer path.
        let token: String = match bearer_token {
            Some(t) => t,
            None => match cookie_token(parts, ADMIN_SESSION_COOKIE) {
                Some(t) => t,
                None => {
                    warn!(
                        "auth rejected: no Authorization header and no {ADMIN_SESSION_COOKIE} cookie"
                    );
                    return Err(AppError::Unauthorized(
                        "missing or invalid Authorization header".into(),
                    ));
                }
            },
        };
        let token = token.as_str();

        // Decode and validate JWT
        let jwt_keys = state
            .jwt_keys()
            .ok_or_else(|| AppError::Unauthorized("auth not configured".into()))?;

        let claims = jwt_keys.decode(token)?;

        // Verify session exists and is authenticated
        let session = get_session(state.sessions_ks(), &claims.session_id)
            .await?
            .ok_or_else(|| {
                warn!(session_id = %claims.session_id, "auth rejected: session not found");
                AppError::Unauthorized("session not found".into())
            })?;

        if session.state != SessionState::Authenticated {
            warn!(session_id = %claims.session_id, "auth rejected: session not in authenticated state");
            return Err(AppError::Unauthorized("session not authenticated".into()));
        }

        let role = Role::parse(&claims.role)?;

        Ok(AuthClaims {
            did: claims.sub,
            role,
            allowed_contexts: claims.contexts,
        })
    }
}

impl AuthClaims {
    /// **UNSAFE**: Synthesize a super-admin claim with no wire-level
    /// verification. Only for **on-host offline CLI** invocations — the
    /// trust boundary is the OS process, not the network.
    ///
    /// Feature-gated behind `cli-synthesis` so this function is physically
    /// absent from enclave and server-only builds. Any caller compiles
    /// iff the feature is on; calling this from a route handler is a bug
    /// that the type system can't catch (the resulting `AuthClaims` is
    /// indistinguishable from a legitimate one), so the name loudly marks
    /// the footgun.
    ///
    /// The trust model: a process that can execute the VTA binary AND
    /// read the keystore + seed store is already trusted by the OS to
    /// act as the VTA itself. Offline CLIs that mutate state (mint keys,
    /// seal bundles, export admin credentials) pre-date any over-the-
    /// wire authentication, so wire-level claims can't gate them. The
    /// caller-supplied `channel` is recorded in the audit log so misuse
    /// can be traced back to the specific CLI path.
    ///
    /// Downstream hardening (tracked as review item 9 follow-up):
    /// - Require an operator-side credential (env var / local config
    ///   pointing at a key in the ACL) before synthesizing.
    /// - Audit-log process identity (`uid`, `pid`, `cwd`) alongside
    ///   `channel` so a forensic investigator can distinguish
    ///   operator-intentional runs from lateral-movement abuse.
    ///
    /// The sentinel DID format `"cli:<channel>"` (not `did:*`) is
    /// deliberate — it doesn't round-trip through DID resolution and
    /// can't be confused with a real caller DID in log correlation.
    #[cfg(feature = "cli-synthesis")]
    pub fn unsafe_local_cli_super_admin(channel: &str) -> Self {
        Self {
            did: format!("cli:{channel}"),
            role: Role::Admin,
            allowed_contexts: Vec::new(),
        }
    }

    /// Returns `true` if the caller is an admin with unrestricted access
    /// (empty `allowed_contexts`).
    pub fn is_super_admin(&self) -> bool {
        self.role == Role::Admin && self.allowed_contexts.is_empty()
    }

    /// Returns `true` if the caller has access to the given context,
    /// either as a super admin or by explicit context assignment.
    pub fn has_context_access(&self, context_id: &str) -> bool {
        self.is_super_admin() || self.allowed_contexts.iter().any(|c| c == context_id)
    }

    /// Check that the caller has access to the given context.
    ///
    /// Admins with an empty `allowed_contexts` list have unrestricted access.
    pub fn require_context(&self, context_id: &str) -> Result<(), AppError> {
        if self.has_context_access(context_id) {
            return Ok(());
        }
        Err(AppError::Forbidden(format!(
            "no access to context: {context_id}"
        )))
    }

    /// If the caller has exactly one allowed context, return it.
    pub fn default_context(&self) -> Option<&str> {
        if self.allowed_contexts.len() == 1 {
            Some(&self.allowed_contexts[0])
        } else {
            None
        }
    }

    /// Require at least Reader role (all roles except Monitor).
    ///
    /// Use for read-only endpoints that access business data (keys, contexts, DIDs).
    /// Monitor can only see metrics and health.
    pub fn require_read(&self) -> Result<(), AppError> {
        if self.role == Role::Monitor {
            return Err(AppError::Forbidden("reader role or higher required".into()));
        }
        Ok(())
    }

    /// Require at least Application role (Admin, Initiator, or Application).
    ///
    /// Use for write operations: signing, cache writes, and other actions that
    /// produce artifacts or modify state.
    pub fn require_write(&self) -> Result<(), AppError> {
        if matches!(self.role, Role::Admin | Role::Initiator | Role::Application) {
            return Ok(());
        }
        Err(AppError::Forbidden(
            "application role or higher required".into(),
        ))
    }

    /// Require the caller to have Admin role.
    pub fn require_admin(&self) -> Result<(), AppError> {
        if self.role == Role::Admin {
            return Ok(());
        }
        Err(AppError::Forbidden("admin role required".into()))
    }

    /// Require the caller to have Admin or Initiator role.
    pub fn require_manage(&self) -> Result<(), AppError> {
        if self.role == Role::Admin || self.role == Role::Initiator {
            return Ok(());
        }
        Err(AppError::Forbidden(
            "admin or initiator role required".into(),
        ))
    }

    /// Require the caller to be a super admin (Admin + unrestricted).
    pub fn require_super_admin(&self) -> Result<(), AppError> {
        if self.is_super_admin() {
            return Ok(());
        }
        Err(AppError::Forbidden("super admin required".into()))
    }
}

/// Extractor that requires the caller to have Admin or Initiator role.
///
/// Use on endpoints that manage ACL entries and other management tasks:
/// ```ignore
/// async fn handler(auth: ManageAuth, ...) { }
/// ```
#[derive(Debug, Clone)]
pub struct ManageAuth(pub AuthClaims);

impl<S: AuthState> FromRequestParts<S> for ManageAuth {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let claims = AuthClaims::from_request_parts(parts, state).await?;

        match claims.role {
            Role::Admin | Role::Initiator => Ok(ManageAuth(claims)),
            _ => {
                warn!(did = %claims.did, role = %claims.role, "auth rejected: admin or initiator role required");
                Err(AppError::Forbidden(
                    "admin or initiator role required".into(),
                ))
            }
        }
    }
}

/// Extractor that requires the caller to have Admin role.
///
/// Use on endpoints that modify configuration, create/delete keys, etc.:
/// ```ignore
/// async fn handler(auth: AdminAuth, ...) { }
/// ```
#[derive(Debug, Clone)]
pub struct AdminAuth(pub AuthClaims);

impl<S: AuthState> FromRequestParts<S> for AdminAuth {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let claims = AuthClaims::from_request_parts(parts, state).await?;

        match claims.role {
            Role::Admin => Ok(AdminAuth(claims)),
            _ => {
                warn!(did = %claims.did, role = %claims.role, "auth rejected: admin role required");
                Err(AppError::Forbidden("admin role required".into()))
            }
        }
    }
}

/// Extractor that requires the caller to be a super admin (Admin role with
/// empty `allowed_contexts`).
///
/// Use on endpoints that only unrestricted administrators should access,
/// such as creating/deleting contexts or modifying global configuration:
/// ```ignore
/// async fn handler(auth: SuperAdminAuth, ...) { }
/// ```
#[derive(Debug, Clone)]
pub struct SuperAdminAuth(pub AuthClaims);

impl<S: AuthState> FromRequestParts<S> for SuperAdminAuth {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let claims = AuthClaims::from_request_parts(parts, state).await?;

        if !claims.is_super_admin() {
            warn!(did = %claims.did, "auth rejected: super admin required");
            return Err(AppError::Forbidden("super admin required".into()));
        }

        Ok(SuperAdminAuth(claims))
    }
}

/// Extractor that requires the caller to have at least Application role
/// (Admin, Initiator, or Application).
///
/// Use on endpoints that perform write operations — signing, cache writes,
/// and other actions that produce artifacts or modify state:
/// ```ignore
/// async fn handler(auth: WriteAuth, ...) { }
/// ```
#[derive(Debug, Clone)]
pub struct WriteAuth(pub AuthClaims);

impl<S: AuthState> FromRequestParts<S> for WriteAuth {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let claims = AuthClaims::from_request_parts(parts, state).await?;

        match claims.role {
            Role::Admin | Role::Initiator | Role::Application => Ok(WriteAuth(claims)),
            _ => {
                warn!(did = %claims.did, role = %claims.role, "auth rejected: application role or higher required");
                Err(AppError::Forbidden(
                    "application role or higher required".into(),
                ))
            }
        }
    }
}

/// Pull a named cookie value off the request `Cookie` headers.
/// Returns `None` when the cookie isn't present. Does **not**
/// percent-decode — cookie values minted by the VTC's admin-login
/// flow are JWTs (base64url + dots), which are ASCII-safe.
fn cookie_token(parts: &Parts, name: &str) -> Option<String> {
    parts
        .headers
        .get_all(axum::http::header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|s| s.split(';'))
        .map(|s| s.trim())
        .find_map(|kv| {
            let (k, v) = kv.split_once('=')?;
            (k == name).then(|| v.to_string())
        })
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "cli-synthesis")]
    use super::*;

    #[cfg(feature = "cli-synthesis")]
    #[test]
    fn local_cli_synthesizes_super_admin_with_channel_sentinel() {
        let claims = AuthClaims::unsafe_local_cli_super_admin("provision-integration");
        assert_eq!(claims.did, "cli:provision-integration");
        assert_eq!(claims.role, Role::Admin);
        assert!(claims.allowed_contexts.is_empty());
        assert!(claims.is_super_admin());
    }

    #[cfg(feature = "cli-synthesis")]
    #[test]
    fn local_cli_grants_any_context_access() {
        let claims = AuthClaims::unsafe_local_cli_super_admin("keys-bundle");
        // Super-admin has access to every context — enforced elsewhere
        // but assert it explicitly here so a future refactor that
        // breaks the invariant gets caught.
        assert!(claims.has_context_access("any-context"));
        assert!(claims.has_context_access("another"));
        claims
            .require_context("prod-mediator")
            .expect("super-admin passes require_context");
    }

    #[cfg(feature = "cli-synthesis")]
    #[test]
    fn local_cli_did_sentinel_cannot_be_confused_with_real_did() {
        // The `cli:<channel>` format must not round-trip as a
        // `did:*` URI — otherwise audit-log correlation would muddle
        // CLI-synthesized claims with real caller identities.
        let claims = AuthClaims::unsafe_local_cli_super_admin("context-reprovision");
        assert!(!claims.did.starts_with("did:"));
        assert!(claims.did.starts_with("cli:"));
    }

    #[cfg(feature = "cli-synthesis")]
    #[test]
    fn local_cli_channel_embedded_in_did() {
        // Audit-log grep'ability: each synthesis records its `channel`
        // distinctly so forensic investigation can attribute CLI
        // actions to the specific code path that ran them.
        let a = AuthClaims::unsafe_local_cli_super_admin("provision-integration");
        let b = AuthClaims::unsafe_local_cli_super_admin("keys-bundle");
        assert_ne!(a.did, b.did);
    }
}
