pub mod backend;
pub mod extractor;
pub mod handlers;
pub mod jwt;
#[cfg(feature = "passkey")]
pub mod passkey;
pub mod session;

pub use backend::{
    AttestationOutcome, AuthAuditEvent, AuthBackend, AuthError, AuthenticateInput, ChallengeInput,
    RefreshInput, RoleResolution, SessionStore,
};
pub use extractor::{AdminAuth, AuthClaims, AuthState, ManageAuth, SuperAdminAuth, WriteAuth};
