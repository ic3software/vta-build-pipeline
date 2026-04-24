//! Structured error type for VTA SDK operations.

/// Errors returned by VTA SDK client operations.
#[derive(Debug, thiserror::Error)]
pub enum VtaError {
    /// Network-level error (connection refused, timeout, DNS failure).
    #[cfg(feature = "client")]
    #[error("network error: {0}")]
    Network(#[from] reqwest::Error),

    /// Authentication failed (401) or token expired.
    #[error("authentication failed: {0}")]
    Auth(String),

    /// Resource not found (404).
    #[error("not found: {0}")]
    NotFound(String),

    /// Request validation error (400).
    #[error("validation error: {0}")]
    Validation(String),

    /// Permission denied (403).
    #[error("forbidden: {0}")]
    Forbidden(String),

    /// Conflict (409) — e.g. duplicate key ID.
    #[error("conflict: {0}")]
    Conflict(String),

    /// Server error (5xx).
    #[error("server error ({status}): {body}")]
    Server { status: u16, body: String },

    /// The operation does not support the transport the client is
    /// configured for (e.g. calling a REST-only helper on a client built
    /// with DIDComm-only transport, or vice versa).
    #[error("unsupported transport: {0}")]
    UnsupportedTransport(String),

    /// DIDComm transport failure (pack/send/pickup). Network-ish —
    /// caller may want to retry. Distinct from [`Self::Network`] which
    /// is REST-specific and carries a `reqwest::Error`.
    #[error("didcomm transport error: {0}")]
    DidcommTransport(String),

    /// Remote endpoint returned an error message over DIDComm. The VTA
    /// (or the peer) encoded a specific status; prefer matching on
    /// this variant before falling back to [`Self::Protocol`].
    #[error("didcomm remote error ({code}): {comment}")]
    DidcommRemote { code: String, comment: String },

    /// Catch-all for protocol-level errors that don't map to a typed
    /// variant above. Prefer a typed variant when adding new call
    /// sites — this exists so legacy dispatch paths still compile.
    #[error("protocol error: {0}")]
    Protocol(String),

    /// Serialization/deserialization error.
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// Catch-all for other errors.
    #[error("{0}")]
    Other(String),
}

impl VtaError {
    /// Create from an HTTP response status and error body.
    #[cfg(feature = "client")]
    pub(crate) fn from_http(status: reqwest::StatusCode, body: String) -> Self {
        match status.as_u16() {
            401 => Self::Auth(body),
            403 => Self::Forbidden(body),
            404 => Self::NotFound(body),
            400 | 422 => Self::Validation(body),
            409 => Self::Conflict(body),
            s if s >= 500 => Self::Server { status: s, body },
            s => Self::Other(format!("{s}: {body}")),
        }
    }

    /// Returns true if this is an authentication/authorization error.
    pub fn is_auth(&self) -> bool {
        matches!(self, Self::Auth(_) | Self::Forbidden(_))
    }

    /// Returns true if this is a network-level error (retryable).
    pub fn is_network(&self) -> bool {
        #[cfg(feature = "client")]
        if matches!(self, Self::Network(_)) {
            return true;
        }
        false
    }

    /// Returns true if the resource was not found.
    pub fn is_not_found(&self) -> bool {
        matches!(self, Self::NotFound(_))
    }
}

impl From<String> for VtaError {
    fn from(s: String) -> Self {
        Self::Other(s)
    }
}

impl From<&str> for VtaError {
    fn from(s: &str) -> Self {
        Self::Other(s.to_string())
    }
}

// Backward-compat conversion from `Box<dyn Error>` (legacy CLI handler
// return type) into a typed `VtaError`.
//
// **Deprecated for new code.** This conversion collapses the error into
// `Other(String)`, dropping the `source()` chain — fine for call sites that
// only surface `Display`, but it breaks programmatic error handling:
// a caller who sees `VtaError::Other(String)` cannot distinguish a
// `Conflict` from a `NotFound` from an `Auth` problem, and so cannot
// emit the CLI-level operator guidance the workspace's CLAUDE.md
// "operator errors should suggest the fix" principle demands.
//
// For new integrations, return a `VtaError` directly or add a typed
// variant with `#[from]` on the underlying cause so the source chain is
// preserved. A `#[deprecated]` marker is not applied to this impl
// because rust-analyzer fires it on every legacy `?` through a
// `Box<dyn Error>` — too noisy during the incremental migration. The
// contract is documented here and in the workspace review tracking.
impl From<Box<dyn std::error::Error>> for VtaError {
    fn from(e: Box<dyn std::error::Error>) -> Self {
        Self::Other(e.to_string())
    }
}

impl From<crate::did_key::DidKeyError> for VtaError {
    fn from(e: crate::did_key::DidKeyError) -> Self {
        Self::Other(e.to_string())
    }
}
