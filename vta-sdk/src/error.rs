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

    /// Gone (410) — the resource existed but is now permanently unavailable.
    /// Most often emitted by the bootstrap carve-out endpoint after it has
    /// been consumed; the CLI surfaces this with a "did you mean to run
    /// `… provision-request`" hint instead of a flat string.
    #[error("gone: {0}")]
    Gone(String),

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

    /// Remote endpoint returned a DIDComm problem-report whose `code`
    /// did not match any of the standard `e.p.msg.*` taxonomy variants
    /// (which map to the typed REST-aligned variants above). Inspect
    /// `code` to handle it; a typed [`Self::Conflict`] / [`Self::NotFound`]
    /// / [`Self::Auth`] / [`Self::Validation`] / [`Self::Server`] will
    /// already have been emitted for the standard codes.
    #[error("didcomm remote error ({code}): {comment}")]
    DidcommRemote { code: String, comment: String },

    /// Programmer-level protocol error (response shape did not match
    /// what the SDK expected — version mismatch or bug). Distinct from
    /// remote-error: a peer that returned a problem-report becomes a
    /// typed variant via [`Self::from_problem_report`], not this one.
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
    ///
    /// Public so a downstream SDK consumer wiring its own HTTP transport
    /// (e.g. a wasm `gloo-net` client) can produce typed `VtaError`s
    /// from status codes without re-implementing the mapping.
    #[cfg(feature = "client")]
    pub fn from_http(status: reqwest::StatusCode, body: String) -> Self {
        match status.as_u16() {
            401 => Self::Auth(body),
            403 => Self::Forbidden(body),
            404 => Self::NotFound(body),
            400 | 422 => Self::Validation(body),
            409 => Self::Conflict(body),
            410 => Self::Gone(body),
            s if s >= 500 => Self::Server { status: s, body },
            s => Self::Other(format!("{s}: {body}")),
        }
    }

    /// Create from a DIDComm problem-report `code` + `comment`. Mirrors
    /// the REST [`Self::from_http`] mapping so callers can `match` on the
    /// same variants regardless of transport.
    ///
    /// Standard codes (`e.p.msg.unauthorized` / `bad-request` / `not-found`
    /// / `conflict` / `internal-error`) become typed variants. Anything
    /// else lands in [`Self::DidcommRemote`] preserving the original code.
    pub fn from_problem_report(code: &str, comment: impl Into<String>) -> Self {
        use crate::protocols::problem_report_codes as c;
        let comment = comment.into();
        match code {
            c::CONFLICT => Self::Conflict(comment),
            c::NOT_FOUND => Self::NotFound(comment),
            c::UNAUTHORIZED => Self::Auth(comment),
            c::BAD_REQUEST => Self::Validation(comment),
            c::INTERNAL => Self::Server {
                status: 500,
                body: comment,
            },
            other => Self::DidcommRemote {
                code: other.to_string(),
                comment,
            },
        }
    }

    /// Returns true if the resource was permanently consumed/gone (410).
    pub fn is_gone(&self) -> bool {
        matches!(self, Self::Gone(_))
    }

    /// Returns true if a create/insert collided with an existing entry (409).
    pub fn is_conflict(&self) -> bool {
        matches!(self, Self::Conflict(_))
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

impl From<crate::did_key::DidKeyError> for VtaError {
    fn from(e: crate::did_key::DidKeyError) -> Self {
        Self::Validation(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "client")]
    #[test]
    fn from_http_410_maps_to_gone() {
        let err = VtaError::from_http(reqwest::StatusCode::GONE, "carve-out closed".into());
        assert!(err.is_gone(), "410 must map to VtaError::Gone, got {err:?}");
    }

    #[test]
    fn problem_report_conflict_maps_to_typed_conflict() {
        let err = VtaError::from_problem_report(
            crate::protocols::problem_report_codes::CONFLICT,
            "key id already exists",
        );
        assert!(matches!(err, VtaError::Conflict(_)), "got {err:?}");
        assert!(err.is_conflict());
    }

    #[test]
    fn problem_report_unknown_code_lands_in_didcomm_remote() {
        let err = VtaError::from_problem_report("e.custom.xyz", "weird thing");
        match err {
            VtaError::DidcommRemote { code, comment } => {
                assert_eq!(code, "e.custom.xyz");
                assert_eq!(comment, "weird thing");
            }
            other => panic!("expected DidcommRemote, got {other:?}"),
        }
    }
}
