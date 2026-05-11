//! Errors produced by the `update` submodule + their mapping to
//! [`AppError`].

use crate::error::AppError;

/// Errors produced by
/// [`crate::operations::did_webvh::update::update_did_webvh`] and
/// [`crate::operations::did_webvh::update::rotate_did_webvh_keys`].
///
/// `From<UpdateDidWebvhError> for AppError` maps each variant to a stable
/// HTTP status: `NotFound` and `Forbidden` both surface as 404 to avoid
/// leaking cross-context existence information; validation errors map to
/// 400; concurrency conflicts map to 409; everything else is 500.
#[derive(Debug, thiserror::Error)]
pub enum UpdateDidWebvhError {
    /// SCID not found, or the DID exists but is owned by a different
    /// context than the caller has admin rights for. Both cases collapse
    /// to a single error variant + 404 status to avoid leaking
    /// cross-context existence.
    #[error("did not found: {0}")]
    NotFound(String),

    /// Caller authenticated successfully but is not an admin of the
    /// DID's context. Mapped to 404 by the REST/DIDComm boundary —
    /// see [`From<UpdateDidWebvhError> for AppError`].
    #[error("forbidden: {0}")]
    Forbidden(String),

    /// Optimistic-concurrency mismatch: the DID's `log_entry_count`
    /// changed between load and write. Caller should re-read and retry.
    #[error("concurrent update: {0}")]
    Conflict(String),

    /// Caller-supplied DID document is malformed (missing `@context`,
    /// `id` doesn't match the existing DID, verificationMethod entries
    /// missing required fields, …).
    #[error("invalid document: {0}")]
    InvalidDocument(String),

    /// Caller-supplied witness configuration is invalid (witness DID
    /// did not resolve, malformed witness entry, …).
    #[error("invalid witness configuration: {0}")]
    InvalidWitness(String),

    /// Caller-supplied watcher URL is invalid (parse error, wrong
    /// scheme, query/fragment present, …).
    #[error("invalid watcher: {0}")]
    InvalidWatcher(String),

    /// Underlying `didwebvh-rs` library error during `update_did`.
    /// Usually indicates a state-machine violation (e.g. signing key
    /// not in the active update_keys set) that the orchestration
    /// should have caught earlier — surface as 500.
    #[error("webvh library error: {0}")]
    Library(String),

    /// Persistence failure (keys keyspace, webvh keyspace, contexts
    /// keyspace).
    #[error("persistence error: {0}")]
    Persistence(String),

    /// Failed to publish the new log entry to the webvh hosting server.
    /// The local log was written successfully; the operator can retry
    /// publication independently.
    #[error("publish error: {0}")]
    Publish(String),
}

impl From<UpdateDidWebvhError> for AppError {
    fn from(err: UpdateDidWebvhError) -> Self {
        match err {
            // Both NotFound and Forbidden map to NotFound at the wire
            // boundary so an admin of context A can't probe whether a
            // DID exists in context B.
            UpdateDidWebvhError::NotFound(msg) | UpdateDidWebvhError::Forbidden(msg) => {
                AppError::NotFound(msg)
            }
            UpdateDidWebvhError::Conflict(msg) => AppError::Conflict(msg),
            UpdateDidWebvhError::InvalidDocument(msg)
            | UpdateDidWebvhError::InvalidWitness(msg)
            | UpdateDidWebvhError::InvalidWatcher(msg) => AppError::Validation(msg),
            UpdateDidWebvhError::Library(msg)
            | UpdateDidWebvhError::Publish(msg)
            | UpdateDidWebvhError::Persistence(msg) => AppError::Internal(msg),
        }
    }
}
