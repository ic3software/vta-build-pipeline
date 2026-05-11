//! Audit log infrastructure — versioned envelope with HMAC-hashed
//! actor / target identifiers and an in-store key history that
//! survives right-to-be-forgotten rotations.
//!
//! See spec §11 of `docs/05-design-notes/vtc-mvp.md` for the design
//! rationale. This crate ships the workspace-wide foundation; the
//! Phase-0 audit-event vocabulary (`CommunityInstalled`,
//! `AdminPasskeyRegistered`, `ConfigChanged`, …) lands in M0.1.5
//! and gets folded into [`event::AuditEvent`] there.
//!
//! ## Module layout
//!
//! - [`event`] — the tagged [`AuditEvent`] enum. A single `Generic`
//!   placeholder variant ships now; concrete variants are added per
//!   the spec's event vocabulary as the rest of Phase 0 lands.
//! - [`envelope`] — the [`AuditEnvelope`] wire shape (event id,
//!   version, timestamps, HMAC-hashed + plaintext identifier pairs).
//! - [`key_store`] — the [`AuditKeyStore`] managing per-community
//!   `audit_key` history: HKDF-derived initial, fresh-random
//!   rotations, indefinite retention so pre-rotation hashes stay
//!   verifiable during compliance investigations.
//! - [`writer`] — [`AuditWriter`] takes events + identifiers, hashes
//!   the identifiers with the active key, and persists the envelope
//!   into an `audit` keyspace.

pub mod envelope;
pub mod event;
pub mod key_store;
pub mod writer;

pub use envelope::{AuditEnvelope, EVENT_VERSION, SCHEMA_VERSION};
pub use event::AuditEvent;
pub use key_store::{AuditKey, AuditKeyStore, KeyId, RotationReason};
pub use writer::AuditWriter;
