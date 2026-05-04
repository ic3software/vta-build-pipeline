//! DIDComm message types for post-setup protocol management
//! (`pnm services disable didcomm`, `pnm mediator …`).
//!
//! Spec: `docs/05-design-notes/didcomm-protocol-management.md`.
//!
//! Naming follows the `firstperson.network/protocols/<name>/1.0`
//! convention used elsewhere in this crate. Two protocols:
//!
//! - **services-management/1.0** — services on/off
//!   (only `disable` is exposed over DIDComm; `enable` is REST-only
//!   by nature, since DIDComm isn't running yet at first-enable
//!   time).
//! - **mediator-management/1.0** — migrate / rollback / drain-cancel
//!   / report.
//!
//! For each request type, a matching `*-result` type exists on the
//! response side. The body shapes mirror the REST request/response
//! types in [`crate::protocol`].

pub const SERVICES_PROTOCOL_BASE: &str =
    "https://firstperson.network/protocols/services-management/1.0";
pub const MEDIATOR_PROTOCOL_BASE: &str =
    "https://firstperson.network/protocols/mediator-management/1.0";

// ── services-management ─────────────────────────────────────────────

pub const DISABLE_DIDCOMM: &str =
    "https://firstperson.network/protocols/services-management/1.0/disable";
pub const DISABLE_DIDCOMM_RESULT: &str =
    "https://firstperson.network/protocols/services-management/1.0/disable-result";

// ── mediator-management ─────────────────────────────────────────────

pub const MIGRATE_MEDIATOR: &str =
    "https://firstperson.network/protocols/mediator-management/1.0/migrate";
pub const MIGRATE_MEDIATOR_RESULT: &str =
    "https://firstperson.network/protocols/mediator-management/1.0/migrate-result";

pub const DRAIN_CANCEL: &str =
    "https://firstperson.network/protocols/mediator-management/1.0/drain-cancel";
pub const DRAIN_CANCEL_RESULT: &str =
    "https://firstperson.network/protocols/mediator-management/1.0/drain-cancel-result";

pub const MEDIATOR_REPORT: &str =
    "https://firstperson.network/protocols/mediator-management/1.0/report";
pub const MEDIATOR_REPORT_RESULT: &str =
    "https://firstperson.network/protocols/mediator-management/1.0/report-result";
