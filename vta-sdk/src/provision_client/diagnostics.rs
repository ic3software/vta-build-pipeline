//! Live checklist of diagnostic steps run against the VTA during the
//! provisioning attempt. Each entry's status is updated as events arrive
//! from the runner; consumers render the whole list with per-step icons
//! and detail text in their UI of choice.

use super::intent::VtaReply;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiagCheck {
    ResolveDid,
    EnumerateServices,
    /// DIDComm-leg of the auth check. The runner emits `Running` /
    /// `Ok` / `Failed` on this row when the configured transport is
    /// DIDComm. When DIDComm isn't advertised by the VTA, this row
    /// stays `Skipped`.
    AuthenticateDIDComm,
    /// REST-leg of the auth check. Emitted when the runner falls back to
    /// REST after a DIDComm failure, when the VTA advertises only REST,
    /// or as a `Skipped` placeholder when the DIDComm path completed
    /// without needing a fallback.
    AuthenticateREST,
    /// FullSetup-only: fetches the VTA's registered webvh-daemon
    /// catalogue so the runner can either auto-pick (0/1 entries) or
    /// surface a choice (2+). Skipped on AdminOnly.
    ListWebvhServers,
    ProvisionIntegration,
}

impl DiagCheck {
    pub fn label(&self) -> &'static str {
        match self {
            Self::ResolveDid => "Resolve VTA DID",
            Self::EnumerateServices => "Enumerate service endpoints",
            Self::AuthenticateDIDComm => "Authenticate via DIDComm",
            Self::AuthenticateREST => "Authenticate via REST",
            Self::ListWebvhServers => "List webvh hosting servers",
            Self::ProvisionIntegration => "Provision integration DID + admin credential",
        }
    }

    /// Ordered list of every check the runner performs, in execution order.
    pub fn all() -> &'static [DiagCheck] {
        &[
            Self::ResolveDid,
            Self::EnumerateServices,
            Self::AuthenticateDIDComm,
            Self::AuthenticateREST,
            Self::ListWebvhServers,
            Self::ProvisionIntegration,
        ]
    }
}

#[derive(Clone, Debug)]
pub enum DiagStatus {
    Pending,
    Running,
    Ok(String),
    Skipped(String),
    Failed(String),
}

#[derive(Clone, Debug)]
pub struct DiagEntry {
    pub check: DiagCheck,
    pub status: DiagStatus,
}

/// Which authentication path the runner actually completed with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protocol {
    DidComm,
    Rest,
}

impl Protocol {
    pub fn label(&self) -> &'static str {
        match self {
            Self::DidComm => "DIDComm",
            Self::Rest => "REST",
        }
    }
}

/// Info about a successful VTA round-trip. Surfaced to the consumer so
/// downstream steps can read the result without re-contacting the VTA.
#[derive(Clone, Debug)]
pub struct ConnectedInfo {
    /// Which transport actually carried the round-trip.
    pub protocol: Protocol,
    /// REST URL advertised by the VTA DID document, for runtime-side
    /// fallback. The provisioning workflow itself does not use it.
    pub rest_url: Option<String>,
    /// DIDComm mediator DID advertised by the VTA. Always `Some` when
    /// `protocol == DidComm`.
    pub mediator_did: Option<String>,
    /// Unified reply — see [`VtaReply`] for the variants.
    pub reply: VtaReply,
}

/// Seed a fresh diagnostics list with every check in `Pending`.
pub fn pending_list() -> Vec<DiagEntry> {
    DiagCheck::all()
        .iter()
        .map(|c| DiagEntry {
            check: *c,
            status: DiagStatus::Pending,
        })
        .collect()
}

/// Apply a single (check, status) update to an existing diagnostics list.
/// If the check is not present, the update is silently ignored (the runner
/// and the list come from the same source so this should not happen in
/// practice — we avoid the panic for robustness).
pub fn apply_update(list: &mut [DiagEntry], check: DiagCheck, status: DiagStatus) {
    for entry in list.iter_mut() {
        if entry.check == check {
            entry.status = status;
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_list_has_all_checks() {
        let list = pending_list();
        assert_eq!(list.len(), DiagCheck::all().len());
        assert!(list.iter().all(|e| matches!(e.status, DiagStatus::Pending)));
    }

    #[test]
    fn apply_update_sets_status_on_matching_check() {
        let mut list = pending_list();
        apply_update(
            &mut list,
            DiagCheck::ResolveDid,
            DiagStatus::Ok("did:webvh:...".into()),
        );
        let resolved = &list[0];
        assert_eq!(resolved.check, DiagCheck::ResolveDid);
        assert!(matches!(resolved.status, DiagStatus::Ok(_)));
    }

    #[test]
    fn all_lists_split_authenticate_rows_in_order() {
        let all = DiagCheck::all();
        assert_eq!(
            all,
            &[
                DiagCheck::ResolveDid,
                DiagCheck::EnumerateServices,
                DiagCheck::AuthenticateDIDComm,
                DiagCheck::AuthenticateREST,
                DiagCheck::ListWebvhServers,
                DiagCheck::ProvisionIntegration,
            ]
        );
    }

    #[test]
    fn authenticate_rows_have_distinct_labels() {
        assert_eq!(
            DiagCheck::AuthenticateDIDComm.label(),
            "Authenticate via DIDComm"
        );
        assert_eq!(DiagCheck::AuthenticateREST.label(), "Authenticate via REST");
    }

    #[test]
    fn provision_label_is_template_agnostic() {
        // Spec invariant: no integration-specific noun in this enum's
        // labels — the per-integration label comes from OperatorMessages.
        let label = DiagCheck::ProvisionIntegration.label();
        assert!(!label.to_lowercase().contains("mediator"));
        assert!(!label.to_lowercase().contains("webvh"));
        assert!(label.contains("integration"));
    }
}
