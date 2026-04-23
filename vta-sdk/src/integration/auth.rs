//! Transport selection + authentication for the integration layer.
//!
//! Tier sequence, in priority order (actual order per invocation is driven
//! by [`TransportPreference`] + whether a `mediator_did` is configured —
//! see [`decide_transport`]):
//!
//! 1. **DIDComm** — identity-native: connecting is authenticating. No
//!    separate challenge-response round-trip, no bearer token to refresh.
//!    Requires a `mediator_did` in [`VtaServiceConfig`]. Preferred when
//!    the integration already speaks DIDComm for its primary workload
//!    (mediators, the typical case).
//! 2. **Lightweight REST** via [`VtaClient::from_credential`]. Works for
//!    VTAs reachable via HTTP(S); uses the `didcomm_light` message
//!    packer to produce the challenge-response envelope and stores the
//!    resulting bearer token with auto-refresh enabled.
//! 3. **Session-based REST** via [`crate::session::challenge_response`].
//!    Same wire flow as tier 2 but routed through the full TDK stack;
//!    kept as a defensive fallback for edge cases where the lightweight
//!    packer doesn't match what the VTA expects.
//!
//! Network errors at tier 2 are returned immediately (the VTA is
//! unreachable; retrying via tier 3 won't help). Non-network errors at
//! tier 2 fall through to tier 3.

use crate::client::VtaClient;
use crate::error::VtaError;

#[cfg(feature = "session")]
use super::TransportPreference;
use super::VtaServiceConfig;

/// Outcome of the transport-selection decision. Pure, deterministic,
/// unit-testable — lets the rest of [`authenticate`] stay focused on
/// side-effectful connect logic.
#[cfg(feature = "session")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TransportPlan {
    /// Try DIDComm first. On failure, fall back to REST tiers (2 → 3).
    DidCommThenRest { mediator_did: String },
    /// Try DIDComm. On failure, error out — do not fall back to REST.
    DidCommOnly { mediator_did: String },
    /// Skip DIDComm, go straight to the REST tiers.
    RestOnly,
    /// Preference required DIDComm but no mediator DID is configured —
    /// fail before any connection attempt with a clear operator message.
    DidCommUnavailable,
}

/// Decide which tier sequence to try, from preference + mediator
/// availability. Pure function; returned [`TransportPlan`] drives
/// [`authenticate`].
///
/// Matrix:
///
/// | preference     | mediator_did | plan                    |
/// |----------------|--------------|-------------------------|
/// | `Auto`         | `Some`       | DIDComm → REST fallback |
/// | `Auto`         | `None`       | REST only               |
/// | `PreferRest`   | any          | REST only               |
/// | `DidCommOnly`  | `Some`       | DIDComm, no fallback    |
/// | `DidCommOnly`  | `None`       | Error (unavailable)     |
#[cfg(feature = "session")]
pub(crate) fn decide_transport(
    preference: TransportPreference,
    mediator_did: Option<&str>,
) -> TransportPlan {
    match (preference, mediator_did) {
        (TransportPreference::PreferRest, _) => TransportPlan::RestOnly,
        (TransportPreference::DidCommOnly, None) => TransportPlan::DidCommUnavailable,
        (TransportPreference::DidCommOnly, Some(m)) => TransportPlan::DidCommOnly {
            mediator_did: m.to_string(),
        },
        (TransportPreference::Auto, None) => TransportPlan::RestOnly,
        (TransportPreference::Auto, Some(m)) => TransportPlan::DidCommThenRest {
            mediator_did: m.to_string(),
        },
    }
}

/// Authenticate to VTA, selecting a transport per the configured
/// [`TransportPreference`].
///
/// See the module-level doc for the tier policy.
pub async fn authenticate(config: &VtaServiceConfig) -> Result<VtaClient, VtaError> {
    let url_override = config.url_override.as_deref();

    #[cfg(feature = "session")]
    {
        let plan = decide_transport(config.transport_preference, config.mediator_did.as_deref());
        match plan {
            TransportPlan::DidCommThenRest { mediator_did } => {
                match try_didcomm(config, &mediator_did).await {
                    Ok(client) => return Ok(client),
                    Err(e) => {
                        tracing::warn!(
                            context = config.context,
                            mediator_did = %mediator_did,
                            error = %e,
                            "DIDComm connect failed; falling back to REST tiers",
                        );
                    }
                }
            }
            TransportPlan::DidCommOnly { mediator_did } => {
                return try_didcomm(config, &mediator_did).await.map_err(|e| {
                    tracing::error!(
                        context = config.context,
                        mediator_did = %mediator_did,
                        error = %e,
                        "DIDComm connect failed and transport_preference is DidCommOnly; \
                         not falling back to REST",
                    );
                    e
                });
            }
            TransportPlan::DidCommUnavailable => {
                return Err(VtaError::Validation(
                    "transport_preference is DidCommOnly but no mediator_did is configured — \
                     set VtaServiceConfig::mediator_did or relax to TransportPreference::Auto"
                        .into(),
                ));
            }
            TransportPlan::RestOnly => { /* fall through to REST below */ }
        }
    }

    try_rest(config, url_override).await
}

/// Tier 1: DIDComm via a mediator. Identity-native auth; no separate
/// bearer token.
#[cfg(feature = "session")]
async fn try_didcomm(config: &VtaServiceConfig, mediator_did: &str) -> Result<VtaClient, VtaError> {
    let credential = &config.credential;
    let client = VtaClient::connect_didcomm(
        &credential.did,
        &credential.private_key_multibase,
        &credential.vta_did,
        mediator_did,
        credential.vta_url.clone(),
    )
    .await?;
    tracing::info!(
        context = config.context,
        mediator_did = %mediator_did,
        vta_did = %credential.vta_did,
        "Connected to VTA (DIDComm)",
    );
    Ok(client)
}

/// Tiers 2 + 3: REST. Lightweight (auto-refresh) first, session-REST as
/// a defensive fallback for non-network errors at tier 2. Network errors
/// propagate immediately — retrying a different REST packer against an
/// unreachable VTA won't help.
async fn try_rest(
    config: &VtaServiceConfig,
    url_override: Option<&str>,
) -> Result<VtaClient, VtaError> {
    match VtaClient::from_credential(&config.credential, url_override).await {
        Ok(client) => {
            tracing::info!(
                context = config.context,
                vta_url = client.base_url(),
                "Connected to VTA (REST, auto-refresh enabled)",
            );
            Ok(client)
        }
        Err(e) if e.is_network() => Err(e),
        Err(e) => {
            tracing::debug!(
                context = config.context,
                error = %e,
                "Lightweight REST auth failed (non-network); trying session REST",
            );

            let credential = &config.credential;
            let vta_url = url_override
                .or(credential.vta_url.as_deref())
                .ok_or_else(|| {
                    VtaError::Validation("VTA URL not found in credential or url_override".into())
                })?;

            let token_result = crate::session::challenge_response(
                vta_url,
                &credential.did,
                &credential.private_key_multibase,
                &credential.vta_did,
            )
            .await?;

            let client = VtaClient::new(vta_url);
            client.set_token_async(token_result.access_token).await;

            tracing::info!(
                context = config.context,
                vta_url = vta_url,
                "Connected to VTA (REST, session auth)",
            );
            Ok(client)
        }
    }
}

#[cfg(all(test, feature = "session"))]
mod tests {
    use super::*;

    #[test]
    fn plan_auto_with_mediator_picks_didcomm_then_rest() {
        let plan = decide_transport(TransportPreference::Auto, Some("did:key:zMed"));
        assert_eq!(
            plan,
            TransportPlan::DidCommThenRest {
                mediator_did: "did:key:zMed".into()
            }
        );
    }

    #[test]
    fn plan_auto_without_mediator_picks_rest_only() {
        let plan = decide_transport(TransportPreference::Auto, None);
        assert_eq!(plan, TransportPlan::RestOnly);
    }

    #[test]
    fn plan_prefer_rest_ignores_mediator() {
        assert_eq!(
            decide_transport(TransportPreference::PreferRest, Some("did:key:zMed")),
            TransportPlan::RestOnly
        );
        assert_eq!(
            decide_transport(TransportPreference::PreferRest, None),
            TransportPlan::RestOnly
        );
    }

    #[test]
    fn plan_didcomm_only_with_mediator_does_not_fall_back() {
        let plan = decide_transport(TransportPreference::DidCommOnly, Some("did:key:zMed"));
        assert_eq!(
            plan,
            TransportPlan::DidCommOnly {
                mediator_did: "did:key:zMed".into()
            }
        );
    }

    #[test]
    fn plan_didcomm_only_without_mediator_errors() {
        let plan = decide_transport(TransportPreference::DidCommOnly, None);
        assert_eq!(plan, TransportPlan::DidCommUnavailable);
    }
}
