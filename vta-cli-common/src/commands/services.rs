//! `pnm services …` command implementations.
//!
//! Spec: `docs/05-design-notes/didcomm-protocol-management.md`.
//!
//! Phase 3 lands `enable didcomm`. Phase 4 fills in `disable
//! didcomm` and `list`.

use vta_sdk::client::VtaClient;
use vta_sdk::protocol::EnableDidcommRequest;

/// `pnm services enable didcomm --mediator-did <did> [--force]
///                              [--handshake-timeout <secs>]`.
pub async fn cmd_services_enable_didcomm(
    client: &VtaClient,
    mediator_did: String,
    force: bool,
    handshake_timeout_secs: Option<u64>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut req = EnableDidcommRequest::new(&mediator_did);
    req.force = force;
    req.handshake_timeout_secs = handshake_timeout_secs;

    let resp = client.enable_didcomm(req).await.map_err(|e| {
        // Surface the operator-friendly message that the route
        // attaches as `suggested_fix` (carried through `VtaError`).
        // The SDK's `VtaError::Protocol` already carries the
        // server-rendered message — print it directly.
        format!("{e}")
    })?;

    println!("DIDComm enabled.");
    println!("  Mediator DID:   {}", resp.mediator_did);
    if !resp.mediator_endpoint.is_empty() {
        println!("  Mediator URL:   {}", resp.mediator_endpoint);
    }
    println!("  New version ID: {}", resp.new_version_id);
    if force {
        println!();
        println!("  Note: --force was set; mediator handshake steps 2-5 were bypassed.");
        println!("  The connection will be validated when the DIDComm runtime starts.");
    } else {
        println!();
        println!("  Note: First-enable runs only handshake step 1 (DID resolution).");
        println!("  The connection is validated when the DIDComm runtime starts after");
        println!("  the next service restart. To validate end-to-end pre-publish, run");
        println!("  `pnm mediator migrate --to <same>` once DIDComm is up.");
    }
    Ok(())
}
