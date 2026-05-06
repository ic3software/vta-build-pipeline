//! `pnm mediator …` command implementations.
//!
//! Spec: `docs/05-design-notes/didcomm-protocol-management.md`.
//!
//! Phase 4 lands `migrate` and the `rollback` alias. `drain cancel`
//! and `report` arrive in P4.3 / P4.4.

use vta_sdk::client::VtaClient;
use vta_sdk::protocol::{DrainCancelRequest, UpdateDidcommRequest};

/// `pnm mediator migrate --to <did> --drain-ttl <secs> [--force]
///                       [--handshake-timeout <secs>]`.
pub async fn cmd_mediator_migrate(
    client: &VtaClient,
    new_mediator_did: String,
    drain_ttl_secs: u64,
    force: bool,
    handshake_timeout_secs: Option<u64>,
) -> Result<(), Box<dyn std::error::Error>> {
    run_migrate(
        client,
        new_mediator_did,
        drain_ttl_secs,
        force,
        handshake_timeout_secs,
        /* rollback = */ false,
    )
    .await
}

/// `pnm mediator rollback --to <did> --drain-ttl <secs>`.
///
/// Mechanically identical to `migrate` but tagged in telemetry as
/// a rollback so reports can distinguish forward and reverse moves.
/// Spec criterion #6 (rollback equivalence): the resulting DID doc
/// matches the pre-migrate state byte-for-byte in `service[]`,
/// modulo `versionId` and the rotated WebVH control keys.
pub async fn cmd_mediator_rollback(
    client: &VtaClient,
    target_mediator_did: String,
    drain_ttl_secs: u64,
    force: bool,
    handshake_timeout_secs: Option<u64>,
) -> Result<(), Box<dyn std::error::Error>> {
    run_migrate(
        client,
        target_mediator_did,
        drain_ttl_secs,
        force,
        handshake_timeout_secs,
        /* rollback = */ true,
    )
    .await
}

async fn run_migrate(
    client: &VtaClient,
    new_mediator_did: String,
    drain_ttl_secs: u64,
    force: bool,
    handshake_timeout_secs: Option<u64>,
    rollback: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut req = UpdateDidcommRequest::new(&new_mediator_did, drain_ttl_secs);
    req.force = force;
    req.handshake_timeout_secs = handshake_timeout_secs;
    req.rollback = rollback;

    let resp = client
        .update_didcomm(req)
        .await
        .map_err(|e| format!("{e}"))?;

    let verb = if rollback { "rolled back" } else { "migrated" };
    println!("Mediator {verb}.");
    println!("  Prior mediator:  {}", resp.prior_mediator_did);
    println!("  Active mediator: {}", resp.active_mediator_did);
    if !resp.active_mediator_endpoint.is_empty() {
        println!("  Active endpoint: {}", resp.active_mediator_endpoint);
    }
    println!("  New version ID:  {}", resp.new_version_id);
    println!(
        "  Drain deadline:  {} (prior listener stays up until then)",
        resp.drains_until
    );
    if force {
        println!();
        println!("  Note: --force was set; mediator handshake steps 2-5 were bypassed.");
    }
    Ok(())
}

/// `pnm mediator drain cancel --mediator-did <did>`.
pub async fn cmd_mediator_drain_cancel(
    client: &VtaClient,
    mediator_did: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let req = DrainCancelRequest { mediator_did };
    let resp = client.drain_cancel(req).await.map_err(|e| format!("{e}"))?;
    println!("Drain cancelled for {}.", resp.mediator_did);
    println!("  Listener was torn down immediately.");
    Ok(())
}

/// `pnm mediator report [--since <rfc3339>] [--until <rfc3339>]
///                      [--format json|table]`.
pub async fn cmd_mediator_report(
    client: &VtaClient,
    since: Option<String>,
    until: Option<String>,
    format: ReportFormat,
) -> Result<(), Box<dyn std::error::Error>> {
    let report = client
        .mediator_report(since.as_deref(), until.as_deref())
        .await
        .map_err(|e| format!("{e}"))?;

    match format {
        ReportFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        ReportFormat::Table => {
            println!("Mediator report");
            if let Some(ref s) = report.since {
                println!("  Window: {s} → {}", report.until);
            } else {
                println!("  Window: (all time) → {}", report.until);
            }
            println!();
            if report.mediators.is_empty() {
                println!("  No inbound DIDComm messages recorded.");
            } else {
                println!("  Per-mediator inbound counts (most recent first):");
                let header_did = "MEDIATOR DID";
                let header_count = "INBOUND";
                println!("    {header_did:<60}  {header_count:>10}  LAST SEEN");
                for m in &report.mediators {
                    println!(
                        "    {:<60}  {:>10}  {}",
                        truncate(&m.mediator_did, 60),
                        m.inbound_count,
                        m.last_seen
                    );
                }
            }
            if !report.senders.is_empty() {
                println!();
                println!("  Senders by last-seen mediator:");
                for s in &report.senders {
                    println!(
                        "    {} → {} (at {})",
                        truncate(&s.sender_did, 50),
                        truncate(&s.last_seen_mediator, 50),
                        s.last_seen_at
                    );
                }
            }
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy)]
pub enum ReportFormat {
    Json,
    Table,
}

impl std::str::FromStr for ReportFormat {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "json" => Ok(Self::Json),
            "table" => Ok(Self::Table),
            other => Err(format!("unknown format `{other}` — use `json` or `table`")),
        }
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(max - 1).collect();
        out.push('…');
        out
    }
}
