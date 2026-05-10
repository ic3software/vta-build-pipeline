//! Dispatch for `pnm services …` (REST + DIDComm transport advertisement).

use vta_cli_common::commands::services;
use vta_sdk::client::VtaClient;

use crate::cli::{DidcommCommands, DrainCommands, RestCommands, ServicesCommands};

pub(crate) async fn run(
    client: &VtaClient,
    command: ServicesCommands,
) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        ServicesCommands::List => services::cmd_services_list(client).await,
        ServicesCommands::Rest { command } => run_rest(client, command).await,
        ServicesCommands::Didcomm { command } => run_didcomm(client, command).await,
        ServicesCommands::Report {
            since,
            until,
            format,
        } => match format.parse::<services::ReportFormat>() {
            Ok(format) => services::cmd_services_report(client, since, until, format).await,
            Err(msg) => Err(msg.into()),
        },
    }
}

async fn run_rest(
    client: &VtaClient,
    command: RestCommands,
) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        RestCommands::Enable { url } => services::cmd_services_rest_enable(client, url).await,
        RestCommands::Update { url } => services::cmd_services_rest_update(client, url).await,
        RestCommands::Disable => services::cmd_services_rest_disable(client).await,
        RestCommands::Rollback => services::cmd_services_rest_rollback(client).await,
    }
}

async fn run_didcomm(
    client: &VtaClient,
    command: DidcommCommands,
) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        DidcommCommands::Enable {
            mediator_did,
            force,
            handshake_timeout,
        } => {
            services::cmd_services_didcomm_enable(client, mediator_did, force, handshake_timeout)
                .await
        }
        DidcommCommands::Update {
            new_mediator_did,
            drain_ttl,
            force,
            handshake_timeout,
        } => {
            services::cmd_services_didcomm_update(
                client,
                new_mediator_did,
                drain_ttl,
                force,
                handshake_timeout,
            )
            .await
        }
        DidcommCommands::Disable { drain_ttl } => {
            services::cmd_services_didcomm_disable(client, drain_ttl).await
        }
        DidcommCommands::Rollback { drain_ttl } => {
            services::cmd_services_didcomm_rollback(client, drain_ttl).await
        }
        DidcommCommands::Drain { command } => match command {
            DrainCommands::List => services::cmd_services_didcomm_drain_list(client).await,
            DrainCommands::Cancel { mediator_did } => {
                services::cmd_services_didcomm_drain_cancel(client, mediator_did).await
            }
        },
    }
}
