//! Dispatch for `pnm config …`.

use vta_cli_common::commands::config as config_cmd;
use vta_sdk::client::VtaClient;

use crate::cli::ConfigCommands;

pub(crate) async fn run(
    client: &VtaClient,
    command: ConfigCommands,
) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        ConfigCommands::Get => config_cmd::cmd_config_get(client, "").await,
        ConfigCommands::Update {
            community_vta_did,
            community_vta_name,
            public_url,
        } => {
            config_cmd::cmd_config_update(
                client,
                "",
                community_vta_did,
                community_vta_name,
                public_url,
            )
            .await
        }
    }
}
