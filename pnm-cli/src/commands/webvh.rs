//! Dispatch for `pnm webvh …`.

use vta_cli_common::commands::webvh;
use vta_sdk::client::VtaClient;

use crate::cli::WebvhCommands;

pub(crate) async fn run(
    client: &VtaClient,
    command: WebvhCommands,
) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        WebvhCommands::AddServer { id, did, label } => {
            webvh::cmd_webvh_server_add(client, id, did, label).await
        }
        WebvhCommands::ListServers => webvh::cmd_webvh_server_list(client).await,
        WebvhCommands::UpdateServer { id, label } => {
            webvh::cmd_webvh_server_update(client, &id, label).await
        }
        WebvhCommands::RemoveServer { id } => webvh::cmd_webvh_server_remove(client, &id).await,
        WebvhCommands::CreateDid {
            context,
            server,
            did_url,
            path,
            label,
            portable,
            mediator_service,
            services,
            pre_rotation,
            did_document,
            did_log,
            no_primary,
            signing_key,
            ka_key,
            template,
            template_context,
            vars,
        } => {
            if server.is_none() && did_url.is_none() {
                Err("either --server or --did-url is required".into())
            } else if server.is_some() && did_url.is_some() {
                Err("--server and --did-url are mutually exclusive".into())
            } else {
                // Default template lookup to the DID's own context so
                // context-local overrides are found before the global
                // fallback.
                let template_context =
                    template_context.or_else(|| template.as_ref().map(|_| context.clone()));
                webvh::cmd_webvh_did_create_with_files(
                    client,
                    context,
                    server,
                    did_url,
                    path,
                    label,
                    portable,
                    mediator_service,
                    services,
                    pre_rotation,
                    did_document,
                    did_log,
                    no_primary,
                    signing_key,
                    ka_key,
                    template,
                    template_context,
                    vars,
                )
                .await
            }
        }
        WebvhCommands::EditDid {
            did,
            document,
            options_file,
            pre_rotation,
            ttl,
            watchers,
            no_watchers,
            label,
            no_confirm,
        } => {
            let flags = vta_cli_common::commands::webvh_edit::EditFlags {
                document_file: document,
                options_file,
                pre_rotation,
                ttl,
                watchers,
                no_watchers,
                label,
            };
            webvh::cmd_webvh_did_edit(client, &did, flags, no_confirm).await
        }
        WebvhCommands::RegisterDid { did, server, force } => {
            webvh::cmd_webvh_did_register_server(client, &did, &server, force).await
        }
        WebvhCommands::ListDids { context, server } => {
            webvh::cmd_webvh_did_list(client, context.as_deref(), server.as_deref()).await
        }
        WebvhCommands::GetDid { did } => webvh::cmd_webvh_did_get(client, &did).await,
        WebvhCommands::DeleteDid { did } => webvh::cmd_webvh_did_delete(client, &did).await,
        WebvhCommands::DidLog { did, out } => {
            webvh::cmd_webvh_did_log(client.base_url(), &did, out).await
        }
    }
}
