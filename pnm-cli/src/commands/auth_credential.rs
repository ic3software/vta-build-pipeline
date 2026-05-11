//! Dispatch for `pnm auth-credential …`.

use vta_cli_common::commands::credentials;
use vta_cli_common::sealed_producer::resolve_recipient;
use vta_sdk::client::VtaClient;

use crate::cli::AuthCredentialCommands;

pub(crate) async fn run(
    client: &VtaClient,
    command: AuthCredentialCommands,
) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        AuthCredentialCommands::Create {
            role,
            label,
            contexts,
            recipient,
            recipient_did,
            recipient_nonce,
        } => match resolve_recipient(
            recipient.as_deref(),
            recipient_did.as_deref(),
            recipient_nonce.as_deref(),
        ) {
            Ok(recipient) => {
                credentials::cmd_auth_credential_create(client, role, label, contexts, recipient)
                    .await
            }
            Err(e) => Err(e),
        },
    }
}
