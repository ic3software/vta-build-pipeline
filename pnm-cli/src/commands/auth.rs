//! Dispatch for `pnm auth …`.
//!
//! Wraps the keyring-backed helpers in [`crate::auth`] so the main
//! dispatch table doesn't have to know about session-store internals.

use crate::auth;
use crate::cli::AuthCommands;

pub(crate) fn run(
    keyring_key: &str,
    command: AuthCommands,
) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        AuthCommands::Logout => {
            auth::logout(keyring_key);
            Ok(())
        }
        AuthCommands::Status => {
            auth::status(keyring_key);
            Ok(())
        }
        AuthCommands::SignChallenge { challenge } => {
            auth::sign_unseal_challenge(keyring_key, &challenge)
        }
    }
}
