//! Azure Key Vault [`SessionBackend`].
//!
//! The Azure SDK is async-only, but [`SessionBackend`] is a sync trait.
//! `tokio::runtime::Handle::current().block_on(...)` panics when called
//! from inside a current-thread tokio runtime — exactly the runtime
//! most CLI consumers use. [`block_on_isolated`] sidesteps this by
//! running the future on a dedicated OS thread carrying its own
//! current-thread runtime.
//!
//! Cost is one thread per call. Acceptable for human-rate session ops
//! (login, refresh, logout) which run at most a handful of times per
//! CLI invocation. Anything hotter should use the OS keyring backend
//! instead.

use crate::session::SessionBackend;

pub(crate) struct AzureBackend {
    pub(crate) vault_url: String,
    pub(crate) secret_prefix: String,
}

impl AzureBackend {
    fn secret_name(&self, key: &str) -> String {
        format!("{}-{}", self.secret_prefix, key)
    }
}

/// Run an async future to completion from a sync trait method.
///
/// Spawns a dedicated OS thread carrying its own `current_thread`
/// runtime, runs the future there, and joins. Used by [`AzureBackend`]
/// to call into the async-only Azure SDK without nesting runtimes.
fn block_on_isolated<F, T>(fut: F) -> T
where
    F: std::future::Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("failed to build isolated tokio runtime for Azure SDK call");
        rt.block_on(fut)
    })
    .join()
    .expect("isolated runtime thread panicked")
}

impl SessionBackend for AzureBackend {
    fn load(&self, key: &str) -> Option<String> {
        let vault_url = self.vault_url.clone();
        let secret_name = self.secret_name(key);
        block_on_isolated(async move {
            use azure_identity::DeveloperToolsCredential;
            use azure_security_keyvault_secrets::SecretClient;

            let credential = match DeveloperToolsCredential::new(None) {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!("Azure credential creation failed: {e}");
                    return None;
                }
            };
            let client = match SecretClient::new(&vault_url, credential, None) {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!("Azure Key Vault client creation failed: {e}");
                    return None;
                }
            };

            match client.get_secret(&secret_name, None).await {
                Ok(response) => match response.into_model() {
                    Ok(model) => model.value,
                    Err(e) => {
                        tracing::warn!("Azure Key Vault response parsing failed: {e}");
                        None
                    }
                },
                Err(e) => {
                    tracing::debug!("Azure Key Vault secret '{secret_name}' not found: {e}");
                    None
                }
            }
        })
    }

    fn save(&self, key: &str, value: &str) -> Result<(), Box<dyn std::error::Error>> {
        let vault_url = self.vault_url.clone();
        let secret_name = self.secret_name(key);
        let value = value.to_string();
        // Box<dyn Error + Send + Sync> is what crosses the runtime
        // boundary; convert to the trait-required Box<dyn Error> after.
        let result: Result<(), Box<dyn std::error::Error + Send + Sync>> =
            block_on_isolated(async move {
                use azure_identity::DeveloperToolsCredential;
                use azure_security_keyvault_secrets::SecretClient;

                let credential = DeveloperToolsCredential::new(None)
                    .map_err(|e| format!("Azure credential error: {e}"))?;
                let client = SecretClient::new(&vault_url, credential, None)
                    .map_err(|e| format!("Azure client error: {e}"))?;

                let params = azure_security_keyvault_secrets::models::SetSecretParameters {
                    value: Some(value),
                    ..Default::default()
                };
                let body = params
                    .try_into()
                    .map_err(|e| format!("Azure request error: {e}"))?;
                client
                    .set_secret(&secret_name, body, None)
                    .await
                    .map_err(|e| format!("failed to store session in Azure Key Vault: {e}"))?;
                Ok(())
            });
        result.map_err(|e| -> Box<dyn std::error::Error> { e.to_string().into() })
    }

    fn clear(&self, key: &str) {
        let vault_url = self.vault_url.clone();
        let secret_name = self.secret_name(key);
        block_on_isolated(async move {
            use azure_identity::DeveloperToolsCredential;
            use azure_security_keyvault_secrets::SecretClient;

            let Ok(credential) = DeveloperToolsCredential::new(None) else {
                return;
            };
            let Ok(client) = SecretClient::new(&vault_url, credential, None) else {
                return;
            };
            let _ = client.delete_secret(&secret_name, None).await;
        })
    }
}
