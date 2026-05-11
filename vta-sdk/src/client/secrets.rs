//! Convenience methods for paginating + bundling key secrets via [`VtaClient`].

use super::VtaClient;
use crate::error::VtaError;

impl VtaClient {
    /// Fetch all secrets for a context, paginating through all keys.
    ///
    /// Returns TDK `Secret` objects ready for use with DIDComm or signing.
    pub async fn fetch_context_secrets(
        &self,
        context_id: &str,
    ) -> Result<Vec<affinidi_tdk::secrets_resolver::secrets::Secret>, VtaError> {
        let page_size = 100u64;
        let mut offset = 0u64;
        let mut secrets = Vec::new();

        loop {
            let resp = self
                .list_keys(offset, page_size, Some("active"), Some(context_id))
                .await?;

            if resp.keys.is_empty() {
                break;
            }

            for key in &resp.keys {
                let secret_resp = self.get_key_secret(&key.key_id).await?;
                let secret = crate::did_key::secret_from_key_response(&secret_resp)?;
                secrets.push(secret);
            }

            offset += resp.keys.len() as u64;
            if offset >= resp.total {
                break;
            }
        }

        Ok(secrets)
    }

    /// Fetch all secrets for a context as a portable
    /// [`DidSecretsBundle`](crate::did_secrets::DidSecretsBundle).
    ///
    /// Resolves the context DID, paginates through all active keys,
    /// fetches each secret, and returns a bundle ready for encoding/transport.
    pub async fn fetch_did_secrets_bundle(
        &self,
        context_id: &str,
    ) -> Result<crate::did_secrets::DidSecretsBundle, VtaError> {
        let ctx = self.get_context(context_id).await?;
        let did = ctx.did.ok_or_else(|| {
            VtaError::Validation(format!("context '{context_id}' has no DID assigned"))
        })?;

        let page_size = 100u64;
        let mut offset = 0u64;
        let mut secrets = Vec::new();

        loop {
            let resp = self
                .list_keys(offset, page_size, Some("active"), Some(context_id))
                .await?;
            if resp.keys.is_empty() {
                break;
            }
            for key in &resp.keys {
                let secret_resp = self.get_key_secret(&key.key_id).await?;
                let mut entry = crate::did_secrets::SecretEntry::from(secret_resp);
                // Use the key's label as the secret ID when it looks like a DID
                // verification method ID (e.g., "did:webvh:...#key-0"). The setup
                // wizard and provisioning flows set labels to match the DID document,
                // so this lets consumers use the bundle directly without remapping.
                if let Some(label) = key.label.as_deref()
                    && (label.contains('#') || label.starts_with("did:"))
                {
                    entry.key_id = label.to_string();
                }
                secrets.push(entry);
            }
            offset += resp.keys.len() as u64;
            if offset >= resp.total {
                break;
            }
        }

        Ok(crate::did_secrets::DidSecretsBundle { did, secrets })
    }
}
