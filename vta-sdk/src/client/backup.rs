//! Backup management methods on [`VtaClient`]: encrypted export and import.

use super::VtaClient;
use crate::error::VtaError;

impl VtaClient {
    /// Export VTA state to an encrypted backup.
    pub async fn backup_export(
        &self,
        password: &str,
        include_audit: bool,
    ) -> Result<crate::protocols::backup_management::types::BackupEnvelope, VtaError> {
        self.rpc(
            crate::protocols::backup_management::EXPORT_BACKUP,
            serde_json::json!({ "password": password, "include_audit": include_audit }),
            crate::protocols::backup_management::EXPORT_BACKUP_RESULT,
            120, // backup can take longer
            |c, url| {
                c.post(format!("{url}/backup/export")).json(
                    &serde_json::json!({ "password": password, "include_audit": include_audit }),
                )
            },
        )
        .await
    }

    /// Import VTA state from an encrypted backup.
    pub async fn backup_import(
        &self,
        backup: &crate::protocols::backup_management::types::BackupEnvelope,
        password: &str,
        confirm: bool,
    ) -> Result<crate::protocols::backup_management::types::ImportResult, VtaError> {
        self.rpc(
            crate::protocols::backup_management::IMPORT_BACKUP,
            serde_json::json!({ "backup": backup, "password": password, "confirm": confirm }),
            crate::protocols::backup_management::IMPORT_BACKUP_RESULT,
            120,
            |c, url| {
                c.post(format!("{url}/backup/import"))
                    .json(&serde_json::json!({ "backup": backup, "password": password, "confirm": confirm }))
            },
        )
        .await
    }
}
