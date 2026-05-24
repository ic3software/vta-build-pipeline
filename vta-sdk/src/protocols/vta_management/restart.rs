use serde::{Deserialize, Serialize};

/// Empty request body for the reload-services / restart operation.
/// Exists so the trust-task envelope's `payload` field has a typed
/// shape; the operation takes no input parameters.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ReloadServicesBody {}

/// Response body for a VTA restart request.
#[derive(Debug, Serialize, Deserialize)]
pub struct RestartResult {
    pub status: String,
}
