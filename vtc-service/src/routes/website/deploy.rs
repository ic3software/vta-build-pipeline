//! `POST /v1/website/deploy` (Phase 5 M5.5.3).
//!
//! Accepts a tar.gz bundle, runs pre-extract path-safety on every
//! entry, extracts to a staging directory, then atomically swaps
//! into place. Live mode renames the staging dir over `root_dir`;
//! managed mode creates a new `gen-N` directory and flips the
//! `current` symlink.

use axum::Json;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use serde::Serialize;
use sha2::{Digest, Sha256};

use vti_common::audit::{AuditEvent, WebsiteBundleDeployedData};
use vti_common::auth::AdminAuth;

use crate::error::AppError;
use crate::server::AppState;
use crate::website::bundle::verify_and_extract;
use crate::website::storage::{next_generation, prune_generations, swap_current_symlink};

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeployResponse {
    pub deploy_mode: String,
    pub bundle_sha256: String,
    pub bundle_size_bytes: u64,
    pub target_generation: u32,
    pub pruned_generations: u32,
}

pub async fn deploy(
    _admin: AdminAuth,
    State(state): State<AppState>,
    body: Bytes,
) -> Result<(StatusCode, Json<DeployResponse>), AppError> {
    let cfg = state.config.read().await;
    let max_bundle = cfg.website.max_bundle_size_mb.saturating_mul(1024 * 1024);
    let root_dir = cfg
        .website
        .root_dir
        .clone()
        .ok_or_else(|| AppError::Validation("website.root_dir is not configured".into()))?;
    let blocklist = cfg.website.executable_blocklist.clone();
    let deploy_mode = cfg.website.deploy_mode.clone();
    let keep = cfg.website.managed_generations_keep;
    drop(cfg);

    if (body.len() as u64) > max_bundle {
        return Err(AppError::Validation(format!(
            "bundle size {} exceeds max_bundle_size_mb",
            body.len()
        )));
    }

    // Decompression cap: max_bundle * expansion ratio. A 50 MiB
    // compressed bundle is allowed to extract to at most ~500 MiB
    // on disk by default — catches gzip bombs (1000:1 ratios) that
    // would otherwise blow up to multi-GiB temporary directories.
    let decompressed_cap =
        max_bundle.saturating_mul(crate::website::bundle::DECOMPRESSION_EXPANSION_RATIO);

    let bundle_sha = hex::encode(Sha256::digest(&body));
    let bundle_size = body.len() as u64;

    let (target_generation, pruned) = match deploy_mode.as_str() {
        "live" => {
            let staging = root_dir.with_extension(format!("staging.{}", rand_suffix()));
            verify_and_extract(&body, &staging, &blocklist, decompressed_cap)?;

            // Atomic swap: rename old root aside, rename staging
            // to root. Best-effort cleanup of the previous dir.
            if root_dir.exists() {
                let previous = root_dir.with_extension(format!("previous.{}", rand_suffix()));
                if let Err(e) = std::fs::rename(&root_dir, &previous) {
                    return Err(AppError::Internal(format!(
                        "rename {root_dir:?} -> {previous:?}: {e}"
                    )));
                }
                // Drop the previous dir — diagnostic recovery is
                // out-of-scope for the MVP write path.
                let _ = std::fs::remove_dir_all(&previous);
            }
            std::fs::rename(&staging, &root_dir).map_err(|e| {
                AppError::Internal(format!("rename {staging:?} -> {root_dir:?}: {e}"))
            })?;
            (0u32, 0u32)
        }
        "managed" => {
            let gen_num = next_generation(&root_dir)?;
            let target_dir = root_dir.join(format!("gen-{gen_num}"));
            verify_and_extract(&body, &target_dir, &blocklist, decompressed_cap)?;
            swap_current_symlink(&root_dir, gen_num)?;
            let pruned = prune_generations(&root_dir, keep)?;
            (gen_num, pruned)
        }
        other => {
            return Err(AppError::Validation(format!(
                "unknown deploy_mode \"{other}\""
            )));
        }
    };

    if let Some(writer) = state.audit_writer.as_ref() {
        let _ = writer
            .write(
                "admin",
                None,
                AuditEvent::WebsiteBundleDeployed(WebsiteBundleDeployedData {
                    bundle_sha256: bundle_sha.clone(),
                    bundle_size_bytes: bundle_size,
                    deploy_mode: deploy_mode.clone(),
                    target_generation,
                    pruned_generations: pruned,
                }),
            )
            .await;
    }

    Ok((
        StatusCode::OK,
        Json(DeployResponse {
            deploy_mode,
            bundle_sha256: bundle_sha,
            bundle_size_bytes: bundle_size,
            target_generation,
            pruned_generations: pruned,
        }),
    ))
}

fn rand_suffix() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{nanos:x}")
}
