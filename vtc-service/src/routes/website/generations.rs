//! `GET /v1/website/generations` + `POST /v1/website/rollback/{gen}`
//! (Phase 5 M5.5.4).
//!
//! Both endpoints are managed-mode-only. Live-mode requests
//! return 400 with `WebsiteNotManagedMode` (encoded as
//! [`AppError::Validation`] for MVP — see the route-module
//! comments).

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;

use vti_common::audit::{AuditEvent, WebsiteGenerationRolledBackData};
use vti_common::auth::AdminAuth;

use crate::error::AppError;
use crate::server::AppState;
use crate::website::storage::{GenerationEntry, list_managed_generations, swap_current_symlink};

pub async fn list(
    _admin: AdminAuth,
    State(state): State<AppState>,
) -> Result<Json<Vec<GenerationEntry>>, AppError> {
    let cfg = state.config.read().await;
    let root_dir = cfg
        .website
        .root_dir
        .clone()
        .ok_or_else(|| AppError::Validation("website.root_dir is not configured".into()))?;
    let deploy_mode = cfg.website.deploy_mode.clone();
    drop(cfg);

    if deploy_mode != "managed" {
        return Err(AppError::Validation(
            "GET /v1/website/generations is only available in managed deploy mode".into(),
        ));
    }

    let gens = list_managed_generations(&root_dir)?;
    Ok(Json(gens))
}

pub async fn rollback(
    _admin: AdminAuth,
    State(state): State<AppState>,
    Path(gen_num): Path<u32>,
) -> Result<StatusCode, AppError> {
    let cfg = state.config.read().await;
    let root_dir = cfg
        .website
        .root_dir
        .clone()
        .ok_or_else(|| AppError::Validation("website.root_dir is not configured".into()))?;
    let deploy_mode = cfg.website.deploy_mode.clone();
    drop(cfg);

    if deploy_mode != "managed" {
        return Err(AppError::Validation(
            "POST /v1/website/rollback/{gen} is only available in managed deploy mode".into(),
        ));
    }

    let from = swap_current_symlink(&root_dir, gen_num)?;
    if from != gen_num
        && let Some(writer) = state.audit_writer.as_ref()
    {
        let _ = writer
            .write(
                "admin",
                None,
                AuditEvent::WebsiteGenerationRolledBack(WebsiteGenerationRolledBackData {
                    from_generation: from,
                    to_generation: gen_num,
                }),
            )
            .await;
    }
    Ok(StatusCode::OK)
}
