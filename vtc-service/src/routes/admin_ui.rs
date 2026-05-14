//! Admin UX route surface (§12.2, Phase 5 M5.7).
//!
//! Two handlers:
//!
//! - **Catch-all** (`GET /admin/*`) → serves the baked SPA from
//!   [`crate::admin_ui`]. SPA history-mode fallback: paths that
//!   don't match a baked file fall back to `index.html` so
//!   client-side routing works.
//! - **Build-info** (`GET /admin/build-info.json`) → returns the
//!   embedded directory's SHA-256 + file count + mode. Unauth —
//!   the daemon's release metadata is public.

#![cfg(feature = "admin-ui")]

use axum::Json;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::response::Response;
use serde::Serialize;

use crate::admin_ui::AdminUiInfo;
use crate::server::AppState;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BuildInfo {
    pub version: String,
    pub index_sha256: String,
    pub file_count: u32,
    pub mode: String,
}

/// `GET /admin/build-info.json` — unauth, surfaces what's baked.
pub async fn build_info(State(state): State<AppState>) -> Json<BuildInfo> {
    let mode = state.config.read().await.admin_ui.mode.clone();
    let info = AdminUiInfo::from_embedded(&mode);
    Json(BuildInfo {
        // The admin SPA carries its own internal version, but
        // the embedded build's SHA-256 is what an operator
        // actually pins against.
        version: env!("CARGO_PKG_VERSION").to_string(),
        index_sha256: (*info.index_sha256).clone(),
        file_count: info.file_count,
        mode: (*info.mode).clone(),
    })
}

/// `GET /admin/*` — serve the baked SPA. When
/// `admin_ui.mode = "external"` this handler is skipped at route
/// attach time and `/admin/*` returns 404.
pub async fn serve_spa(req: Request<Body>) -> Response {
    crate::admin_ui::serve(req).await
}
