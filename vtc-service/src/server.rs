use std::sync::Arc;
use std::time::Duration;

use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
use affinidi_tdk::common::TDKSharedState;
use affinidi_tdk::common::config::TDKConfig;
use affinidi_tdk::messaging::ATM;
use affinidi_tdk::messaging::config::ATMConfig;
use affinidi_tdk::secrets_resolver::{SecretsResolver, ThreadedSecretsResolver, secrets::Secret};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64;

use crate::auth::AuthState;
use crate::auth::jwt::JwtKeys;
use crate::auth::session::cleanup_expired_sessions;
use crate::config::{AppConfig, AuthConfig};
use crate::error::AppError;
use crate::install::{InstallTokenSigner, InstallTokenStore};
use crate::keys::seed_store::SecretStore;
use crate::messaging;
use crate::routes;
use crate::setup::VtcKeyBundle;
use crate::store::{KeyspaceHandle, Store};
use crate::supervisor::{SupervisorKind, detect_supervisor};
use tokio::sync::{RwLock, watch};
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing::{debug, error, info, warn};
use vti_common::audit::{AuditKeyStore, AuditWriter};
use vti_common::auth::passkey::{PasskeyState, build_webauthn};
use webauthn_rs::Webauthn;
use zeroize::Zeroizing;

/// Default enrolment-invite TTL surfaced by `PasskeyState::enrollment_ttl`.
/// Admin-invite enrolment lands in M0.6; until then this constant is the
/// canonical "how long is an admin invite redeemable" value. An hour
/// is the same default `webvh-common`'s passkey routes use.
const DEFAULT_ENROLLMENT_TTL_SECS: u64 = 60 * 60;

#[derive(Clone)]
#[allow(dead_code)]
pub struct AppState {
    pub sessions_ks: KeyspaceHandle,
    pub acl_ks: KeyspaceHandle,
    pub community_ks: KeyspaceHandle,
    pub config_ks: KeyspaceHandle,
    pub passkey_ks: KeyspaceHandle,
    pub install_ks: KeyspaceHandle,
    pub members_ks: KeyspaceHandle,
    pub audit_ks: KeyspaceHandle,
    pub audit_key_ks: KeyspaceHandle,
    pub config: Arc<RwLock<AppConfig>>,
    pub did_resolver: Option<DIDCacheClient>,
    pub secrets_resolver: Option<Arc<ThreadedSecretsResolver>>,
    pub jwt_keys: Option<Arc<JwtKeys>>,
    pub atm: Option<ATM>,
    /// WebAuthn relying-party handle. `None` when `config.public_url`
    /// is unset at startup — the install + admin-passkey routes 503
    /// in that case (per `PasskeyState` contract).
    pub webauthn: Option<Arc<Webauthn>>,
    /// Cached `public_url` snapshot for `PasskeyState::public_url`.
    /// Held alongside the `Webauthn` so the trait impl doesn't need
    /// to take an async read-lock on the config every request.
    pub public_url: Option<String>,
    /// EdDSA signer that verifies install tokens and mints setup-session
    /// tokens at the end of the claim ceremony. `None` until the secret
    /// store yields key material — install routes 503 in that case.
    pub install_signer: Option<Arc<InstallTokenSigner>>,
    /// Wraps `install_ks` with the claim-window state machine. Cheap
    /// to clone; always present once `install_ks` is open.
    pub install_store: InstallTokenStore,
    /// HMAC-actor-hashing audit envelope writer. `None` until the
    /// secret store yields key material (the audit key is HKDF-
    /// derived from the master seed). Endpoints that emit audit
    /// events 503 in that case.
    pub audit_writer: Option<AuditWriter>,
    /// Sender half of the shared graceful-shutdown channel.
    /// `POST /v1/admin/config/restart` flips this to `true` to
    /// trigger the same drain path SIGINT/SIGTERM use.
    pub shutdown_tx: watch::Sender<bool>,
    /// Cached supervisor probe (M0.8.3). Computed once at startup
    /// — process supervisors don't change during the daemon's
    /// lifetime, and a cached value lets tests inject
    /// `Some(Manual)` / `None` without racing other tests on the
    /// shared `std::env`.
    pub supervisor: Option<SupervisorKind>,
}

impl AuthState for AppState {
    fn jwt_keys(&self) -> Option<&Arc<JwtKeys>> {
        self.jwt_keys.as_ref()
    }
    fn sessions_ks(&self) -> &KeyspaceHandle {
        &self.sessions_ks
    }
}

impl PasskeyState for AppState {
    fn webauthn(&self) -> Option<&Arc<Webauthn>> {
        self.webauthn.as_ref()
    }

    fn acl_ks(&self) -> &KeyspaceHandle {
        &self.acl_ks
    }

    fn access_token_expiry(&self) -> u64 {
        // `config` is wrapped in an `Arc<RwLock<…>>`; the trait method
        // is sync. `try_read` returns immediately — if a writer is
        // mid-update we fall through to the workspace default so the
        // auth layer never blocks. The default values match the
        // compiled-in `AuthConfig::default()` and the runtime tax of
        // missing a recently-updated value is bounded by the JWT TTL
        // anyway.
        self.config
            .try_read()
            .map(|c| c.auth.access_token_expiry)
            .unwrap_or(AuthConfig::default().access_token_expiry)
    }

    fn refresh_token_expiry(&self) -> u64 {
        self.config
            .try_read()
            .map(|c| c.auth.refresh_token_expiry)
            .unwrap_or(AuthConfig::default().refresh_token_expiry)
    }

    fn public_url(&self) -> Option<&str> {
        self.public_url.as_deref()
    }

    fn enrollment_ttl(&self) -> u64 {
        DEFAULT_ENROLLMENT_TTL_SECS
    }
}

pub async fn run(
    config: AppConfig,
    store: Store,
    secret_store: Box<dyn SecretStore>,
) -> Result<(), AppError> {
    // Open cached keyspace handles
    let sessions_ks = store.keyspace("sessions")?;
    let acl_ks = store.keyspace("acl")?;
    let community_ks = store.keyspace("community")?;
    let config_ks = store.keyspace("config")?;
    let passkey_ks = store.keyspace("passkey")?;
    let install_ks = store.keyspace("install")?;
    let install_store = InstallTokenStore::new(install_ks.clone());
    let members_ks = store.keyspace("members")?;
    let audit_ks = store.keyspace("audit")?;
    let audit_key_ks = store.keyspace("audit_key")?;

    // Initialize auth infrastructure. Pass the audit keyspaces in so
    // `init_auth` can derive the HMAC audit key from the same secret
    // store contents it uses for the install signer.
    let (did_resolver, secrets_resolver, jwt_keys, atm, install_signer, audit_writer) = init_auth(
        &config,
        &*secret_store,
        audit_ks.clone(),
        audit_key_ks.clone(),
    )
    .await;

    // Build WebAuthn relying party handle from `public_url`. Optional —
    // a serverless / pre-setup deployment has no public URL yet and
    // the install + admin-passkey routes will 503 until one is set.
    let public_url = config.public_url.clone();
    let webauthn = match &public_url {
        Some(url) => match build_webauthn(url) {
            Ok(w) => Some(Arc::new(w)),
            Err(e) => {
                warn!(
                    "failed to build WebAuthn relying party from public_url '{url}': {e} — passkey routes disabled"
                );
                None
            }
        },
        None => {
            debug!("public_url not configured — WebAuthn / passkey routes disabled");
            None
        }
    };

    // Bind TCP listener on the main thread for early port validation
    let addr = format!("{}:{}", config.server.host, config.server.port);
    let std_listener = std::net::TcpListener::bind(&addr).map_err(AppError::Io)?;
    std_listener.set_nonblocking(true).map_err(AppError::Io)?;
    info!("server listening addr={addr}");

    // Shutdown coordination
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // Spawn signal handler on the main tokio runtime
    tokio::spawn({
        let shutdown_tx = shutdown_tx.clone();
        async move {
            shutdown_signal().await;
            let _ = shutdown_tx.send(true);
        }
    });

    // Gather DIDComm thread inputs
    let didcomm_config = config.clone();
    let didcomm_secrets = secrets_resolver.clone();
    let didcomm_vtc_did = config.vtc_did.clone();

    // Gather storage thread inputs
    let storage_sessions_ks = sessions_ks.clone();
    let storage_auth_config = config.auth.clone();
    let has_auth = jwt_keys.is_some();

    // Build AppState for the REST thread
    let state = AppState {
        sessions_ks,
        acl_ks,
        community_ks,
        config_ks,
        passkey_ks,
        install_ks,
        members_ks,
        audit_ks,
        audit_key_ks,
        config: Arc::new(RwLock::new(config)),
        did_resolver,
        secrets_resolver,
        jwt_keys,
        atm,
        webauthn,
        public_url,
        install_signer,
        install_store,
        audit_writer,
        shutdown_tx: shutdown_tx.clone(),
        supervisor: detect_supervisor(),
    };

    // M0.10: consume + audit any pending emergency-bootstrap marker
    // left behind by `vtc admin emergency-bootstrap`. The marker is
    // **one-shot**: `take_pending_emergency` deletes it as part of
    // reading, so a restart loop emits the loud event exactly once.
    if let (Some(pending), Some(writer)) = (
        state
            .install_store
            .take_pending_emergency()
            .await
            .ok()
            .flatten(),
        state.audit_writer.as_ref(),
    ) {
        warn!(
            operator_hostname = %pending.operator_hostname,
            invoked_at = %pending.invoked_at,
            "EMERGENCY BOOTSTRAP was invoked since the daemon last ran — auditing now",
        );
        if let Err(e) = writer
            .write(
                "did:key:vtc-emergency",
                None,
                vti_common::audit::AuditEvent::EmergencyBootstrapInvoked(
                    vti_common::audit::EmergencyBootstrapData {
                        operator_hostname: pending.operator_hostname,
                        invoked_at: pending.invoked_at,
                    },
                ),
            )
            .await
        {
            error!(error = %e, "failed to emit EmergencyBootstrapInvoked envelope");
        }
    }

    // Snapshot the CORS allowlist before the AppState `move` into
    // the REST thread. The layer is fixed at start-up; a future
    // M0.8.x extension can swap the layer on `POST /v1/admin/config/reload`
    // if operators demand live updates.
    let rest_cors = state.config.read().await.cors.clone();

    // Spawn three named OS threads
    let mut rest_shutdown_rx = shutdown_rx.clone();
    let rest_handle = std::thread::Builder::new()
        .name("vtc-rest".into())
        .spawn(move || run_rest_thread(std_listener, state, rest_cors, &mut rest_shutdown_rx))
        .map_err(|e| AppError::Internal(format!("failed to spawn REST thread: {e}")))?;

    let mut didcomm_shutdown_rx = shutdown_rx.clone();
    let didcomm_handle = std::thread::Builder::new()
        .name("vtc-didcomm".into())
        .spawn(move || {
            run_didcomm_thread(
                didcomm_config,
                didcomm_secrets,
                didcomm_vtc_did,
                &mut didcomm_shutdown_rx,
            )
        })
        .map_err(|e| AppError::Internal(format!("failed to spawn DIDComm thread: {e}")))?;

    let mut storage_shutdown_rx = shutdown_rx.clone();
    let storage_handle = std::thread::Builder::new()
        .name("vtc-storage".into())
        .spawn(move || {
            run_storage_thread(
                store,
                storage_sessions_ks,
                storage_auth_config,
                has_auth,
                &mut storage_shutdown_rx,
            )
        })
        .map_err(|e| AppError::Internal(format!("failed to spawn storage thread: {e}")))?;

    // Join REST + DIDComm in parallel, then storage last
    let (rest_result, didcomm_result) = tokio::join!(
        tokio::task::spawn_blocking(move || rest_handle.join()),
        tokio::task::spawn_blocking(move || didcomm_handle.join()),
    );

    // If either thread panicked, trigger shutdown for the remaining threads
    let mut any_panic = false;

    match rest_result {
        Ok(Ok(())) => info!("REST thread stopped"),
        Ok(Err(_panic)) => {
            error!("REST thread panicked");
            any_panic = true;
        }
        Err(e) => {
            error!("failed to join REST thread: {e}");
            any_panic = true;
        }
    }

    match didcomm_result {
        Ok(Ok(())) => info!("DIDComm thread stopped"),
        Ok(Err(_panic)) => {
            error!("DIDComm thread panicked");
            any_panic = true;
        }
        Err(e) => {
            error!("failed to join DIDComm thread: {e}");
            any_panic = true;
        }
    }

    if any_panic {
        let _ = shutdown_tx.send(true);
    }

    // Join storage last — guarantees all writes flushed before database closes
    match storage_handle.join() {
        Ok(()) => info!("storage thread stopped"),
        Err(_panic) => {
            error!("storage thread panicked");
            any_panic = true;
        }
    }

    if any_panic {
        return Err(AppError::Internal("one or more threads panicked".into()));
    }

    info!("server shut down");
    Ok(())
}

/// Storage thread: runs session cleanup loop and persists the store on shutdown.
fn run_storage_thread(
    store: Store,
    sessions_ks: KeyspaceHandle,
    auth_config: AuthConfig,
    has_auth: bool,
    shutdown_rx: &mut watch::Receiver<bool>,
) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to build storage runtime");

    rt.block_on(async {
        info!("storage thread started");

        if has_auth {
            let interval = Duration::from_secs(auth_config.session_cleanup_interval);
            let mut timer = tokio::time::interval(interval);
            // First tick completes immediately; skip it so cleanup doesn't run at startup
            timer.tick().await;

            loop {
                tokio::select! {
                    _ = timer.tick() => {
                        if let Err(e) = cleanup_expired_sessions(&sessions_ks, auth_config.challenge_ttl).await {
                            warn!("session cleanup error: {e}");
                        }
                    }
                    _ = shutdown_rx.changed() => {
                        info!("storage thread shutting down");
                        break;
                    }
                }
            }
        } else {
            // No auth — just wait for shutdown
            let _ = shutdown_rx.changed().await;
            info!("storage thread shutting down");
        }

        // Persist store before closing
        if let Err(e) = store.persist().await {
            error!("failed to persist store on shutdown: {e}");
        } else {
            info!("store persisted");
        }
    });
}

/// Build the [`CorsLayer`] applied to every REST response. Honours
/// the spec §9.3 allowlist:
///
/// - Empty `allowed_origins` → CORS is disabled (no cross-origin
///   responses set the headers); same-origin path-mode deployments
///   never need an entry.
/// - Each origin is reflected verbatim by the `Origin` header
///   match; wildcards are refused at config-load (see
///   `crate::config::validate_cors`), so by the time we get here
///   every entry is a literal `http(s)://host[:port]`.
///
/// `Access-Control-Allow-Headers` is fixed at the workspace's
/// "common" header set (Authorization, Content-Type, Trust-Task,
/// Idempotency-Key). `Access-Control-Allow-Credentials` is `true`
/// so the admin SPA can carry the future cookie session over the
/// allowlist edge; an empty allowlist disables CORS entirely so
/// `credentials: true` is harmless there.
fn build_cors_layer(cors: &crate::config::CorsConfig) -> CorsLayer {
    use axum::http::Method;
    use axum::http::header::{
        ACCESS_CONTROL_ALLOW_HEADERS, AUTHORIZATION, CONTENT_TYPE, HeaderName, HeaderValue,
    };

    if cors.allowed_origins.is_empty() {
        // No origins → same-origin only.
        return CorsLayer::new();
    }

    let allowed_origins: Vec<HeaderValue> = cors
        .allowed_origins
        .iter()
        .filter_map(|o| o.parse::<HeaderValue>().ok())
        .collect();

    let allowed_methods = vec![
        Method::GET,
        Method::POST,
        Method::PUT,
        Method::PATCH,
        Method::DELETE,
        Method::OPTIONS,
    ];

    let allowed_headers: Vec<HeaderName> = vec![
        AUTHORIZATION,
        CONTENT_TYPE,
        ACCESS_CONTROL_ALLOW_HEADERS,
        HeaderName::from_static("trust-task"),
        HeaderName::from_static("idempotency-key"),
    ];

    CorsLayer::new()
        .allow_origin(allowed_origins)
        .allow_methods(allowed_methods)
        .allow_headers(allowed_headers)
        .allow_credentials(true)
}

/// REST thread: serves the Axum HTTP server.
fn run_rest_thread(
    std_listener: std::net::TcpListener,
    state: AppState,
    cors: crate::config::CorsConfig,
    shutdown_rx: &mut watch::Receiver<bool>,
) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to build REST runtime");

    rt.block_on(async {
        info!("REST thread started");

        let listener = tokio::net::TcpListener::from_std(std_listener)
            .expect("failed to convert std TcpListener to tokio TcpListener");

        let cors_layer = build_cors_layer(&cors);

        let app = routes::router()
            .with_state(state)
            .layer(cors_layer)
            .layer(TraceLayer::new_for_http());

        let shutdown_rx = shutdown_rx.clone();
        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let mut rx = shutdown_rx;
                let _ = rx.changed().await;
            })
            .await
            .expect("axum serve failed");

        info!("REST thread shutting down");
    });
}

/// DIDComm thread: runs the DIDComm service until shutdown.
fn run_didcomm_thread(
    config: AppConfig,
    secrets_resolver: Option<Arc<ThreadedSecretsResolver>>,
    vtc_did: Option<String>,
    shutdown_rx: &mut watch::Receiver<bool>,
) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to build DIDComm runtime");

    rt.block_on(async {
        info!("DIDComm thread started");

        let (sr, did) = match (&secrets_resolver, &vtc_did) {
            (Some(sr), Some(did)) => (sr, did.as_str()),
            _ => {
                info!("DIDComm not configured — thread idle");
                let _ = shutdown_rx.changed().await;
                info!("DIDComm thread shutting down (idle)");
                return;
            }
        };

        messaging::run_didcomm_service(&config, sr, did, shutdown_rx).await;

        info!("DIDComm thread shutting down");
    });
}

/// Initialize DID resolver, secrets resolver, and JWT keys for authentication.
///
/// Returns `None` values if the VTC DID is not configured (server still starts
/// so the setup wizard can be run first).
///
/// Loads a serialized [`crate::setup::VtcKeyBundle`] from the secret
/// store. The bundle is what the VTA's `provision-integration` flow
/// produced at setup time; it carries the integration DID + the
/// Ed25519 + X25519 keys that back `vtc_did#key-0` / `#key-1`.
/// Install-token signing key + audit key are HKDF-derived from the
/// Ed25519 private bytes (32 B IKM) with `/v2` info strings — see
/// `tasks/vtc-mvp/vta-driven-keys.md` §5.2.
async fn init_auth(
    config: &AppConfig,
    secret_store: &dyn SecretStore,
    audit_ks: KeyspaceHandle,
    audit_key_ks: KeyspaceHandle,
) -> (
    Option<DIDCacheClient>,
    Option<Arc<ThreadedSecretsResolver>>,
    Option<Arc<JwtKeys>>,
    Option<ATM>,
    Option<Arc<InstallTokenSigner>>,
    Option<AuditWriter>,
) {
    let vtc_did = match &config.vtc_did {
        Some(did) => did.clone(),
        None => {
            warn!("vtc_did not configured — auth endpoints will not work (run setup first)");
            return (None, None, None, None, None, None);
        }
    };

    // Load the VtcKeyBundle from the secret store. Backwards-compat
    // window: tests + the legacy bootstrap flow still feed 64 raw
    // bytes (`[Ed25519:32 || X25519:32]`) directly; we accept that
    // shape too and synthesize an in-memory bundle. Production
    // setup writes the JSON shape via `inline_secret_for_bundle`.
    let stored = match secret_store.get().await {
        Ok(Some(s)) => s,
        Ok(None) => {
            warn!("no key material found — auth endpoints will not work (run setup first)");
            return (None, None, None, None, None, None);
        }
        Err(e) => {
            warn!("failed to load key material: {e} — auth endpoints will not work");
            return (None, None, None, None, None, None);
        }
    };

    let (ed25519_bytes, x25519_bytes) = match decode_secret_store_value(&vtc_did, &stored) {
        Ok(pair) => pair,
        Err(msg) => {
            warn!("{msg}");
            return (None, None, None, None, None, None);
        }
    };

    // Derive the install-token signer from the 32-byte Ed25519
    // private. HKDF info is `vtc-install-jwt-key/v2` — bumped from
    // /v1 alongside the VTA-driven-keys rework so any pre-rework
    // deployment that still feeds a BIP-39-derived 64-byte seed
    // derives a different signing key and fails token verification
    // loudly instead of silently accepting tokens minted under the
    // old derivation. See `tasks/vtc-mvp/vta-driven-keys.md` §5.2.
    let install_signer = match InstallTokenSigner::from_master_seed(&*ed25519_bytes) {
        Ok(s) => Some(Arc::new(s)),
        Err(e) => {
            warn!("failed to derive install token signer: {e} — install routes disabled");
            None
        }
    };

    // Derive the HMAC audit key from the same 32 bytes. The
    // `AuditKeyStore` info string is also bumped to /v2 in
    // vti-common — see the rework note there.
    let audit_writer = {
        let key_store = AuditKeyStore::new(audit_key_ks);
        match key_store.ensure_initial(&*ed25519_bytes).await {
            Ok(_) => Some(AuditWriter::new(audit_ks, key_store)),
            Err(e) => {
                warn!("failed to derive initial audit key: {e} — audit-emitting routes disabled");
                None
            }
        }
    };

    // 1. DID resolver (local mode)
    let did_resolver = match DIDCacheClient::new(DIDCacheConfigBuilder::default().build()).await {
        Ok(r) => r,
        Err(e) => {
            warn!("failed to create DID resolver: {e} — auth endpoints will not work");
            return (None, None, None, None, install_signer, audit_writer);
        }
    };

    // 2. Secrets resolver with VTC's Ed25519 + X25519 secrets
    let (secrets_resolver, _handle) = ThreadedSecretsResolver::new(None).await;

    let mut signing_secret = Secret::generate_ed25519(None, Some(&*ed25519_bytes));
    signing_secret.id = format!("{vtc_did}#key-0");
    secrets_resolver.insert(signing_secret).await;

    match Secret::generate_x25519(None, Some(&*x25519_bytes)) {
        Ok(mut ka_secret) => {
            ka_secret.id = format!("{vtc_did}#key-1");
            secrets_resolver.insert(ka_secret).await;
        }
        Err(e) => warn!("failed to create VTC key-agreement secret: {e}"),
    }

    // 3. JWT signing key from config (random key, not derived from VTC keys)
    let jwt_keys = match &config.auth.jwt_signing_key {
        Some(b64) => match decode_jwt_key(b64) {
            Ok(k) => k,
            Err(e) => {
                warn!("failed to load JWT signing key: {e} — auth endpoints will not work");
                return (
                    Some(did_resolver),
                    Some(Arc::new(secrets_resolver)),
                    None,
                    None,
                    install_signer,
                    audit_writer,
                );
            }
        },
        None => {
            warn!(
                "auth.jwt_signing_key not configured — auth endpoints will not work (run setup first)"
            );
            return (
                Some(did_resolver),
                Some(Arc::new(secrets_resolver)),
                None,
                None,
                install_signer,
                audit_writer,
            );
        }
    };

    // 4. Build ATM for DIDComm message unpacking (used by auth endpoints)
    let secrets_resolver = Arc::new(secrets_resolver);
    let atm = {
        let tdk_config = TDKConfig::builder()
            .with_did_resolver(did_resolver.clone())
            .with_secrets_resolver((*secrets_resolver).clone())
            .with_load_environment(false)
            .build();
        match tdk_config {
            Ok(cfg) => match TDKSharedState::new(cfg).await {
                Ok(tdk) => {
                    match ATM::new(ATMConfig::builder().build().unwrap(), Arc::new(tdk)).await {
                        Ok(a) => Some(a),
                        Err(e) => {
                            warn!("failed to create ATM for auth unpack: {e}");
                            None
                        }
                    }
                }
                Err(e) => {
                    warn!("failed to create TDK shared state: {e}");
                    None
                }
            },
            Err(e) => {
                warn!("failed to build TDK config: {e}");
                None
            }
        }
    };

    info!("auth initialized for DID {vtc_did}");

    (
        Some(did_resolver),
        Some(secrets_resolver),
        Some(Arc::new(jwt_keys)),
        atm,
        install_signer,
        audit_writer,
    )
}

/// Decode a base64url-no-pad JWT signing key and construct `JwtKeys`.
fn decode_jwt_key(b64: &str) -> Result<JwtKeys, AppError> {
    let bytes = BASE64
        .decode(b64)
        .map_err(|e| AppError::Config(format!("invalid jwt_signing_key base64: {e}")))?;
    let key_bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| AppError::Config("jwt_signing_key must be exactly 32 bytes".into()))?;
    let keys = JwtKeys::from_ed25519_bytes(&key_bytes, "VTC")?;
    debug!("JWT signing key decoded successfully");
    Ok(keys)
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => info!("received SIGINT"),
        () = terminate => info!("received SIGTERM"),
    }
}

/// Pull the Ed25519 + X25519 private bytes out of whatever the
/// secret store handed us.
///
/// Accepts two on-disk shapes:
/// - **New** — a serialized [`VtcKeyBundle`] (JSON). Production
///   shape after `vtc setup`. Decoded via
///   [`VtcKeyBundle::from_secret_store_bytes`].
/// - **Legacy** — 64 raw bytes `[Ed25519:32 || X25519:32]`. Used
///   by integration-test fixtures and the not-yet-replaced
///   bootstrap CLI path. Synthesizes an in-memory bundle so
///   downstream code stays identical.
///
/// Returns `(ed25519_priv, x25519_priv)` on success; `Err(msg)`
/// otherwise. Both halves come back inside `Zeroizing` so a
/// best-effort scrub fires on drop.
fn decode_secret_store_value(
    vtc_did: &str,
    stored: &[u8],
) -> Result<(Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>), String> {
    if stored.len() == 64 {
        // Legacy raw-bytes shape — used by every integration-test
        // fixture today. Promote into a bundle-shaped pair via a
        // direct copy.
        let mut ed = Zeroizing::new([0u8; 32]);
        let mut x = Zeroizing::new([0u8; 32]);
        ed.copy_from_slice(&stored[..32]);
        x.copy_from_slice(&stored[32..]);
        return Ok((ed, x));
    }
    let bundle = VtcKeyBundle::from_secret_store_bytes(stored)
        .map_err(|e| format!("secret store payload not a VtcKeyBundle: {e}"))?;
    if bundle.integration_did != vtc_did {
        return Err(format!(
            "VtcKeyBundle DID '{}' does not match config.vtc_did '{}' — refusing to init auth",
            bundle.integration_did, vtc_did
        ));
    }
    let ed = bundle
        .ed25519_private_bytes()
        .map_err(|e| format!("bundle Ed25519 decode: {e}"))?;
    let x = bundle
        .x25519_private_bytes()
        .map_err(|e| format!("bundle X25519 decode: {e}"))?;
    Ok((ed, x))
}
