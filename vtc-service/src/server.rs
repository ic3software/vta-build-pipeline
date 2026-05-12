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
use crate::store::{KeyspaceHandle, Store};
use crate::supervisor::{SupervisorKind, detect_supervisor};
use tokio::sync::{RwLock, watch};
use tower_http::trace::TraceLayer;
use tracing::{debug, error, info, warn};
use vti_common::audit::{AuditKeyStore, AuditWriter};
use vti_common::auth::passkey::{PasskeyState, build_webauthn};
use webauthn_rs::Webauthn;

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

    // Spawn three named OS threads
    let mut rest_shutdown_rx = shutdown_rx.clone();
    let rest_handle = std::thread::Builder::new()
        .name("vtc-rest".into())
        .spawn(move || run_rest_thread(std_listener, state, &mut rest_shutdown_rx))
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

/// REST thread: serves the Axum HTTP server.
fn run_rest_thread(
    std_listener: std::net::TcpListener,
    state: AppState,
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

        let app = routes::router()
            .with_state(state)
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
/// Loads 64 raw bytes from the secret store: first 32 = Ed25519 signing key,
/// last 32 = X25519 key-agreement key.
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

    // Load key material from secret store (64 bytes: 32 Ed25519 + 32 X25519)
    let key_material = match secret_store.get().await {
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

    if key_material.len() != 64 {
        warn!(
            "key material is {} bytes, expected 64 — auth endpoints will not work",
            key_material.len()
        );
        return (None, None, None, None, None, None);
    }

    let Ok(ed25519_bytes): Result<&[u8; 32], _> = key_material[..32].try_into() else {
        warn!("key material corrupted — auth endpoints will not work");
        return (None, None, None, None, None, None);
    };
    let Ok(x25519_bytes): Result<&[u8; 32], _> = key_material[32..].try_into() else {
        warn!("key material corrupted — auth endpoints will not work");
        return (None, None, None, None, None, None);
    };

    // Derive the install-token signer from the full 64-byte secret.
    // HKDF's `info = "vtc-install-jwt-key/v1"` domain-separates this
    // key from every other seed-derived secret in the daemon (audit
    // key, future session key). Available even if downstream auth
    // init fails, so the install routes can run before the VTC's
    // own DIDComm transport comes up.
    let install_signer = match InstallTokenSigner::from_master_seed(&key_material) {
        Ok(s) => Some(Arc::new(s)),
        Err(e) => {
            warn!("failed to derive install token signer: {e} — install routes disabled");
            None
        }
    };

    // Derive the HMAC audit key from the same master seed (different
    // HKDF `info`) and build the writer. Idempotent across restarts;
    // the very first boot creates an `Initial` row and the active
    // marker, subsequent boots no-op.
    let audit_writer = {
        let key_store = AuditKeyStore::new(audit_key_ks);
        match key_store.ensure_initial(&key_material).await {
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

    let mut signing_secret = Secret::generate_ed25519(None, Some(ed25519_bytes));
    signing_secret.id = format!("{vtc_did}#key-0");
    secrets_resolver.insert(signing_secret).await;

    match Secret::generate_x25519(None, Some(x25519_bytes)) {
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
