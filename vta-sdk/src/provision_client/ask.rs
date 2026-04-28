//! Holder-side parameters for an online `provision-integration` request.
//!
//! [`ProvisionAsk`] mirrors the SDK's
//! [`crate::provision_integration::BootstrapAsk::TemplateBootstrap`] without
//! requiring callers to construct `DidTemplateRef` directly. Use the typed
//! builders ([`ProvisionAsk::didcomm_mediator`], [`ProvisionAsk::webvh_control`],
//! [`ProvisionAsk::webvh_daemon`], [`ProvisionAsk::webvh_server`], etc.) for
//! the templates that ship with `vta-service`. For an operator-supplied
//! template, use [`ProvisionAsk::for_template`] with the template name and
//! variable bindings the template's `requiredVars` declares.
//!
//! Adding a built-in template to `vta-service` without adding a curated
//! builder here is an SDK-side bug — the equivalence tests at the bottom
//! of this file catch the drift.

use std::collections::BTreeMap;

use chrono::Duration;
use serde_json::Value;

use crate::provision_integration::ProvisionRequestBuilder;

/// Names of the built-in templates shipped by `vta-service`. Each one has
/// a typed builder below.
pub const BUILTIN_MEDIATOR_TEMPLATE: &str = "didcomm-mediator";
pub const BUILTIN_VTA_ADMIN_TEMPLATE: &str = "vta-admin";
pub const BUILTIN_WEBVH_CONTROL_TEMPLATE: &str = "webvh-control";
pub const BUILTIN_WEBVH_DAEMON_TEMPLATE: &str = "webvh-daemon";
pub const BUILTIN_WEBVH_SERVER_TEMPLATE: &str = "webvh-server";

/// Default validity on a wizard-issued VP for the online path — chosen to
/// comfortably cover the round-trip with the verifier's ±5min skew margin
/// without leaving a stale request valid long enough to resurface.
pub const DEFAULT_VALIDITY: Duration = Duration::minutes(15);

/// Holder-side parameters for an online provisioning request.
#[derive(Debug, Clone)]
pub struct ProvisionAsk {
    /// VTA context the integration will live in. Becomes the ACL scope.
    pub context: String,
    /// Template name for the integration's DID.
    pub integration_template: String,
    /// Variables supplied to the integration template renderer. Must
    /// satisfy the template's `requiredVars` at the VTA.
    pub integration_template_vars: BTreeMap<String, Value>,
    /// Template name for the VTA-minted long-term admin DID. When `None`,
    /// the authorization VC's subject stays the setup DID and no
    /// rollover happens — the legacy shape; not the default.
    pub admin_template: Option<String>,
    /// Variables supplied to the admin template renderer. Empty in the
    /// common case; the built-in `vta-admin` template takes none.
    pub admin_template_vars: BTreeMap<String, Value>,
    /// Operator-facing label for audit logs. Not covered by the VP proof
    /// cryptographically, but recorded in provisioning logs.
    pub label: Option<String>,
    /// VP freshness window. Defaults to [`DEFAULT_VALIDITY`].
    pub validity: Duration,
}

impl ProvisionAsk {
    /// Generic builder — caller supplies the template name and variable
    /// bindings. Use this for operator-supplied or third-party templates.
    /// For the built-ins, prefer the typed builders below.
    pub fn for_template(
        name: impl Into<String>,
        vars: BTreeMap<String, Value>,
        context: impl Into<String>,
    ) -> Self {
        Self {
            context: context.into(),
            integration_template: name.into(),
            integration_template_vars: vars,
            admin_template: Some(BUILTIN_VTA_ADMIN_TEMPLATE.to_string()),
            admin_template_vars: BTreeMap::new(),
            label: None,
            validity: DEFAULT_VALIDITY,
        }
    }

    /// Curated builder for the built-in `didcomm-mediator` template. Mints
    /// the mediator's integration DID with `URL` set to the public URL the
    /// mediator will accept DIDComm at.
    pub fn didcomm_mediator(context: impl Into<String>, mediator_url: impl Into<String>) -> Self {
        let mut vars = BTreeMap::new();
        vars.insert("URL".to_string(), Value::String(mediator_url.into()));
        Self::for_template(BUILTIN_MEDIATOR_TEMPLATE, vars, context)
    }

    /// Curated builder for the built-in `webvh-control` template. Mints
    /// a control-plane node's DID with both a `WebVHHosting` service at
    /// `host_url` and a `DIDCommMessaging` service routed through
    /// `mediator_did`. Use for nodes that both publish DID logs over HTTP
    /// and accept DIDComm (admin RPC, witness coordination, etc.).
    pub fn webvh_control(
        context: impl Into<String>,
        host_url: impl Into<String>,
        mediator_did: impl Into<String>,
    ) -> Self {
        let mut vars = BTreeMap::new();
        vars.insert("URL".to_string(), Value::String(host_url.into()));
        vars.insert(
            "MEDIATOR_DID".to_string(),
            Value::String(mediator_did.into()),
        );
        Self::for_template(BUILTIN_WEBVH_CONTROL_TEMPLATE, vars, context)
    }

    /// Curated builder for the built-in `webvh-daemon` template. Mints a
    /// hosting daemon's DID with a `WebVHHosting` service at `host_url`.
    /// No DIDComm — use [`Self::webvh_control`] if the daemon also needs
    /// to accept DIDComm.
    pub fn webvh_daemon(context: impl Into<String>, host_url: impl Into<String>) -> Self {
        let mut vars = BTreeMap::new();
        vars.insert("URL".to_string(), Value::String(host_url.into()));
        Self::for_template(BUILTIN_WEBVH_DAEMON_TEMPLATE, vars, context)
    }

    /// Curated builder for the built-in `webvh-server` template. Mints a
    /// witness/watcher/server DID that talks DIDComm through
    /// `mediator_did` and exposes no public HTTP endpoint. The DID
    /// document carries only a `DIDCommMessaging` service.
    pub fn webvh_server(context: impl Into<String>, mediator_did: impl Into<String>) -> Self {
        let mut vars = BTreeMap::new();
        vars.insert(
            "MEDIATOR_DID".to_string(),
            Value::String(mediator_did.into()),
        );
        Self::for_template(BUILTIN_WEBVH_SERVER_TEMPLATE, vars, context)
    }

    /// Curated builder for the built-in `vta-admin` template — mint a
    /// standalone long-term admin DID without an associated integration.
    /// The admin-rollover path is disabled (the integration template *is*
    /// the admin template here).
    pub fn vta_admin(context: impl Into<String>) -> Self {
        let mut ask = Self::for_template(BUILTIN_VTA_ADMIN_TEMPLATE, BTreeMap::new(), context);
        ask.admin_template = None;
        ask
    }

    /// Attach a human-readable audit label.
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    /// Override the VP freshness window. Online callers stick with
    /// [`DEFAULT_VALIDITY`].
    pub fn with_validity(mut self, d: Duration) -> Self {
        self.validity = d;
        self
    }

    /// Disable admin-DID rollover — the VC subject stays the setup DID,
    /// and no second DID is minted. Rarely what production callers want;
    /// exposed for tests that pin the legacy shape.
    #[cfg(test)]
    pub fn without_admin_rollover(mut self) -> Self {
        self.admin_template = None;
        self.admin_template_vars.clear();
        self
    }

    /// Translate this ask into a fully-configured
    /// [`ProvisionRequestBuilder`]. The caller chooses how to sign:
    /// [`ProvisionRequestBuilder::sign_with`] for an existing keypair, or
    /// [`ProvisionRequestBuilder::sign_ephemeral`] for a fresh one.
    pub(crate) fn to_builder(&self) -> ProvisionRequestBuilder {
        let mut builder = ProvisionRequestBuilder::new(self.integration_template.clone())
            .vars(self.integration_template_vars.clone())
            .context_hint(self.context.clone())
            .validity(self.validity);
        if let Some(ref name) = self.admin_template {
            builder = builder.admin_template(name.clone());
            for (k, v) in &self.admin_template_vars {
                builder = builder.admin_template_var(k.clone(), v.clone());
            }
        }
        if let Some(ref label) = self.label {
            builder = builder.label(label.clone()).note(label.clone());
        }
        builder
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::did_templates::load_embedded;
    use crate::provision_integration::BootstrapAsk;

    #[test]
    fn builtin_template_constants_resolve_in_registry() {
        // Drift detector: every curated builder uses one of these
        // constants as its template name. If `vta-service` renames or
        // removes a built-in, this fails.
        for name in [
            BUILTIN_MEDIATOR_TEMPLATE,
            BUILTIN_VTA_ADMIN_TEMPLATE,
            BUILTIN_WEBVH_CONTROL_TEMPLATE,
            BUILTIN_WEBVH_DAEMON_TEMPLATE,
            BUILTIN_WEBVH_SERVER_TEMPLATE,
        ] {
            load_embedded(name).unwrap_or_else(|e| {
                panic!("built-in template {name} not in vta-sdk registry: {e}")
            });
        }
    }

    #[test]
    fn didcomm_mediator_sets_url_var_and_template() {
        let ask = ProvisionAsk::didcomm_mediator("ctx", "https://m.example.com");
        assert_eq!(ask.context, "ctx");
        assert_eq!(ask.integration_template, BUILTIN_MEDIATOR_TEMPLATE);
        assert_eq!(
            ask.integration_template_vars["URL"],
            Value::String("https://m.example.com".into())
        );
        assert_eq!(
            ask.admin_template.as_deref(),
            Some(BUILTIN_VTA_ADMIN_TEMPLATE)
        );
        assert_eq!(ask.validity, DEFAULT_VALIDITY);
    }

    #[test]
    fn webvh_server_sets_mediator_did_var() {
        let ask = ProvisionAsk::webvh_server("ctx", "did:webvh:m.example.com");
        assert_eq!(ask.integration_template, BUILTIN_WEBVH_SERVER_TEMPLATE);
        assert_eq!(
            ask.integration_template_vars["MEDIATOR_DID"],
            Value::String("did:webvh:m.example.com".into())
        );
    }

    #[test]
    fn webvh_daemon_sets_url_var() {
        let ask = ProvisionAsk::webvh_daemon("ctx", "https://h.example.com");
        assert_eq!(ask.integration_template, BUILTIN_WEBVH_DAEMON_TEMPLATE);
        assert_eq!(
            ask.integration_template_vars["URL"],
            Value::String("https://h.example.com".into())
        );
    }

    #[test]
    fn webvh_control_sets_url_and_mediator_did_vars() {
        let ask =
            ProvisionAsk::webvh_control("ctx", "https://h.example.com", "did:webvh:m.example.com");
        assert_eq!(ask.integration_template, BUILTIN_WEBVH_CONTROL_TEMPLATE);
        assert_eq!(
            ask.integration_template_vars["URL"],
            Value::String("https://h.example.com".into())
        );
        assert_eq!(
            ask.integration_template_vars["MEDIATOR_DID"],
            Value::String("did:webvh:m.example.com".into())
        );
    }

    #[test]
    fn vta_admin_disables_rollover() {
        let ask = ProvisionAsk::vta_admin("ctx");
        assert_eq!(ask.integration_template, BUILTIN_VTA_ADMIN_TEMPLATE);
        assert!(ask.integration_template_vars.is_empty());
        assert!(ask.admin_template.is_none());
    }

    #[test]
    fn for_template_defaults_to_admin_rollover_via_vta_admin() {
        let ask = ProvisionAsk::for_template("custom-template", BTreeMap::new(), "ctx");
        assert_eq!(ask.integration_template, "custom-template");
        assert_eq!(
            ask.admin_template.as_deref(),
            Some(BUILTIN_VTA_ADMIN_TEMPLATE)
        );
    }

    #[test]
    fn without_admin_rollover_clears_admin_fields() {
        let ask = ProvisionAsk::didcomm_mediator("ctx", "https://m").without_admin_rollover();
        assert!(ask.admin_template.is_none());
        assert!(ask.admin_template_vars.is_empty());
    }

    /// Snapshot the builder output for one curated builder vs `for_template`
    /// with the equivalent vars. Confirms the curated path produces an
    /// identical `BootstrapAsk` shape.
    #[tokio::test]
    async fn curated_didcomm_mediator_equivalent_to_for_template() {
        let curated = ProvisionAsk::didcomm_mediator("ctx", "https://m.example.com");

        let mut vars = BTreeMap::new();
        vars.insert(
            "URL".to_string(),
            Value::String("https://m.example.com".into()),
        );
        let generic = ProvisionAsk::for_template(BUILTIN_MEDIATOR_TEMPLATE, vars, "ctx");

        assert_signed_vps_have_equivalent_ask(&curated, &generic).await;
    }

    #[tokio::test]
    async fn curated_webvh_server_equivalent_to_for_template() {
        let curated = ProvisionAsk::webvh_server("ctx", "did:webvh:m.example.com");

        let mut vars = BTreeMap::new();
        vars.insert(
            "MEDIATOR_DID".to_string(),
            Value::String("did:webvh:m.example.com".into()),
        );
        let generic = ProvisionAsk::for_template(BUILTIN_WEBVH_SERVER_TEMPLATE, vars, "ctx");

        assert_signed_vps_have_equivalent_ask(&curated, &generic).await;
    }

    #[tokio::test]
    async fn curated_webvh_daemon_equivalent_to_for_template() {
        let curated = ProvisionAsk::webvh_daemon("ctx", "https://h.example.com");

        let mut vars = BTreeMap::new();
        vars.insert(
            "URL".to_string(),
            Value::String("https://h.example.com".into()),
        );
        let generic = ProvisionAsk::for_template(BUILTIN_WEBVH_DAEMON_TEMPLATE, vars, "ctx");

        assert_signed_vps_have_equivalent_ask(&curated, &generic).await;
    }

    #[tokio::test]
    async fn curated_webvh_control_equivalent_to_for_template() {
        let curated =
            ProvisionAsk::webvh_control("ctx", "https://h.example.com", "did:webvh:m.example.com");

        let mut vars = BTreeMap::new();
        vars.insert(
            "URL".to_string(),
            Value::String("https://h.example.com".into()),
        );
        vars.insert(
            "MEDIATOR_DID".to_string(),
            Value::String("did:webvh:m.example.com".into()),
        );
        let generic = ProvisionAsk::for_template(BUILTIN_WEBVH_CONTROL_TEMPLATE, vars, "ctx");

        assert_signed_vps_have_equivalent_ask(&curated, &generic).await;
    }

    /// vta-admin disables admin rollover, so the equivalence is against a
    /// `for_template(...)` that has been similarly stripped.
    #[tokio::test]
    async fn curated_vta_admin_equivalent_to_for_template_without_rollover() {
        let curated = ProvisionAsk::vta_admin("ctx");

        let mut generic =
            ProvisionAsk::for_template(BUILTIN_VTA_ADMIN_TEMPLATE, BTreeMap::new(), "ctx");
        generic.admin_template = None;

        assert_signed_vps_have_equivalent_ask(&curated, &generic).await;
    }

    /// Sign each ask with deterministic key material and assert the two
    /// resulting `BootstrapAsk::TemplateBootstrap` values match field-for-
    /// field. The signed VP's nonce / signature differ between calls
    /// (RNG-driven), but the embedded ask is fully determined by the
    /// builder inputs.
    async fn assert_signed_vps_have_equivalent_ask(a: &ProvisionAsk, b: &ProvisionAsk) {
        let (seed, pub_bytes) = crate::sealed_transfer::generate_ed25519_keypair();
        let client_did = affinidi_crypto::did_key::ed25519_pub_to_did_key(&pub_bytes);

        let vp_a = a
            .to_builder()
            .sign_with(&seed, &client_did)
            .await
            .expect("sign curated");
        let vp_b = b
            .to_builder()
            .sign_with(&seed, &client_did)
            .await
            .expect("sign generic");

        let BootstrapAsk::TemplateBootstrap(inner_a) = &vp_a.ask;
        let BootstrapAsk::TemplateBootstrap(inner_b) = &vp_b.ask;

        assert_eq!(inner_a.template.name, inner_b.template.name);
        assert_eq!(inner_a.template.vars, inner_b.template.vars);
        assert_eq!(inner_a.context_hint, inner_b.context_hint);
        assert_eq!(
            inner_a.admin_template.as_ref().map(|t| &t.name),
            inner_b.admin_template.as_ref().map(|t| &t.name)
        );
        assert_eq!(
            inner_a.admin_template.as_ref().map(|t| &t.vars),
            inner_b.admin_template.as_ref().map(|t| &t.vars)
        );
    }
}
