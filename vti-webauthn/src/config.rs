//! Verifier configuration.
//!
//! [`VerifierConfig`] pins the Relying-Party ID, expected origin, and
//! user-verification policy that every call to [`crate::verify_assertion`]
//! evaluates against. Construct it once at boot from your service's public
//! URL and reuse across requests.

use thiserror::Error;
use url::Url;

/// Configuration for the WebAuthn assertion verifier.
#[derive(Debug, Clone)]
pub struct VerifierConfig {
    /// Relying-Party ID expected in `authenticatorData.rpIdHash`.
    /// Bare hostname only — no scheme, no port, no path.
    ///
    /// Example: `"control.example.com"`.
    pub rp_id: String,

    /// Origin expected in `clientData.origin`. Includes scheme; default
    /// port stripped (443 for `https`, 80 for `http`). Case-normalised to
    /// lowercase host.
    ///
    /// Example: `"https://control.example.com"`.
    pub expected_origin: String,

    /// When `true`, the UV (user-verified) flag MUST be set on the
    /// assertion. When `false`, UV is informational only — surfaced via
    /// [`crate::VerifiedAssertion::user_verified`] for the caller to
    /// apply its own policy.
    pub require_user_verification: bool,
}

impl VerifierConfig {
    /// Construct a config from the service's public URL.
    ///
    /// Normalisation rules (matches WebAuthn-spec browser behaviour):
    /// - Host is lowercased.
    /// - Port is stripped if it equals the scheme default (443 for
    ///   `https`, 80 for `http`); any other port is preserved.
    /// - No path, query, or fragment are kept — only `scheme://host[:port]`.
    /// - Only `https` and `http` schemes are accepted.
    ///
    /// Errors if the URL is malformed, has no host, or uses an
    /// unsupported scheme.
    pub fn from_public_url(public_url: &str, require_uv: bool) -> Result<Self, ConfigError> {
        let url = Url::parse(public_url)
            .map_err(|e| ConfigError::InvalidUrl(format!("parse failed: {e}")))?;

        let scheme = url.scheme();
        if scheme != "https" && scheme != "http" {
            return Err(ConfigError::InvalidUrl(format!(
                "scheme must be https or http; got {scheme}"
            )));
        }

        let host = url
            .host_str()
            .ok_or(ConfigError::NoHostInUrl)?
            .to_ascii_lowercase();
        if host.is_empty() {
            return Err(ConfigError::NoHostInUrl);
        }

        let port_segment = match url.port() {
            None => String::new(),
            Some(p) if p == default_port(scheme) => String::new(),
            Some(p) => format!(":{p}"),
        };

        let expected_origin = format!("{scheme}://{host}{port_segment}");

        Ok(Self {
            rp_id: host,
            expected_origin,
            require_user_verification: require_uv,
        })
    }
}

/// Default port for the supported schemes.
const fn default_port(scheme: &str) -> u16 {
    match scheme.as_bytes() {
        b"https" => 443,
        b"http" => 80,
        // Caller has already validated scheme before this is reached.
        _ => 0,
    }
}

/// Errors constructing a [`VerifierConfig`].
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum ConfigError {
    /// The supplied URL could not be parsed or used an unsupported scheme.
    #[error("invalid public_url: {0}")]
    InvalidUrl(String),
    /// The URL parsed but had no host component (file://, relative, etc.).
    #[error("public_url has no host component")]
    NoHostInUrl,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_simple_https_url() {
        let c = VerifierConfig::from_public_url("https://control.example.com", true).unwrap();
        assert_eq!(c.rp_id, "control.example.com");
        assert_eq!(c.expected_origin, "https://control.example.com");
        assert!(c.require_user_verification);
    }

    #[test]
    fn strips_default_https_port() {
        let c = VerifierConfig::from_public_url("https://example.com:443", false).unwrap();
        assert_eq!(c.rp_id, "example.com");
        assert_eq!(c.expected_origin, "https://example.com");
        assert!(!c.require_user_verification);
    }

    #[test]
    fn strips_default_http_port() {
        let c = VerifierConfig::from_public_url("http://example.com:80", false).unwrap();
        assert_eq!(c.expected_origin, "http://example.com");
    }

    #[test]
    fn preserves_non_default_port() {
        let c = VerifierConfig::from_public_url("https://example.com:8443", false).unwrap();
        assert_eq!(c.expected_origin, "https://example.com:8443");
    }

    #[test]
    fn lowercases_host() {
        let c = VerifierConfig::from_public_url("https://EXAMPLE.com", false).unwrap();
        assert_eq!(c.rp_id, "example.com");
        assert_eq!(c.expected_origin, "https://example.com");
    }

    #[test]
    fn ignores_path_query_fragment() {
        let c =
            VerifierConfig::from_public_url("https://example.com/some/path?query=1#frag", false)
                .unwrap();
        assert_eq!(c.expected_origin, "https://example.com");
    }

    #[test]
    fn rejects_non_http_scheme() {
        let err = VerifierConfig::from_public_url("ftp://example.com", false).unwrap_err();
        assert!(
            matches!(err, ConfigError::InvalidUrl(ref s) if s.contains("scheme")),
            "got {err:?}"
        );
    }

    #[test]
    fn rejects_malformed_url() {
        let err = VerifierConfig::from_public_url("not a url", false).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidUrl(_)), "got {err:?}");
    }

    #[test]
    fn rejects_url_without_host() {
        // file:// URLs parse but have no host.
        let err = VerifierConfig::from_public_url("file:///path", false).unwrap_err();
        assert!(
            matches!(err, ConfigError::InvalidUrl(_) | ConfigError::NoHostInUrl),
            "got {err:?}"
        );
    }
}
