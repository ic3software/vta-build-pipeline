use serde::{Deserialize, Serialize};

/// Client sends to `POST /auth/challenge`.
///
/// Wire shape conforms to `spec/auth/challenge/0.1`: the `did` field
/// serialises as `subject` per the canonical payload schema. The Rust
/// identifier stays `did` for consistency with `AuthClaims.did` and
/// the rest of the codebase. `alias = "did"` keeps clients that still
/// send the legacy name working through one upgrade cycle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeRequest {
    #[serde(rename = "subject", alias = "did")]
    pub did: String,
}

/// Trust-task payload for `spec/vta/auth/revoke-session/1.0` (request)
/// — revoke a single session by id.
///
/// Authorisation: the caller (via `AuthClaims`) must own the session
/// OR have `Role::Admin`. Enforced in the dispatcher handler, not the
/// schema.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RevokeSessionRequest {
    /// Identifier of the session to revoke.
    pub session_id: String,
}

/// Trust-task payload for `spec/vta/auth/revoke-session/1.0#response`
/// — empty success body.
///
/// Modelled as a struct (rather than `()`) so future fields (e.g.
/// `revokedAt: DateTime<Utc>`) can be added without a wire-format
/// version bump (additive per serde defaults).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct RevokeSessionResponse {}

/// Server responds from `POST /auth/challenge`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChallengeResponse {
    pub session_id: String,
    pub data: ChallengeData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChallengeData {
    pub challenge: String,
    /// TEE attestation evidence bound to the challenge nonce.
    /// Present when the VTA is running inside a TEE, proving the challenge
    /// was generated within a trusted execution environment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tee_attestation: Option<serde_json::Value>,
}

/// Server responds from `POST /auth/`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticateResponse {
    #[serde(default)]
    pub session_id: Option<String>,
    pub data: AuthenticateData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticateData {
    pub access_token: String,
    pub access_expires_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_expires_at: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn revoke_session_request_round_trips() {
        let req = RevokeSessionRequest {
            session_id: "sess-abc-123".to_string(),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"sessionId\":\"sess-abc-123\""), "{json}");
        let parsed: RevokeSessionRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.session_id, "sess-abc-123");
    }

    #[test]
    fn revoke_session_response_is_empty_object() {
        let resp = RevokeSessionResponse::default();
        let json = serde_json::to_string(&resp).unwrap();
        assert_eq!(json, "{}", "empty success body");
    }

    #[test]
    fn test_challenge_response_camel_case() {
        let json = r#"{
            "sessionId": "sess-abc",
            "data": { "challenge": "nonce123" }
        }"#;
        let resp: ChallengeResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.session_id, "sess-abc");
        assert_eq!(resp.data.challenge, "nonce123");
    }

    #[test]
    fn test_authenticate_response_camel_case() {
        let json = r#"{
            "data": {
                "accessToken": "jwt.token.here",
                "accessExpiresAt": 1700001000
            }
        }"#;
        let resp: AuthenticateResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.data.access_token, "jwt.token.here");
        assert_eq!(resp.data.access_expires_at, 1700001000);
        assert!(resp.session_id.is_none());
        assert!(resp.data.refresh_token.is_none());
        assert!(resp.data.refresh_expires_at.is_none());
    }

    #[test]
    fn test_authenticate_response_full() {
        let json = r#"{
            "sessionId": "sess-123",
            "data": {
                "accessToken": "jwt.token.here",
                "accessExpiresAt": 1700001000,
                "refreshToken": "refresh-abc",
                "refreshExpiresAt": 1700002000
            }
        }"#;
        let resp: AuthenticateResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.session_id.as_deref(), Some("sess-123"));
        assert_eq!(resp.data.access_token, "jwt.token.here");
        assert_eq!(resp.data.access_expires_at, 1700001000);
        assert_eq!(resp.data.refresh_token.as_deref(), Some("refresh-abc"));
        assert_eq!(resp.data.refresh_expires_at, Some(1700002000));
    }

    #[test]
    fn test_challenge_request_serialize() {
        // Wire format conforms to spec/auth/challenge/0.1: the field
        // is `subject` on the wire (canonical). `did` is accepted on
        // input via `serde(alias)` for backwards compatibility.
        let req = ChallengeRequest {
            did: "did:key:z6Mk123".to_string(),
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["subject"], "did:key:z6Mk123");
        assert!(json.get("did").is_none());

        // Legacy clients still sending `did` continue to parse.
        let legacy: ChallengeRequest = serde_json::from_str(r#"{"did":"did:key:legacy"}"#).unwrap();
        assert_eq!(legacy.did, "did:key:legacy");
    }

    #[test]
    fn test_authenticate_response_serialize_skips_none() {
        let resp = AuthenticateResponse {
            session_id: Some("sess-1".to_string()),
            data: AuthenticateData {
                access_token: "tok".to_string(),
                access_expires_at: 100,
                refresh_token: None,
                refresh_expires_at: None,
            },
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert!(json["data"].get("refreshToken").is_none());
        assert!(json["data"].get("refreshExpiresAt").is_none());
    }
}
