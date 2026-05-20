//! Test-only helper for the vti-didcomm-js round-trip harness.
//!
//! Reads a JSON blob from stdin describing a JWE to unpack:
//!
//! ```json
//! {
//!   "jwe": "<the full JWE JSON string>",
//!   "recipient_kid": "did:example:recipient#x",
//!   "recipient_private_x_b64u": "<base64url 32-byte X25519 scalar>",
//!   "sender_public_x_b64u": "<base64url 32-byte X25519 public key>"
//! }
//! ```
//!
//! Calls `affinidi-messaging-didcomm::unpack` (the same code path
//! the VTA's DIDComm router uses) and emits one of:
//!
//! ```json
//! { "ok": true, "plaintext": <the unpacked Message as JSON>,
//!   "sender_kid": "...", "recipient_kid": "...", "authenticated": true }
//! ```
//! ```json
//! { "ok": false, "error": "..." }
//! ```
//!
//! Designed for `Node:child_process.spawn` from the JS test runner.
//! Process exits 0 on either outcome — failures land in the `ok`
//! field so the test can assert on a structured shape. Non-zero
//! exit only on stdin/stdout I/O or JSON-parse errors before we
//! got to the unpack call.

use std::io::{self, Read, Write};

use affinidi_messaging_didcomm::{
    crypto::key_agreement::{Curve, PrivateKeyAgreement, PublicKeyAgreement},
    message::unpack::{UnpackResult, unpack},
};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Deserialize)]
struct Request {
    jwe: String,
    recipient_kid: String,
    recipient_private_x_b64u: String,
    /// Optional — when absent the Rust unpack runs without sender
    /// auth verification (anoncrypt-style); when present it requires
    /// the authcrypt sender key to match.
    #[serde(default)]
    sender_public_x_b64u: Option<String>,
}

fn main() {
    // Single fallible path then a `match` on the outcome — keeps
    // the structured-error envelope shape consistent across all
    // failure modes.
    match run() {
        Ok(value) => {
            println!("{value}");
        }
        Err(e) => {
            // Differentiate I/O / parse failures (eprintln + exit
            // code) from unpack failures (which are reported as
            // `ok: false` in the JSON envelope, exit 0). Anything
            // that lands here is the former.
            eprintln!("didcomm-unpack helper: {e}");
            std::process::exit(1);
        }
    }
}

fn run() -> Result<String, String> {
    let mut input = String::new();
    io::stdin()
        .read_to_string(&mut input)
        .map_err(|e| format!("read stdin: {e}"))?;
    io::stdout()
        .flush()
        .map_err(|e| format!("flush stdout: {e}"))?;

    let req: Request =
        serde_json::from_str(&input).map_err(|e| format!("parse request JSON: {e}"))?;

    let recipient_private_bytes = URL_SAFE_NO_PAD
        .decode(&req.recipient_private_x_b64u)
        .map_err(|e| format!("decode recipient_private_x_b64u: {e}"))?;
    let recipient_private =
        PrivateKeyAgreement::from_raw_bytes(Curve::X25519, &recipient_private_bytes)
            .map_err(|e| format!("build PrivateKeyAgreement: {e}"))?;

    let sender_public = if let Some(s) = &req.sender_public_x_b64u {
        let bytes = URL_SAFE_NO_PAD
            .decode(s)
            .map_err(|e| format!("decode sender_public_x_b64u: {e}"))?;
        let arr: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| "sender_public_x must be 32 bytes".to_string())?;
        Some(PublicKeyAgreement::X25519(arr))
    } else {
        None
    };

    // The unpack call itself — every failure here lands in the
    // structured response, not a non-zero exit.
    let result = unpack(
        &req.jwe,
        Some(&req.recipient_kid),
        Some(&recipient_private),
        sender_public.as_ref(),
        /* signer_public */ None,
    );

    let envelope: Value = match result {
        Ok(UnpackResult::Encrypted {
            message,
            authenticated,
            sender_kid,
            recipient_kid,
        }) => {
            let plaintext = message_to_json(&message)?;
            json!({
                "ok": true,
                "kind": "encrypted",
                "plaintext": plaintext,
                "authenticated": authenticated,
                "sender_kid": sender_kid,
                "recipient_kid": recipient_kid,
            })
        }
        Ok(UnpackResult::Signed {
            message,
            signer_kid,
        }) => {
            let plaintext = message_to_json(&message)?;
            json!({
                "ok": true,
                "kind": "signed",
                "plaintext": plaintext,
                "signer_kid": signer_kid,
            })
        }
        Ok(UnpackResult::Plaintext(message)) => {
            let plaintext = message_to_json(&message)?;
            json!({
                "ok": true,
                "kind": "plaintext",
                "plaintext": plaintext,
            })
        }
        Err(e) => json!({
            "ok": false,
            "error": e.to_string(),
        }),
    };

    serde_json::to_string(&envelope).map_err(|e| format!("serialize response: {e}"))
}

/// `affinidi_messaging_didcomm::message::Message` doesn't impl
/// Serialize for arbitrary inspection — serialize it to JSON via
/// the crate's `to_json()` method and re-parse so the caller sees
/// the full plaintext shape.
fn message_to_json(msg: &affinidi_messaging_didcomm::message::Message) -> Result<Value, String> {
    let bytes = msg
        .to_json()
        .map_err(|e| format!("Message::to_json: {e}"))?;
    let s = std::str::from_utf8(&bytes).map_err(|e| format!("Message JSON not UTF-8: {e}"))?;
    serde_json::from_str(s).map_err(|e| format!("re-parse Message JSON: {e}"))
}
