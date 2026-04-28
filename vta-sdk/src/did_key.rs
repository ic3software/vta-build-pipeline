/// Encode an Ed25519 public key as a multibase Base58BTC string with multicodec prefix `0xed01`.
pub fn ed25519_multibase_pubkey(public_key_bytes: &[u8; 32]) -> String {
    let mut buf = Vec::with_capacity(34);
    buf.extend_from_slice(&[0xed, 0x01]);
    buf.extend_from_slice(public_key_bytes);
    multibase::encode(multibase::Base::Base58Btc, &buf)
}

/// Known 2-byte multicodec varint prefix for Ed25519 public keys.
const ED25519_PUB_CODEC: [u8; 2] = [0xed, 0x01];

/// Decode an Ed25519 public key from its multibase form. Inverse of
/// [`ed25519_multibase_pubkey`]. Accepts both multicodec-prefixed
/// (`0xed01`) and raw-bytes encodings; returns the 32-byte key.
pub fn decode_ed25519_public_key_multibase(mb: &str) -> Result<[u8; 32], DidKeyError> {
    let (_, raw) = multibase::decode(mb).map_err(|e| DidKeyError::Multibase(e.to_string()))?;
    let key_bytes = if raw.len() >= 2 && [raw[0], raw[1]] == ED25519_PUB_CODEC {
        &raw[2..]
    } else {
        &raw[..]
    };
    key_bytes
        .try_into()
        .map_err(|_| DidKeyError::InvalidSeedLength)
}

/// Known 2-byte multicodec varint prefixes for private keys.
const ED25519_PRIV_CODEC: [u8; 2] = [0x80, 0x26]; // 0x1300
const X25519_PRIV_CODEC: [u8; 2] = [0x82, 0x26]; // 0x1302
const P256_PRIV_CODEC: [u8; 2] = [0x86, 0x26]; // 0x1306

/// Decode a multibase-encoded private key to raw bytes.
///
/// Accepts both:
/// - Multicodec-prefixed: 2-byte prefix + raw key bytes (standard format)
/// - Raw: just the key bytes (legacy/backwards-compatible)
///
/// Strips known private-key multicodec prefixes (Ed25519, X25519, P256)
/// before returning the raw key bytes.
pub fn decode_private_key_multibase(mb: &str) -> Result<[u8; 32], DidKeyError> {
    let (_, raw) = multibase::decode(mb).map_err(|e| DidKeyError::Multibase(e.to_string()))?;
    let key_bytes = if raw.len() >= 2 {
        match [raw[0], raw[1]] {
            ED25519_PRIV_CODEC | X25519_PRIV_CODEC | P256_PRIV_CODEC => &raw[2..],
            _ => &raw[..],
        }
    } else {
        &raw[..]
    };
    key_bytes
        .try_into()
        .map_err(|_| DidKeyError::InvalidSeedLength)
}

/// Ed25519 signing + X25519 key-agreement secrets for a `did:key`.
#[cfg(feature = "didcomm")]
pub struct DidKeySecrets {
    pub signing: affinidi_tdk::secrets_resolver::secrets::Secret,
    pub key_agreement: affinidi_tdk::secrets_resolver::secrets::Secret,
}

/// Construct Ed25519 signing + X25519 key-agreement secrets for a `did:key`.
///
/// The `did` must start with `did:key:`. The `seed` is the 32-byte Ed25519
/// private key seed.
#[cfg(feature = "didcomm")]
pub fn secrets_from_did_key(did: &str, seed: &[u8; 32]) -> Result<DidKeySecrets, DidKeyError> {
    use affinidi_tdk::secrets_resolver::secrets::Secret;

    let ed_pub_mb = did
        .strip_prefix("did:key:")
        .ok_or(DidKeyError::InvalidDidKey)?;

    // Ed25519 signing secret
    let mut signing = Secret::generate_ed25519(None, Some(seed));
    signing.id = format!("{did}#{ed_pub_mb}");

    // X25519 key-agreement secret (derived from Ed25519)
    let mut key_agreement = signing
        .to_x25519()
        .map_err(|e| DidKeyError::X25519Conversion(e.to_string()))?;
    let x_pub_mb = key_agreement
        .get_public_keymultibase()
        .map_err(|e| DidKeyError::X25519Conversion(e.to_string()))?;
    key_agreement.id = format!("{did}#{x_pub_mb}");

    Ok(DidKeySecrets {
        signing,
        key_agreement,
    })
}

#[derive(Debug)]
pub enum DidKeyError {
    Multibase(String),
    InvalidSeedLength,
    InvalidDidKey,
    #[cfg(feature = "didcomm")]
    X25519Conversion(String),
}

impl std::fmt::Display for DidKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Multibase(e) => write!(f, "invalid private key multibase: {e}"),
            Self::InvalidSeedLength => write!(f, "private key seed must be 32 bytes"),
            Self::InvalidDidKey => write!(f, "invalid did:key format"),
            #[cfg(feature = "didcomm")]
            Self::X25519Conversion(e) => write!(f, "X25519 conversion failed: {e}"),
        }
    }
}

impl std::error::Error for DidKeyError {}

/// Convert a [`GetKeySecretResponse`](crate::client::GetKeySecretResponse) into
/// an `affinidi_tdk` [`Secret`].
///
/// The response's `private_key_multibase` is a multicodec-prefixed multibase
/// string (e.g. ed25519-priv `0x8026`). `Secret::from_multibase` handles the
/// decoding for all supported key types.
#[cfg(feature = "client")]
pub fn secret_from_key_response(
    resp: &crate::client::GetKeySecretResponse,
) -> Result<affinidi_tdk::secrets_resolver::secrets::Secret, DidKeyError> {
    affinidi_tdk::secrets_resolver::secrets::Secret::from_multibase(
        &resp.private_key_multibase,
        None,
    )
    .map_err(|e| DidKeyError::Multibase(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ed25519_multibase_pubkey_format() {
        let key = [0u8; 32];
        let result = ed25519_multibase_pubkey(&key);
        // Should start with 'z' (Base58BTC) and decode to [0xed, 0x01] + key
        assert!(result.starts_with('z'));

        let (_, decoded) = multibase::decode(&result).unwrap();
        assert_eq!(decoded.len(), 34);
        assert_eq!(decoded[0], 0xed);
        assert_eq!(decoded[1], 0x01);
        assert_eq!(&decoded[2..], &key);
    }

    #[test]
    fn test_decode_private_key_multibase_roundtrip() {
        let seed = [42u8; 32];
        let encoded = multibase::encode(multibase::Base::Base58Btc, seed);
        let decoded = decode_private_key_multibase(&encoded).unwrap();
        assert_eq!(decoded, seed);
    }

    #[test]
    fn test_decode_private_key_multibase_with_codec_prefix() {
        let seed = [42u8; 32];
        let mut prefixed = Vec::with_capacity(34);
        prefixed.extend_from_slice(&ED25519_PRIV_CODEC);
        prefixed.extend_from_slice(&seed);
        let encoded = multibase::encode(multibase::Base::Base58Btc, &prefixed);
        let decoded = decode_private_key_multibase(&encoded).unwrap();
        assert_eq!(decoded, seed);
    }

    #[test]
    fn test_decode_private_key_multibase_invalid() {
        let result = decode_private_key_multibase("!!!bad!!!");
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_private_key_multibase_wrong_length() {
        let encoded = multibase::encode(multibase::Base::Base58Btc, [1u8; 16]);
        let result = decode_private_key_multibase(&encoded);
        assert!(matches!(result, Err(DidKeyError::InvalidSeedLength)));
    }

    /// Pin the verification-method-ID contract for `did:key` secrets.
    ///
    /// Regression guard: a previous PR landed VTA `did:key` support where
    /// downstream DIDComm consumers hardcoded `{did}#key-0` / `{did}#key-1`
    /// as fragment IDs. For `did:key` the spec says VM IDs are the
    /// multibase public-key fragment (`{did}#{ed_pub_mb}` /
    /// `{did}#{x_pub_mb}`), so those lookups missed and the secrets vector
    /// was empty. This test pins the fragment shape `secrets_from_did_key`
    /// produces so that contract is checked at the SDK boundary, not just
    /// at the consumer site.
    #[cfg(feature = "didcomm")]
    #[test]
    fn test_secrets_from_did_key_uses_multibase_fragment_ids() {
        use affinidi_tdk::secrets_resolver::secrets::Secret;

        let seed = [42u8; 32];
        let ed_secret = Secret::generate_ed25519(None, Some(&seed));
        let ed_pub_mb = ed_secret.get_public_keymultibase().unwrap();
        let did = format!("did:key:{ed_pub_mb}");

        let secrets = secrets_from_did_key(&did, &seed).expect("did:key secrets");

        // Signing VM ID must be {did}#{ed_pub_mb} — not the legacy
        // #key-0 webvh convention.
        assert_eq!(secrets.signing.id, format!("{did}#{ed_pub_mb}"));
        assert_ne!(secrets.signing.id, format!("{did}#key-0"));

        // Key-agreement VM ID must use a multibase fragment that differs
        // from the signing fragment (X25519 ≠ Ed25519 public bytes), and
        // must not be the legacy #key-1.
        assert!(
            secrets.key_agreement.id.starts_with(&format!("{did}#z")),
            "key_agreement.id should start with `{did}#z`, got: {}",
            secrets.key_agreement.id
        );
        assert_ne!(secrets.key_agreement.id, format!("{did}#key-1"));
        assert_ne!(secrets.key_agreement.id, secrets.signing.id);
    }

    /// `secrets_from_did_key` is the only place the runtime X25519 secret
    /// is constructed for a `did:key` VTA. Make sure repeated calls with
    /// the same seed produce the same key-agreement ID, so a peer that
    /// resolves the DID document encrypts to the same key the VTA holds.
    #[cfg(feature = "didcomm")]
    #[test]
    fn test_secrets_from_did_key_is_deterministic() {
        use affinidi_tdk::secrets_resolver::secrets::Secret;

        let seed = [7u8; 32];
        let ed_secret = Secret::generate_ed25519(None, Some(&seed));
        let did = format!("did:key:{}", ed_secret.get_public_keymultibase().unwrap());

        let a = secrets_from_did_key(&did, &seed).unwrap();
        let b = secrets_from_did_key(&did, &seed).unwrap();
        assert_eq!(a.signing.id, b.signing.id);
        assert_eq!(a.key_agreement.id, b.key_agreement.id);
    }

    #[cfg(feature = "didcomm")]
    #[test]
    fn test_secrets_from_did_key_rejects_non_did_key() {
        let seed = [1u8; 32];
        let result = secrets_from_did_key("did:webvh:abc:example.com:vta", &seed);
        assert!(matches!(result, Err(DidKeyError::InvalidDidKey)));
    }
}
