//! Multikey decoding — multibase + multicodec → algorithm + raw public-key bytes.
//!
//! Per the W3C Controller Document spec, a `publicKeyMultibase` value is
//! a multibase-encoded byte string whose first bytes are a multicodec
//! varint prefix identifying the key type. This module decodes that
//! into a [`VerificationAlgorithm`] + raw public-key bytes for the
//! signature verifier.
//!
//! ## Supported multicodecs
//!
//! | Code | Algorithm | Key encoding |
//! |---|---|---|
//! | `0x1200` | P-256 | 33-byte compressed SEC1 (header 0x02 or 0x03 + 32-byte x) |
//!
//! Multibase variant MUST be `z` (base58btc) per the W3C Multikey spec.
//! Other multicodecs and non-base58btc multibase variants are rejected
//! with [`ResolverError::MalformedVm`].

use crate::resolver::{ResolverError, VerificationAlgorithm};

/// Multicodec varint integer for the P-256 public-key type.
const MULTICODEC_P256: u64 = 0x1200;

/// Decode a `publicKeyMultibase` value into algorithm + raw public-key
/// bytes (multicodec prefix stripped).
///
/// For P-256, the returned bytes are the 33-byte compressed SEC1 form
/// (header `0x02` or `0x03` followed by 32 bytes of x-coordinate). The
/// signature verifier consumes this form directly.
pub fn decode_multikey(
    multibase_str: &str,
) -> Result<(VerificationAlgorithm, Vec<u8>), ResolverError> {
    // 1. Multibase decode. The W3C Multikey spec mandates base58btc
    //    (the `z` multibase prefix); reject anything else.
    let (base, bytes) = multibase::decode(multibase_str)
        .map_err(|e| ResolverError::MalformedVm(format!("multibase decode failed: {e}")))?;
    if !matches!(base, multibase::Base::Base58Btc) {
        return Err(ResolverError::MalformedVm(format!(
            "Multikey requires base58btc encoding (prefix `z`); got {base:?}"
        )));
    }

    // 2. Read the multicodec varint prefix.
    let (codec, rest) = unsigned_varint::decode::u64(&bytes)
        .map_err(|e| ResolverError::MalformedVm(format!("multicodec varint decode failed: {e}")))?;

    // 3. Map to algorithm + validate key bytes for that algorithm.
    let algorithm = match codec {
        MULTICODEC_P256 => {
            if rest.len() != 33 {
                return Err(ResolverError::MalformedVm(format!(
                    "P-256 multikey must be 33 bytes (compressed SEC1); got {} bytes",
                    rest.len()
                )));
            }
            // SEC1 compressed point header MUST be 0x02 or 0x03.
            // (0x04 would be uncompressed and not what Multikey carries.)
            if rest[0] != 0x02 && rest[0] != 0x03 {
                return Err(ResolverError::MalformedVm(format!(
                    "P-256 compressed point header must be 0x02 or 0x03; got 0x{:02x}",
                    rest[0]
                )));
            }
            VerificationAlgorithm::P256
        }
        other => {
            return Err(ResolverError::MalformedVm(format!(
                "unsupported multicodec 0x{other:x} (v0.1 supports P-256 / 0x1200 only)"
            )));
        }
    };

    Ok((algorithm, rest.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: build a base58btc-encoded multikey string from a known
    /// codec varint + key bytes.
    fn encode(codec_varint: &[u8], key: &[u8]) -> String {
        let mut bytes = Vec::with_capacity(codec_varint.len() + key.len());
        bytes.extend_from_slice(codec_varint);
        bytes.extend_from_slice(key);
        multibase::encode(multibase::Base::Base58Btc, &bytes)
    }

    /// P-256 multicodec 0x1200 varint = [0x80, 0x24].
    const P256_VARINT: [u8; 2] = [0x80, 0x24];

    #[test]
    fn decodes_valid_p256_multikey() {
        // 33-byte compressed P-256 point: header 0x02 + 32 bytes of x.
        let mut key = vec![0x02u8];
        key.extend(std::iter::repeat_n(0xAAu8, 32));
        let mk = encode(&P256_VARINT, &key);

        let (alg, bytes) = decode_multikey(&mk).expect("decodes");
        assert_eq!(alg, VerificationAlgorithm::P256);
        assert_eq!(bytes, key);
    }

    #[test]
    fn decodes_p256_with_0x03_header() {
        let mut key = vec![0x03u8];
        key.extend(std::iter::repeat_n(0x55u8, 32));
        let mk = encode(&P256_VARINT, &key);

        let (alg, bytes) = decode_multikey(&mk).expect("decodes");
        assert_eq!(alg, VerificationAlgorithm::P256);
        assert_eq!(bytes[0], 0x03);
        assert_eq!(bytes.len(), 33);
    }

    #[test]
    fn rejects_p256_with_wrong_header() {
        let mut key = vec![0x04u8]; // uncompressed marker — wrong shape for Multikey
        key.extend(std::iter::repeat_n(0xAAu8, 32));
        let mk = encode(&P256_VARINT, &key);

        let err = decode_multikey(&mk).unwrap_err();
        assert!(
            matches!(err, ResolverError::MalformedVm(ref s) if s.contains("0x02 or 0x03")),
            "got {err:?}"
        );
    }

    #[test]
    fn rejects_p256_with_wrong_length() {
        // Only 16 bytes of "key" instead of 33.
        let mut key = vec![0x02u8];
        key.extend(std::iter::repeat_n(0xAAu8, 15));
        let mk = encode(&P256_VARINT, &key);

        let err = decode_multikey(&mk).unwrap_err();
        assert!(
            matches!(err, ResolverError::MalformedVm(ref s) if s.contains("33 bytes")),
            "got {err:?}"
        );
    }

    #[test]
    fn rejects_unknown_multicodec() {
        // Ed25519 multicodec 0xed = varint [0xed, 0x01].
        // Valid in W3C Multikey, but unsupported in v0.1.
        let key = vec![0xAAu8; 32];
        let mk = encode(&[0xed, 0x01], &key);

        let err = decode_multikey(&mk).unwrap_err();
        assert!(
            matches!(err, ResolverError::MalformedVm(ref s) if s.contains("unsupported multicodec")),
            "got {err:?}"
        );
    }

    #[test]
    fn rejects_non_base58btc_multibase() {
        // Encode in base64 (multibase prefix `m`) instead of base58btc.
        let mut bytes = Vec::from(P256_VARINT);
        bytes.push(0x02);
        bytes.extend(std::iter::repeat_n(0xAAu8, 32));
        let mk = multibase::encode(multibase::Base::Base64, &bytes);

        let err = decode_multikey(&mk).unwrap_err();
        assert!(
            matches!(err, ResolverError::MalformedVm(ref s) if s.contains("base58btc")),
            "got {err:?}"
        );
    }

    #[test]
    fn rejects_malformed_multibase() {
        let err = decode_multikey("not-a-multibase-string").unwrap_err();
        assert!(matches!(err, ResolverError::MalformedVm(_)), "got {err:?}");
    }
}
