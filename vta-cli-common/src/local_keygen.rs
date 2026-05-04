//! Client-side did:key generation.
//!
//! Replaces the server-side `POST /auth/credentials` endpoint for flows where
//! an operator or consumer wants an admin identity bound to a context. The
//! key never crosses the wire:
//!
//! 1. Caller mints a random 32-byte Ed25519 seed locally.
//! 2. Derives `did:key:...` from the public half.
//! 3. Sends `POST /acl` with the public DID + desired role/contexts.
//! 4. Keeps the private half in the returned [`CredentialBundle`] — either
//!    to use locally or to seal via `sealed_producer` for transport.
//!
//! The VTA never sees the private key. Contrast with the pre-5c6 flow where
//! `POST /auth/credentials` generated the key server-side and returned it in
//! a base64 JSON field — a private key in flight over plaintext JSON.

use ed25519_dalek::SigningKey;
use rand::Rng;
use vta_sdk::credentials::CredentialBundle;
use vta_sdk::prelude::ed25519_multibase_pubkey;

/// Mint a fresh Ed25519 keypair and derive a `did:key`.
///
/// Returns `(did, private_key_multibase)` where `private_key_multibase` is
/// the raw 32-byte seed encoded as Base58Btc multibase — matching the
/// format used by `CredentialBundle.private_key_multibase` and the rest
/// of the workspace.
fn mint_ed25519_did_key() -> (String, String) {
    let mut seed = [0u8; 32];
    rand::rng().fill_bytes(&mut seed);
    let signing_key = SigningKey::from_bytes(&seed);
    let public_key = signing_key.verifying_key().to_bytes();
    let multibase_pubkey = ed25519_multibase_pubkey(&public_key);
    let did = format!("did:key:{multibase_pubkey}");
    let private_key_multibase = multibase::encode(multibase::Base::Base58Btc, seed);
    (did, private_key_multibase)
}

/// Generate a fresh Ed25519 keypair, derive a `did:key`, and package the
/// result as a [`CredentialBundle`] bound to the given VTA DID/URL.
///
/// Returns `(bundle, did)`. The `did` is a convenience echo of
/// `bundle.did` for callers that also need it for the ACL entry.
pub fn generate_admin_did_key(
    vta_did: impl Into<String>,
    vta_url: Option<String>,
) -> (CredentialBundle, String) {
    let (did, private_key_multibase) = mint_ed25519_did_key();
    let bundle = CredentialBundle {
        did: did.clone(),
        private_key_multibase,
        vta_did: vta_did.into(),
        vta_url,
    };
    (bundle, did)
}

/// Mint a fresh Ed25519 `did:key` with no VTA binding.
///
/// Returns `(did, private_key_multibase)`. Used by the deferred-VTA-DID
/// `pnm setup` flow: phase 1 mints this keypair and parks it in the
/// keyring as a `PendingVtaBinding` session; phase 2 supplies the VTA
/// DID and lifts the session to `PendingRotation`.
///
/// Unlike [`generate_admin_did_key`], this does not construct a
/// [`CredentialBundle`] — the `CredentialBundle.vta_did` field is
/// required and not yet known at mint time.
pub fn generate_unbound_admin_did_key() -> (String, String) {
    mint_ed25519_did_key()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_did_is_did_key() {
        let (bundle, did) = generate_admin_did_key("did:key:z6MkVTA", None);
        assert_eq!(bundle.did, did);
        assert!(did.starts_with("did:key:z"));
        assert_eq!(bundle.vta_did, "did:key:z6MkVTA");
        assert!(bundle.vta_url.is_none());
    }

    #[test]
    fn generated_dids_are_unique() {
        let a = generate_admin_did_key("did:key:z6MkVTA", None).1;
        let b = generate_admin_did_key("did:key:z6MkVTA", None).1;
        assert_ne!(a, b);
    }

    #[test]
    fn private_key_multibase_roundtrips_to_seed() {
        let (bundle, _) = generate_admin_did_key("did:key:z6MkVTA", None);
        let (_, decoded) = multibase::decode(&bundle.private_key_multibase).unwrap();
        assert_eq!(decoded.len(), 32, "Ed25519 seed must be 32 bytes");
    }

    #[test]
    fn derived_did_matches_seed() {
        let (bundle, did) = generate_admin_did_key("did:key:z6MkVTA", None);
        // Re-derive from the private key and confirm we land on the same DID.
        let (_, seed_bytes) = multibase::decode(&bundle.private_key_multibase).unwrap();
        let seed: [u8; 32] = seed_bytes.try_into().unwrap();
        let signing_key = SigningKey::from_bytes(&seed);
        let pubkey = signing_key.verifying_key().to_bytes();
        let rederived = format!("did:key:{}", ed25519_multibase_pubkey(&pubkey));
        assert_eq!(rederived, did);
    }

    #[test]
    fn unbound_did_key_has_valid_shape() {
        let (did, private_key_multibase) = generate_unbound_admin_did_key();
        assert!(did.starts_with("did:key:z"));
        let (_, decoded) = multibase::decode(&private_key_multibase).unwrap();
        assert_eq!(decoded.len(), 32, "Ed25519 seed must be 32 bytes");
    }

    #[test]
    fn unbound_dids_are_unique() {
        let (a, _) = generate_unbound_admin_did_key();
        let (b, _) = generate_unbound_admin_did_key();
        assert_ne!(a, b);
    }

    #[test]
    fn unbound_seed_round_trips_to_did() {
        let (did, private_key_multibase) = generate_unbound_admin_did_key();
        let (_, seed_bytes) = multibase::decode(&private_key_multibase).unwrap();
        let seed: [u8; 32] = seed_bytes.try_into().unwrap();
        let signing_key = SigningKey::from_bytes(&seed);
        let pubkey = signing_key.verifying_key().to_bytes();
        let rederived = format!("did:key:{}", ed25519_multibase_pubkey(&pubkey));
        assert_eq!(rederived, did);
    }
}
