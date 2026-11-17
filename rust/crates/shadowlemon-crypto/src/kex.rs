//! Ephemeral X25519 key agreement.
//!
//! Private material is held in zeroizing wrappers and is dropped as soon as
//! the session keys have been derived, which provides forward secrecy.

use getrandom::fill;
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};
use zeroize::ZeroizeOnDrop;

use crate::{is_all_zero, CryptoError, EPHEMERAL_KEY_LEN};

/// An ephemeral X25519 key pair.
#[derive(Clone, ZeroizeOnDrop)]
pub struct EphemeralKeyPair {
    private: [u8; EPHEMERAL_KEY_LEN],
    public: [u8; EPHEMERAL_KEY_LEN],
}

impl EphemeralKeyPair {
    /// Generate a fresh key pair from the operating system CSPRNG.
    pub fn generate() -> Result<Self, CryptoError> {
        let mut private = [0u8; EPHEMERAL_KEY_LEN];
        fill(&mut private)?;
        Ok(Self::from_private(private))
    }

    /// Rebuild a key pair from existing private bytes (used by test vectors
    /// and by callers that manage their own entropy source).
    #[must_use]
    pub fn from_private(private: [u8; EPHEMERAL_KEY_LEN]) -> Self {
        let secret = StaticSecret::from(private);
        let public = PublicKey::from(&secret).to_bytes();
        Self { private, public }
    }

    /// Public key bytes to place in the handshake envelope.
    #[must_use]
    pub const fn public_bytes(&self) -> &[u8; EPHEMERAL_KEY_LEN] {
        &self.public
    }

    /// Private key bytes. Callers must not retain this slice beyond the key
    /// exchange; copying it defeats the zeroization guarantees of this type.
    #[must_use]
    pub const fn private_bytes(&self) -> &[u8; EPHEMERAL_KEY_LEN] {
        &self.private
    }

    /// Compute the shared secret with a peer public key.
    pub fn compute_shared_secret(
        &self,
        peer_pub: &[u8; EPHEMERAL_KEY_LEN],
    ) -> Result<[u8; EPHEMERAL_KEY_LEN], CryptoError> {
        compute_shared_secret(&self.private, peer_pub)
    }
}

/// Compute the raw X25519 shared secret between a private key and a peer
/// public key.
///
/// Rejects keys that produce an all-zero (non-contributory) result, which
/// would otherwise give an attacker who supplies a low-order point a publicly
/// known session key.
pub fn compute_shared_secret(
    our_priv: &[u8; EPHEMERAL_KEY_LEN],
    peer_pub: &[u8; EPHEMERAL_KEY_LEN],
) -> Result<[u8; EPHEMERAL_KEY_LEN], CryptoError> {
    let secret = StaticSecret::from(*our_priv);
    let public = PublicKey::from(*peer_pub);
    let shared: SharedSecret = secret.diffie_hellman(&public);
    let bytes = shared.to_bytes();
    if !shared.was_contributory() || is_all_zero(&bytes) {
        return Err(CryptoError::AllZeroSharedSecret);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex<const N: usize>(s: &str) -> [u8; N] {
        let v: Vec<u8> = (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect();
        v.try_into().unwrap()
    }

    /// RFC 7748 section 6.1, Alice and Bob.
    #[test]
    fn rfc7748_x25519_vectors() {
        let alice_priv = hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let alice_pub = hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        let bob_priv = hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        let bob_pub = hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        let expected = hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

        assert_eq!(
            EphemeralKeyPair::from_private(alice_priv).public_bytes(),
            &alice_pub
        );
        assert_eq!(
            EphemeralKeyPair::from_private(bob_priv).public_bytes(),
            &bob_pub
        );
        assert_eq!(
            compute_shared_secret(&alice_priv, &bob_pub).unwrap(),
            expected
        );
        assert_eq!(
            compute_shared_secret(&bob_priv, &alice_pub).unwrap(),
            expected
        );
    }

    /// RFC 7748 section 5.2, first X25519 function test vector.
    #[test]
    fn rfc7748_function_vector() {
        let scalar = hex::<32>("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
        let u_coordinate =
            hex::<32>("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
        let expected =
            hex::<32>("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");
        assert_eq!(
            compute_shared_secret(&scalar, &u_coordinate).unwrap(),
            expected
        );
    }

    /// RFC 7748 section 6: a low-order point (u = 0) forces an all-zero shared
    /// secret, which must be rejected before any key material is derived.
    #[test]
    fn rejects_all_zero_shared_secret() {
        let priv_key =
            hex::<32>("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
        assert_eq!(
            compute_shared_secret(&priv_key, &[0u8; 32]),
            Err(CryptoError::AllZeroSharedSecret)
        );
    }

    #[test]
    fn generated_pairs_agree() {
        let a = EphemeralKeyPair::generate().unwrap();
        let b = EphemeralKeyPair::generate().unwrap();
        assert_ne!(a.public_bytes(), b.public_bytes());
        assert_eq!(
            a.compute_shared_secret(b.public_bytes()).unwrap(),
            b.compute_shared_secret(a.public_bytes()).unwrap()
        );
    }
}
