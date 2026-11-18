//! AEAD sealing with 24-byte wire nonces.
//!
//! The wire format always carries [`crate::WIRE_NONCE_LEN`] bytes, regardless
//! of suite. The AEAD nonce is the **last** `suite.nonce_len()` bytes:
//! XChaCha20-Poly1305 uses all 24, while both AES-GCM suites use
//! `wire_nonce[12..24]`. The leading 12 bytes may be rewritten by a traffic
//! nonce pattern and must never reach AES-GCM.

use aead::{array::typenum::Unsigned, Aead, AeadCore, KeyInit, Nonce, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use chacha20poly1305::XChaCha20Poly1305;
use zeroize::Zeroizing;

use crate::{
    suite::Suite, CryptoError, WireNonce, AEAD_TAG_LEN, PAYLOAD_NONCE_INDEX, PAYLOAD_NONCE_MASK,
};

/// Derive the AEAD nonce from a wire nonce by taking its last `suite.nonce_len()`
/// bytes. Never use the first 12 bytes for AES-GCM: they can be deterministic.
#[must_use]
pub fn aead_nonce(wire_nonce: &WireNonce, suite: Suite) -> &[u8] {
    &wire_nonce[crate::WIRE_NONCE_LEN - suite.nonce_len()..]
}

/// Derive the wire nonce used to protect a UDP payload from the metadata
/// nonce: XOR byte 16 with 0x01. Byte 16 is inside the random region, outside
/// the user hint (bytes 20..24) and outside a traffic pattern (bytes 0..12),
/// and it is inside the AEAD nonce of every suite.
#[must_use]
pub fn udp_payload_nonce(metadata_nonce: &WireNonce) -> WireNonce {
    let mut derived = *metadata_nonce;
    derived[PAYLOAD_NONCE_INDEX] ^= PAYLOAD_NONCE_MASK;
    derived
}

/// Convert a byte slice to the nonce type of an AEAD algorithm, with a
/// checked length so malformed inputs are reported instead of panicking.
fn checked_nonce<A: Aead>(nonce: &[u8]) -> Result<Nonce<A>, CryptoError> {
    let want = <A as AeadCore>::NonceSize::USIZE;
    if nonce.len() != want {
        return Err(CryptoError::InvalidNonceLength {
            got: nonce.len(),
            want,
        });
    }
    Nonce::<A>::try_from(nonce).map_err(|_| CryptoError::InvalidNonceLength {
        got: nonce.len(),
        want,
    })
}

/// Generic seal helper over the `aead` trait, shared by the concrete suites
/// and by the RFC vector tests for the underlying 12-byte-nonce algorithms.
fn seal_with<A: Aead>(
    aead: &A,
    nonce: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let nonce = checked_nonce::<A>(nonce)?;
    let payload = Payload {
        msg: plaintext,
        aad,
    };
    Ok(aead.encrypt(&nonce, payload)?)
}

/// Generic open helper, the inverse of [`seal_with`].
fn open_with<A: Aead>(
    aead: &A,
    nonce: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let nonce = checked_nonce::<A>(nonce)?;
    let payload = Payload {
        msg: ciphertext,
        aad,
    };
    Ok(aead.decrypt(&nonce, payload)?)
}

enum Inner {
    XChaCha(XChaCha20Poly1305),
    Aes256(Aes256Gcm),
    Aes128(Aes128Gcm),
}

/// An AEAD key for one of the supported suites.
///
/// The raw key is copied into a zeroizing buffer; callers may erase their own
/// copy as soon as this value is constructed.
pub struct AeadKey {
    suite: Suite,
    key: Zeroizing<Vec<u8>>,
    inner: Inner,
}

impl AeadKey {
    /// Construct a key from exactly `suite.key_len()` bytes.
    pub fn new(suite: Suite, key: &[u8]) -> Result<Self, CryptoError> {
        if !suite.is_valid() {
            return Err(CryptoError::UnknownSuite(suite.as_u8()));
        }
        if key.len() != suite.key_len() {
            return Err(CryptoError::InvalidKeyLength {
                suite,
                got: key.len(),
                want: suite.key_len(),
            });
        }
        let owned = Zeroizing::new(key.to_vec());
        // The length was checked above, so all three constructors must accept
        // the key; keep the mapping explicit rather than panicking.
        let invalid_len = |_| CryptoError::InvalidKeyLength {
            suite,
            got: key.len(),
            want: suite.key_len(),
        };
        let inner = match suite {
            Suite::XChaCha20Poly1305 => {
                Inner::XChaCha(XChaCha20Poly1305::new_from_slice(&owned).map_err(invalid_len)?)
            }
            Suite::Aes256Gcm => {
                Inner::Aes256(Aes256Gcm::new_from_slice(&owned).map_err(invalid_len)?)
            }
            Suite::Aes128Gcm => {
                Inner::Aes128(Aes128Gcm::new_from_slice(&owned).map_err(invalid_len)?)
            }
        };
        Ok(Self {
            suite,
            key: owned,
            inner,
        })
    }

    /// Suite of this key.
    #[must_use]
    pub const fn suite(&self) -> Suite {
        self.suite
    }

    /// Key length in bytes.
    #[must_use]
    pub const fn key_len(&self) -> usize {
        self.suite.key_len()
    }

    /// Wire nonce length in bytes (always 24).
    #[must_use]
    pub const fn wire_nonce_len(&self) -> usize {
        crate::WIRE_NONCE_LEN
    }

    /// Bytes added to a plaintext by sealing (the 16-byte tag).
    #[must_use]
    pub const fn overhead(&self) -> usize {
        AEAD_TAG_LEN
    }

    /// Raw key bytes, available for KDF composition only.
    #[must_use]
    pub fn key_bytes(&self) -> &[u8] {
        &self.key
    }

    fn check_nonce(&self, nonce: &WireNonce) -> Result<(), CryptoError> {
        if nonce.len() != crate::WIRE_NONCE_LEN {
            return Err(CryptoError::InvalidNonceLength {
                got: nonce.len(),
                want: crate::WIRE_NONCE_LEN,
            });
        }
        Ok(())
    }

    /// Seal metadata (or any message that uses the wire nonce directly).
    /// The result is ciphertext followed by the 16-byte tag.
    pub fn seal(&self, wire_nonce: &WireNonce, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.seal_with_aad(wire_nonce, plaintext, &[])
    }

    /// Open a message sealed with [`AeadKey::seal`].
    pub fn open(&self, wire_nonce: &WireNonce, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.open_with_aad(wire_nonce, ciphertext, &[])
    }

    /// Seal with explicit additional authenticated data.
    pub fn seal_with_aad(
        &self,
        wire_nonce: &WireNonce,
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        self.check_nonce(wire_nonce)?;
        let nonce = aead_nonce(wire_nonce, self.suite);
        match &self.inner {
            Inner::XChaCha(aead) => seal_with(aead, nonce, plaintext, aad),
            Inner::Aes256(aead) => seal_with(aead, nonce, plaintext, aad),
            Inner::Aes128(aead) => seal_with(aead, nonce, plaintext, aad),
        }
    }

    /// Open with explicit additional authenticated data.
    pub fn open_with_aad(
        &self,
        wire_nonce: &WireNonce,
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        self.check_nonce(wire_nonce)?;
        let nonce = aead_nonce(wire_nonce, self.suite);
        match &self.inner {
            Inner::XChaCha(aead) => open_with(aead, nonce, ciphertext, aad),
            Inner::Aes256(aead) => open_with(aead, nonce, ciphertext, aad),
            Inner::Aes128(aead) => open_with(aead, nonce, ciphertext, aad),
        }
    }

    /// Seal a UDP payload using the byte-16-flipped payload nonce.
    pub fn seal_payload(
        &self,
        metadata_nonce: &WireNonce,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        self.seal(&udp_payload_nonce(metadata_nonce), plaintext)
    }

    /// Open a UDP payload using the byte-16-flipped payload nonce.
    pub fn open_payload(
        &self,
        metadata_nonce: &WireNonce,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        self.open(&udp_payload_nonce(metadata_nonce), ciphertext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        assert_eq!(cleaned.len() % 2, 0, "bad hex string: {s:?}");
        (0..cleaned.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&cleaned[i..i + 2], 16).unwrap())
            .collect()
    }

    fn wire_from_iv(iv: &[u8]) -> WireNonce {
        assert_eq!(iv.len(), 12);
        let mut nonce = [0xAAu8; crate::WIRE_NONCE_LEN];
        nonce[12..].copy_from_slice(iv);
        nonce
    }

    #[test]
    fn aes_uses_last_twelve_wire_bytes() {
        for suite in [Suite::Aes256Gcm, Suite::Aes128Gcm] {
            let wire = wire_from_iv(&[
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
            ]);
            assert_eq!(aead_nonce(&wire, suite), &wire[12..24]);
            assert_ne!(aead_nonce(&wire, suite), &wire[0..12]);
        }
        let wire = [0x11u8; 24];
        assert_eq!(aead_nonce(&wire, Suite::XChaCha20Poly1305), &wire[..]);
    }

    #[test]
    fn payload_nonce_helpers() {
        let metadata = [0x10u8; 24];
        let udp = udp_payload_nonce(&metadata);
        assert_eq!(udp[16], 0x11);
        assert_eq!(udp[..16], metadata[..16]);
        assert_eq!(udp[17..], metadata[17..]);
        assert_eq!(udp_payload_nonce(&udp), metadata);
    }

    /// RFC 8439 section 2.8.2, ChaCha20-Poly1305 with AAD.
    #[test]
    fn rfc8439_chacha20_poly1305_vector() {
        let key = hex("808182838485868788898a8b8c8d8e8f\
             909192939495969798999a9b9c9d9e9f");
        let nonce = hex("070000004041424344454647");
        let aad = hex("50515253c0c1c2c3c4c5c6c7");
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let expected = hex(
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6\
             3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b369\
             2ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3f\
             f4def08e4b7a9de576d26586cec64b6116\
             1ae10b594f09e26a7e902ecbd0600691",
        );

        let cipher = chacha20poly1305::ChaCha20Poly1305::new_from_slice(&key).unwrap();
        let sealed = seal_with(&cipher, &nonce, plaintext, &aad).unwrap();
        assert_eq!(sealed, expected);
        assert_eq!(
            open_with(&cipher, &nonce, &sealed, &aad).unwrap(),
            plaintext
        );
        assert!(open_with(&cipher, &nonce, &sealed, b"wrong aad").is_err());
    }

    /// GCM specification test cases 13, 14 and 15 (AES-256-GCM).
    #[test]
    fn nist_aes256_gcm_vectors() {
        let key = [0u8; 32];
        let nonce = wire_from_iv(&[0u8; 12]);
        let cipher = AeadKey::new(Suite::Aes256Gcm, &key).unwrap();

        // Test case 13: empty plaintext.
        assert_eq!(
            cipher.seal(&nonce, b"").unwrap(),
            hex("530f8afbc74536b9a963b4f1c4cb738b")
        );

        // Test case 14: one AES block.
        let sealed = cipher.seal(&nonce, &[0u8; 16]).unwrap();
        assert_eq!(
            sealed,
            hex("cea7403d4d606b6e074ec5d3baf39d18\
                 d0d1c8a799996bf0265b98b5d48ab919")
        );

        // Test case 15: 64-byte plaintext, key and IV from the spec.
        let key = hex("feffe9928665731c6d6a8f9467308308\
                       feffe9928665731c6d6a8f9467308308");
        let cipher = AeadKey::new(Suite::Aes256Gcm, &key).unwrap();
        let nonce = wire_from_iv(&hex("cafebabefacedbaddecaf888"));
        let plaintext = hex("d9313225f88406e5a55909c5aff5269a\
             86a7a9531534f7da2e4c303d8a318a72\
             1c3c0c95956809532fcf0e2449a6b525\
             b16aedf5aa0de657ba637b391aafd255");
        let expected = hex("522dc1f099567d07f47f37a32a84427d\
             643a8cdcbfe5c0c97598a2bd2555d1aa\
             8cb08e48590dbb3da7b08b1056828838\
             c5f61e6393ba7a0abcc9f662898015ad\
             b094dac5d93471bdec1a502270e3cc6c");
        let sealed = cipher.seal(&nonce, &plaintext).unwrap();
        assert_eq!(sealed, expected);
        assert_eq!(cipher.open(&nonce, &sealed).unwrap(), plaintext);
    }

    /// GCM specification test cases 1, 2 and 3 (AES-128-GCM).
    #[test]
    fn nist_aes128_gcm_vectors() {
        let key = [0u8; 16];
        let nonce = wire_from_iv(&[0u8; 12]);
        let cipher = AeadKey::new(Suite::Aes128Gcm, &key).unwrap();

        assert_eq!(
            cipher.seal(&nonce, b"").unwrap(),
            hex("58e2fccefa7e3061367f1d57a4e7455a")
        );
        assert_eq!(
            cipher.seal(&nonce, &[0u8; 16]).unwrap(),
            hex("0388dace60b6a392f328c2b971b2fe78\
                 ab6e47d42cec13bdf53a67b21257bddf")
        );

        let cipher =
            AeadKey::new(Suite::Aes128Gcm, &hex("feffe9928665731c6d6a8f9467308308")).unwrap();
        let nonce = wire_from_iv(&hex("cafebabefacedbaddecaf888"));
        let plaintext = hex("d9313225f88406e5a55909c5aff5269a\
             86a7a9531534f7da2e4c303d8a318a72\
             1c3c0c95956809532fcf0e2449a6b525\
             b16aedf5aa0de657ba637b391aafd255");
        let expected = hex("42831ec2217774244b7221b784d0d49c\
             e3aa212f2c02a4e035c17e2329aca12e\
             21d514b25466931c7d8f6a5aac84aa05\
             1ba30b396a0aac973d58e091473f5985\
             4d5c2af327cd64a62cf35abd2ba6fab4");
        assert_eq!(cipher.seal(&nonce, &plaintext).unwrap(), expected);
        assert_eq!(cipher.key_len(), 16);
    }

    #[test]
    fn leading_wire_bytes_do_not_affect_aes_gcm() {
        // The first 12 wire bytes are allowed to be a deterministic traffic
        // pattern. Changing them must not change an AES-GCM seal, but must
        // change an XChaCha20-Poly1305 seal.
        let key = [3u8; 32];
        let a = wire_from_iv(&[9u8; 12]);
        let mut b = a;
        b[0] ^= 0xff;
        let aes = AeadKey::new(Suite::Aes256Gcm, &key).unwrap();
        let xchacha = AeadKey::new(Suite::XChaCha20Poly1305, &key).unwrap();
        assert_eq!(aes.seal(&a, b"msg").unwrap(), aes.seal(&b, b"msg").unwrap());
        assert_ne!(
            xchacha.seal(&a, b"msg").unwrap(),
            xchacha.seal(&b, b"msg").unwrap()
        );
    }

    #[test]
    fn payload_sealing_round_trips_and_rejects_tampering() {
        for suite in Suite::all_suites() {
            let key = vec![5u8; suite.key_len()];
            let cipher = AeadKey::new(suite, &key).unwrap();
            let nonce = [0x42u8; 24];
            let sealed = cipher.seal_payload(&nonce, b"payload").unwrap();
            assert_eq!(sealed.len(), b"payload".len() + AEAD_TAG_LEN);
            assert_eq!(cipher.open_payload(&nonce, &sealed).unwrap(), b"payload");
            // The metadata nonce must not open a payload.
            assert!(cipher.open(&nonce, &sealed).is_err());
            let mut tampered = sealed.clone();
            tampered[0] ^= 1;
            assert!(cipher.open_payload(&nonce, &tampered).is_err());
        }
    }

    #[test]
    fn key_lengths_are_enforced() {
        for suite in Suite::all_suites() {
            assert!(AeadKey::new(suite, &[0u8; 1]).is_err());
            assert!(AeadKey::new(suite, &[0u8; 32]).is_ok() == (suite.key_len() == 32));
        }
    }
}
