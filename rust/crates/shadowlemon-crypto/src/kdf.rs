//! Static key and directional session key derivation for protocol V0.2.
//!
//! All constants and byte concatenations in this module are part of the wire
//! protocol. Do not reformat the domain-separation strings.

use hkdf::Hkdf;
use pbkdf2::pbkdf2_hmac;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{suite::Suite, CryptoError, KEY_LEN, PBKDF2_ITERATIONS, SALT_LEN};

/// Static key salt, frozen as `SHA256("ShadowLemon V0.2 static key salt")`.
pub const STATIC_KEY_SALT_INFO: &[u8] = b"ShadowLemon V0.2 static key salt";
/// HKDF info prefix of the client-to-server direction.
pub const C2S_INFO: &[u8] = b"ShadowLemon V0.2 c2s";
/// HKDF info prefix of the server-to-client direction.
pub const S2C_INFO: &[u8] = b"ShadowLemon V0.2 s2c";
/// HKDF info prefix of 0-RTT client-to-server early data.
pub const EARLY_C2S_INFO: &[u8] = b"ShadowLemon V0.2 0rtt c2s";
/// HKDF info prefix of 0-RTT server-to-client early data.
pub const EARLY_S2C_INFO: &[u8] = b"ShadowLemon V0.2 0rtt s2c";

/// A key derived from the user credential and the envelope suite.
///
/// Only the first `suite.key_len()` bytes are used for the AEAD; the rest of
/// the 32-byte PBKDF2 output is kept zeroed so that accidental use of the full
/// buffer cannot bypass the suite truncation rule.
#[derive(Clone, ZeroizeOnDrop)]
pub struct StaticKey {
    bytes: [u8; KEY_LEN],
    len: usize,
}

impl StaticKey {
    /// The truncated key bytes, whose length is the envelope suite key length.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    /// Length of the usable key material in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the key contains no usable bytes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl AsRef<[u8]> for StaticKey {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

/// One directional data-plane key.
#[derive(Clone, ZeroizeOnDrop)]
pub struct SessionKey {
    bytes: [u8; KEY_LEN],
    len: usize,
}

impl SessionKey {
    /// Key bytes, `final_suite.key_len()` long.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    /// Length of the key in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the key contains no usable bytes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl AsRef<[u8]> for SessionKey {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

/// `SHA256(password || 0x00 || username)` — the password decorated with the
/// user name. The NUL byte keeps `(password, username)` pairs unambiguous.
#[must_use]
pub fn hash_password(password: &[u8], username: &str) -> [u8; KEY_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(password);
    hasher.update([0x00]);
    hasher.update(username.as_bytes());
    hasher.finalize().into()
}

/// Fixed salt of the static key derivation.
#[must_use]
pub fn static_key_salt() -> [u8; KEY_LEN] {
    Sha256::digest(STATIC_KEY_SALT_INFO).into()
}

/// Derive the static envelope key of a user.
///
/// ```text
/// hashedPassword = SHA256(password || 0x00 || username)
/// salt           = SHA256("ShadowLemon V0.2 static key salt")
/// staticKey      = PBKDF2-HMAC-SHA256(hashedPassword, salt, 4096, 32)
///                [0:envelope_suite.key_len()]
/// ```
pub fn derive_static_key(
    username: &str,
    password: &[u8],
    envelope_suite: Suite,
) -> Result<StaticKey, CryptoError> {
    if !envelope_suite.is_valid() {
        return Err(CryptoError::UnknownSuite(envelope_suite.as_u8()));
    }
    let hashed = hash_password(password, username);
    let salt = static_key_salt();
    let mut all = [0u8; KEY_LEN];
    pbkdf2_hmac::<Sha256>(&hashed, &salt, PBKDF2_ITERATIONS, &mut all);

    let len = envelope_suite.key_len();
    let mut bytes = [0u8; KEY_LEN];
    bytes[..len].copy_from_slice(&all[..len]);
    all.zeroize();
    Ok(StaticKey { bytes, len })
}

/// HKDF-SHA256 expansion used by both key derivations. Kept as a separate
/// function so it can be checked against the RFC 5869 vectors directly.
pub fn hkdf_sha256(
    secret: &[u8],
    salt: &[u8],
    info: &[u8],
    out_len: usize,
) -> Result<Vec<u8>, CryptoError> {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), secret);
    let mut out = vec![0u8; out_len];
    hkdf.expand(info, &mut out)
        .map_err(|_| CryptoError::HkdfInvalidLength)?;
    Ok(out)
}

/// Build the HKDF info of a directional session key:
/// `prefix || version || suite_byte`.
fn session_info(prefix: &[u8], version: u8, suite: Suite) -> Vec<u8> {
    let mut info = Vec::with_capacity(prefix.len() + 2);
    info.extend_from_slice(prefix);
    info.push(version);
    info.push(suite.as_u8());
    info
}

/// Derive the two directional session keys of an established X25519 exchange.
///
/// ```text
/// salt  = SHA256(static_key || client_salt || server_salt)
/// info  = "ShadowLemon V0.2 c2s" || [version] || [suite_byte]   (and " s2c")
/// c2s   = HKDF-SHA256(shared_secret, salt, info, final_suite.key_len())
/// ```
///
/// `version` is the protocol version byte carried in the handshake; callers
/// that speak the current version should use [`crate::DEFAULT_PROTOCOL_VERSION`]
/// or the [`derive_session_keys_v4`] convenience wrapper.
pub fn derive_session_keys(
    static_key: &[u8],
    client_salt: &[u8],
    server_salt: &[u8],
    shared_secret: &[u8],
    version: u8,
    final_suite: Suite,
) -> Result<(SessionKey, SessionKey), CryptoError> {
    if !final_suite.is_valid() {
        return Err(CryptoError::UnknownSuite(final_suite.as_u8()));
    }
    if static_key.is_empty() || static_key.len() > KEY_LEN {
        return Err(CryptoError::InvalidKeyLength {
            suite: final_suite,
            got: static_key.len(),
            want: final_suite.key_len(),
        });
    }
    if client_salt.len() != SALT_LEN {
        return Err(CryptoError::InvalidSaltLength {
            field: "client salt",
            got: client_salt.len(),
            want: SALT_LEN,
        });
    }
    if server_salt.len() != SALT_LEN {
        return Err(CryptoError::InvalidSaltLength {
            field: "server salt",
            got: server_salt.len(),
            want: SALT_LEN,
        });
    }
    if shared_secret.len() != KEY_LEN {
        return Err(CryptoError::InvalidKeyLength {
            suite: final_suite,
            got: shared_secret.len(),
            want: KEY_LEN,
        });
    }

    let mut hasher = Sha256::new();
    hasher.update(static_key);
    hasher.update(client_salt);
    hasher.update(server_salt);
    let salt = hasher.finalize();

    let key_len = final_suite.key_len();
    let c2s_bytes = hkdf_sha256(
        shared_secret,
        &salt,
        &session_info(C2S_INFO, version, final_suite),
        key_len,
    )?;
    let s2c_bytes = hkdf_sha256(
        shared_secret,
        &salt,
        &session_info(S2C_INFO, version, final_suite),
        key_len,
    )?;

    let mut c2s = [0u8; KEY_LEN];
    let mut s2c = [0u8; KEY_LEN];
    c2s[..key_len].copy_from_slice(&c2s_bytes);
    s2c[..key_len].copy_from_slice(&s2c_bytes);
    Ok((
        SessionKey {
            bytes: c2s,
            len: key_len,
        },
        SessionKey {
            bytes: s2c,
            len: key_len,
        },
    ))
}

/// [`derive_session_keys`] with the current protocol version (4).
pub fn derive_session_keys_v4(
    static_key: &[u8],
    client_salt: &[u8],
    server_salt: &[u8],
    shared_secret: &[u8],
    final_suite: Suite,
) -> Result<(SessionKey, SessionKey), CryptoError> {
    derive_session_keys(
        static_key,
        client_salt,
        server_salt,
        shared_secret,
        crate::DEFAULT_PROTOCOL_VERSION,
        final_suite,
    )
}

/// Derive the two directional 0-RTT early keys from the static key alone.
///
/// Both peers can compute these from the handshake request, before any X25519
/// exchange or server salt is available. The salt binds the session id so
/// different sessions get independent keys, but there is no ephemeral input:
/// early application data protected with these keys has **no forward secrecy**
/// and must not outlive the handshake.
///
/// ```text
/// salt = SHA256(static_key || u32be(session_id))
/// info = "ShadowLemon V0.2 0rtt c2s" || [version] || [suite_byte]   (and " s2c")
/// c2s  = HKDF-SHA256(static_key, salt, info, suite.key_len())
/// ```
pub fn derive_early_keys(
    static_key: &[u8],
    session_id: u32,
    suite: Suite,
) -> Result<(SessionKey, SessionKey), CryptoError> {
    if !suite.is_valid() {
        return Err(CryptoError::UnknownSuite(suite.as_u8()));
    }
    if static_key.is_empty() || static_key.len() > KEY_LEN {
        return Err(CryptoError::InvalidKeyLength {
            suite,
            got: static_key.len(),
            want: suite.key_len(),
        });
    }

    let mut hasher = Sha256::new();
    hasher.update(static_key);
    hasher.update(session_id.to_be_bytes());
    let salt = hasher.finalize();

    let key_len = suite.key_len();
    let version = crate::DEFAULT_PROTOCOL_VERSION;
    let c2s_bytes = hkdf_sha256(
        static_key,
        &salt,
        &session_info(EARLY_C2S_INFO, version, suite),
        key_len,
    )?;
    let s2c_bytes = hkdf_sha256(
        static_key,
        &salt,
        &session_info(EARLY_S2C_INFO, version, suite),
        key_len,
    )?;

    let mut c2s = [0u8; KEY_LEN];
    let mut s2c = [0u8; KEY_LEN];
    c2s[..key_len].copy_from_slice(&c2s_bytes);
    s2c[..key_len].copy_from_slice(&s2c_bytes);
    Ok((
        SessionKey {
            bytes: c2s,
            len: key_len,
        },
        SessionKey {
            bytes: s2c,
            len: key_len,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        assert_eq!(s.len() % 2, 0);
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// RFC 6070, appendix A. PBKDF2-HMAC-SHA256 is checked with the equivalent
    /// vectors published by RFC 7914 / common test suites where RFC 6070 only
    /// specifies SHA-1; the SHA-1 shape is verified through the generic
    /// `pbkdf2` entry point below.
    #[test]
    fn rfc6070_pbkdf2_sha1_shapes() {
        use pbkdf2::pbkdf2;
        use sha1::Sha1;

        let mut out = [0u8; 20];
        pbkdf2::<hmac::Hmac<Sha1>>(b"password", b"salt", 1, &mut out).unwrap();
        assert_eq!(
            out.as_slice(),
            hex("0c60c80f961f0e71f3a9b524af6012062fe037a6")
        );

        pbkdf2::<hmac::Hmac<Sha1>>(b"password", b"salt", 2, &mut out).unwrap();
        assert_eq!(
            out.as_slice(),
            hex("ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957")
        );

        pbkdf2::<hmac::Hmac<Sha1>>(b"password", b"salt", 4096, &mut out).unwrap();
        assert_eq!(
            out.as_slice(),
            hex("4b007901b765489abead49d926f721d065a429c1")
        );

        let mut out25 = [0u8; 25];
        pbkdf2::<hmac::Hmac<Sha1>>(
            b"passwordPASSWORDpassword",
            b"saltSALTsaltSALTsaltSALTsaltSALTsalt",
            4096,
            &mut out25,
        )
        .unwrap();
        assert_eq!(
            out25.as_slice(),
            hex("3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038")
        );
    }

    /// RFC 6070 vectors expressed with PBKDF2-HMAC-SHA256 (the primitive this
    /// crate actually uses), cross-checked values generated from the RFC 6070
    /// password/salt/iteration inputs.
    #[test]
    fn pbkdf2_hmac_sha256_vectors() {
        let mut out = [0u8; 20];
        pbkdf2_hmac::<Sha256>(b"password", b"salt", 1, &mut out);
        assert_eq!(
            out.as_slice(),
            hex("120fb6cffcf8b32c43e7225256c4f837a86548c9")
        );
        pbkdf2_hmac::<Sha256>(b"password", b"salt", 2, &mut out);
        assert_eq!(
            out.as_slice(),
            hex("ae4d0c95af6b46d32d0adff928f06dd02a303f8e")
        );
        pbkdf2_hmac::<Sha256>(b"password", b"salt", 4096, &mut out);
        assert_eq!(
            out.as_slice(),
            hex("c5e478d59288c841aa530db6845c4c8d962893a0")
        );
        let mut out25 = [0u8; 25];
        pbkdf2_hmac::<Sha256>(
            b"passwordPASSWORDpassword",
            b"saltSALTsaltSALTsaltSALTsaltSALTsalt",
            4096,
            &mut out25,
        );
        assert_eq!(
            out25.as_slice(),
            hex("348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c")
        );
    }

    /// RFC 5869 appendix A, test cases 1 and 2.
    #[test]
    fn rfc5869_hkdf_vectors() {
        let ikm = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let salt = hex("000102030405060708090a0b0c");
        let info = hex("f0f1f2f3f4f5f6f7f8f9");
        let okm = hkdf_sha256(&ikm, &salt, &info, 42).unwrap();
        assert_eq!(
            okm,
            hex("3cb25f25faacd57a90434f64d0362f2a\
                 2d2d0a90cf1a5a4c5db02d56ecc4c5bf\
                 34007208d5b887185865")
        );

        let ikm = hex("000102030405060708090a0b0c0d0e0f\
             101112131415161718191a1b1c1d1e1f\
             202122232425262728292a2b2c2d2e2f\
             303132333435363738393a3b3c3d3e3f\
             404142434445464748494a4b4c4d4e4f");
        let salt = hex("606162636465666768696a6b6c6d6e6f\
             707172737475767778797a7b7c7d7e7f\
             808182838485868788898a8b8c8d8e8f\
             909192939495969798999a9b9c9d9e9f\
             a0a1a2a3a4a5a6a7a8a9aaabacadaeaf");
        let info = hex("b0b1b2b3b4b5b6b7b8b9babbbcbdbebf\
             c0c1c2c3c4c5c6c7c8c9cacbcccdcecf\
             d0d1d2d3d4d5d6d7d8d9dadbdcdddedf\
             e0e1e2e3e4e5e6e7e8e9eaebecedeeef\
             f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        let okm = hkdf_sha256(&ikm, &salt, &info, 82).unwrap();
        assert_eq!(
            okm,
            hex("b11e398dc80327a1c8e7f78c596a4934\
                 4f012eda2d4efad8a050cc4c19afa97c\
                 59045a99cac7827271cb41c65e590e09\
                 da3275600c2f09b8367793a9aca3db71\
                 cc30c58179ec3e87c14c01d5c1f3434f\
                 1d87")
        );
    }

    #[test]
    fn hash_password_uses_nul_separator() {
        // SHA256 of the single byte 0x00, i.e. an empty password and user.
        let mut expected = [0u8; 32];
        expected.copy_from_slice(&hex(
            "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
        ));
        assert_eq!(hash_password(b"", ""), expected);
        assert_ne!(hash_password(b"ab", "c"), hash_password(b"a", "bc"));
    }

    #[test]
    fn static_key_derivation_is_suite_truncated_and_deterministic() {
        let full = derive_static_key("alice", b"password", Suite::XChaCha20Poly1305).unwrap();
        let aes256 = derive_static_key("alice", b"password", Suite::Aes256Gcm).unwrap();
        let aes128 = derive_static_key("alice", b"password", Suite::Aes128Gcm).unwrap();
        assert_eq!(full.len(), 32);
        assert_eq!(aes256.len(), 32);
        assert_eq!(aes128.len(), 16);
        assert_eq!(full.as_slice(), aes256.as_slice());
        assert_eq!(&full.as_slice()[..16], aes128.as_slice());

        let hashed = hash_password(b"password", "alice");
        let salt = static_key_salt();
        let mut expected = [0u8; KEY_LEN];
        pbkdf2_hmac::<Sha256>(&hashed, &salt, PBKDF2_ITERATIONS, &mut expected);
        assert_eq!(full.as_slice(), expected);

        assert_ne!(
            derive_static_key("alice", b"password", Suite::Aes128Gcm)
                .unwrap()
                .as_slice(),
            derive_static_key("alice", b"passworx", Suite::Aes128Gcm)
                .unwrap()
                .as_slice(),
        );
    }

    #[test]
    fn session_keys_are_directional_and_version_bound() {
        let static_key = derive_static_key("alice", b"password", Suite::Aes256Gcm).unwrap();
        let shared = [7u8; 32];
        let client = [1u8; 16];
        let server = [2u8; 16];
        let (c2s, s2c) = derive_session_keys_v4(
            static_key.as_slice(),
            &client,
            &server,
            &shared,
            Suite::XChaCha20Poly1305,
        )
        .unwrap();
        assert_eq!(c2s.len(), 32);
        assert_eq!(s2c.len(), 32);
        assert_ne!(c2s.as_slice(), s2c.as_slice());
        assert_eq!(
            derive_session_keys_v4(
                static_key.as_slice(),
                &client,
                &server,
                &shared,
                Suite::XChaCha20Poly1305,
            )
            .unwrap()
            .0
            .as_slice(),
            c2s.as_slice()
        );
        let (c2s_v3, _) = derive_session_keys(
            static_key.as_slice(),
            &client,
            &server,
            &shared,
            3,
            Suite::XChaCha20Poly1305,
        )
        .unwrap();
        assert_ne!(c2s_v3.as_slice(), c2s.as_slice());

        let (c2s_128, _) = derive_session_keys_v4(
            static_key.as_slice(),
            &client,
            &server,
            &shared,
            Suite::Aes128Gcm,
        )
        .unwrap();
        assert_eq!(c2s_128.len(), 16);
    }

    #[test]
    fn session_keys_reject_bad_inputs() {
        let shared = [7u8; 32];
        let salt = [0u8; 16];
        assert!(derive_session_keys_v4(&[], &salt, &salt, &shared, Suite::Aes256Gcm).is_err());
        assert!(
            derive_session_keys_v4(&[1u8; 32], &[0u8; 15], &salt, &shared, Suite::Aes256Gcm)
                .is_err()
        );
        assert!(
            derive_session_keys_v4(&[1u8; 32], &salt, &[0u8; 17], &shared, Suite::Aes256Gcm)
                .is_err()
        );
        assert!(
            derive_session_keys_v4(&[1u8; 32], &salt, &salt, &[0u8; 31], Suite::Aes256Gcm).is_err()
        );
    }

    #[test]
    fn early_keys_are_deterministic() {
        let static_key = derive_static_key("alice", b"password", Suite::Aes256Gcm).unwrap();
        let suite = Suite::XChaCha20Poly1305;

        let (c2s, s2c) = derive_early_keys(static_key.as_slice(), 0x0102_0304, suite).unwrap();
        let (c2s_again, s2c_again) =
            derive_early_keys(static_key.as_slice(), 0x0102_0304, suite).unwrap();

        assert_eq!(c2s.as_slice(), c2s_again.as_slice());
        assert_eq!(s2c.as_slice(), s2c_again.as_slice());
        assert_ne!(c2s.as_slice(), s2c.as_slice());
        assert_eq!(c2s.len(), suite.key_len());
        assert_eq!(s2c.len(), suite.key_len());
    }

    #[test]
    fn early_keys_bind_the_session_id() {
        let static_key = derive_static_key("alice", b"password", Suite::Aes256Gcm).unwrap();
        let suite = Suite::Aes256Gcm;

        let (c2s, s2c) = derive_early_keys(static_key.as_slice(), 1, suite).unwrap();
        let (other_c2s, other_s2c) = derive_early_keys(static_key.as_slice(), 2, suite).unwrap();
        assert_ne!(c2s.as_slice(), other_c2s.as_slice());
        assert_ne!(s2c.as_slice(), other_s2c.as_slice());
    }

    #[test]
    fn early_keys_differ_from_x25519_session_keys() {
        let static_key = derive_static_key("alice", b"password", Suite::Aes256Gcm).unwrap();
        let suite = Suite::XChaCha20Poly1305;
        let session_id = 0x0102_0304;
        let shared = [7u8; 32];
        let client = [1u8; 16];
        let server = [2u8; 16];

        let (early_c2s, early_s2c) =
            derive_early_keys(static_key.as_slice(), session_id, suite).unwrap();
        let (session_c2s, session_s2c) =
            derive_session_keys_v4(static_key.as_slice(), &client, &server, &shared, suite)
                .unwrap();

        assert_ne!(early_c2s.as_slice(), session_c2s.as_slice());
        assert_ne!(early_s2c.as_slice(), session_s2c.as_slice());
    }

    #[test]
    fn early_keys_reject_bad_inputs() {
        let suite = Suite::Aes256Gcm;
        assert_eq!(
            derive_early_keys(&[], 1, suite).err().unwrap(),
            CryptoError::InvalidKeyLength {
                suite,
                got: 0,
                want: suite.key_len(),
            }
        );
        assert_eq!(
            derive_early_keys(&[1u8; KEY_LEN + 1], 1, suite)
                .err()
                .unwrap(),
            CryptoError::InvalidKeyLength {
                suite,
                got: KEY_LEN + 1,
                want: suite.key_len(),
            }
        );
        let (c2s, _) = derive_early_keys(&[1u8; KEY_LEN], 1, Suite::Aes128Gcm).unwrap();
        assert_eq!(c2s.len(), 16);
    }
}
