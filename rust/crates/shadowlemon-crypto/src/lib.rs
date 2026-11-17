//! Cryptographic primitives for the ShadowLemon V0.2 wire protocol.
//!
//! The crate is deliberately dependency-light and free of I/O: it implements
//! the frozen byte-level rules shared by the client and the server.
//!
//! * [`suite`] – AEAD suite identifiers and their wire names.
//! * [`kdf`] – static key and directional session key derivation.
//! * [`kex`] – ephemeral X25519 key agreement with low-order point rejection.
//! * [`aead`] – 24-byte wire nonces, AEAD nonce truncation and payload nonces.
//! * [`hint`] – keyed four-byte user hints embedded in wire nonces.
//! * [`envelope`] – handshake request/response serialisation and validation.

#![forbid(unsafe_code)]

use thiserror::Error;
use zeroize::Zeroizing;

pub mod aead;
pub mod envelope;
pub mod hint;
pub mod kdf;
pub mod kex;
pub mod suite;

/// Length of the nonce carried on the wire, in bytes. This is the same for
/// every cipher suite; the AEAD nonce is derived from it (see [`aead`]).
pub const WIRE_NONCE_LEN: usize = 24;
/// A 24-byte wire nonce. The AEAD nonce is a suffix of this value.
pub type WireNonce = [u8; WIRE_NONCE_LEN];
/// Length of the AEAD authentication tag, in bytes, for every supported suite.
pub const AEAD_TAG_LEN: usize = 16;
/// Length of a PBKDF2 / X25519 / SHA-256 key, in bytes.
pub const KEY_LEN: usize = 32;
/// Length of the client and server handshake salts, in bytes.
pub const SALT_LEN: usize = 16;
/// Length of an X25519 public key or shared secret, in bytes.
pub const EPHEMERAL_KEY_LEN: usize = 32;
/// Length of the keyed user hint, in bytes.
pub const HINT_LEN: usize = 4;
/// Number of leading wire nonce bytes fed into the user hint.
pub const HINT_NONCE_PREFIX_LEN: usize = 16;
/// Index of the wire nonce byte flipped to derive a UDP payload nonce.
pub const PAYLOAD_NONCE_INDEX: usize = 16;
/// Value XORed into [`PAYLOAD_NONCE_INDEX`] for UDP payloads.
pub const PAYLOAD_NONCE_MASK: u8 = 0x01;
/// PBKDF2 iteration count of the static key (frozen protocol constant).
pub const PBKDF2_ITERATIONS: u32 = 4096;
/// Domain-separation prefix used by every V0.2 derivation.
pub const PROTOCOL_IDENTIFIER: &str = "ShadowLemon V0.2";
/// Protocol version byte mixed into the session HKDF info.
pub const DEFAULT_PROTOCOL_VERSION: u8 = 4;
/// Maximum number of cipher suites in a handshake request.
pub const MAX_HANDSHAKE_SUITES: usize = 4;
/// Length of a handshake request without its suite list.
pub const HANDSHAKE_REQUEST_FIXED_LEN: usize = 51;
/// Length of a handshake response.
pub const HANDSHAKE_RESPONSE_LEN: usize = 51;

/// A heap-backed secret buffer that is erased when dropped.
pub type SecretBuf = Zeroizing<Vec<u8>>;

/// Errors produced by the crypto crate.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CryptoError {
    /// A suite byte does not name a supported cipher suite.
    #[error("unknown cipher suite id {0}")]
    UnknownSuite(u8),
    /// A textual suite name was not recognised.
    #[error("unknown cipher suite name {0:?}")]
    UnknownSuiteName(String),
    /// A key buffer had the wrong length for its suite.
    #[error("key length {got} is invalid for {suite} (want {want})")]
    InvalidKeyLength {
        /// The selected suite.
        suite: crate::suite::Suite,
        /// Length actually supplied.
        got: usize,
        /// Length required by the suite.
        want: usize,
    },
    /// A nonce had the wrong length.
    #[error("nonce length {got} is invalid (want {want})")]
    InvalidNonceLength {
        /// Length actually supplied.
        got: usize,
        /// Length required.
        want: usize,
    },
    /// A salt had the wrong length.
    #[error("{field} length {got} is invalid (want {want})")]
    InvalidSaltLength {
        /// Name of the offending field.
        field: &'static str,
        /// Length actually supplied.
        got: usize,
        /// Length required.
        want: usize,
    },
    /// The peer's X25519 public key produced an all-zero shared secret.
    #[error("X25519 shared secret is all zero (peer public key is not usable)")]
    AllZeroSharedSecret,
    /// A handshake message could not be parsed or validated.
    #[error("malformed handshake: {0}")]
    MalformedHandshake(String),
    /// A handshake request repeated a cipher suite.
    #[error("duplicate cipher suite {0} in handshake request")]
    DuplicateSuite(u8),
    /// A peer advertised a protocol version this build does not speak.
    #[error("unsupported protocol version {got} (want {want})")]
    UnsupportedVersion {
        /// Version received.
        got: u8,
        /// Version expected.
        want: u8,
    },
    /// An AEAD seal or open operation failed.
    #[error("AEAD operation failed: {0}")]
    Aead(#[from] ::aead::Error),
    /// The operating system random source failed.
    #[error("random number generation failed: {0}")]
    Random(String),
    /// HKDF could not produce the requested amount of key material.
    #[error("HKDF output length is invalid")]
    HkdfInvalidLength,
}

impl From<getrandom::Error> for CryptoError {
    fn from(err: getrandom::Error) -> Self {
        Self::Random(err.to_string())
    }
}

/// Constant-time equality for fixed-size secret comparisons.
///
/// Uses the `subtle` implementation exposed by `x25519-dalek`'s dependency
/// tree through a plain XOR accumulator; inputs are always fixed length at
/// the call sites in this crate.
#[must_use]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Returns true when every byte of `b` is zero.
#[must_use]
pub fn is_all_zero(b: &[u8]) -> bool {
    let mut acc = 0u8;
    for &byte in b {
        acc |= byte;
    }
    acc == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_time_helpers() {
        assert!(constant_time_eq(b"shadow", b"shadow"));
        assert!(!constant_time_eq(b"shadow", b"lemon!"));
        assert!(!constant_time_eq(b"short", b"longer"));
        assert!(is_all_zero(&[0, 0, 0]));
        assert!(!is_all_zero(&[0, 1, 0]));
    }
}
