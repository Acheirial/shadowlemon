//! Deployment-wide secret shared by all wire-visible fast filters.
//!
//! Values derived from this secret must never be guessable by a passive
//! observer. Both peers must set [`ENVELOPE_SECRET_ENV`] to the same
//! high-entropy value. There is deliberately no built-in default: a published
//! constant would let an observer derive the UDP routing envelope keystream
//! and correlate sessions by their `kind` and session id.

use std::sync::OnceLock;

use sha2::{Digest, Sha256};

/// Environment variable holding the deployment secret (UTF-8, non-empty).
pub const ENVELOPE_SECRET_ENV: &str = "SHADOWLEMON_ENVELOPE_SECRET";

/// Length of the envelope keystream prefix, in bytes.
pub const ENVELOPE_KEYSTREAM_LEN: usize = 5;

static SECRET: OnceLock<Vec<u8>> = OnceLock::new();

/// Returns the process-wide deployment secret.
///
/// Both peers must set `SHADOWLEMON_ENVELOPE_SECRET` to the same high-entropy
/// value before start-up. Missing, empty or non-UTF-8 values are rejected: a
/// published fallback would let a passive observer derive the routing envelope
/// keystream from the per-packet nonce and recover `kind` / session ids.
/// The value is read once and cached for the lifetime of the process.
#[must_use]
pub fn deployment_secret() -> &'static [u8] {
    SECRET.get_or_init(|| {
        let value = std::env::var(ENVELOPE_SECRET_ENV).unwrap_or_else(|_| {
            panic!("{ENVELOPE_SECRET_ENV} must be set to the same high-entropy value on both peers")
        });
        assert!(!value.is_empty(), "{ENVELOPE_SECRET_ENV} must not be empty");
        value.into_bytes()
    })
}

/// Derives the 5-byte envelope keystream for `salt`:
/// `SHA256(deployment_secret() || salt)[0:5]`.
#[must_use]
pub fn envelope_keystream(salt: &[u8]) -> [u8; ENVELOPE_KEYSTREAM_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(deployment_secret());
    hasher.update(salt);
    let digest = hasher.finalize();
    let mut out = [0u8; ENVELOPE_KEYSTREAM_LEN];
    out.copy_from_slice(&digest[..ENVELOPE_KEYSTREAM_LEN]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_is_non_empty_and_stable() {
        let secret = deployment_secret();
        assert!(!secret.is_empty());
        assert_eq!(secret, deployment_secret());
    }

    #[test]
    fn keystream_matches_sha256_definition() {
        let salt = b"0123456789abcdef";
        let mut input = Vec::new();
        input.extend_from_slice(deployment_secret());
        input.extend_from_slice(salt);
        let digest = Sha256::digest(&input);
        assert_eq!(envelope_keystream(salt), digest[..ENVELOPE_KEYSTREAM_LEN]);
        assert_eq!(envelope_keystream(salt), envelope_keystream(salt));
    }

    #[test]
    fn keystream_binds_to_salt() {
        assert_ne!(envelope_keystream(b"salt-a"), envelope_keystream(b"salt-b"));
    }
}
