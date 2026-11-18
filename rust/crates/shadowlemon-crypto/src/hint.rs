//! Keyed user hints embedded in the last four bytes of a wire nonce.
//!
//! The hint is a fast filter that lets a server pick which user's key to try
//! first. It is **not** an authentication check: a match must never grant
//! access by itself. The pepper is the process-wide deployment secret (see
//! [`crate::deployment::deployment_secret`]); using a public hardcoded value
//! would let a passive observer enumerate usernames offline.

use sha2::{Digest, Sha256};

use crate::{
    constant_time_eq, deployment::deployment_secret, WireNonce, HINT_LEN, HINT_NONCE_PREFIX_LEN,
};

/// Compute the four-byte keyed hint of `username` for a wire nonce:
/// `SHA256(deployment_secret() || username || nonce[0:16])[0:4]`.
#[must_use]
pub fn user_hint(username: &[u8], wire_nonce: &WireNonce) -> [u8; HINT_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(deployment_secret());
    hasher.update(username);
    hasher.update(&wire_nonce[..HINT_NONCE_PREFIX_LEN]);
    let digest = hasher.finalize();
    let mut hint = [0u8; HINT_LEN];
    hint.copy_from_slice(&digest[..HINT_LEN]);
    hint
}

/// Overwrite the last four bytes of a wire nonce with the keyed user hint.
pub fn write_user_hint(wire_nonce: &mut WireNonce, username: &[u8]) {
    let hint = user_hint(username, wire_nonce);
    let end = wire_nonce.len();
    wire_nonce[end - HINT_LEN..].copy_from_slice(&hint);
}

/// Check whether the hint carried in a wire nonce belongs to `username`.
#[must_use]
pub fn check_user_hint(username: &[u8], wire_nonce: &WireNonce) -> bool {
    let expected = user_hint(username, wire_nonce);
    let end = wire_nonce.len();
    constant_time_eq(&expected, &wire_nonce[end - HINT_LEN..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hint_matches_sha256_definition() {
        let nonce = [0x11u8; 24];
        let hint = user_hint(b"alice", &nonce);
        let mut input = Vec::new();
        input.extend_from_slice(deployment_secret());
        input.extend_from_slice(b"alice");
        input.extend_from_slice(&nonce[..16]);
        let digest = Sha256::digest(&input);
        assert_eq!(hint, digest[..4]);
    }

    #[test]
    fn hint_writes_and_checks_last_four_bytes() {
        let mut nonce = [0x42u8; 24];
        let original_prefix = nonce[..16].to_vec();
        write_user_hint(&mut nonce, b"alice");
        assert_eq!(nonce[..16], original_prefix[..]);
        assert!(check_user_hint(b"alice", &nonce));
        assert!(!check_user_hint(b"bob", &nonce));

        let expected = user_hint(b"alice", &[0x42u8; 24]);
        assert_eq!(&nonce[20..], &expected[..]);
    }

    #[test]
    fn hint_binds_to_nonce_prefix() {
        let mut a = [0u8; 24];
        let mut b = [0u8; 24];
        b[0] = 1;
        assert_ne!(user_hint(b"alice", &a), user_hint(b"alice", &b));
        // Bytes outside the 16-byte prefix do not affect the hint.
        a[20] = 9;
        b[20] = 9;
        b[0] = 0;
        assert_eq!(user_hint(b"alice", &a), user_hint(b"alice", &b));
    }
}
