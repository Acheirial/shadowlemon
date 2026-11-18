//! Replay-cache signature calculation (spec §8.1).
//!
//! The signature is FNV-1a over exactly 29 bytes:
//!
//! ```text
//! u32be(inputLen) || byte(domain) || wireNonce[0:24]
//! ```
//!
//! The length is placed first so different-length messages cannot collide,
//! and the full 24-byte nonce is covered so a fixed traffic-pattern prefix
//! still leaves ample entropy. Note that V0.2 uses a **32-bit** length prefix
//! and UDP domains `1/2`; the Go V0.1 reference used a 64-bit length and
//! domains `1/2/3`. The spec is authoritative here.

use crate::{WireError, WireNonce, WIRE_NONCE_LEN};

/// FNV-1a 64-bit offset basis (spec §8.1).
pub const FNV1A64_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
/// FNV-1a 64-bit prime (spec §8.1).
pub const FNV1A64_PRIME: u64 = 0x0000_0100_0000_01b3;
/// Number of bytes fed into FNV-1a for one signature: `4 + 1 + 24`.
pub const REPLAY_SIGNATURE_INPUT_LEN: usize = 4 + 1 + WIRE_NONCE_LEN;

/// Replay-cache domain, isolating unrelated traffic flows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ReplayDomain {
    /// UDP client-to-server datagrams.
    UdpClientToServer = 1,
    /// UDP server-to-client datagrams.
    UdpServerToClient = 2,
}

impl ReplayDomain {
    /// Wire value of this domain (`1` or `2`).
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Compute FNV-1a 64 over `bytes` using the spec constants.
#[must_use]
pub fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash = FNV1A64_OFFSET_BASIS;
    for &byte in bytes {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(FNV1A64_PRIME);
    }
    hash
}

/// Compute the 64-bit replay signature for one message.
///
/// `input_len` is the total byte length of the checked message, including the
/// 24-byte wire nonce when the frame carries one. Lengths beyond `u32::MAX`
/// are rejected rather than truncated.
pub fn replay_signature(
    input_len: usize,
    domain: ReplayDomain,
    wire_nonce: &WireNonce,
) -> Result<u64, WireError> {
    let len = u32::try_from(input_len).map_err(|_| WireError::InputLengthTooLarge(input_len))?;
    let mut message = [0u8; REPLAY_SIGNATURE_INPUT_LEN];
    message[..4].copy_from_slice(&len.to_be_bytes());
    message[4] = domain.as_u8();
    message[5..].copy_from_slice(wire_nonce);
    Ok(fnv1a64(&message))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Published FNV-1a 64 golden values, written as literals.
    #[test]
    fn fnv_golden_vectors() {
        assert_eq!(fnv1a64(b""), 0xcbf2_9ce4_8422_2325);
        assert_eq!(fnv1a64(b"a"), 0xaf63_dc4c_8601_ec8c);
        assert_eq!(fnv1a64(b"foobar"), 0x8594_4171_f739_67e8);
    }

    #[test]
    fn signature_golden_vector() {
        // m = u32be(72) || 0x01 || 0x42 * 24, hashed independently.
        assert_eq!(
            replay_signature(72, ReplayDomain::UdpClientToServer, &[0x42; 24]).unwrap(),
            0x4bd6_ad18_f957_8274
        );
    }

    #[test]
    fn signature_is_domain_and_length_separated() {
        let nonce = [7u8; 24];
        let base = replay_signature(72, ReplayDomain::UdpClientToServer, &nonce).unwrap();
        assert_ne!(
            base,
            replay_signature(72, ReplayDomain::UdpServerToClient, &nonce).unwrap()
        );
        assert_ne!(
            base,
            replay_signature(73, ReplayDomain::UdpClientToServer, &nonce).unwrap()
        );
        let mut other = nonce;
        other[23] ^= 1;
        assert_ne!(
            base,
            replay_signature(72, ReplayDomain::UdpClientToServer, &other).unwrap()
        );
    }

    #[test]
    fn signature_rejects_length_overflow() {
        assert_eq!(
            replay_signature(usize::MAX, ReplayDomain::UdpClientToServer, &[0; 24]).unwrap_err(),
            WireError::InputLengthTooLarge(usize::MAX)
        );
    }
}
