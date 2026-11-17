//! Wire framing and packet layout for ShadowLemon V0.2.
//!
//! This crate implements the authoritative byte-level rules of
//! `rust/docs/protocol-v0.2.md` §4–§8 without depending on a concrete AEAD:
//!
//! * [`Metadata`] – the three exact 32-byte metadata layouts (types 2–11),
//!   with receive-side validation per §6 and §7.5 and zeroed reserved bytes
//!   on send.
//! * [`encode_segment`] / [`decode_segment`] – complete segment framing
//!   (24-byte nonce, encrypted metadata + tag, padding, payload + tag,
//!   padding) through the small [`Cipher`] trait.
//! * [`padding`] – prefix/suffix padding length generation, including the Go
//!   `min == max -> max - 1` anti-fingerprint rule.
//! * [`replay_signature`] – FNV-1a 64 replay-cache signatures (§8.1).
//! * [`low_entropy`] – the simplified V0.2 low-entropy transform (§7), behind
//!   the default-off `low-entropy` feature.
//!
//! Parsers never panic: arbitrary attacker-controlled bytes produce a
//! [`WireError`] instead.

#![forbid(unsafe_code)]

pub mod error;
pub mod metadata;
pub mod padding;
pub mod replay_sig;
pub mod segment;

#[cfg(feature = "low-entropy")]
pub mod low_entropy;

/// Length of the wire nonce carried by every segment that includes one.
pub const WIRE_NONCE_LEN: usize = 24;
/// A 24-byte wire nonce. The AEAD nonce is derived from its suffix.
pub type WireNonce = [u8; WIRE_NONCE_LEN];
/// Exact plaintext metadata length from spec §6.
pub const METADATA_LEN: usize = 32;
/// AEAD authentication tag length for every supported suite.
pub const TAG_LEN: usize = 16;
/// Maximum payload length in session metadata (types 2–5).
pub const MAX_SESSION_PAYLOAD: usize = 1024;
/// Maximum application fragment length in data metadata (types 6–11).
pub const MAX_FRAGMENT: usize = 32768;
/// Wire nonce byte flipped to derive a UDP payload nonce (spec §4.2).
pub const PAYLOAD_NONCE_INDEX: usize = 16;
/// Value XORed into [`PAYLOAD_NONCE_INDEX`] for UDP payloads.
pub const PAYLOAD_NONCE_MASK: u8 = 0x01;

pub use error::{CipherError, WireError};
pub use metadata::{
    low_entropy_encoded_len, low_entropy_stride, DataMetadata, LowEntropyMetadata, Metadata,
    SessionMetadata, METADATA_LENGTH,
};
pub use padding::{PaddingConfig, PaddingRange};
pub use replay_sig::{
    fnv1a64, replay_signature, ReplayDomain, FNV1A64_OFFSET_BASIS, FNV1A64_PRIME,
    REPLAY_SIGNATURE_INPUT_LEN,
};
pub use segment::{
    decode_segment, encode_segment, frame_len, increment_nonce, payload_block_len, Cipher,
    DecodeOptions, EncodeOptions, PayloadNonce, Segment, META_BLOCK_LEN, NONCE_AND_META_LEN,
};

#[cfg(feature = "low-entropy")]
pub use low_entropy::{
    decode, encode, generate_half_mask, infer_polarity, repeat32, validate_params, LowEntropyParams,
};
