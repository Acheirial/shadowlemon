//! Errors produced by the wire codec.
//!
//! Every parser in this crate returns one of these errors instead of panicking,
//! so arbitrary (attacker-controlled) bytes can be fed to [`crate::Metadata::parse`]
//! and [`crate::decode_segment`] safely.

use thiserror::Error;

/// Failure reported by a [`crate::Cipher`] implementation.
///
/// The wire crate intentionally does not depend on a concrete AEAD. Adapters
/// map their native error (for example `CryptoError` from the crypto crate)
/// into this small, allocation-light type.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CipherError {
    /// The underlying cipher rejected an operation (bad tag, bad key, ...).
    #[error("cipher operation failed: {0}")]
    Failed(String),
}

impl CipherError {
    /// Convenience constructor from any displayable error.
    pub fn failed(error: impl core::fmt::Display) -> Self {
        Self::Failed(error.to_string())
    }
}

/// Errors produced while encoding or decoding ShadowLemon V0.2 wire data.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum WireError {
    /// An encrypted metadata block was not exactly 32 bytes.
    #[error("metadata must be exactly 32 bytes (got {0})")]
    MetadataLength(usize),
    /// The decrypted metadata plaintext was not exactly 32 bytes.
    #[error("decrypted metadata must be exactly 32 bytes (got {0})")]
    MetadataPlaintextLength(usize),
    /// The protocol type byte was not in the V0.2 range `2..=11`.
    #[error("invalid protocol type {0}")]
    InvalidProtocolType(u8),
    /// A session metadata payload exceeded `MAX_SESSION_PAYLOAD`.
    #[error("session payload length {0} exceeds {max}", max = crate::MAX_SESSION_PAYLOAD)]
    SessionPayloadTooLong(usize),
    /// A data metadata payload exceeded `MAX_FRAGMENT`.
    #[error("data payload length {0} exceeds {max}", max = crate::MAX_FRAGMENT)]
    DataPayloadTooLong(usize),
    /// A low-entropy metadata block declared an invalid mode.
    #[error("invalid low entropy mode {0} (want 1..=4)")]
    InvalidLowEntropyMode(u8),
    /// A low-entropy metadata block declared an invalid rotation.
    #[error("invalid low entropy mask rotation {0} (want 0..=63)")]
    InvalidMaskRotation(u8),
    /// The half-mask popcount did not match the mode's fixed step.
    #[error("low entropy half-mask popcount {got} does not match {want}")]
    InvalidHalfMaskPopcount {
        /// Popcount observed in the 32-bit half-mask.
        got: u32,
        /// Popcount required by the mode (`4 * C`).
        want: u32,
    },
    /// The low-entropy encoded length did not match `ceil(extracted / C) * 8`.
    #[error("low entropy encoded length {got} does not match expected {want}")]
    LowEntropyLengthMismatch {
        /// Declared or observed encoded length.
        got: usize,
        /// Length implied by the extracted length and mode.
        want: usize,
    },
    /// The encoded payload length was not a multiple of eight.
    #[error("low entropy payload length {0} is not a multiple of eight")]
    UnalignedLowEntropyLength(usize),
    /// A zero extracted length was paired with a non-zero encoded length.
    #[error("zero extracted length requires a zero encoded length (got {0})")]
    EmptyLowEntropyPayload(usize),
    /// Low-entropy data was encountered in a build without the `low-entropy` feature.
    #[error("low entropy support is not compiled in")]
    LowEntropyDisabled,
    /// Mixed filler-bit polarity was found while decoding a low-entropy body.
    #[error("low entropy filler bits use mixed polarity")]
    MixedFillerPolarity,
    /// A later low-entropy chunk disagreed with the first chunk's polarity.
    #[error("low entropy filler polarity is inconsistent across chunks")]
    FillerPolarityMismatch,
    /// A wire nonce had the wrong length.
    #[error("wire nonce must be exactly 24 bytes (got {0})")]
    NonceLength(usize),
    /// A frame was shorter than its mandatory fixed part.
    #[error("frame too short: got {got} bytes, need at least {want}")]
    FrameTooShort {
        /// Observed frame length.
        got: usize,
        /// Minimum required frame length.
        want: usize,
    },
    /// A frame's total length disagreed with its metadata fields.
    #[error("frame length mismatch: metadata implies {declared} bytes, frame has {actual}")]
    FrameLengthMismatch {
        /// Length implied by the metadata.
        declared: usize,
        /// Actual frame length.
        actual: usize,
    },
    /// A padding field's actual length disagreed with the metadata.
    #[error("{field} padding length mismatch: metadata says {declared}, got {actual}")]
    PaddingLengthMismatch {
        /// Name of the padding field ("prefix" or "suffix").
        field: &'static str,
        /// Length declared in the metadata.
        declared: usize,
        /// Number of padding bytes supplied or read.
        actual: usize,
    },
    /// The plaintext payload length disagreed with the metadata.
    #[error("payload length mismatch: metadata says {declared}, got {actual}")]
    PayloadLengthMismatch {
        /// Length declared in the metadata.
        declared: usize,
        /// Actual plaintext length.
        actual: usize,
    },
    /// A padding range was malformed (minimum greater than maximum, or > 255).
    #[error("invalid padding range {min}..={max}")]
    InvalidPaddingRange {
        /// Requested minimum.
        min: usize,
        /// Requested maximum.
        max: usize,
    },
    /// A replay input length did not fit in the 32-bit length prefix.
    #[error("replay input length {0} exceeds u32")]
    InputLengthTooLarge(usize),
    /// A sealed block had an unexpected length.
    #[error("{block} cipher block must be {want} bytes (got {got})")]
    CipherBlockLength {
        /// Name of the block ("metadata" or "payload").
        block: &'static str,
        /// Observed length.
        got: usize,
        /// Required length.
        want: usize,
    },
    /// The underlying AEAD failed to seal or open a block.
    #[error(transparent)]
    Cipher(#[from] CipherError),
}
