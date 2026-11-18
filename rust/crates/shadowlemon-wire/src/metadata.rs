//! The 32-byte plaintext metadata layouts from spec §6.
//!
//! Metadata is always 32 bytes on the wire after AEAD decryption. All integers
//! are big-endian. Reserved bytes (including byte 1 for non-low-entropy types)
//! are **ignored on receive** and **zeroed on send**, exactly as required by
//! spec §6. Every field that matters is covered by the AEAD authentication tag.
//!
//! * [`SessionMetadata`] – types 2 (`openSessionRequest`), 3
//!   (`openSessionResponse`), 4 (`closeSessionRequest`), 5
//!   (`closeSessionResponse`).
//! * [`DataMetadata`] – types 6/7 (data) and 8/9 (acks).
//! * [`LowEntropyMetadata`] – types 10/11, the simplified V0.2 low-entropy
//!   extension (the *transform* itself lives in the feature-gated
//!   [`crate::low_entropy`] module, but the metadata layout is always present).

use crate::{WireError, MAX_FRAGMENT, MAX_SESSION_PAYLOAD, METADATA_LEN};

/// Fixed plaintext metadata length in bytes.
pub const METADATA_LENGTH: usize = METADATA_LEN;

/// Big-endian u16 reader. Panic-free for any index pair within the slice.
fn read_u16(buf: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([buf[at], buf[at + 1]])
}

/// Big-endian u32 reader. Panic-free for any index pair within the slice.
fn read_u32(buf: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([buf[at], buf[at + 1], buf[at + 2], buf[at + 3]])
}

/// Returns the fixed source-bytes-per-chunk step `C` for a low-entropy mode.
///
/// Modes 1, 2, 3, 4 map to 4, 5, 6, 7 respectively (spec §7.1). Unknown modes
/// return `None`.
#[must_use]
pub const fn low_entropy_stride(mode: u8) -> Option<usize> {
    match mode {
        1 => Some(4),
        2 => Some(5),
        3 => Some(6),
        4 => Some(7),
        _ => None,
    }
}

/// Encoded length of `extracted_len` payload bytes in low-entropy mode `mode`.
///
/// The result is `ceil(extracted_len / C) * 8`, or `None` for an unknown mode.
#[must_use]
pub const fn low_entropy_encoded_len(extracted_len: usize, mode: u8) -> Option<usize> {
    match low_entropy_stride(mode) {
        Some(c) => Some((extracted_len.div_ceil(c)) * 8),
        None => None,
    }
}

/// Session metadata (protocol types 2, 3, 4, 5), spec §6.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionMetadata {
    /// Protocol type; one of 2, 3, 4, 5.
    pub protocol_type: u8,
    /// Session identifier.
    pub session_id: u32,
    /// Per-direction sequence number.
    pub sequence: u32,
    /// Payload length in bytes (excluding the 16-byte AEAD tag), `<= 1024`.
    pub payload_len: u16,
    /// Length of padding 2 (suffix).
    pub suffix_len: u8,
}

/// Data / ACK metadata (protocol types 6, 7, 8, 9), spec §6.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataMetadata {
    /// Protocol type; one of 6, 7, 8, 9.
    pub protocol_type: u8,
    /// Session identifier.
    pub session_id: u32,
    /// Per-direction sequence number.
    pub sequence: u32,
    /// Sliding-window left edge (unacknowledged sequence number).
    pub unack: u32,
    /// Receive window size, in segments.
    pub window: u16,
    /// Fragment number, counting down to zero for the last fragment.
    pub fragment: u8,
    /// Length of padding 1 (prefix).
    pub prefix_len: u8,
    /// Payload length in bytes (excluding the 16-byte AEAD tag), `<= 32768`.
    pub payload_len: u16,
    /// Length of padding 2 (suffix).
    pub suffix_len: u8,
}

/// Low-entropy data metadata (protocol types 10, 11), spec §6.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LowEntropyMetadata {
    /// Protocol type; one of 10, 11.
    pub protocol_type: u8,
    /// Low-entropy mode; one of 1, 2, 3, 4.
    pub mode: u8,
    /// Session identifier.
    pub session_id: u32,
    /// Per-direction sequence number.
    pub sequence: u32,
    /// Sliding-window left edge.
    pub unack: u32,
    /// Receive window size, in segments.
    pub window: u16,
    /// Fragment number, counting down to zero for the last fragment.
    pub fragment: u8,
    /// Length of padding 1 (prefix).
    pub prefix_len: u8,
    /// **Encoded** body length in bytes; a multiple of eight.
    pub payload_len: u16,
    /// Length of padding 2 (suffix).
    pub suffix_len: u8,
    /// 32-bit half-mask, repeated into the 64-bit mask (spec §7.2).
    pub half_mask: u32,
    /// Length of the ciphertext body **before** low-entropy encoding.
    pub extracted_len: u16,
    /// Per-chunk circular-right-rotation `R`, in `0..=63`.
    pub rotation: u8,
}

/// Parsed representation of the 32-byte metadata plaintext.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Metadata {
    /// A session-control message (types 2–5).
    Session(SessionMetadata),
    /// A data or ACK message (types 6–9).
    Data(DataMetadata),
    /// A low-entropy data message (types 10–11).
    LowEntropy(LowEntropyMetadata),
}

impl Metadata {
    /// Construct session metadata of the given protocol type.
    #[must_use]
    pub const fn session(
        protocol_type: u8,
        session_id: u32,
        sequence: u32,
        payload_len: u16,
        suffix_len: u8,
    ) -> Self {
        Self::Session(SessionMetadata {
            protocol_type,
            session_id,
            sequence,
            payload_len,
            suffix_len,
        })
    }

    /// Construct data metadata of the given protocol type.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub const fn data(
        protocol_type: u8,
        session_id: u32,
        sequence: u32,
        unack: u32,
        window: u16,
        fragment: u8,
        prefix_len: u8,
        payload_len: u16,
        suffix_len: u8,
    ) -> Self {
        Self::Data(DataMetadata {
            protocol_type,
            session_id,
            sequence,
            unack,
            window,
            fragment,
            prefix_len,
            payload_len,
            suffix_len,
        })
    }

    /// Construct low-entropy metadata of the given protocol type.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub const fn low_entropy(
        protocol_type: u8,
        mode: u8,
        session_id: u32,
        sequence: u32,
        unack: u32,
        window: u16,
        fragment: u8,
        prefix_len: u8,
        payload_len: u16,
        suffix_len: u8,
        half_mask: u32,
        extracted_len: u16,
        rotation: u8,
    ) -> Self {
        Self::LowEntropy(LowEntropyMetadata {
            protocol_type,
            mode,
            session_id,
            sequence,
            unack,
            window,
            fragment,
            prefix_len,
            payload_len,
            suffix_len,
            half_mask,
            extracted_len,
            rotation,
        })
    }

    /// Parse a 32-byte metadata plaintext, validating spec §6 and §7.5.
    ///
    /// Reserved bytes (byte 1 for non-low-entropy types and the trailing
    /// reserved regions) are deliberately ignored. This function never panics.
    pub fn parse(buf: &[u8]) -> Result<Self, WireError> {
        if buf.len() != METADATA_LEN {
            return Err(WireError::MetadataLength(buf.len()));
        }
        let parsed = match buf[0] {
            2..=5 => Self::Session(SessionMetadata {
                protocol_type: buf[0],
                session_id: read_u32(buf, 2),
                sequence: read_u32(buf, 6),
                payload_len: read_u16(buf, 10),
                suffix_len: buf[12],
            }),
            6..=9 => Self::Data(DataMetadata {
                protocol_type: buf[0],
                session_id: read_u32(buf, 2),
                sequence: read_u32(buf, 6),
                unack: read_u32(buf, 10),
                window: read_u16(buf, 14),
                fragment: buf[16],
                prefix_len: buf[17],
                payload_len: read_u16(buf, 18),
                suffix_len: buf[20],
            }),
            10 | 11 => Self::LowEntropy(LowEntropyMetadata {
                protocol_type: buf[0],
                mode: buf[1],
                session_id: read_u32(buf, 2),
                sequence: read_u32(buf, 6),
                unack: read_u32(buf, 10),
                window: read_u16(buf, 14),
                fragment: buf[16],
                prefix_len: buf[17],
                payload_len: read_u16(buf, 18),
                suffix_len: buf[20],
                half_mask: read_u32(buf, 21),
                extracted_len: read_u16(buf, 25),
                rotation: buf[27],
            }),
            other => return Err(WireError::InvalidProtocolType(other)),
        };
        parsed.validate()?;
        Ok(parsed)
    }

    /// Validate all type-specific constraints, including spec §7.5.
    ///
    /// Also used by the segment encoder, because metadata fields are public
    /// and a caller can construct an inconsistent value directly.
    pub fn validate(&self) -> Result<(), WireError> {
        match self {
            Self::Session(meta) => {
                if !(2..=5).contains(&meta.protocol_type) {
                    return Err(WireError::InvalidProtocolType(meta.protocol_type));
                }
                if usize::from(meta.payload_len) > MAX_SESSION_PAYLOAD {
                    return Err(WireError::SessionPayloadTooLong(usize::from(
                        meta.payload_len,
                    )));
                }
            }
            Self::Data(meta) => {
                if !(6..=9).contains(&meta.protocol_type) {
                    return Err(WireError::InvalidProtocolType(meta.protocol_type));
                }
                if usize::from(meta.payload_len) > MAX_FRAGMENT {
                    return Err(WireError::DataPayloadTooLong(usize::from(meta.payload_len)));
                }
            }
            Self::LowEntropy(meta) => validate_low_entropy(meta)?,
        }
        Ok(())
    }

    /// Encode to the exact 32-byte plaintext layout.
    ///
    /// Every reserved byte is written as zero, as required for senders by §6.
    #[must_use]
    pub fn encode(&self) -> [u8; METADATA_LEN] {
        let mut out = [0u8; METADATA_LEN];
        match self {
            Self::Session(meta) => {
                out[0] = meta.protocol_type;
                out[2..6].copy_from_slice(&meta.session_id.to_be_bytes());
                out[6..10].copy_from_slice(&meta.sequence.to_be_bytes());
                out[10..12].copy_from_slice(&meta.payload_len.to_be_bytes());
                out[12] = meta.suffix_len;
            }
            Self::Data(meta) => {
                out[0] = meta.protocol_type;
                out[2..6].copy_from_slice(&meta.session_id.to_be_bytes());
                out[6..10].copy_from_slice(&meta.sequence.to_be_bytes());
                out[10..14].copy_from_slice(&meta.unack.to_be_bytes());
                out[14..16].copy_from_slice(&meta.window.to_be_bytes());
                out[16] = meta.fragment;
                out[17] = meta.prefix_len;
                out[18..20].copy_from_slice(&meta.payload_len.to_be_bytes());
                out[20] = meta.suffix_len;
            }
            Self::LowEntropy(meta) => {
                out[0] = meta.protocol_type;
                out[1] = meta.mode;
                out[2..6].copy_from_slice(&meta.session_id.to_be_bytes());
                out[6..10].copy_from_slice(&meta.sequence.to_be_bytes());
                out[10..14].copy_from_slice(&meta.unack.to_be_bytes());
                out[14..16].copy_from_slice(&meta.window.to_be_bytes());
                out[16] = meta.fragment;
                out[17] = meta.prefix_len;
                out[18..20].copy_from_slice(&meta.payload_len.to_be_bytes());
                out[20] = meta.suffix_len;
                out[21..25].copy_from_slice(&meta.half_mask.to_be_bytes());
                out[25..27].copy_from_slice(&meta.extracted_len.to_be_bytes());
                out[27] = meta.rotation;
            }
        }
        out
    }

    /// Protocol type byte (0 is never produced by a valid metadata value).
    #[must_use]
    pub const fn protocol_type(&self) -> u8 {
        match self {
            Self::Session(m) => m.protocol_type,
            Self::Data(m) => m.protocol_type,
            Self::LowEntropy(m) => m.protocol_type,
        }
    }

    /// Session identifier, common to all layouts.
    #[must_use]
    pub const fn session_id(&self) -> u32 {
        match self {
            Self::Session(m) => m.session_id,
            Self::Data(m) => m.session_id,
            Self::LowEntropy(m) => m.session_id,
        }
    }

    /// Sequence number, common to all layouts.
    #[must_use]
    pub const fn sequence(&self) -> u32 {
        match self {
            Self::Session(m) => m.sequence,
            Self::Data(m) => m.sequence,
            Self::LowEntropy(m) => m.sequence,
        }
    }

    /// Unacknowledged sequence number (zero for session metadata).
    #[must_use]
    pub const fn unack(&self) -> u32 {
        match self {
            Self::Session(_) => 0,
            Self::Data(m) => m.unack,
            Self::LowEntropy(m) => m.unack,
        }
    }

    /// Receive window size (zero for session metadata).
    #[must_use]
    pub const fn window(&self) -> u16 {
        match self {
            Self::Session(_) => 0,
            Self::Data(m) => m.window,
            Self::LowEntropy(m) => m.window,
        }
    }

    /// Fragment number (zero for session metadata).
    #[must_use]
    pub const fn fragment(&self) -> u8 {
        match self {
            Self::Session(_) => 0,
            Self::Data(m) => m.fragment,
            Self::LowEntropy(m) => m.fragment,
        }
    }

    /// Prefix padding length (zero for session metadata).
    #[must_use]
    pub const fn prefix_len(&self) -> u8 {
        match self {
            Self::Session(_) => 0,
            Self::Data(m) => m.prefix_len,
            Self::LowEntropy(m) => m.prefix_len,
        }
    }

    /// Declared payload length (encoded length for low-entropy metadata).
    #[must_use]
    pub const fn payload_len(&self) -> u16 {
        match self {
            Self::Session(m) => m.payload_len,
            Self::Data(m) => m.payload_len,
            Self::LowEntropy(m) => m.payload_len,
        }
    }

    /// Suffix padding length.
    #[must_use]
    pub const fn suffix_len(&self) -> u8 {
        match self {
            Self::Session(m) => m.suffix_len,
            Self::Data(m) => m.suffix_len,
            Self::LowEntropy(m) => m.suffix_len,
        }
    }

    /// True for protocol types 10 and 11.
    #[must_use]
    pub const fn is_low_entropy(&self) -> bool {
        matches!(self, Self::LowEntropy(_))
    }

    /// Low-entropy mode, or `None` for non-low-entropy metadata.
    #[must_use]
    pub const fn low_entropy_mode(&self) -> Option<u8> {
        match self {
            Self::LowEntropy(m) => Some(m.mode),
            _ => None,
        }
    }

    /// Low-entropy half-mask, or `None` for non-low-entropy metadata.
    #[must_use]
    pub const fn low_entropy_half_mask(&self) -> Option<u32> {
        match self {
            Self::LowEntropy(m) => Some(m.half_mask),
            _ => None,
        }
    }

    /// Low-entropy extracted (pre-transform) length, or `None` otherwise.
    #[must_use]
    pub const fn low_entropy_extracted_len(&self) -> Option<u16> {
        match self {
            Self::LowEntropy(m) => Some(m.extracted_len),
            _ => None,
        }
    }

    /// Low-entropy mask rotation, or `None` for non-low-entropy metadata.
    #[must_use]
    pub const fn low_entropy_rotation(&self) -> Option<u8> {
        match self {
            Self::LowEntropy(m) => Some(m.rotation),
            _ => None,
        }
    }
}

/// Validate the low-entropy-specific rules of spec §7.5 (items 1–6).
fn validate_low_entropy(meta: &LowEntropyMetadata) -> Result<(), WireError> {
    if !(10..=11).contains(&meta.protocol_type) {
        return Err(WireError::InvalidProtocolType(meta.protocol_type));
    }
    let stride =
        low_entropy_stride(meta.mode).ok_or(WireError::InvalidLowEntropyMode(meta.mode))?;
    let want_popcount = (4 * stride) as u32;
    let got_popcount = meta.half_mask.count_ones();
    if got_popcount != want_popcount {
        return Err(WireError::InvalidHalfMaskPopcount {
            got: got_popcount,
            want: want_popcount,
        });
    }
    if meta.rotation > 63 {
        return Err(WireError::InvalidMaskRotation(meta.rotation));
    }
    if usize::from(meta.extracted_len) > MAX_FRAGMENT {
        return Err(WireError::DataPayloadTooLong(usize::from(
            meta.extracted_len,
        )));
    }
    if meta.extracted_len == 0 && meta.payload_len != 0 {
        return Err(WireError::EmptyLowEntropyPayload(usize::from(
            meta.payload_len,
        )));
    }
    let encoded_len = low_entropy_encoded_len(usize::from(meta.extracted_len), meta.mode)
        .ok_or(WireError::InvalidLowEntropyMode(meta.mode))?;
    if usize::from(meta.payload_len) != encoded_len {
        return Err(WireError::LowEntropyLengthMismatch {
            got: usize::from(meta.payload_len),
            want: encoded_len,
        });
    }
    if usize::from(meta.payload_len) % 8 != 0 {
        return Err(WireError::UnalignedLowEntropyLength(usize::from(
            meta.payload_len,
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Hand-written golden vectors from spec §6. They are literals, not
    // produced by `Metadata::encode`.
    const SESSION_GOLDEN: [u8; 32] = [
        0x02, 0x00, // type, flags/reserved
        0x01, 0x02, 0x03, 0x04, // session id
        0x00, 0x00, 0x00, 0x2a, // sequence
        0x01, 0x00, // payload length 256
        0x07, // suffix length
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 19 reserved
    ];

    const DATA_GOLDEN: [u8; 32] = [
        0x07, 0x00, // type, flags/reserved
        0x0a, 0x0b, 0x0c, 0x0d, // session id
        0x00, 0x00, 0x01, 0x00, // sequence 256
        0x00, 0x00, 0x00, 0xf0, // unack 240
        0x04, 0x00, // window 1024
        0x03, // fragment
        0x05, // prefix length
        0x08, 0x00, // payload length 2048
        0x09, // suffix length
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 11 reserved
    ];

    const LOW_ENTROPY_GOLDEN: [u8; 32] = [
        0x0a, 0x02, // type 10, mode 2 (C = 5)
        0x11, 0x22, 0x33, 0x44, // session id
        0x00, 0x00, 0x00, 0x10, // sequence 16
        0x00, 0x00, 0x00, 0x08, // unack 8
        0x00, 0x20, // window 32
        0x01, // fragment
        0x02, // prefix length
        0x00, 0xa0, // encoded payload length 160
        0x03, // suffix length
        0x00, 0x0f, 0xff, 0xff, // half mask (20 ones)
        0x00, 0x64, // extracted length 100
        0x07, // rotation
        0, 0, 0, 0, // 4 reserved
    ];

    #[test]
    fn golden_session_metadata() {
        let m = Metadata::parse(&SESSION_GOLDEN).unwrap();
        assert_eq!(m, Metadata::session(2, 0x0102_0304, 42, 256, 7));
        assert_eq!(m.encode(), SESSION_GOLDEN);
        assert_eq!(m.protocol_type(), 2);
        assert_eq!(m.session_id(), 0x0102_0304);
        assert_eq!(m.sequence(), 42);
        assert_eq!(m.payload_len(), 256);
        assert_eq!(m.suffix_len(), 7);
        assert_eq!(m.prefix_len(), 0);
    }

    #[test]
    fn golden_data_metadata() {
        let m = Metadata::parse(&DATA_GOLDEN).unwrap();
        assert_eq!(
            m,
            Metadata::data(7, 0x0a0b_0c0d, 256, 240, 1024, 3, 5, 2048, 9)
        );
        assert_eq!(m.encode(), DATA_GOLDEN);
        assert_eq!(m.protocol_type(), 7);
        assert_eq!(m.unack(), 240);
        assert_eq!(m.window(), 1024);
        assert_eq!(m.fragment(), 3);
        assert_eq!(m.prefix_len(), 5);
        assert_eq!(m.suffix_len(), 9);
    }

    #[test]
    fn golden_low_entropy_metadata() {
        let m = Metadata::parse(&LOW_ENTROPY_GOLDEN).unwrap();
        assert_eq!(
            m,
            Metadata::low_entropy(
                10,
                2,
                0x1122_3344,
                16,
                8,
                32,
                1,
                2,
                160,
                3,
                0x000f_ffff,
                100,
                7
            )
        );
        assert_eq!(m.encode(), LOW_ENTROPY_GOLDEN);
        assert_eq!(m.low_entropy_mode(), Some(2));
        assert_eq!(m.low_entropy_half_mask(), Some(0x000f_ffff));
        assert_eq!(m.low_entropy_extracted_len(), Some(100));
        assert_eq!(m.low_entropy_rotation(), Some(7));
        assert!(m.is_low_entropy());
        // ceil(100 / 5) * 8 = 160
        assert_eq!(low_entropy_encoded_len(100, 2), Some(160));
    }

    #[test]
    fn reserved_bytes_are_ignored_on_parse_and_zeroed_on_encode() {
        let mut noisy = SESSION_GOLDEN;
        noisy[1] = 0xff;
        noisy[13] = 0xab;
        noisy[31] = 0xcd;
        assert_eq!(Metadata::parse(&noisy).unwrap().encode(), SESSION_GOLDEN);

        let mut noisy = DATA_GOLDEN;
        noisy[1] = 0xff;
        noisy[21] = 0xab;
        assert_eq!(Metadata::parse(&noisy).unwrap().encode(), DATA_GOLDEN);
    }

    #[test]
    fn reserved_bytes_of_low_entropy_are_ignored() {
        let mut noisy = LOW_ENTROPY_GOLDEN;
        noisy[28] = 0xff;
        noisy[31] = 0xee;
        assert_eq!(
            Metadata::parse(&noisy).unwrap().encode(),
            LOW_ENTROPY_GOLDEN
        );
    }

    #[test]
    fn rejects_invalid_metadata() {
        assert_eq!(
            Metadata::parse(&[0u8; 31]).unwrap_err(),
            WireError::MetadataLength(31)
        );
        let mut bad = SESSION_GOLDEN;
        bad[0] = 1;
        assert_eq!(
            Metadata::parse(&bad).unwrap_err(),
            WireError::InvalidProtocolType(1)
        );
        bad[0] = 12;
        assert_eq!(
            Metadata::parse(&bad).unwrap_err(),
            WireError::InvalidProtocolType(12)
        );

        let mut bad = SESSION_GOLDEN;
        let too_long = (crate::MAX_SESSION_PAYLOAD + 1) as u16;
        bad[10..12].copy_from_slice(&too_long.to_be_bytes());
        assert_eq!(
            Metadata::parse(&bad).unwrap_err(),
            WireError::SessionPayloadTooLong(usize::from(too_long))
        );

        let mut bad = DATA_GOLDEN;
        bad[18..20].copy_from_slice(&32769u16.to_be_bytes());
        assert_eq!(
            Metadata::parse(&bad).unwrap_err(),
            WireError::DataPayloadTooLong(32769)
        );
    }

    #[test]
    fn rejects_invalid_low_entropy_fields() {
        let mut bad = LOW_ENTROPY_GOLDEN;
        bad[1] = 0; // mode 0 disabled
        assert_eq!(
            Metadata::parse(&bad).unwrap_err(),
            WireError::InvalidLowEntropyMode(0)
        );

        let mut bad = LOW_ENTROPY_GOLDEN;
        bad[21..25].copy_from_slice(&0x0000_ffffu32.to_be_bytes()); // 16 ones, want 20
        assert_eq!(
            Metadata::parse(&bad).unwrap_err(),
            WireError::InvalidHalfMaskPopcount { got: 16, want: 20 }
        );

        let mut bad = LOW_ENTROPY_GOLDEN;
        bad[27] = 64;
        assert_eq!(
            Metadata::parse(&bad).unwrap_err(),
            WireError::InvalidMaskRotation(64)
        );

        let mut bad = LOW_ENTROPY_GOLDEN;
        bad[18..20].copy_from_slice(&96u16.to_be_bytes()); // want 160
        assert_eq!(
            Metadata::parse(&bad).unwrap_err(),
            WireError::LowEntropyLengthMismatch { got: 96, want: 160 }
        );

        let mut bad = LOW_ENTROPY_GOLDEN;
        bad[18..20].copy_from_slice(&0u16.to_be_bytes());
        bad[25..27].copy_from_slice(&0u16.to_be_bytes());
        assert!(Metadata::parse(&bad).is_ok()); // empty low-entropy body is valid

        let mut bad = LOW_ENTROPY_GOLDEN;
        bad[25..27].copy_from_slice(&0u16.to_be_bytes());
        assert_eq!(
            Metadata::parse(&bad).unwrap_err(),
            WireError::EmptyLowEntropyPayload(160)
        );
    }
}
