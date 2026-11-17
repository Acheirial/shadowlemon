//! Complete V0.2 segment framing (spec §4, reference-go-v3.md §7.1).
//!
//! Frame layout:
//!
//! ```text
//! [wire nonce (0 or 24)] [encrypted metadata (32)] [metadata tag (16)]
//! [padding 1] [encrypted payload body (payloadLen)] [payload tag (16)]
//! [padding 2]
//! ```
//!
//! The 24-byte nonce is present on the first message of every TCP cipher
//! chain and on every UDP datagram; subsequent TCP messages omit it and the
//! receiver reconstructs it from the implicit nonce chain. Metadata and
//! payload are sealed with the same key but different nonces: by flipping byte
//! 16 of the wire nonce for UDP, or by incrementing the 24-byte big-endian
//! counter for TCP. The caller can also supply both nonces explicitly (for
//! example from the crypto crate's chain state).
//!
//! All AEAD work goes through [`Cipher`], a small trait defined here so the
//! framing can be tested with a deterministic fake cipher without pulling in
//! any concrete cryptographic dependency.

use crate::{
    CipherError, Metadata, WireError, WireNonce, METADATA_LEN, PAYLOAD_NONCE_INDEX,
    PAYLOAD_NONCE_MASK, TAG_LEN, WIRE_NONCE_LEN,
};

/// Encrypted metadata block length (`32 + 16`).
pub const META_BLOCK_LEN: usize = METADATA_LEN + TAG_LEN;
/// Length of the fixed part of a frame when the nonce is carried (72 bytes).
pub const NONCE_AND_META_LEN: usize = WIRE_NONCE_LEN + META_BLOCK_LEN;

/// Minimal AEAD abstraction used by the framing layer.
///
/// `seal` returns ciphertext followed by a 16-byte authentication tag;
/// `open` reverses it and reports a [`CipherError`] on authentication failure.
/// Implementations must accept a full 24-byte wire nonce and perform the
/// suite-specific AEAD-nonce truncation internally.
pub trait Cipher {
    /// Seal `plaintext` with `wire_nonce`.
    fn seal(&self, wire_nonce: &WireNonce, plaintext: &[u8]) -> Result<Vec<u8>, CipherError>;

    /// Open `ciphertext` (with trailing tag) with `wire_nonce`.
    fn open(&self, wire_nonce: &WireNonce, ciphertext: &[u8]) -> Result<Vec<u8>, CipherError>;
}

/// How to derive the payload nonce from the metadata wire nonce (spec §4.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadNonce {
    /// UDP: XOR byte 16 of the metadata nonce with `0x01`.
    UdpFlip,
    /// TCP implicit chain: add one to the 24-byte big-endian metadata nonce.
    TcpIncrement,
    /// Use a nonce supplied by the caller (for example from a crypto chain).
    Explicit(WireNonce),
}

impl PayloadNonce {
    /// Derive the payload nonce from the metadata wire nonce.
    #[must_use]
    pub fn derive(self, metadata_nonce: &WireNonce) -> WireNonce {
        match self {
            Self::UdpFlip => {
                let mut nonce = *metadata_nonce;
                nonce[PAYLOAD_NONCE_INDEX] ^= PAYLOAD_NONCE_MASK;
                nonce
            }
            Self::TcpIncrement => increment_nonce(metadata_nonce),
            Self::Explicit(nonce) => nonce,
        }
    }
}

/// Add one to a 24-byte big-endian nonce, wrapping at `2^192`.
#[must_use]
pub fn increment_nonce(nonce: &WireNonce) -> WireNonce {
    let mut next = *nonce;
    for byte in next.iter_mut().rev() {
        let (value, carry) = byte.overflowing_add(1);
        *byte = value;
        if !carry {
            break;
        }
    }
    next
}

/// Length of the payload block: zero when empty, otherwise `len + 16` for the
/// authentication tag.
#[must_use]
pub const fn payload_block_len(payload_len: usize) -> usize {
    if payload_len == 0 {
        0
    } else {
        payload_len + TAG_LEN
    }
}

/// Total frame length implied by metadata fields.
#[must_use]
pub const fn frame_len(
    prefix_len: usize,
    payload_len: usize,
    suffix_len: usize,
    include_nonce: bool,
) -> usize {
    let nonce_len = if include_nonce { WIRE_NONCE_LEN } else { 0 };
    nonce_len + META_BLOCK_LEN + prefix_len + payload_block_len(payload_len) + suffix_len
}

/// One decoded (or to-be-encoded) segment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment {
    /// Parsed metadata plaintext.
    pub metadata: Metadata,
    /// The 24-byte wire nonce used to encrypt metadata.
    pub wire_nonce: WireNonce,
    /// Prefix padding (padding 1), matching `metadata.prefix_len()`.
    pub prefix_padding: Vec<u8>,
    /// Plaintext application payload (before encryption / after decryption).
    pub payload: Vec<u8>,
    /// Suffix padding (padding 2), matching `metadata.suffix_len()`.
    pub suffix_padding: Vec<u8>,
    /// Filler polarity used for a low-entropy body; inferred when decoding.
    ///
    /// Ignored for non-low-entropy metadata.
    pub low_entropy_polarity: bool,
}

impl Segment {
    /// Build a segment from metadata and a payload, with empty padding.
    #[must_use]
    pub fn new(metadata: Metadata, wire_nonce: WireNonce, payload: Vec<u8>) -> Self {
        Self {
            metadata,
            wire_nonce,
            prefix_padding: Vec::new(),
            payload,
            suffix_padding: Vec::new(),
            low_entropy_polarity: false,
        }
    }
}

/// Options for [`encode_segment`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncodeOptions {
    /// Whether to write the explicit 24-byte wire nonce.
    pub include_nonce: bool,
    /// How to derive the payload nonce.
    pub payload_nonce: PayloadNonce,
}

impl Default for EncodeOptions {
    fn default() -> Self {
        Self {
            include_nonce: true,
            payload_nonce: PayloadNonce::UdpFlip,
        }
    }
}

/// Options for [`decode_segment`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodeOptions {
    /// Whether the frame carries an explicit 24-byte wire nonce.
    pub include_nonce: bool,
    /// Metadata nonce to use when the frame omits it (TCP implicit chain).
    pub implicit_metadata_nonce: WireNonce,
    /// How to derive the payload nonce.
    pub payload_nonce: PayloadNonce,
}

impl Default for DecodeOptions {
    fn default() -> Self {
        Self {
            include_nonce: true,
            implicit_metadata_nonce: [0u8; WIRE_NONCE_LEN],
            payload_nonce: PayloadNonce::UdpFlip,
        }
    }
}

/// Encode a segment into its complete wire frame.
///
/// Validates metadata constraints, padding lengths and payload lengths before
/// encrypting. For low-entropy metadata (feature `low-entropy`) the plaintext
/// is sealed first, the ciphertext body is low-entropy encoded, and the AEAD
/// tag is appended outside the transformed body as required by spec §7.3.
pub fn encode_segment<C: Cipher>(
    cipher: &C,
    segment: &Segment,
    options: &EncodeOptions,
) -> Result<Vec<u8>, WireError> {
    segment.metadata.validate()?;
    let prefix_len = usize::from(segment.metadata.prefix_len());
    let suffix_len = usize::from(segment.metadata.suffix_len());
    if segment.prefix_padding.len() != prefix_len {
        return Err(WireError::PaddingLengthMismatch {
            field: "prefix",
            declared: prefix_len,
            actual: segment.prefix_padding.len(),
        });
    }
    if segment.suffix_padding.len() != suffix_len {
        return Err(WireError::PaddingLengthMismatch {
            field: "suffix",
            declared: suffix_len,
            actual: segment.suffix_padding.len(),
        });
    }

    let metadata_plain = segment.metadata.encode();
    let metadata_sealed = cipher.seal(&segment.wire_nonce, &metadata_plain)?;
    if metadata_sealed.len() != META_BLOCK_LEN {
        return Err(WireError::CipherBlockLength {
            block: "metadata",
            got: metadata_sealed.len(),
            want: META_BLOCK_LEN,
        });
    }

    let payload_nonce = options.payload_nonce.derive(&segment.wire_nonce);
    let payload_block = encode_payload(cipher, segment, &payload_nonce)?;

    let declared_payload_len = usize::from(segment.metadata.payload_len());
    let total = frame_len(
        prefix_len,
        declared_payload_len,
        suffix_len,
        options.include_nonce,
    );
    let mut out = Vec::with_capacity(total);
    if options.include_nonce {
        out.extend_from_slice(&segment.wire_nonce);
    }
    out.extend_from_slice(&metadata_sealed);
    out.extend_from_slice(&segment.prefix_padding);
    out.extend_from_slice(&payload_block);
    out.extend_from_slice(&segment.suffix_padding);
    Ok(out)
}

/// Build the encrypted (and possibly low-entropy encoded) payload block.
fn encode_payload<C: Cipher>(
    cipher: &C,
    segment: &Segment,
    payload_nonce: &WireNonce,
) -> Result<Vec<u8>, WireError> {
    #[cfg(feature = "low-entropy")]
    if let Metadata::LowEntropy(meta) = segment.metadata {
        let declared = usize::from(meta.payload_len);
        let extracted = usize::from(meta.extracted_len);
        if segment.payload.len() != extracted {
            return Err(WireError::PayloadLengthMismatch {
                declared: extracted,
                actual: segment.payload.len(),
            });
        }
        if extracted == 0 {
            return Ok(Vec::new());
        }
        let sealed = cipher.seal(payload_nonce, &segment.payload)?;
        if sealed.len() != extracted + TAG_LEN {
            return Err(WireError::CipherBlockLength {
                block: "payload",
                got: sealed.len(),
                want: extracted + TAG_LEN,
            });
        }
        let (ciphertext, tag) = sealed.split_at(extracted);
        let params = crate::LowEntropyParams::new(
            meta.mode,
            meta.rotation,
            meta.half_mask,
            segment.low_entropy_polarity,
        )?;
        let encoded = crate::low_entropy::encode(ciphertext, &params)?;
        if encoded.len() != declared {
            return Err(WireError::LowEntropyLengthMismatch {
                got: encoded.len(),
                want: declared,
            });
        }
        let mut block = Vec::with_capacity(encoded.len() + TAG_LEN);
        block.extend_from_slice(&encoded);
        block.extend_from_slice(tag);
        return Ok(block);
    }

    #[cfg(not(feature = "low-entropy"))]
    if segment.metadata.is_low_entropy() && !segment.payload.is_empty() {
        return Err(WireError::LowEntropyDisabled);
    }

    let declared = usize::from(segment.metadata.payload_len());
    if segment.payload.len() != declared {
        return Err(WireError::PayloadLengthMismatch {
            declared,
            actual: segment.payload.len(),
        });
    }
    if declared == 0 {
        return Ok(Vec::new());
    }
    let sealed = cipher.seal(payload_nonce, &segment.payload)?;
    if sealed.len() != declared + TAG_LEN {
        return Err(WireError::CipherBlockLength {
            block: "payload",
            got: sealed.len(),
            want: declared + TAG_LEN,
        });
    }
    Ok(sealed)
}

/// Decode a complete wire frame into a [`Segment`].
///
/// Parsing never panics on malformed input: every length is checked before it
/// is used to slice the buffer. The metadata is decrypted and parsed before
/// the variable-length part is read, exactly as recommended by spec §10.
pub fn decode_segment<C: Cipher>(
    cipher: &C,
    bytes: &[u8],
    options: &DecodeOptions,
) -> Result<Segment, WireError> {
    let meta_start = if options.include_nonce {
        WIRE_NONCE_LEN
    } else {
        0
    };
    let fixed_len = meta_start + META_BLOCK_LEN;
    if bytes.len() < fixed_len {
        return Err(WireError::FrameTooShort {
            got: bytes.len(),
            want: fixed_len,
        });
    }

    let metadata_nonce = if options.include_nonce {
        let mut nonce = [0u8; WIRE_NONCE_LEN];
        nonce.copy_from_slice(&bytes[..WIRE_NONCE_LEN]);
        nonce
    } else {
        options.implicit_metadata_nonce
    };

    let metadata_plain = cipher.open(&metadata_nonce, &bytes[meta_start..fixed_len])?;
    if metadata_plain.len() != METADATA_LEN {
        return Err(WireError::MetadataPlaintextLength(metadata_plain.len()));
    }
    let metadata = Metadata::parse(&metadata_plain)?;

    let prefix_len = usize::from(metadata.prefix_len());
    let payload_len = usize::from(metadata.payload_len());
    let suffix_len = usize::from(metadata.suffix_len());
    let declared_total = frame_len(prefix_len, payload_len, suffix_len, options.include_nonce);
    if bytes.len() != declared_total {
        return Err(WireError::FrameLengthMismatch {
            declared: declared_total,
            actual: bytes.len(),
        });
    }

    let mut at = fixed_len;
    let prefix_padding = bytes[at..at + prefix_len].to_vec();
    at += prefix_len;
    let block_len = payload_block_len(payload_len);
    let payload_block = &bytes[at..at + block_len];
    at += block_len;
    let suffix_padding = bytes[at..at + suffix_len].to_vec();

    let payload_nonce = options.payload_nonce.derive(&metadata_nonce);
    let (payload, low_entropy_polarity) =
        decode_payload(cipher, &metadata, payload_nonce, payload_block, payload_len)?;

    Ok(Segment {
        metadata,
        wire_nonce: metadata_nonce,
        prefix_padding,
        payload,
        suffix_padding,
        low_entropy_polarity,
    })
}

/// Decrypt (and possibly low-entropy decode) a payload block.
fn decode_payload<C: Cipher>(
    cipher: &C,
    metadata: &Metadata,
    payload_nonce: WireNonce,
    payload_block: &[u8],
    payload_len: usize,
) -> Result<(Vec<u8>, bool), WireError> {
    #[cfg(feature = "low-entropy")]
    if let Metadata::LowEntropy(meta) = metadata {
        let extracted = usize::from(meta.extracted_len);
        if extracted == 0 {
            return Ok((Vec::new(), false));
        }
        let encoded = &payload_block[..payload_len];
        let tag = &payload_block[payload_len..];
        let ciphertext = crate::low_entropy::decode(
            encoded,
            extracted,
            meta.mode,
            meta.rotation,
            meta.half_mask,
        )?;
        let polarity = crate::low_entropy::infer_polarity(
            encoded,
            extracted,
            meta.mode,
            meta.rotation,
            meta.half_mask,
        )?;
        let mut sealed = Vec::with_capacity(ciphertext.len() + TAG_LEN);
        sealed.extend_from_slice(&ciphertext);
        sealed.extend_from_slice(tag);
        let plaintext = cipher.open(&payload_nonce, &sealed)?;
        if plaintext.len() != extracted {
            return Err(WireError::PayloadLengthMismatch {
                declared: extracted,
                actual: plaintext.len(),
            });
        }
        return Ok((plaintext, polarity));
    }

    #[cfg(not(feature = "low-entropy"))]
    if metadata.is_low_entropy() && payload_len != 0 {
        return Err(WireError::LowEntropyDisabled);
    }

    if payload_len == 0 {
        return Ok((Vec::new(), false));
    }
    let plaintext = cipher.open(&payload_nonce, payload_block)?;
    if plaintext.len() != payload_len {
        return Err(WireError::PayloadLengthMismatch {
            declared: payload_len,
            actual: plaintext.len(),
        });
    }
    Ok((plaintext, false))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Metadata as M, WireNonce as Nonce};
    use proptest::prelude::*;

    /// Deterministic fake cipher: ciphertext is plaintext with a fixed tag.
    #[derive(Debug, Default)]
    struct TestCipher;

    impl Cipher for TestCipher {
        fn seal(&self, _nonce: &Nonce, plaintext: &[u8]) -> Result<Vec<u8>, CipherError> {
            let mut out = plaintext.to_vec();
            out.extend_from_slice(&[0xee; TAG_LEN]);
            Ok(out)
        }

        fn open(&self, _nonce: &Nonce, ciphertext: &[u8]) -> Result<Vec<u8>, CipherError> {
            if ciphertext.len() < TAG_LEN {
                return Err(CipherError::failed("short ciphertext"));
            }
            let split = ciphertext.len() - TAG_LEN;
            if ciphertext[split..] != [0xee; TAG_LEN] {
                return Err(CipherError::failed("bad tag"));
            }
            Ok(ciphertext[..split].to_vec())
        }
    }

    const NONCE: Nonce = [0x42; WIRE_NONCE_LEN];

    // Hand-written metadata plaintext from spec §6.2 for the golden frame.
    const META_PLAIN: [u8; METADATA_LEN] = [
        0x06, 0x00, // type 6, flags/reserved
        0x01, 0x02, 0x03, 0x04, // session id
        0x00, 0x00, 0x00, 0x07, // sequence 7
        0x00, 0x00, 0x00, 0x03, // unack 3
        0x00, 0x10, // window 16
        0x00, // fragment (last)
        0x02, // prefix length 2
        0x00, 0x04, // payload length 4
        0x01, // suffix length 1
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 11 reserved
    ];
    const PREFIX: [u8; 2] = [0x11, 0x22];
    const PAYLOAD: [u8; 4] = [0xaa, 0xbb, 0xcc, 0xdd];
    const SUFFIX: [u8; 1] = [0x33];

    fn golden_frame() -> Vec<u8> {
        let mut frame = Vec::new();
        frame.extend_from_slice(&NONCE);
        frame.extend_from_slice(&META_PLAIN);
        frame.extend_from_slice(&[0xee; TAG_LEN]);
        frame.extend_from_slice(&PREFIX);
        frame.extend_from_slice(&PAYLOAD);
        frame.extend_from_slice(&[0xee; TAG_LEN]);
        frame.extend_from_slice(&SUFFIX);
        frame
    }

    fn golden_segment() -> Segment {
        let mut segment = Segment::new(
            M::data(6, 0x0102_0304, 7, 3, 16, 0, 2, 4, 1),
            NONCE,
            PAYLOAD.to_vec(),
        );
        segment.prefix_padding = PREFIX.to_vec();
        segment.suffix_padding = SUFFIX.to_vec();
        segment
    }

    #[test]
    fn golden_segment_round_trip() {
        let cipher = TestCipher;
        let frame = encode_segment(&cipher, &golden_segment(), &EncodeOptions::default()).unwrap();
        assert_eq!(frame, golden_frame());
        assert_eq!(frame.len(), 24 + 32 + 16 + 2 + 4 + 16 + 1);
        assert_eq!(
            decode_segment(&cipher, &frame, &DecodeOptions::default()).unwrap(),
            golden_segment()
        );
    }

    #[test]
    fn tcp_implicit_nonce_omits_nonce() {
        let cipher = TestCipher;
        let options = EncodeOptions {
            include_nonce: false,
            payload_nonce: PayloadNonce::TcpIncrement,
        };
        let frame = encode_segment(&cipher, &golden_segment(), &options).unwrap();
        assert_eq!(frame.len(), 32 + 16 + 2 + 4 + 16 + 1);
        assert_eq!(&frame[..4], &META_PLAIN[..4]);

        let decode_options = DecodeOptions {
            include_nonce: false,
            implicit_metadata_nonce: NONCE,
            payload_nonce: PayloadNonce::TcpIncrement,
        };
        let decoded = decode_segment(&cipher, &frame, &decode_options).unwrap();
        assert_eq!(decoded, golden_segment());
        assert_eq!(decoded.wire_nonce, NONCE);
    }

    #[test]
    fn empty_payload_has_no_tag() {
        let cipher = TestCipher;
        let segment = Segment::new(M::session(4, 1, 2, 0, 3), NONCE, Vec::new());
        let mut segment = segment;
        segment.suffix_padding = vec![0x77; 3];
        let frame = encode_segment(&cipher, &segment, &EncodeOptions::default()).unwrap();
        assert_eq!(frame.len(), 24 + 32 + 16 + 3);
        assert_eq!(
            decode_segment(&cipher, &frame, &DecodeOptions::default()).unwrap(),
            segment
        );
    }

    #[test]
    fn explicit_payload_nonce_is_used() {
        let cipher = TestCipher;
        let payload_nonce = [0x99u8; WIRE_NONCE_LEN];
        let options = EncodeOptions {
            include_nonce: true,
            payload_nonce: PayloadNonce::Explicit(payload_nonce),
        };
        let frame = encode_segment(&cipher, &golden_segment(), &options).unwrap();
        let decode_options = DecodeOptions {
            include_nonce: true,
            implicit_metadata_nonce: [0; WIRE_NONCE_LEN],
            payload_nonce: PayloadNonce::Explicit(payload_nonce),
        };
        assert_eq!(
            decode_segment(&cipher, &frame, &decode_options).unwrap(),
            golden_segment()
        );
    }

    #[test]
    fn rejects_bad_lengths_and_tampering() {
        let cipher = TestCipher;
        let frame = golden_frame();

        let mut short = frame.clone();
        short.truncate(71);
        assert_eq!(
            decode_segment(&cipher, &short, &DecodeOptions::default()).unwrap_err(),
            WireError::FrameTooShort { got: 71, want: 72 }
        );

        let mut longer = frame.clone();
        longer.push(0);
        assert!(matches!(
            decode_segment(&cipher, &longer, &DecodeOptions::default()).unwrap_err(),
            WireError::FrameLengthMismatch { .. }
        ));

        let mut bad_tag = frame.clone();
        bad_tag[24 + 32] ^= 0xff;
        assert!(decode_segment(&cipher, &bad_tag, &DecodeOptions::default()).is_err());

        let mut bad_padding = golden_segment();
        bad_padding.prefix_padding.clear();
        assert!(matches!(
            encode_segment(&cipher, &bad_padding, &EncodeOptions::default()).unwrap_err(),
            WireError::PaddingLengthMismatch { .. }
        ));
    }

    #[test]
    fn nonce_helpers_match_spec() {
        let nonce = [0x10u8; WIRE_NONCE_LEN];
        let flipped = PayloadNonce::UdpFlip.derive(&nonce);
        assert_eq!(flipped[16], 0x11);
        assert_eq!(flipped[17], 0x10);

        let mut next = nonce;
        next[WIRE_NONCE_LEN - 1] = 0x11;
        assert_eq!(increment_nonce(&nonce), next);
        assert_eq!(PayloadNonce::TcpIncrement.derive(&nonce), next);

        let mut carry = [0u8; WIRE_NONCE_LEN];
        carry[22] = 0xff;
        carry[23] = 0xff;
        let mut expected_carry = [0u8; WIRE_NONCE_LEN];
        expected_carry[21] = 1;
        assert_eq!(increment_nonce(&carry), expected_carry);
        assert_eq!(
            increment_nonce(&[0xffu8; WIRE_NONCE_LEN]),
            [0u8; WIRE_NONCE_LEN]
        );

        assert_eq!(payload_block_len(0), 0);
        assert_eq!(payload_block_len(5), 21);
        assert_eq!(frame_len(2, 4, 1, true), 24 + 32 + 16 + 2 + 4 + 16 + 1);
        assert_eq!(frame_len(2, 4, 1, false), 32 + 16 + 2 + 4 + 16 + 1);
    }

    #[cfg(feature = "low-entropy")]
    #[test]
    fn low_entropy_segment_round_trip() {
        let cipher = TestCipher;
        for polarity in [false, true] {
            let body = [0x0f, 0xf0, 0x33, 0xcc];
            let meta = M::low_entropy(10, 1, 0x1122_3344, 9, 1, 16, 0, 0, 8, 0, 0x0000_ffff, 4, 0);
            let mut segment = Segment::new(meta, NONCE, body.to_vec());
            segment.low_entropy_polarity = polarity;

            let frame = encode_segment(&cipher, &segment, &EncodeOptions::default()).unwrap();
            assert_eq!(frame.len(), 24 + 32 + 16 + 8 + 16);
            let encoded_body = &frame[24 + 48..24 + 48 + 8];
            let want = if polarity {
                [0xff, 0xff, 0x0f, 0xf0, 0xff, 0xff, 0x33, 0xcc]
            } else {
                [0x00, 0x00, 0x0f, 0xf0, 0x00, 0x00, 0x33, 0xcc]
            };
            assert_eq!(encoded_body, &want);

            let decoded = decode_segment(&cipher, &frame, &DecodeOptions::default()).unwrap();
            assert_eq!(decoded, segment);
            assert_eq!(decoded.low_entropy_polarity, polarity);
        }
    }

    #[cfg(not(feature = "low-entropy"))]
    #[test]
    fn low_entropy_segment_is_rejected_without_feature() {
        let cipher = TestCipher;
        let meta = M::low_entropy(10, 1, 1, 0, 0, 0, 0, 0, 8, 0, 0x0000_ffff, 4, 0);
        let segment = Segment::new(meta, NONCE, vec![0x0f, 0xf0, 0x33, 0xcc]);
        assert_eq!(
            encode_segment(&cipher, &segment, &EncodeOptions::default()).unwrap_err(),
            WireError::LowEntropyDisabled
        );
    }

    proptest! {
        #[test]
        fn segment_framing_round_trip(
            session_id in any::<u32>(),
            sequence in any::<u32>(),
            unack in any::<u32>(),
            window in any::<u16>(),
            prefix_len in 0u8..=8,
            suffix_len in 0u8..=8,
            payload in prop::collection::vec(any::<u8>(), 0..64),
            nonce in prop::array::uniform24(any::<u8>()),
            include_nonce in any::<bool>(),
        ) {
            let payload_len = u16::try_from(payload.len()).unwrap();
            let meta = M::data(7, session_id, sequence, unack, window, 0,
                prefix_len, payload_len, suffix_len);
            let mut segment = Segment::new(meta, nonce, payload);
            segment.prefix_padding = vec![0x5a; usize::from(prefix_len)];
            segment.suffix_padding = vec![0xa5; usize::from(suffix_len)];
            let enc_opts = EncodeOptions { include_nonce, payload_nonce: PayloadNonce::UdpFlip };
            let frame = encode_segment(&TestCipher, &segment, &enc_opts)?;
            prop_assert_eq!(frame.len(), frame_len(
                usize::from(prefix_len), payload_len as usize,
                usize::from(suffix_len), include_nonce));
            let dec_opts = DecodeOptions {
                include_nonce,
                implicit_metadata_nonce: nonce,
                payload_nonce: PayloadNonce::UdpFlip,
            };
            let decoded = decode_segment(&TestCipher, &frame, &dec_opts)?;
            prop_assert_eq!(decoded, segment);
        }

        #[test]
        fn decode_never_panics_on_arbitrary_bytes(
            data in prop::collection::vec(any::<u8>(), 0..160),
            include_nonce in any::<bool>(),
        ) {
            let options = DecodeOptions { include_nonce, ..DecodeOptions::default() };
            let _ = decode_segment(&TestCipher, &data, &options);
        }
    }
}
