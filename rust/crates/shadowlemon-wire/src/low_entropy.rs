//! Simplified V0.2 low-entropy transform (spec §7, types 10/11).
//!
//! This module is feature-gated behind `low-entropy` (default off). It is a
//! deliberately small, stateless implementation of the V0.2 rules:
//!
//! * fixed step `C` per mode (4/5/6/7) and half-mask popcount `K = 4C`;
//! * 64-bit mask = `repeat32(half_mask)`;
//! * chunk mask = `rotr64(initial_mask, (i * R) % 64)`;
//! * per-segment random filler polarity, inferred from the first chunk and
//!   checked across all chunks on decode;
//! * the 16-byte AEAD tag lives **outside** this transform and is handled by
//!   [`crate::encode_segment`] / [`crate::decode_segment`].
//!
//! Both functions validate their parameters before touching the data and never
//! panic, including on malformed input.

use crate::{
    low_entropy_encoded_len, low_entropy_stride, LowEntropyMetadata, WireError, MAX_FRAGMENT,
};

/// Parameters of one low-entropy-encoded body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LowEntropyParams {
    /// Mode 1..=4, selecting the fixed step `C`.
    pub mode: u8,
    /// Circular-right rotation `R` in `0..=63`.
    pub rotation: u8,
    /// 32-bit half-mask, repeated into the 64-bit mask.
    pub half_mask: u32,
    /// Filler-bit polarity shared by every chunk of this segment.
    pub polarity: bool,
}

impl LowEntropyParams {
    /// Build parameters, validating mode, rotation and half-mask popcount.
    pub fn new(mode: u8, rotation: u8, half_mask: u32, polarity: bool) -> Result<Self, WireError> {
        validate_params(mode, rotation, half_mask)?;
        Ok(Self {
            mode,
            rotation,
            half_mask,
            polarity,
        })
    }

    /// Build parameters directly from low-entropy metadata.
    pub fn from_metadata(meta: &LowEntropyMetadata) -> Result<Self, WireError> {
        Self::new(meta.mode, meta.rotation, meta.half_mask, false)
    }
}

/// Validate the low-entropy codec parameters and return the step `C`.
pub fn validate_params(mode: u8, rotation: u8, half_mask: u32) -> Result<usize, WireError> {
    let stride = low_entropy_stride(mode).ok_or(WireError::InvalidLowEntropyMode(mode))?;
    if rotation > 63 {
        return Err(WireError::InvalidMaskRotation(rotation));
    }
    let want = (4 * stride) as u32;
    let got = half_mask.count_ones();
    if got != want {
        return Err(WireError::InvalidHalfMaskPopcount { got, want });
    }
    Ok(stride)
}

/// Repeat a 32-bit half-mask into the 64-bit mask used by the transform.
#[must_use]
pub const fn repeat32(half_mask: u32) -> u64 {
    (half_mask as u64) << 32 | half_mask as u64
}

/// Mask used by chunk `i`: `rotr64(initial_mask, (i * R) % 64)`.
#[must_use]
pub const fn chunk_mask(initial_mask: u64, chunk_index: usize, rotation: u8) -> u64 {
    let shift = (chunk_index * rotation as usize) % 64;
    initial_mask.rotate_right(shift as u32)
}

/// Bit positions selected by a mask, ordered low to high.
fn set_positions(mask: u64) -> Vec<usize> {
    (0..64).filter(|bit| (mask >> bit) & 1 == 1).collect()
}

/// Infer the filler-bit polarity of the first chunk of an encoded body.
///
/// Returns `false` for an empty body (there are no chunks to infer from).
pub fn infer_polarity(
    encoded: &[u8],
    extracted_len: usize,
    mode: u8,
    rotation: u8,
    half_mask: u32,
) -> Result<bool, WireError> {
    let stride = validate_params(mode, rotation, half_mask)?;
    let expected_len = low_entropy_encoded_len(extracted_len, mode)
        .ok_or(WireError::InvalidLowEntropyMode(mode))?;
    if encoded.len() != expected_len {
        return Err(WireError::LowEntropyLengthMismatch {
            got: encoded.len(),
            want: expected_len,
        });
    }
    if extracted_len == 0 {
        return Ok(false);
    }
    let mask = chunk_mask(repeat32(half_mask), 0, rotation);
    let positions = set_positions(mask);
    let s_len = stride.min(extracted_len);
    let mut data_mask = 0u64;
    for k in 0..s_len * 8 {
        let position = positions
            .get(k)
            .copied()
            .ok_or(WireError::InvalidHalfMaskPopcount {
                got: positions.len() as u32,
                want: (8 * stride) as u32,
            })?;
        data_mask |= 1u64 << position;
    }
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&encoded[..8]);
    let filler = u64::from_be_bytes(bytes) & !data_mask;
    if filler == 0 {
        Ok(false)
    } else if filler == !data_mask {
        Ok(true)
    } else {
        Err(WireError::MixedFillerPolarity)
    }
}

/// Encode a ciphertext body into a low-entropy body.
///
/// `body.len()` is the extracted (pre-transform) length. The caller is
/// responsible for sealing the plaintext first and for appending the AEAD tag
/// *outside* the returned bytes.
pub fn encode(body: &[u8], params: &LowEntropyParams) -> Result<Vec<u8>, WireError> {
    let stride = validate_params(params.mode, params.rotation, params.half_mask)?;
    let extracted_len = body.len();
    if extracted_len > MAX_FRAGMENT {
        return Err(WireError::DataPayloadTooLong(extracted_len));
    }
    let encoded_len = low_entropy_encoded_len(extracted_len, params.mode)
        .ok_or(WireError::InvalidLowEntropyMode(params.mode))?;
    // The encoded body length is carried in a u16 metadata field. For mode 1
    // (C=4) an extracted body of 32768 bytes would encode to 65536 bytes, so
    // the effective per-fragment cap is 32764 bytes (see spec section 7.6).
    if encoded_len > u16::MAX as usize {
        return Err(WireError::DataPayloadTooLong(extracted_len));
    }
    let mut encoded = vec![0u8; encoded_len];
    let initial_mask = repeat32(params.half_mask);

    for (i, out) in encoded.chunks_exact_mut(8).enumerate() {
        let mask = chunk_mask(initial_mask, i, params.rotation);
        let positions = set_positions(mask);
        let s_len = stride.min(extracted_len - i * stride);
        let mut source = 0u64;
        for &byte in &body[i * stride..i * stride + s_len] {
            source = (source << 8) | u64::from(byte);
        }
        let mut chunk = 0u64;
        let mut data_mask = 0u64;
        for k in 0..s_len * 8 {
            let Some(&position) = positions.get(k) else {
                return Err(WireError::InvalidHalfMaskPopcount {
                    got: positions.len() as u32,
                    want: (8 * stride) as u32,
                });
            };
            data_mask |= 1u64 << position;
            if (source >> k) & 1 == 1 {
                chunk |= 1u64 << position;
            }
        }
        if params.polarity {
            chunk |= !data_mask;
        }
        out.copy_from_slice(&chunk.to_be_bytes());
    }
    Ok(encoded)
}

/// Decode a low-entropy body back into the original ciphertext body.
///
/// `extracted_len` is the pre-transform length carried in the metadata.
/// Filler polarity is inferred from the first chunk and checked on every
/// later chunk; mixed polarity is rejected.
pub fn decode(
    encoded: &[u8],
    extracted_len: usize,
    mode: u8,
    rotation: u8,
    half_mask: u32,
) -> Result<Vec<u8>, WireError> {
    let stride = validate_params(mode, rotation, half_mask)?;
    if extracted_len > MAX_FRAGMENT {
        return Err(WireError::DataPayloadTooLong(extracted_len));
    }
    let expected_len = low_entropy_encoded_len(extracted_len, mode)
        .ok_or(WireError::InvalidLowEntropyMode(mode))?;
    if encoded.len() != expected_len {
        return Err(WireError::LowEntropyLengthMismatch {
            got: encoded.len(),
            want: expected_len,
        });
    }
    let mut decoded = vec![0u8; extracted_len];
    if extracted_len == 0 {
        return Ok(decoded);
    }

    let initial_mask = repeat32(half_mask);
    let mut polarity: Option<bool> = None;

    for (i, bytes) in encoded.chunks_exact(8).enumerate() {
        let mask = chunk_mask(initial_mask, i, rotation);
        let positions = set_positions(mask);
        let s_len = stride.min(extracted_len - i * stride);
        let mut data_mask = 0u64;
        for k in 0..s_len * 8 {
            let Some(&position) = positions.get(k) else {
                return Err(WireError::InvalidHalfMaskPopcount {
                    got: positions.len() as u32,
                    want: (8 * stride) as u32,
                });
            };
            data_mask |= 1u64 << position;
        }
        let filler_mask = !data_mask;
        let mut chunk_bytes = [0u8; 8];
        chunk_bytes.copy_from_slice(bytes);
        let chunk = u64::from_be_bytes(chunk_bytes);
        let filler = chunk & filler_mask;

        let polarity_set = match polarity {
            None => {
                if filler == 0 {
                    false
                } else if filler == filler_mask {
                    true
                } else {
                    return Err(WireError::MixedFillerPolarity);
                }
            }
            Some(known) => {
                let valid = if known {
                    filler == filler_mask
                } else {
                    filler == 0
                };
                if !valid {
                    return Err(WireError::FillerPolarityMismatch);
                }
                known
            }
        };
        polarity = Some(polarity_set);

        let mut value = 0u64;
        for (k, &position) in positions.iter().take(s_len * 8).enumerate() {
            if (chunk >> position) & 1 == 1 {
                value |= 1u64 << k;
            }
        }
        let value_bytes = value.to_be_bytes();
        decoded[i * stride..i * stride + s_len].copy_from_slice(&value_bytes[8 - s_len..]);
    }
    Ok(decoded)
}

/// Draw a half-mask with the exact popcount required by `mode`.
///
/// `next` supplies random `u32` values. The first draw seeds the mask; further
/// draws select a bit to flip until the popcount matches. This avoids pure
/// rejection sampling, which becomes impractically slow for `K = 28`.
pub fn generate_half_mask(mut next: impl FnMut() -> u32, mode: u8) -> Result<u32, WireError> {
    let stride = low_entropy_stride(mode).ok_or(WireError::InvalidLowEntropyMode(mode))?;
    let want = (4 * stride) as u32;
    let mut mask = next();
    let mut current = mask.count_ones();
    let mut attempts = 0u32;
    while current != want && attempts < 4096 {
        attempts += 1;
        let bit = next() % 32;
        let flag = 1u32 << bit;
        if current < want && mask & flag == 0 {
            mask |= flag;
            current += 1;
        } else if current > want && mask & flag != 0 {
            mask &= !flag;
            current -= 1;
        }
    }
    if current == want {
        Ok(mask)
    } else {
        Err(WireError::InvalidHalfMaskPopcount { got: current, want })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn params(mode: u8, rotation: u8, half_mask: u32, polarity: bool) -> LowEntropyParams {
        LowEntropyParams::new(mode, rotation, half_mask, polarity).unwrap()
    }

    // Hand-computed golden bodies for mode 1 (C=4), half-mask 0x0000FFFF,
    // rotation 0, body [0F F0 33 CC]. The mask selects bits 0..15 and 32..47,
    // so the source bits land in the low 16 and high-word bits 4..11.
    const BODY: [u8; 4] = [0x0f, 0xf0, 0x33, 0xcc];
    const ENCODED_ZERO_POLARITY: [u8; 8] = [0x00, 0x00, 0x0f, 0xf0, 0x00, 0x00, 0x33, 0xcc];
    const ENCODED_ONE_POLARITY: [u8; 8] = [0xff, 0xff, 0x0f, 0xf0, 0xff, 0xff, 0x33, 0xcc];

    #[test]
    fn golden_encode_zero_polarity() {
        let got = encode(&BODY, &params(1, 0, 0x0000_ffff, false)).unwrap();
        assert_eq!(got, ENCODED_ZERO_POLARITY);
    }

    #[test]
    fn golden_encode_one_polarity() {
        let got = encode(&BODY, &params(1, 0, 0x0000_ffff, true)).unwrap();
        assert_eq!(got, ENCODED_ONE_POLARITY);
    }

    #[test]
    fn golden_decode_both_polarities() {
        assert_eq!(
            decode(&ENCODED_ZERO_POLARITY, 4, 1, 0, 0x0000_ffff).unwrap(),
            BODY
        );
        assert_eq!(
            decode(&ENCODED_ONE_POLARITY, 4, 1, 0, 0x0000_ffff).unwrap(),
            BODY
        );
    }

    #[test]
    fn rejects_mixed_and_inconsistent_polarity() {
        let mut mixed = ENCODED_ZERO_POLARITY;
        mixed[1] |= 0x01; // flips a filler bit (high-word bit 16) toward polarity 1
        assert_eq!(
            decode(&mixed, 4, 1, 0, 0x0000_ffff).unwrap_err(),
            WireError::MixedFillerPolarity
        );

        // Two chunks: first has zero filler, second has one filler -> mismatch.
        let body = [0xaau8; 8]; // C=4 -> two chunks
        let mut encoded = encode(&body, &params(1, 0, 0x0000_ffff, false)).unwrap();
        encoded[9] |= 0x01; // filler bit (high-word bit 16) of chunk 1
        assert_eq!(
            decode(&encoded, 8, 1, 0, 0x0000_ffff).unwrap_err(),
            WireError::FillerPolarityMismatch
        );
    }

    #[test]
    fn validates_params_and_lengths() {
        assert_eq!(
            LowEntropyParams::new(0, 0, 0x0000_ffff, false).unwrap_err(),
            WireError::InvalidLowEntropyMode(0)
        );
        assert_eq!(
            LowEntropyParams::new(1, 64, 0x0000_ffff, false).unwrap_err(),
            WireError::InvalidMaskRotation(64)
        );
        assert_eq!(
            LowEntropyParams::new(1, 0, 0x0000_fffe, false).unwrap_err(),
            WireError::InvalidHalfMaskPopcount { got: 15, want: 16 }
        );
        assert_eq!(
            decode(&[0u8; 7], 4, 1, 0, 0x0000_ffff).unwrap_err(),
            WireError::LowEntropyLengthMismatch { got: 7, want: 8 }
        );
        assert_eq!(decode(&[], 0, 1, 0, 0x0000_ffff).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn repeat_and_rotation_helpers() {
        assert_eq!(repeat32(0x0000_ffff), 0x0000_ffff_0000_ffff);
        let initial = 0b1010u64;
        assert_eq!(chunk_mask(initial, 0, 0), initial);
        assert_eq!(chunk_mask(initial, 1, 1), initial.rotate_right(1));
        assert_eq!(chunk_mask(initial, 2, 33), initial.rotate_right(66 % 64));
    }

    #[test]
    fn generates_masks_with_exact_popcount() {
        for mode in 1u8..=4 {
            let mut value = mode as u32;
            let mask = generate_half_mask(
                || {
                    value = value.wrapping_mul(0x9e37_79b9).wrapping_add(0x7f4a_7c15);
                    value
                },
                mode,
            )
            .unwrap();
            assert_eq!(
                mask.count_ones(),
                4 * low_entropy_stride(mode).unwrap() as u32
            );
        }
    }

    #[test]
    fn encode_rejects_bodies_whose_encoded_length_exceeds_u16() {
        // Mode 1 has C=4: 32768 bytes would encode to 65536 bytes, which
        // cannot fit the u16 payload length field (spec section 7.6).
        let half_mask = 0xffff_0000u32; // popcount 16 = 4 * C
        let params = LowEntropyParams::new(1, 0, half_mask, false).unwrap();
        assert!(encode(&vec![0u8; 32768], &params).is_err());
        // The largest accepted body for mode 1 is 32764 bytes.
        assert!(encode(&vec![0u8; 32764], &params).is_ok());
        // Other modes stay capped by MAX_FRAGMENT (32768).
        let half_mask = 0xffff_f000u32; // popcount 20 = 4 * 5
        let params = LowEntropyParams::new(2, 0, half_mask, false).unwrap();
        assert!(encode(&vec![0u8; 32768], &params).is_ok());
    }

    proptest! {
        #[test]
        fn encode_decode_round_trip(
            body in prop::collection::vec(any::<u8>(), 0..80),
            mode in 1u8..=4,
            rotation in 0u8..=63,
            polarity in any::<bool>(),
            seed in any::<u32>(),
        ) {
            // A rotated run-of-ones has exactly 4*C bits set by construction.
            let ones = 4 * low_entropy_stride(mode).unwrap();
            let base = if ones == 32 {
                u32::MAX
            } else {
                (1u32 << ones) - 1
            };
            let half_mask = base.rotate_left(seed % 32);
            let params = LowEntropyParams::new(mode, rotation, half_mask, polarity)?;
            let encoded = encode(&body, &params)?;
            prop_assert_eq!(encoded.len(), low_entropy_encoded_len(body.len(), mode).unwrap());
            let decoded = decode(&encoded, body.len(), mode, rotation, half_mask)?;
            prop_assert_eq!(decoded, body);
        }

        #[test]
        fn decode_never_panics_on_arbitrary_bytes(
            data in prop::collection::vec(any::<u8>(), 0..96),
            mode in 0u8..=6,
            rotation in 0u8..=70,
            half_mask in any::<u32>(),
            extracted in 0usize..=40,
        ) {
            let _ = decode(&data, extracted, mode, rotation, half_mask);
        }
    }
}
