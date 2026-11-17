//! Prefix/suffix padding generation (reference-go-v3.md §7.7).
//!
//! Padding is unencrypted random bytes used to tune the entropy and the
//! longest run of printable characters in a segment. Lengths are configured
//! as `min..=max` ranges; randomness is supplied by the caller so this crate
//! stays independent of any RNG and encoding/round-trip tests are deterministic.
//!
//! # `min == max` is deliberately reduced
//!
//! The Go reference's `choosePaddingLength` never returns a fixed length when
//! `min == max`: it returns `max - 1` instead. A constant padding length would
//! be a stable traffic fingerprint (reference-go-v3.md §7.7 and appendix item
//! 14). `max == 0` is the sole exception and yields an empty padding block.

use crate::WireError;

/// An inclusive `min..=max` range of padding lengths, in bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PaddingRange {
    /// Minimum length (inclusive).
    pub min: usize,
    /// Maximum length (inclusive).
    pub max: usize,
}

impl PaddingRange {
    /// Build a range, rejecting `min > max` and `max > 255` (the metadata
    /// padding-length fields are single bytes).
    pub fn new(min: usize, max: usize) -> Result<Self, WireError> {
        if min > max || max > u8::MAX as usize {
            return Err(WireError::InvalidPaddingRange { min, max });
        }
        Ok(Self { min, max })
    }

    /// Choose a length within this range using `rand_below(n)`, which must
    /// return a uniformly distributed value in `0..n`.
    ///
    /// When `min == max > 0`, returns `max - 1` to avoid a fixed-length
    /// fingerprint. The supplied value is clamped to `0..n`, so a broken RNG
    /// never produces an out-of-range length.
    #[must_use]
    pub fn choose(&self, mut rand_below: impl FnMut(usize) -> usize) -> usize {
        if self.max == 0 {
            return 0;
        }
        if self.min >= self.max {
            // Go's `choosePaddingLength`: min == max collapses to max - 1.
            return self.max - 1;
        }
        let span = self.max - self.min + 1;
        let offset = rand_below(span).min(span - 1);
        self.min + offset
    }

    /// Generate a random padding block whose length came from [`Self::choose`]
    /// and whose bytes come from `rand_byte`.
    #[must_use]
    pub fn generate(
        &self,
        rand_below: impl FnMut(usize) -> usize,
        mut rand_byte: impl FnMut() -> u8,
    ) -> Vec<u8> {
        let len = self.choose(rand_below);
        (0..len).map(|_| rand_byte()).collect()
    }
}

/// Prefix (padding 1) and suffix (padding 2) length configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PaddingConfig {
    /// Range for padding 1, placed before the payload body.
    pub prefix: PaddingRange,
    /// Range for padding 2, placed after the payload tag.
    pub suffix: PaddingRange,
}

impl PaddingConfig {
    /// Build a configuration from a prefix and a suffix range.
    #[must_use]
    pub const fn new(prefix: PaddingRange, suffix: PaddingRange) -> Self {
        Self { prefix, suffix }
    }

    /// Generate prefix padding.
    #[must_use]
    pub fn generate_prefix(
        &self,
        rand_below: impl FnMut(usize) -> usize,
        rand_byte: impl FnMut() -> u8,
    ) -> Vec<u8> {
        self.prefix.generate(rand_below, rand_byte)
    }

    /// Generate suffix padding.
    #[must_use]
    pub fn generate_suffix(
        &self,
        rand_below: impl FnMut(usize) -> usize,
        rand_byte: impl FnMut() -> u8,
    ) -> Vec<u8> {
        self.suffix.generate(rand_below, rand_byte)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equal_min_max_yields_max_minus_one() {
        let range = PaddingRange::new(8, 8).unwrap();
        assert_eq!(range.choose(|_| 0), 7);
        assert_eq!(range.choose(|_| 999), 7);
        assert_eq!(PaddingRange::new(1, 1).unwrap().choose(|_| 0), 0);
        assert_eq!(PaddingRange::new(0, 0).unwrap().choose(|_| 0), 0);
    }

    #[test]
    fn varying_range_is_uniform_inclusive() {
        let range = PaddingRange::new(3, 6).unwrap();
        for (draw, want) in [(0, 3), (1, 4), (2, 5), (3, 6)] {
            assert_eq!(range.choose(move |_| draw), want);
        }
        // Defensive clamping: an out-of-range RNG result stays in bounds.
        assert_eq!(range.choose(|_| usize::MAX), 6);
    }

    #[test]
    fn generate_uses_supplied_rng() {
        let range = PaddingRange::new(2, 4).unwrap();
        let mut byte = 0xa0u8;
        let out = range.generate(
            |_| 0,
            || {
                let b = byte;
                byte = byte.wrapping_add(1);
                b
            },
        );
        assert_eq!(out, vec![0xa0, 0xa1]);

        let config = PaddingConfig::new(PaddingRange::new(2, 2).unwrap(), range);
        assert_eq!(config.generate_prefix(|_| 0, || 0x11), vec![0x11]);
        assert_eq!(
            config.generate_suffix(|_| 2, || 0x22),
            vec![0x22, 0x22, 0x22, 0x22]
        );
    }

    #[test]
    fn rejects_invalid_ranges() {
        assert_eq!(
            PaddingRange::new(5, 4).unwrap_err(),
            WireError::InvalidPaddingRange { min: 5, max: 4 }
        );
        assert_eq!(
            PaddingRange::new(0, 256).unwrap_err(),
            WireError::InvalidPaddingRange { min: 0, max: 256 }
        );
    }
}
