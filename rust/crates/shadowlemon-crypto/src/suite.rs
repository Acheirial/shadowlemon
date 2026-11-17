//! Cipher suite identifiers, wire names and parameter lookup tables.

use std::{fmt, str::FromStr};

use crate::CryptoError;

/// A symmetric AEAD cipher suite.
///
/// The numeric value is part of the wire format: it is carried in the
/// handshake request and response. Existing values must never be reassigned;
/// new suites must be appended.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub enum Suite {
    /// XChaCha20-Poly1305 with a 32-byte key and a 24-byte AEAD nonce.
    XChaCha20Poly1305 = 0,
    /// AES-256-GCM with a 32-byte key and a 12-byte AEAD nonce.
    Aes256Gcm = 1,
    /// AES-128-GCM with a 16-byte key and a 12-byte AEAD nonce.
    Aes128Gcm = 2,
}

impl Suite {
    /// Canonical configuration name of this suite.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::XChaCha20Poly1305 => "XCHACHA20_POLY1305",
            Self::Aes256Gcm => "AES_256_GCM",
            Self::Aes128Gcm => "AES_128_GCM",
        }
    }

    /// Numeric wire identifier of this suite.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Length in bytes of the AEAD key.
    #[must_use]
    pub const fn key_len(self) -> usize {
        match self {
            Self::XChaCha20Poly1305 | Self::Aes256Gcm => 32,
            Self::Aes128Gcm => 16,
        }
    }

    /// Length in bytes of the AEAD nonce.
    ///
    /// XChaCha20-Poly1305 consumes the whole 24-byte wire nonce; both AES-GCM
    /// variants consume only its last 12 bytes.
    #[must_use]
    pub const fn nonce_len(self) -> usize {
        match self {
            Self::XChaCha20Poly1305 => crate::WIRE_NONCE_LEN,
            Self::Aes256Gcm | Self::Aes128Gcm => 12,
        }
    }

    /// Whether this suite is supported by this build.
    #[must_use]
    pub const fn is_valid(self) -> bool {
        matches!(
            self,
            Self::XChaCha20Poly1305 | Self::Aes256Gcm | Self::Aes128Gcm
        )
    }

    /// Build a suite from a wire byte, returning `None` for unknown values.
    #[must_use]
    pub const fn from_u8(raw: u8) -> Option<Self> {
        match raw {
            0 => Some(Self::XChaCha20Poly1305),
            1 => Some(Self::Aes256Gcm),
            2 => Some(Self::Aes128Gcm),
            _ => None,
        }
    }

    /// All supported suites, in preference order.
    #[must_use]
    pub const fn all_suites() -> [Self; 3] {
        [Self::XChaCha20Poly1305, Self::Aes256Gcm, Self::Aes128Gcm]
    }
}

impl fmt::Display for Suite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl FromStr for Suite {
    type Err = CryptoError;

    /// Parse a config-style suite name. Matching is case-insensitive and
    /// `_`, `-` and space separators are optional, so `AES_256_GCM`,
    /// `aes-256-gcm`, `Aes 256 Gcm` and `AES256GCM` all name the same suite.
    fn from_str(name: &str) -> Result<Self, Self::Err> {
        let normalized: String = name
            .trim()
            .chars()
            .filter(|c| *c != '_' && *c != '-' && *c != ' ')
            .flat_map(char::to_uppercase)
            .collect();
        match normalized.as_str() {
            "XCHACHA20POLY1305" | "CIPHERSUITEXCHACHA20POLY1305" => Ok(Self::XChaCha20Poly1305),
            "AES256GCM" | "CIPHERSUITEAES256GCM" => Ok(Self::Aes256Gcm),
            "AES128GCM" | "CIPHERSUITEAES128GCM" => Ok(Self::Aes128Gcm),
            _ => Err(CryptoError::UnknownSuiteName(name.to_owned())),
        }
    }
}

impl TryFrom<u8> for Suite {
    type Error = CryptoError;

    fn try_from(raw: u8) -> Result<Self, Self::Error> {
        Self::from_u8(raw).ok_or(CryptoError::UnknownSuite(raw))
    }
}

impl From<Suite> for u8 {
    fn from(suite: Suite) -> Self {
        suite.as_u8()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suite_parameters() {
        assert_eq!(Suite::XChaCha20Poly1305.as_u8(), 0);
        assert_eq!(Suite::Aes256Gcm.as_u8(), 1);
        assert_eq!(Suite::Aes128Gcm.as_u8(), 2);
        assert_eq!(Suite::XChaCha20Poly1305.key_len(), 32);
        assert_eq!(Suite::Aes256Gcm.key_len(), 32);
        assert_eq!(Suite::Aes128Gcm.key_len(), 16);
        assert_eq!(Suite::XChaCha20Poly1305.nonce_len(), 24);
        assert_eq!(Suite::Aes256Gcm.nonce_len(), 12);
        assert_eq!(Suite::Aes128Gcm.nonce_len(), 12);
        assert!(Suite::all_suites().iter().all(|s| s.is_valid()));
        assert!(Suite::from_u8(3).is_none());
    }

    #[test]
    fn suite_names_are_flexible() {
        for name in [
            "XCHACHA20_POLY1305",
            "xchacha20-poly1305",
            "XChaCha20 Poly1305",
            "xchacha20poly1305",
        ] {
            assert_eq!(name.parse::<Suite>().unwrap(), Suite::XChaCha20Poly1305);
        }
        for name in [
            "AES_256_GCM",
            "aes-256-gcm",
            "Aes 256 Gcm",
            "AES256GCM",
            "  aes_256_gcm  ",
        ] {
            assert_eq!(name.parse::<Suite>().unwrap(), Suite::Aes256Gcm);
        }
        for name in ["AES_128_GCM", "aes-128-gcm", "Aes128Gcm"] {
            assert_eq!(name.parse::<Suite>().unwrap(), Suite::Aes128Gcm);
        }
        // Config enum names from `config-v0.2.md` are accepted as aliases.
        assert_eq!(
            "CIPHER_SUITE_XCHACHA20_POLY1305".parse::<Suite>().unwrap(),
            Suite::XChaCha20Poly1305
        );
        assert_eq!(
            "CIPHER_SUITE_AES_256_GCM".parse::<Suite>().unwrap(),
            Suite::Aes256Gcm
        );
        assert_eq!(
            "CIPHER_SUITE_AES_128_GCM".parse::<Suite>().unwrap(),
            Suite::Aes128Gcm
        );
        for name in ["", "CHACHA20_POLY1305", "AES_192_GCM", "nonsense"] {
            assert!(name.parse::<Suite>().is_err());
        }
    }

    #[test]
    fn suite_display_round_trips() {
        for suite in Suite::all_suites() {
            assert_eq!(suite.to_string().parse::<Suite>().unwrap(), suite);
        }
    }
}
