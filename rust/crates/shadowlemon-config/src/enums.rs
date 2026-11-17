//! String-valued enums used by the configuration JSON.
//!
//! Every enum is serialized as its canonical (case-sensitive) protobuf name.
//! For protobuf-JSON compatibility a numeric value is also accepted on input;
//! it is converted to the matching name and always written back as a string.
//! Unrecognized input is preserved as [`Unknown`](enum-with-unknown) so that
//! [`crate::Validate::validate`] can point at the exact offending field.

use std::fmt;

/// Common behavior of the string-valued config enums.
///
/// Implemented by [`string_enum!`] so validation helpers can check enums
/// generically without matching every concrete type.
pub trait KnownEnum {
    /// Whether the value is one of the enum's declared names/numbers.
    fn is_known(&self) -> bool;
    /// The raw text of an unrecognized value, for diagnostics.
    fn unknown(&self) -> Option<&str>;
}

/// Declares a config enum with canonical names and protobuf numeric values.
///
/// An extra `Unknown(String)` variant captures unrecognized input. This is
/// deliberate: it lets validation reject bad values with a precise config path
/// instead of failing early inside serde with no location information.
macro_rules! string_enum {
    (
        $(#[$meta:meta])*
        $name:ident {
            default = $default:ident;
            $(
                $(#[$variant_meta:meta])*
                $variant:ident => $wire:literal = $num:expr
            ),* $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(Clone, Debug, PartialEq, Eq, Hash)]
        pub enum $name {
            $(
                $(#[$variant_meta])*
                $variant,
            )*
            /// An unrecognized name or number, kept verbatim for diagnostics.
            Unknown(String),
        }

        impl $name {
            /// The canonical JSON name of a known value.
            #[must_use]
            pub const fn as_str(&self) -> Option<&'static str> {
                match self {
                    $(Self::$variant => Some($wire),)*
                    Self::Unknown(_) => None,
                }
            }

            /// The protobuf numeric value of a known value.
            #[must_use]
            pub const fn as_i32(&self) -> Option<i32> {
                match self {
                    $(Self::$variant => Some($num),)*
                    Self::Unknown(_) => None,
                }
            }

            /// Whether this is one of the enum's declared values.
            #[must_use]
            pub const fn is_known(&self) -> bool {
                match self {
                    $(Self::$variant => true,)*
                    Self::Unknown(_) => false,
                }
            }

            /// The raw text carried by an [`Self::Unknown`] value.
            #[must_use]
            pub fn unknown(&self) -> Option<&str> {
                match self {
                    Self::Unknown(raw) => Some(raw),
                    _ => None,
                }
            }

            /// Parse a case-sensitive canonical name. Unknown names are
            /// captured rather than rejected so validation can report a path.
            #[must_use]
            pub fn from_name(name: &str) -> Self {
                match name {
                    $($wire => Self::$variant,)*
                    _ => Self::Unknown(name.to_owned()),
                }
            }

            /// Parse a protobuf numeric value, capturing unknown numbers.
            #[must_use]
            pub fn from_number(num: i32) -> Self {
                match num {
                    $($num => Self::$variant,)*
                    _ => Self::Unknown(num.to_string()),
                }
            }

            fn from_i64(num: i64) -> Self {
                match i32::try_from(num) {
                    Ok(n) => Self::from_number(n),
                    Err(_) => Self::Unknown(num.to_string()),
                }
            }

            /// The default (protobuf zero) value of this enum.
            #[must_use]
            pub const fn default_value() -> Self {
                Self::$default
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::default_value()
            }
        }

        impl KnownEnum for $name {
            fn is_known(&self) -> bool {
                $name::is_known(self)
            }

            fn unknown(&self) -> Option<&str> {
                $name::unknown(self)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                match self {
                    $(Self::$variant => f.write_str($wire),)*
                    Self::Unknown(raw) => f.write_str(raw),
                }
            }
        }

        impl serde::Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                match self {
                    $(Self::$variant => serializer.serialize_str($wire),)*
                    Self::Unknown(raw) => serializer.serialize_str(raw),
                }
            }
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct EnumVisitor;

                impl<'de> serde::de::Visitor<'de> for EnumVisitor {
                    type Value = $name;

                    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                        f.write_str(concat!("a ", stringify!($name), " name or number"))
                    }

                    fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E>
                    where
                        E: serde::de::Error,
                    {
                        Ok($name::from_name(value))
                    }

                    fn visit_i64<E>(self, value: i64) -> std::result::Result<Self::Value, E>
                    where
                        E: serde::de::Error,
                    {
                        Ok($name::from_i64(value))
                    }

                    fn visit_u64<E>(self, value: u64) -> std::result::Result<Self::Value, E>
                    where
                        E: serde::de::Error,
                    {
                        if let Ok(n) = i64::try_from(value) {
                            Ok($name::from_i64(n))
                        } else {
                            Ok($name::Unknown(value.to_string()))
                        }
                    }
                }

                deserializer.deserialize_any(EnumVisitor)
            }
        }
    };
}

string_enum! {
    /// Severity threshold for logging.
    LoggingLevel {
        default = Default;
        Default => "DEFAULT" = 0,
        Fatal => "FATAL" = 1,
        Error => "ERROR" = 2,
        Warn => "WARN" = 3,
        Info => "INFO" = 4,
        Debug => "DEBUG" = 5,
        Trace => "TRACE" = 6,
    }
}

string_enum! {
    /// IP version preference used when resolving domain names.
    DualStack {
        default = UseFirstIp;
        UseFirstIp => "USE_FIRST_IP" = 0,
        PreferIpv4 => "PREFER_IPv4" = 1,
        PreferIpv6 => "PREFER_IPv6" = 2,
        OnlyIpv4 => "ONLY_IPv4" = 3,
        OnlyIpv6 => "ONLY_IPv6" = 4,
    }
}

string_enum! {
    /// Transport protocol of a port binding.
    TransportProtocol {
        default = UnknownTransportProtocol;
        UnknownTransportProtocol => "UNKNOWN_TRANSPORT_PROTOCOL" = 0,
        Udp => "UDP" = 1,
        Tcp => "TCP" = 2,
    }
}

string_enum! {
    /// Protocol spoken by a forward or egress proxy.
    ProxyProtocol {
        default = UnknownProxyProtocol;
        UnknownProxyProtocol => "UNKNOWN_PROXY_PROTOCOL" = 0,
        Socks5ProxyProtocol => "SOCKS5_PROXY_PROTOCOL" = 1,
    }
}

string_enum! {
    /// How frequently a network connection is reused.
    MultiplexingLevel {
        default = MultiplexingDefault;
        MultiplexingDefault => "MULTIPLEXING_DEFAULT" = 0,
        MultiplexingOff => "MULTIPLEXING_OFF" = 1,
        MultiplexingLow => "MULTIPLEXING_LOW" = 2,
        MultiplexingMiddle => "MULTIPLEXING_MIDDLE" = 3,
        MultiplexingHigh => "MULTIPLEXING_HIGH" = 4,
    }
}

string_enum! {
    /// When a client starts sending payload relative to handshake completion.
    HandshakeMode {
        default = HandshakeDefault;
        HandshakeDefault => "HANDSHAKE_DEFAULT" = 0,
        HandshakeStandard => "HANDSHAKE_STANDARD" = 1,
        HandshakeNoWait => "HANDSHAKE_NO_WAIT" = 2,
    }
}

string_enum! {
    /// Strategy used to manipulate the nonce prefix.
    NonceType {
        default = NonceTypeRandom;
        NonceTypeRandom => "NONCE_TYPE_RANDOM" = 0,
        NonceTypePrintable => "NONCE_TYPE_PRINTABLE" = 1,
        NonceTypePrintableSubset => "NONCE_TYPE_PRINTABLE_SUBSET" = 2,
        NonceTypeFixed => "NONCE_TYPE_FIXED" = 3,
    }
}

string_enum! {
    /// Amount of entropy reduction used by the feature-gated low entropy mode.
    LowEntropyMode {
        default = Off;
        Off => "LOW_ENTROPY_MODE_OFF" = 0,
        Mode32 => "LOW_ENTROPY_MODE_32" = 1,
        Mode40 => "LOW_ENTROPY_MODE_40" = 2,
        Mode48 => "LOW_ENTROPY_MODE_48" = 3,
        Mode56 => "LOW_ENTROPY_MODE_56" = 4,
    }
}

string_enum! {
    /// Rotation applied to the low-entropy mask between adjacent chunks.
    ///
    /// Numeric values follow the protobuf enum: `ROTATE_RIGHT_k = k` and
    /// `ROTATE_LEFT_k = 16 * k`.
    LowEntropyMaskRotation {
        default = NoRotation;
        NoRotation => "LOW_ENTROPY_MASK_NO_ROTATION" = 0,
        RotateRight1 => "LOW_ENTROPY_MASK_ROTATE_RIGHT_1" = 1,
        RotateRight2 => "LOW_ENTROPY_MASK_ROTATE_RIGHT_2" = 2,
        RotateRight3 => "LOW_ENTROPY_MASK_ROTATE_RIGHT_3" = 3,
        RotateRight4 => "LOW_ENTROPY_MASK_ROTATE_RIGHT_4" = 4,
        RotateRight5 => "LOW_ENTROPY_MASK_ROTATE_RIGHT_5" = 5,
        RotateRight6 => "LOW_ENTROPY_MASK_ROTATE_RIGHT_6" = 6,
        RotateRight7 => "LOW_ENTROPY_MASK_ROTATE_RIGHT_7" = 7,
        RotateRight8 => "LOW_ENTROPY_MASK_ROTATE_RIGHT_8" = 8,
        RotateRight9 => "LOW_ENTROPY_MASK_ROTATE_RIGHT_9" = 9,
        RotateRight10 => "LOW_ENTROPY_MASK_ROTATE_RIGHT_10" = 10,
        RotateRight11 => "LOW_ENTROPY_MASK_ROTATE_RIGHT_11" = 11,
        RotateRight12 => "LOW_ENTROPY_MASK_ROTATE_RIGHT_12" = 12,
        RotateRight13 => "LOW_ENTROPY_MASK_ROTATE_RIGHT_13" = 13,
        RotateRight14 => "LOW_ENTROPY_MASK_ROTATE_RIGHT_14" = 14,
        RotateRight15 => "LOW_ENTROPY_MASK_ROTATE_RIGHT_15" = 15,
        RotateLeft1 => "LOW_ENTROPY_MASK_ROTATE_LEFT_1" = 16,
        RotateLeft2 => "LOW_ENTROPY_MASK_ROTATE_LEFT_2" = 32,
        RotateLeft3 => "LOW_ENTROPY_MASK_ROTATE_LEFT_3" = 48,
        RotateLeft4 => "LOW_ENTROPY_MASK_ROTATE_LEFT_4" = 64,
        RotateLeft5 => "LOW_ENTROPY_MASK_ROTATE_LEFT_5" = 80,
        RotateLeft6 => "LOW_ENTROPY_MASK_ROTATE_LEFT_6" = 96,
        RotateLeft7 => "LOW_ENTROPY_MASK_ROTATE_LEFT_7" = 112,
        RotateLeft8 => "LOW_ENTROPY_MASK_ROTATE_LEFT_8" = 128,
        RotateLeft9 => "LOW_ENTROPY_MASK_ROTATE_LEFT_9" = 144,
        RotateLeft10 => "LOW_ENTROPY_MASK_ROTATE_LEFT_10" = 160,
        RotateLeft11 => "LOW_ENTROPY_MASK_ROTATE_LEFT_11" = 176,
        RotateLeft12 => "LOW_ENTROPY_MASK_ROTATE_LEFT_12" = 192,
        RotateLeft13 => "LOW_ENTROPY_MASK_ROTATE_LEFT_13" = 208,
        RotateLeft14 => "LOW_ENTROPY_MASK_ROTATE_LEFT_14" = 224,
        RotateLeft15 => "LOW_ENTROPY_MASK_ROTATE_LEFT_15" = 240,
    }
}

string_enum! {
    /// Action applied to traffic matching an egress rule.
    EgressAction {
        default = Proxy;
        Proxy => "PROXY" = 0,
        Direct => "DIRECT" = 1,
        Reject => "REJECT" = 2,
    }
}

string_enum! {
    /// Cipher suite identifiers from the configuration layer.
    ///
    /// These numbers (0..3) are *not* the handshake wire suite numbers; use
    /// [`config_suite_to_wire`] to translate them.
    CipherSuite {
        default = Unspecified;
        Unspecified => "CIPHER_SUITE_UNSPECIFIED" = 0,
        XChaCha20Poly1305 => "CIPHER_SUITE_XCHACHA20_POLY1305" = 1,
        Aes256Gcm => "CIPHER_SUITE_AES_256_GCM" = 2,
        Aes128Gcm => "CIPHER_SUITE_AES_128_GCM" = 3,
    }
}

/// Translate a configuration [`CipherSuite`] into the handshake wire suite
/// number documented in `config-v0.2.md` §2.
///
/// Returns `None` for `CIPHER_SUITE_UNSPECIFIED` and for unknown values; both
/// are rejected by validation and can never reach a handshake.
#[must_use]
pub fn config_suite_to_wire(suite: CipherSuite) -> Option<u8> {
    match suite {
        CipherSuite::XChaCha20Poly1305 => Some(0),
        CipherSuite::Aes256Gcm => Some(1),
        CipherSuite::Aes128Gcm => Some(2),
        _ => None,
    }
}

/// Translate a [`LowEntropyMaskRotation`] into the single wire byte `R`
/// described in `config-v0.2.md` §6 (right rotations map to `k`, left
/// rotations map to `64 - k`, no rotation maps to `0`).
#[must_use]
pub fn mask_rotation_to_wire(rotation: LowEntropyMaskRotation) -> Option<u8> {
    match rotation {
        LowEntropyMaskRotation::NoRotation => Some(0),
        LowEntropyMaskRotation::Unknown(_) => None,
        other => {
            let n = other.as_i32()?;
            if (1..=15).contains(&n) {
                Some(n as u8)
            } else if (16..=240).contains(&n) && n % 16 == 0 {
                Some((64 - n / 16) as u8)
            } else {
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cipher_suite_mapping_table() {
        let cases = [
            (CipherSuite::Unspecified, None),
            (CipherSuite::XChaCha20Poly1305, Some(0)),
            (CipherSuite::Aes256Gcm, Some(1)),
            (CipherSuite::Aes128Gcm, Some(2)),
            (CipherSuite::Unknown("bogus".into()), None),
        ];
        for (suite, wire) in cases {
            assert_eq!(config_suite_to_wire(suite.clone()), wire, "{suite:?}");
        }
    }

    #[test]
    fn cipher_suite_names_and_numbers() {
        assert_eq!(
            CipherSuite::from_name("CIPHER_SUITE_AES_256_GCM"),
            CipherSuite::Aes256Gcm
        );
        assert_eq!(CipherSuite::from_number(3), CipherSuite::Aes128Gcm);
        // Names are case sensitive.
        assert!(!CipherSuite::from_name("cipher_suite_aes_256_gcm").is_known());
        // Numbers are accepted and round-trip back out as canonical strings.
        assert_eq!(
            serde_json::to_string(&CipherSuite::from_number(1)).unwrap(),
            "\"CIPHER_SUITE_XCHACHA20_POLY1305\""
        );
        assert_eq!(
            serde_json::from_str::<CipherSuite>("2").unwrap(),
            CipherSuite::Aes256Gcm
        );
    }

    #[test]
    fn mask_rotation_wire_mapping() {
        assert_eq!(
            mask_rotation_to_wire(LowEntropyMaskRotation::NoRotation),
            Some(0)
        );
        assert_eq!(
            mask_rotation_to_wire(LowEntropyMaskRotation::RotateRight7),
            Some(7)
        );
        assert_eq!(
            mask_rotation_to_wire(LowEntropyMaskRotation::RotateRight15),
            Some(15)
        );
        assert_eq!(
            mask_rotation_to_wire(LowEntropyMaskRotation::RotateLeft1),
            Some(63)
        );
        assert_eq!(
            mask_rotation_to_wire(LowEntropyMaskRotation::RotateLeft15),
            Some(49)
        );
        assert_eq!(
            mask_rotation_to_wire(LowEntropyMaskRotation::Unknown("x".into())),
            None
        );
    }
}
