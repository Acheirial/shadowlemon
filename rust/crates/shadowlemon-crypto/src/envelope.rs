//! Handshake envelope serialisation and strict, panic-free parsing.

use crate::{
    suite::Suite, CryptoError, EPHEMERAL_KEY_LEN, HANDSHAKE_REQUEST_FIXED_LEN,
    HANDSHAKE_RESPONSE_LEN, MAX_HANDSHAKE_SUITES, SALT_LEN,
};

/// Length of the fixed header preceding the suite list in a request.
pub const REQUEST_HEADER_LEN: usize = 3;
/// Handshake succeeded.
pub const STATUS_OK: u8 = 0;
/// No cipher suite is shared by the two peers.
pub const STATUS_NO_SUITE: u8 = 2;

/// First handshake message, sent by the client.
///
/// Wire layout: `version_min(1) version_max(1) suite_count(1) suites(n)
/// eph_pub(32) client_salt(16)`, i.e. 51 + n bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HandshakeRequest {
    /// Lowest protocol version the client accepts.
    pub version_min: u8,
    /// Highest protocol version the client accepts.
    pub version_max: u8,
    /// Cipher suites in client preference order, 1 to 4 entries.
    pub suites: Vec<Suite>,
    /// X25519 ephemeral public key.
    pub eph_pub: [u8; EPHEMERAL_KEY_LEN],
    /// Random salt contributed by the client.
    pub client_salt: [u8; SALT_LEN],
}

impl HandshakeRequest {
    /// Serialize to the wire format. Use [`HandshakeRequest::validate`] first
    /// if the fields came from an untrusted source.
    #[must_use]
    pub fn marshal(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(HANDSHAKE_REQUEST_FIXED_LEN + self.suites.len());
        bytes.push(self.version_min);
        bytes.push(self.version_max);
        bytes.push(self.suites.len() as u8);
        for suite in &self.suites {
            bytes.push(suite.as_u8());
        }
        bytes.extend_from_slice(&self.eph_pub);
        bytes.extend_from_slice(&self.client_salt);
        bytes
    }

    /// Check the invariants that make a request safe to negotiate on.
    pub fn validate(&self) -> Result<(), CryptoError> {
        if self.suites.is_empty() || self.suites.len() > MAX_HANDSHAKE_SUITES {
            return Err(CryptoError::MalformedHandshake(format!(
                "request carries {} suites, want 1..={}",
                self.suites.len(),
                MAX_HANDSHAKE_SUITES
            )));
        }
        for (i, suite) in self.suites.iter().enumerate() {
            if !suite.is_valid() {
                return Err(CryptoError::UnknownSuite(suite.as_u8()));
            }
            if self.suites[..i].contains(suite) {
                return Err(CryptoError::DuplicateSuite(suite.as_u8()));
            }
        }
        if self.version_min > self.version_max
            || self.version_min > crate::DEFAULT_PROTOCOL_VERSION
            || self.version_max < crate::DEFAULT_PROTOCOL_VERSION
        {
            return Err(CryptoError::MalformedHandshake(format!(
                "request version range {}-{} does not contain {}",
                self.version_min,
                self.version_max,
                crate::DEFAULT_PROTOCOL_VERSION
            )));
        }
        Ok(())
    }

    /// Parse a request from the beginning of `input`.
    ///
    /// Returns the parsed value and the number of bytes consumed, so that a
    /// caller can find application data following the envelope. Truncation,
    /// zero or excessive suite counts, unknown or duplicate suites and an
    /// inverted version range are all rejected. This function never panics,
    /// whatever the input.
    pub fn parse(input: &[u8]) -> Result<(Self, usize), CryptoError> {
        if input.len() < REQUEST_HEADER_LEN {
            return Err(CryptoError::MalformedHandshake(format!(
                "request is {} bytes, want at least {}",
                input.len(),
                REQUEST_HEADER_LEN
            )));
        }
        let suite_count = usize::from(input[2]);
        if suite_count == 0 || suite_count > MAX_HANDSHAKE_SUITES {
            return Err(CryptoError::MalformedHandshake(format!(
                "request carries {} suites, want 1..={}",
                suite_count, MAX_HANDSHAKE_SUITES
            )));
        }
        let consumed = HANDSHAKE_REQUEST_FIXED_LEN + suite_count;
        if input.len() < consumed {
            return Err(CryptoError::MalformedHandshake(format!(
                "request is {} bytes, want at least {}",
                input.len(),
                consumed
            )));
        }

        let mut suites = Vec::with_capacity(suite_count);
        for &raw in &input[REQUEST_HEADER_LEN..REQUEST_HEADER_LEN + suite_count] {
            let suite = Suite::from_u8(raw).ok_or(CryptoError::UnknownSuite(raw))?;
            if suites.contains(&suite) {
                return Err(CryptoError::DuplicateSuite(raw));
            }
            suites.push(suite);
        }

        let mut eph_pub = [0u8; EPHEMERAL_KEY_LEN];
        eph_pub.copy_from_slice(&input[REQUEST_HEADER_LEN + suite_count..][..EPHEMERAL_KEY_LEN]);
        let mut client_salt = [0u8; SALT_LEN];
        client_salt.copy_from_slice(&input[consumed - SALT_LEN..consumed]);

        let request = Self {
            version_min: input[0],
            version_max: input[1],
            suites,
            eph_pub,
            client_salt,
        };
        request.validate()?;
        Ok((request, consumed))
    }
}

/// Second handshake message, sent by the server. Always 51 bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HandshakeResponse {
    /// [`STATUS_OK`] or [`STATUS_NO_SUITE`].
    pub status: u8,
    /// Negotiated protocol version, or zero in a failure response.
    pub version: u8,
    /// Negotiated data-plane suite, or zero in a failure response.
    pub suite: Suite,
    /// Server's X25519 ephemeral public key.
    pub eph_pub: [u8; EPHEMERAL_KEY_LEN],
    /// Random salt contributed by the server.
    pub server_salt: [u8; SALT_LEN],
}

impl HandshakeResponse {
    /// Build a successful response.
    #[must_use]
    pub fn success(
        version: u8,
        suite: Suite,
        eph_pub: [u8; EPHEMERAL_KEY_LEN],
        server_salt: [u8; SALT_LEN],
    ) -> Self {
        Self {
            status: STATUS_OK,
            version,
            suite,
            eph_pub,
            server_salt,
        }
    }

    /// Build the single failure response: no shared cipher suite.
    #[must_use]
    pub fn no_suite() -> Self {
        Self {
            status: STATUS_NO_SUITE,
            version: 0,
            suite: Suite::XChaCha20Poly1305,
            eph_pub: [0u8; EPHEMERAL_KEY_LEN],
            server_salt: [0u8; SALT_LEN],
        }
    }

    /// Whether this response completed the handshake.
    #[must_use]
    pub const fn is_ok(&self) -> bool {
        self.status == STATUS_OK
    }

    /// Serialize to the fixed 51-byte wire format.
    #[must_use]
    pub fn marshal(&self) -> [u8; HANDSHAKE_RESPONSE_LEN] {
        let mut bytes = [0u8; HANDSHAKE_RESPONSE_LEN];
        bytes[0] = self.status;
        bytes[1] = self.version;
        bytes[2] = self.suite.as_u8();
        bytes[3..3 + EPHEMERAL_KEY_LEN].copy_from_slice(&self.eph_pub);
        bytes[3 + EPHEMERAL_KEY_LEN..].copy_from_slice(&self.server_salt);
        bytes
    }

    /// Parse an exactly 51-byte response. This function never panics.
    pub fn parse(input: &[u8]) -> Result<Self, CryptoError> {
        if input.len() != HANDSHAKE_RESPONSE_LEN {
            return Err(CryptoError::MalformedHandshake(format!(
                "response is {} bytes, want {}",
                input.len(),
                HANDSHAKE_RESPONSE_LEN
            )));
        }
        let status = input[0];
        let version = input[1];
        if status != STATUS_OK && status != STATUS_NO_SUITE {
            return Err(CryptoError::MalformedHandshake(format!(
                "response status {status} is unknown"
            )));
        }
        // A failure response carries no negotiated parameters; the spec fixes
        // them to zero, so an unknown suite byte there is simply ignored.
        let suite = if status == STATUS_NO_SUITE {
            Suite::from_u8(input[2]).unwrap_or(Suite::XChaCha20Poly1305)
        } else {
            Suite::from_u8(input[2]).ok_or(CryptoError::UnknownSuite(input[2]))?
        };
        if status == STATUS_OK && version != crate::DEFAULT_PROTOCOL_VERSION {
            return Err(CryptoError::UnsupportedVersion {
                got: version,
                want: crate::DEFAULT_PROTOCOL_VERSION,
            });
        }

        let mut eph_pub = [0u8; EPHEMERAL_KEY_LEN];
        eph_pub.copy_from_slice(&input[3..3 + EPHEMERAL_KEY_LEN]);
        let mut server_salt = [0u8; SALT_LEN];
        server_salt.copy_from_slice(&input[3 + EPHEMERAL_KEY_LEN..]);
        Ok(Self {
            status,
            version,
            suite,
            eph_pub,
            server_salt,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_request() -> HandshakeRequest {
        HandshakeRequest {
            version_min: 4,
            version_max: 4,
            suites: vec![Suite::XChaCha20Poly1305, Suite::Aes256Gcm, Suite::Aes128Gcm],
            eph_pub: [1u8; EPHEMERAL_KEY_LEN],
            client_salt: [2u8; SALT_LEN],
        }
    }

    #[test]
    fn request_round_trip_and_consumed_length() {
        let request = sample_request();
        let bytes = request.marshal();
        assert_eq!(bytes.len(), HANDSHAKE_REQUEST_FIXED_LEN + 3);
        let trailing = b"application data";
        let mut with_tail = bytes.clone();
        with_tail.extend_from_slice(trailing);
        let (parsed, consumed) = HandshakeRequest::parse(&with_tail).unwrap();
        assert_eq!(parsed, request);
        assert_eq!(consumed, bytes.len());
    }

    #[test]
    fn request_rejects_malformed_inputs() {
        let good = sample_request().marshal();

        for len in 0..good.len() {
            assert!(HandshakeRequest::parse(&good[..len]).is_err());
        }
        // Zero suites.
        let mut zero = good.clone();
        zero[2] = 0;
        assert!(HandshakeRequest::parse(&zero).is_err());
        // Too many suites.
        let mut many = good.clone();
        many[2] = 5;
        assert!(HandshakeRequest::parse(&many).is_err());
        // Unknown suite byte.
        let mut unknown = good.clone();
        unknown[3] = 99;
        assert!(HandshakeRequest::parse(&unknown).is_err());
        // Duplicate suite.
        let mut duplicate = sample_request();
        duplicate.suites = vec![Suite::Aes256Gcm, Suite::Aes256Gcm];
        assert_eq!(
            HandshakeRequest::parse(&duplicate.marshal()),
            Err(CryptoError::DuplicateSuite(1))
        );
        // Inverted version range.
        let mut range = sample_request();
        range.version_min = 5;
        range.version_max = 4;
        assert!(HandshakeRequest::parse(&range.marshal()).is_err());
        // Range that does not contain the only supported version (4).
        let mut old = sample_request();
        old.version_min = 3;
        old.version_max = 3;
        assert!(HandshakeRequest::parse(&old.marshal()).is_err());
    }

    #[test]
    fn response_round_trip_and_failure() {
        let response = HandshakeResponse::success(
            crate::DEFAULT_PROTOCOL_VERSION,
            Suite::Aes128Gcm,
            [3u8; EPHEMERAL_KEY_LEN],
            [4u8; SALT_LEN],
        );
        let bytes = response.marshal();
        assert_eq!(bytes.len(), 51);
        assert_eq!(HandshakeResponse::parse(&bytes).unwrap(), response);

        let failure = HandshakeResponse::no_suite();
        let bytes = failure.marshal();
        assert_eq!(bytes.len(), 51);
        assert_eq!(HandshakeResponse::parse(&bytes).unwrap(), failure);
        assert!(!failure.is_ok());
    }

    #[test]
    fn response_rejects_malformed_inputs() {
        let good = HandshakeResponse::success(4, Suite::Aes256Gcm, [1u8; 32], [2u8; 16]).marshal();
        assert!(HandshakeResponse::parse(&good[..50]).is_err());
        assert!(HandshakeResponse::parse(&[0u8; 52]).is_err());

        let mut status = good;
        status[0] = 1;
        assert!(HandshakeResponse::parse(&status).is_err());

        let mut version = good;
        version[1] = 3;
        assert!(HandshakeResponse::parse(&version).is_err());

        let mut suite = good;
        suite[2] = 250;
        assert!(HandshakeResponse::parse(&suite).is_err());
    }

    proptest::proptest! {
        #[test]
        fn parsers_never_panic(data in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..128)) {
            let _ = HandshakeRequest::parse(&data);
            let _ = HandshakeResponse::parse(&data);
        }
    }
}
