//! 1-RTT handshake state machines for ShadowLemon V0.2 (spec §3).
//!
//! The handshake protects exactly two messages with a static key derived from
//! the user credential: the `openSessionRequest` payload (a 51 + suite_count
//! byte prefix, then a two-byte length-prefixed piggyback region padded with
//! random bytes to the session payload capacity) and the `openSessionResponse`
//! payload (a fixed 51 bytes). Once both peers know the
//! server's ephemeral key and salt, all data-plane keys come from a fresh
//! X25519 exchange. The ephemeral private key is zeroized as soon as the
//! directional session keys have been derived.
//!
//! Both state machines are transport independent: they consume and produce
//! complete wire frames ([`shadowlemon_wire::encode_segment`] /
//! [`shadowlemon_wire::decode_segment`]). An I/O layer writes the returned
//! bytes and feeds received frames into [`ClientHandshake::process_response`]
//! or [`ServerHandshake::accept`].

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use rand::Rng;
use shadowlemon_crypto::{
    aead::AeadKey,
    envelope::{HandshakeRequest, HandshakeResponse, STATUS_NO_SUITE},
    hint::write_user_hint,
    kdf::{derive_early_keys, derive_session_keys_v4, derive_static_key, hash_password, StaticKey},
    kex::EphemeralKeyPair,
    suite::Suite,
    CryptoError, WireNonce, DEFAULT_PROTOCOL_VERSION, HANDSHAKE_REQUEST_FIXED_LEN,
    HANDSHAKE_RESPONSE_LEN, MAX_HANDSHAKE_SUITES,
};
use shadowlemon_wire::{
    decode_segment, encode_segment, increment_nonce, Cipher, CipherError, DecodeOptions,
    EncodeOptions, Metadata, PayloadNonce, WireError, META_BLOCK_LEN, WIRE_NONCE_LEN,
};
use thiserror::Error;
use tracing::debug;

use crate::{
    serveruser::{Decryption, Registry, SourceKey, User, UserDecryptor},
    underlay::MAX_SUFFIX_PADDING,
};

/// The client waits at most ten seconds for the handshake response.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Protocol type of `openSessionRequest`.
pub const TYPE_OPEN_SESSION_REQUEST: u8 = 2;
/// Protocol type of `openSessionResponse`.
pub const TYPE_OPEN_SESSION_RESPONSE: u8 = 3;
/// Random reduction applied to the piggyback capacity of a handshake request.
///
/// The resulting request payload length is drawn from
/// `MAX_SESSION_PAYLOAD - PIGGYBACK_SLACK ..= MAX_SESSION_PAYLOAD`, so the
/// first datagram of a session overlaps the regular data-frame size range
/// instead of standing out as a fixed-size beacon.
const PIGGYBACK_SLACK: usize = 28;

/// Which framing rules the surrounding connection uses.
///
/// External transport is UDP-only, so every handshake message carries its own
/// nonce. The enum is retained as an explicit parameter to the handshake state
/// machine and for API compatibility.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandshakeTransport {
    /// UDP/datagram underlay: every message carries its own nonce.
    Datagram,
}

impl HandshakeTransport {
    const fn payload_nonce(self) -> PayloadNonce {
        PayloadNonce::UdpFlip
    }
}

/// Broad failure class, suitable for a metric label or log field.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum HandshakeErrorKind {
    /// Local I/O or framing failure.
    Transport,
    /// The handshake response did not arrive within ten seconds.
    Timeout,
    /// No user/suite pair authenticated the envelope.
    Authentication,
    /// A message was truncated, malformed, duplicated or out of policy.
    Malformed,
    /// A peer advertised a version this build does not speak.
    UnsupportedVersion,
    /// Both peers authenticated but have no common cipher suite.
    NoCommonSuite,
    /// X25519 produced a non-contributory (all-zero) shared secret.
    InvalidKeyExchange,
    /// A local configuration error (for example an empty suite list).
    Configuration,
}

impl HandshakeErrorKind {
    /// Stable lower-case name of this class.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Transport => "transport",
            Self::Timeout => "timeout",
            Self::Authentication => "authentication",
            Self::Malformed => "malformed",
            Self::UnsupportedVersion => "version",
            Self::NoCommonSuite => "no_common_suite",
            Self::InvalidKeyExchange => "invalid_key_exchange",
            Self::Configuration => "configuration",
        }
    }
}

/// A handshake failure, with a stable class for logging and a human-readable
/// detail for local diagnostics.
#[derive(Debug, Error)]
pub enum HandshakeError {
    /// The transport or the wire codec failed.
    #[error("handshake transport error: {0}")]
    Transport(String),
    /// No response arrived before the ten-second deadline.
    #[error("handshake timed out after {0:?}")]
    Timeout(Duration),
    /// Envelope authentication failed.
    #[error("handshake authentication failed: {0}")]
    Authentication(String),
    /// A message was structurally invalid.
    #[error("malformed handshake: {0}")]
    Malformed(String),
    /// The negotiated version was not four.
    #[error("unsupported protocol version {0}")]
    UnsupportedVersion(u8),
    /// The authenticated peers have no suite in common.
    #[error("no common cipher suite")]
    NoCommonSuite,
    /// The peer's ephemeral public key was unusable.
    #[error("invalid key exchange: {0}")]
    InvalidKeyExchange(String),
    /// The local handshake configuration was invalid.
    #[error("invalid handshake configuration: {0}")]
    Configuration(String),
}

impl HandshakeError {
    /// Classification used for logging/metrics.
    #[must_use]
    pub const fn kind(&self) -> HandshakeErrorKind {
        match self {
            Self::Transport(_) => HandshakeErrorKind::Transport,
            Self::Timeout(_) => HandshakeErrorKind::Timeout,
            Self::Authentication(_) => HandshakeErrorKind::Authentication,
            Self::Malformed(_) | Self::Configuration(_) => HandshakeErrorKind::Malformed,
            Self::UnsupportedVersion(_) => HandshakeErrorKind::UnsupportedVersion,
            Self::NoCommonSuite => HandshakeErrorKind::NoCommonSuite,
            Self::InvalidKeyExchange(_) => HandshakeErrorKind::InvalidKeyExchange,
        }
    }
}

impl From<CryptoError> for HandshakeError {
    fn from(err: CryptoError) -> Self {
        match err {
            CryptoError::AllZeroSharedSecret => Self::InvalidKeyExchange(err.to_string()),
            CryptoError::UnsupportedVersion { got, .. } => Self::UnsupportedVersion(got),
            other => Self::Malformed(other.to_string()),
        }
    }
}

impl From<WireError> for HandshakeError {
    fn from(err: WireError) -> Self {
        Self::Malformed(err.to_string())
    }
}

/// Thin [`Cipher`] adapter around a crypto-crate [`AeadKey`].
pub struct AeadCipher {
    key: AeadKey,
}

impl AeadCipher {
    /// Wrap an AEAD key for use by the wire framing layer.
    #[must_use]
    pub const fn new(key: AeadKey) -> Self {
        Self { key }
    }

    /// The wrapped key.
    #[must_use]
    pub const fn key(&self) -> &AeadKey {
        &self.key
    }
}

impl Cipher for AeadCipher {
    fn seal(&self, wire_nonce: &WireNonce, plaintext: &[u8]) -> Result<Vec<u8>, CipherError> {
        self.key
            .seal(wire_nonce, plaintext)
            .map_err(CipherError::failed)
    }

    fn open(&self, wire_nonce: &WireNonce, ciphertext: &[u8]) -> Result<Vec<u8>, CipherError> {
        self.key
            .open(wire_nonce, ciphertext)
            .map_err(CipherError::failed)
    }
}

/// Result of a successful handshake on either peer.
///
/// The two AEAD keys are ready to be installed into a data-plane
/// [`Session`](crate::session::Session).
pub struct EstablishedHandshake {
    /// Session identifier carried in every metadata frame.
    pub session_id: u32,
    /// Negotiated data-plane suite.
    pub suite: Suite,
    /// Client-to-server data key.
    pub c2s_key: AeadKey,
    /// Server-to-client data key.
    pub s2c_key: AeadKey,
    /// Early (0-RTT) client-to-server key derived from the static key.
    pub early_c2s_key: AeadKey,
    /// Early (0-RTT) server-to-client key derived from the static key.
    pub early_s2c_key: AeadKey,
    /// Application bytes that followed the handshake prefix in the request.
    pub piggyback: Vec<u8>,
    /// Authenticated user name, when the peer is the client.
    pub user: Option<String>,
}

impl EstablishedHandshake {
    /// Consume the result and return the directional keys.
    #[must_use]
    pub fn into_keys(self) -> (AeadKey, AeadKey) {
        (self.c2s_key, self.s2c_key)
    }
}

/// Outcome of processing a handshake response.
pub enum ClientOutcome {
    /// The session keys are installed; the data plane may start.
    Established(Box<EstablishedHandshake>),
    /// The server authenticated us but rejected every offered suite.
    ///
    /// The response is valid and the caller should close quietly; no session
    /// keys were derived.
    NoCommonSuite,
}

/// State of a client handshake.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientHandshakeState {
    /// No request has been built yet.
    Ready,
    /// A request was emitted; a response is expected.
    AwaitingResponse,
    /// A successful response was processed.
    Established,
    /// The handshake failed terminally.
    Failed,
}

/// Server-side envelope decryptor backed by the crypto crate's AEAD.
///
/// It is deliberately stateless with respect to authentication: a candidate
/// user is discovered *only* when a tag verifies. The keyed hint merely orders
/// the trials performed by [`Registry::discover`].
///
/// When a trial succeeds, the derived static key bytes are remembered in a
/// small side table so the server can protect its response with the very same
/// key (and mix it into the HKDF salt). The table is keyed by user name and
/// suite; the ephemeral private key itself is never retained here.
type KeyMap = Arc<Mutex<HashMap<(String, Suite), Vec<u8>>>>;

#[derive(Debug, Default)]
pub struct AeadUserDecryptor {
    keys: KeyMap,
}

impl AeadUserDecryptor {
    /// Create an empty decryptor/keystore.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Static key bytes of a previously authenticated `(user, suite)` pair.
    #[must_use]
    pub fn static_key(&self, user: &str, suite: Suite) -> Option<Vec<u8>> {
        self.keys
            .lock()
            .ok()?
            .get(&(user.to_owned(), suite))
            .cloned()
    }

    /// Number of remembered authentications (useful for tests/diagnostics).
    #[must_use]
    pub fn remembered(&self) -> usize {
        self.keys.lock().map_or(0, |keys| keys.len())
    }
}

impl UserDecryptor for AeadUserDecryptor {
    fn try_decrypt(
        &self,
        user: &User,
        suites: &[Suite],
        nonce: &WireNonce,
        ciphertext: &[u8],
    ) -> Option<Decryption> {
        for &suite in suites {
            let static_key = derive_static_key(user.name(), user.credential(), suite).ok()?;
            let cipher = AeadCipher::new(AeadKey::new(suite, static_key.as_slice()).ok()?);
            if let Ok(plaintext) = cipher.open(nonce, ciphertext) {
                if let Ok(mut keys) = self.keys.lock() {
                    keys.insert(
                        (user.name().to_owned(), suite),
                        static_key.as_slice().to_vec(),
                    );
                }
                return Some(Decryption { suite, plaintext });
            }
        }
        None
    }
}

/// Build a server registry wired to an AEAD-backed decryptor.
///
/// Returns both halves: the registry is shared with the accept loop, while the
/// decryptor supplies the envelope key of an authenticated user back to
/// [`ServerHandshake`].
#[must_use]
pub fn build_registry(
    users: impl IntoIterator<Item = User>,
    hint_mandatory: bool,
) -> (Arc<Registry>, Arc<AeadUserDecryptor>) {
    let decryptor = Arc::new(AeadUserDecryptor::new());
    let registry = Arc::new(Registry::new(users, hint_mandatory, decryptor.clone()));
    (registry, decryptor)
}

/// Client-side handshake state machine.
pub struct ClientHandshake {
    username: String,
    credential: [u8; 32],
    /// PBKDF2 result derived once at construction and reused by `early_keys`;
    /// deriving it per connection (and twice more per handshake) is pure waste.
    static_key: StaticKey,
    suites: Vec<Suite>,
    session_id: u32,
    transport: HandshakeTransport,
    envelope: AeadCipher,
    request_nonce: WireNonce,
    ephemeral: Option<EphemeralKeyPair>,
    client_salt: Option<[u8; 16]>,
    state: ClientHandshakeState,
    started_at: Option<Instant>,
}

impl ClientHandshake {
    /// Prepare a client handshake.
    ///
    /// `credential` is the 32-byte credential the server registry stores for
    /// this user (see [`User::credential`]); [`Self::with_password`] derives it
    /// from a plain password. The same bytes are used as the PBKDF2 password
    /// input on both sides, which is required because `serveruser` stores only
    /// the credential and the crypto crate hashes its password argument.
    pub fn new(
        username: impl Into<String>,
        credential: [u8; 32],
        suites: Vec<Suite>,
        session_id: u32,
        transport: HandshakeTransport,
    ) -> Result<Self, HandshakeError> {
        validate_suite_list(&suites)?;
        if session_id == 0 {
            return Err(HandshakeError::Configuration(
                "session id 0 is reserved".to_owned(),
            ));
        }
        let username = username.into();
        if username.is_empty() {
            return Err(HandshakeError::Configuration(
                "user name must not be empty".to_owned(),
            ));
        }
        let static_key = derive_static_key(&username, &credential, suites[0])?;
        let envelope = AeadCipher::new(AeadKey::new(suites[0], static_key.as_slice())?);
        let mut request_nonce = random_wire_nonce();
        write_user_hint(&mut request_nonce, username.as_bytes());
        Ok(Self {
            username,
            credential,
            static_key,
            suites,
            session_id,
            transport,
            envelope,
            request_nonce,
            ephemeral: None,
            client_salt: None,
            state: ClientHandshakeState::Ready,
            started_at: None,
        })
    }

    /// Derive the credential from a plain password and build a handshake.
    pub fn with_password(
        username: impl Into<String>,
        password: &[u8],
        suites: Vec<Suite>,
        session_id: u32,
        transport: HandshakeTransport,
    ) -> Result<Self, HandshakeError> {
        let username = username.into();
        let credential = hash_password(password, &username);
        Self::new(username, credential, suites, session_id, transport)
    }

    /// User name whose hint is written into the request nonce.
    #[must_use]
    pub fn username(&self) -> &str {
        &self.username
    }

    /// The 32-byte credential used as PBKDF2 password input.
    #[must_use]
    pub const fn credential(&self) -> &[u8; 32] {
        &self.credential
    }

    /// Current state.
    #[must_use]
    pub const fn state(&self) -> ClientHandshakeState {
        self.state
    }

    /// Bytes of application data that can still be attached to the request.
    #[must_use]
    pub fn piggyback_capacity(&self) -> usize {
        shadowlemon_wire::MAX_SESSION_PAYLOAD
            .saturating_sub(HANDSHAKE_REQUEST_FIXED_LEN + self.suites.len())
    }

    /// Keys for 0-RTT early application data.
    ///
    /// These are derived only from the static key, the session id and the
    /// envelope suite, so both peers can compute them from the first flight
    /// before any X25519 exchange completes. Early data therefore has **no
    /// forward secrecy**; only the post-handshake data keys do.
    pub fn early_keys(&self) -> Result<(AeadKey, AeadKey), HandshakeError> {
        let (c2s, s2c) =
            derive_early_keys(self.static_key.as_slice(), self.session_id, self.suites[0])?;
        Ok((
            AeadKey::new(self.suites[0], c2s.as_slice())?,
            AeadKey::new(self.suites[0], s2c.as_slice())?,
        ))
    }

    /// Deadline of the handshake, once it has been started.
    #[must_use]
    pub fn deadline(&self) -> Option<Instant> {
        self.started_at.map(|start| start + HANDSHAKE_TIMEOUT)
    }

    /// Verify that the ten-second handshake deadline has not passed.
    pub fn check_timeout(&self, now: Instant) -> Result<(), HandshakeError> {
        if let Some(deadline) = self.deadline() {
            if now >= deadline {
                return Err(HandshakeError::Timeout(HANDSHAKE_TIMEOUT));
            }
        }
        Ok(())
    }

    /// Build and encrypt the `openSessionRequest` frame.
    ///
    /// At most [`Self::piggyback_capacity`] minus two bytes of `piggyback` are
    /// attached. A two-byte little-endian length prefix lets the server strip
    /// the random bytes that pad the rest of the region to full capacity, so
    /// the ciphertext length no longer reveals the SOCKS5 command / address
    /// type / domain length. The caller must queue the remainder for the data
    /// plane. Repeated calls are rejected: a handshake emits exactly one
    /// request.
    pub fn build_request(&mut self, piggyback: &[u8]) -> Result<Vec<u8>, HandshakeError> {
        self.check_timeout(Instant::now())?;
        if self.state != ClientHandshakeState::Ready {
            return Err(HandshakeError::Malformed(
                "a client handshake emits exactly one request".to_owned(),
            ));
        }
        let ephemeral = EphemeralKeyPair::generate()?;
        let client_salt = random_salt();
        let request = HandshakeRequest {
            version_min: DEFAULT_PROTOCOL_VERSION,
            version_max: DEFAULT_PROTOCOL_VERSION,
            suites: self.suites.clone(),
            eph_pub: *ephemeral.public_bytes(),
            client_salt,
        };
        request.validate()?;
        let request_bytes = request.marshal();
        // Draw the piggyback region length from a wide interval so the first
        // datagram of a session is not a fixed-size fingerprint. The upper
        // bound stays inside the MTU budget even with the maximum suffix; the
        // lower bound keeps the frame within the size range of data frames.
        let capacity = self.piggyback_capacity() - rand::random_range(0..=PIGGYBACK_SLACK);
        // Two bytes are reserved for the length prefix; the rest of the region
        // is filled with random bytes so the ciphertext length does not reveal
        // the piggyback's real size.
        let usable = capacity.saturating_sub(2);
        let attached = piggyback.len().min(usable);
        let attached_len = u16::try_from(attached).expect("piggyback fits capacity");
        let mut payload = Vec::with_capacity(request_bytes.len() + capacity);
        payload.extend_from_slice(&request_bytes);
        payload.extend_from_slice(&attached_len.to_le_bytes());
        payload.extend_from_slice(&piggyback[..attached]);
        payload.resize(request_bytes.len() + capacity, 0);
        if attached < usable {
            rand::rng().fill_bytes(&mut payload[request_bytes.len() + 2 + attached..]);
        }

        // A random-length suffix breaks the fixed 140/150-byte handshake frame
        // fingerprint. The server reads the variable part from the decrypted
        // metadata lengths, so no fixed-size reader depends on this.
        let suffix: Vec<u8> = if MAX_SUFFIX_PADDING == 0 {
            Vec::new()
        } else {
            let len = rand::random_range(0..=MAX_SUFFIX_PADDING);
            (0..len).map(|_| rand::random::<u8>()).collect()
        };
        let metadata = Metadata::session(
            TYPE_OPEN_SESSION_REQUEST,
            self.session_id,
            0,
            payload_len(&payload)?,
            u8::try_from(suffix.len()).expect("suffix padding <= 32"),
        );
        let mut segment = shadowlemon_wire::Segment::new(metadata, self.request_nonce, payload);
        segment.suffix_padding = suffix;
        let options = EncodeOptions {
            include_nonce: true,
            payload_nonce: self.transport.payload_nonce(),
        };
        let frame = encode_segment(&self.envelope, &segment, &options)?;

        self.ephemeral = Some(ephemeral);
        self.client_salt = Some(client_salt);
        self.state = ClientHandshakeState::AwaitingResponse;
        self.started_at = Some(Instant::now());
        Ok(frame)
    }

    /// Decrypt and validate the `openSessionResponse`, installing session keys.
    ///
    /// The envelope cipher is reused verbatim; there is no time-slot scan and
    /// no second user discovery step. A `status=2` response is parsed specially:
    /// version and suite bytes on a failure response are ignored (§3.2, Go
    /// `parseHandshakeResponse` behavior).
    pub fn process_response(&mut self, frame: &[u8]) -> Result<ClientOutcome, HandshakeError> {
        self.check_timeout(Instant::now())?;
        if self.state != ClientHandshakeState::AwaitingResponse {
            return Err(HandshakeError::Malformed(
                "no handshake response is expected in this state".to_owned(),
            ));
        }
        let ephemeral = self
            .ephemeral
            .as_ref()
            .ok_or_else(|| HandshakeError::Configuration("missing ephemeral key".to_owned()))?;
        let client_salt = self
            .client_salt
            .ok_or_else(|| HandshakeError::Configuration("missing client salt".to_owned()))?;

        let (include_nonce, implicit_nonce) = if self.transport == HandshakeTransport::Datagram {
            (true, [0u8; WIRE_NONCE_LEN])
        } else {
            // The response uses the static-key chain: request metadata N,
            // request payload N+1, response metadata N+2, payload N+3.
            (
                false,
                increment_nonce(&increment_nonce(&self.request_nonce)),
            )
        };
        let options = DecodeOptions {
            include_nonce,
            implicit_metadata_nonce: implicit_nonce,
            payload_nonce: self.transport.payload_nonce(),
        };
        let segment = decode_segment(&self.envelope, frame, &options)?;
        let metadata = match segment.metadata {
            Metadata::Session(meta) => meta,
            _ => {
                return Err(HandshakeError::Malformed(
                    "handshake response is not a session segment".to_owned(),
                ))
            }
        };
        if metadata.protocol_type != TYPE_OPEN_SESSION_RESPONSE
            || metadata.session_id != self.session_id
        {
            return Err(HandshakeError::Malformed(
                "unexpected response type or session id".to_owned(),
            ));
        }
        if segment.payload.len() < HANDSHAKE_RESPONSE_LEN {
            return Err(HandshakeError::Malformed(format!(
                "response payload has {} bytes, want {HANDSHAKE_RESPONSE_LEN}",
                segment.payload.len()
            )));
        }
        let response = HandshakeResponse::parse(&segment.payload[..HANDSHAKE_RESPONSE_LEN])?;
        let trailing = segment.payload[HANDSHAKE_RESPONSE_LEN..].to_vec();

        if response.status == STATUS_NO_SUITE {
            // Go behaviour: status 2 short-circuits before version/suite checks.
            self.state = ClientHandshakeState::Failed;
            self.ephemeral = None;
            self.client_salt = None;
            return Ok(ClientOutcome::NoCommonSuite);
        }
        if response.version != DEFAULT_PROTOCOL_VERSION {
            return Err(HandshakeError::UnsupportedVersion(response.version));
        }
        if !self.suites.contains(&response.suite) {
            return Err(HandshakeError::Malformed(format!(
                "server selected unoffered suite {}",
                response.suite
            )));
        }
        let shared = ephemeral.compute_shared_secret(&response.eph_pub)?;
        let envelope_key = self.envelope.key().key_bytes();
        let (c2s, s2c) = derive_session_keys_v4(
            envelope_key,
            &client_salt,
            &response.server_salt,
            &shared,
            response.suite,
        )?;
        let (early_c2s, early_s2c) = self.early_keys()?;
        let established = EstablishedHandshake {
            session_id: self.session_id,
            suite: response.suite,
            c2s_key: AeadKey::new(response.suite, c2s.as_slice())?,
            s2c_key: AeadKey::new(response.suite, s2c.as_slice())?,
            early_c2s_key: early_c2s,
            early_s2c_key: early_s2c,
            piggyback: trailing,
            user: None,
        };

        // Dropping the pair zeroizes the ephemeral private key (forward secrecy).
        self.ephemeral = None;
        self.client_salt = None;
        self.state = ClientHandshakeState::Established;
        Ok(ClientOutcome::Established(Box::new(established)))
    }
}

impl std::fmt::Debug for ServerHandshakeResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Established {
                response,
                piggyback,
                user,
                ..
            } => f
                .debug_struct("Established")
                .field("response_len", &response.len())
                .field("piggyback_len", &piggyback.len())
                .field("user", user)
                .finish(),
            Self::NoCommonSuite { response } => f
                .debug_struct("NoCommonSuite")
                .field("response_len", &response.len())
                .finish(),
        }
    }
}

/// State of a server handshake.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServerHandshakeState {
    /// Waiting for the first `openSessionRequest`.
    Ready,
    /// The request failed validation; zero response bytes must be written.
    Rejected,
    /// Both peers authenticated but no suite was shared; `status=2` was sent.
    NoCommonSuite,
    /// Session keys were installed.
    Established,
}

/// Successful server-side handshake, including the bytes to write back.
pub enum ServerHandshakeResult {
    /// Success: send `response`, install `session`, forward `piggyback`.
    Established {
        /// The encrypted `openSessionResponse` frame.
        response: Vec<u8>,
        /// Ready-to-install data-plane keys.
        session: Box<EstablishedHandshake>,
        /// Early (0-RTT) client-to-server key for the initial data frames.
        early_c2s_key: Box<AeadKey>,
        /// Early (0-RTT) server-to-client key for the initial reply frames.
        early_s2c_key: Box<AeadKey>,
        /// Application data that followed the request prefix.
        piggyback: Vec<u8>,
        /// Authenticated user name.
        user: String,
    },
    /// The only failure that writes bytes: an encrypted `status=2` response.
    NoCommonSuite {
        /// The encrypted `openSessionResponse` frame.
        response: Vec<u8>,
    },
}

/// Server-side handshake state machine.
#[derive(Debug)]
pub struct ServerHandshake {
    registry: Arc<Registry>,
    decryptor: Arc<AeadUserDecryptor>,
    allowed_suites: Vec<Suite>,
    session_id: u32,
    transport: HandshakeTransport,
    source: Option<SourceKey>,
    state: ServerHandshakeState,
}

impl ServerHandshake {
    /// Prepare a server handshake for one inbound session.
    pub fn new(
        registry: Arc<Registry>,
        decryptor: Arc<AeadUserDecryptor>,
        allowed_suites: Vec<Suite>,
        session_id: u32,
        transport: HandshakeTransport,
        source: Option<SourceKey>,
    ) -> Result<Self, HandshakeError> {
        // An empty server list means "accept every suite in preference order".
        let allowed_suites = if allowed_suites.is_empty() {
            Suite::all_suites().to_vec()
        } else {
            allowed_suites
        };
        validate_suite_list(&allowed_suites)?;
        if session_id == 0 {
            return Err(HandshakeError::Configuration(
                "session id 0 is reserved".to_owned(),
            ));
        }
        Ok(Self {
            registry,
            decryptor,
            allowed_suites,
            session_id,
            transport,
            source,
            state: ServerHandshakeState::Ready,
        })
    }

    /// Current state.
    #[must_use]
    pub const fn state(&self) -> ServerHandshakeState {
        self.state
    }

    /// Authenticate and answer one `openSessionRequest`.
    ///
    /// Every error path is a **silent drop**: the caller must write zero bytes
    /// and close the connection/datagram flow. Only
    /// [`ServerHandshakeResult::NoCommonSuite`] writes a response after a
    /// failed (but authenticated) negotiation.
    pub fn accept(&mut self, frame: &[u8]) -> Result<ServerHandshakeResult, HandshakeError> {
        if self.state != ServerHandshakeState::Ready {
            return Err(HandshakeError::Malformed(
                "server handshake already consumed a request".to_owned(),
            ));
        }
        if frame.len() < WIRE_NONCE_LEN + META_BLOCK_LEN {
            self.state = ServerHandshakeState::Rejected;
            return Err(HandshakeError::Malformed(format!(
                "handshake frame has {} bytes, want at least {}",
                frame.len(),
                WIRE_NONCE_LEN + META_BLOCK_LEN
            )));
        }

        let mut nonce = [0u8; WIRE_NONCE_LEN];
        nonce.copy_from_slice(&frame[..WIRE_NONCE_LEN]);
        let auth = match self.registry.discover(
            &nonce,
            &frame[WIRE_NONCE_LEN..WIRE_NONCE_LEN + META_BLOCK_LEN],
            self.source,
        ) {
            Ok(auth) => auth,
            Err(err) => {
                debug!(kind = HandshakeErrorKind::Authentication.as_str(), %err, "user discovery failed");
                self.state = ServerHandshakeState::Rejected;
                return Err(HandshakeError::Authentication(err.to_string()));
            }
        };
        let static_key = self
            .decryptor
            .static_key(auth.name(), auth.suite())
            .ok_or_else(|| HandshakeError::Authentication("lost envelope key".to_owned()))?;
        let (early_c2s, early_s2c) = derive_early_keys(&static_key, self.session_id, auth.suite())?;
        let envelope = AeadCipher::new(AeadKey::new(auth.suite(), &static_key)?);

        let response_nonce = if self.transport == HandshakeTransport::Datagram {
            random_wire_nonce()
        } else {
            increment_nonce(&increment_nonce(&nonce))
        };
        // The request is always the first message of the static-key chain and
        // therefore carries an explicit nonce. Only the stream-mode response
        // switches to the implicit chain (N+2 for metadata, N+3 for payload).
        let request_options = DecodeOptions {
            include_nonce: true,
            implicit_metadata_nonce: nonce,
            payload_nonce: self.transport.payload_nonce(),
        };
        let segment = decode_segment(&envelope, frame, &request_options)?;
        let metadata = match segment.metadata {
            Metadata::Session(meta) => meta,
            _ => {
                self.state = ServerHandshakeState::Rejected;
                return Err(HandshakeError::Malformed(
                    "handshake request is not a session segment".to_owned(),
                ));
            }
        };
        if metadata.protocol_type != TYPE_OPEN_SESSION_REQUEST
            || metadata.session_id != self.session_id
        {
            self.state = ServerHandshakeState::Rejected;
            return Err(HandshakeError::Malformed(
                "unexpected request type or session id".to_owned(),
            ));
        }
        // Go behaviour: the first version byte is checked before the structured
        // parse so V0.1 peers never receive a single byte back.
        let payload = segment.payload;
        if payload.first() != Some(&DEFAULT_PROTOCOL_VERSION) {
            self.state = ServerHandshakeState::Rejected;
            return Err(HandshakeError::UnsupportedVersion(
                payload.first().copied().unwrap_or(0),
            ));
        }
        let (request, consumed) = HandshakeRequest::parse(&payload)?;
        auth.record(&self.registry);
        // The client pads the piggyback region to full capacity and prepends a
        // two-byte little-endian length prefix. Strip both so downstream code
        // still sees exactly the application data the client attached.
        let region = &payload[consumed..];
        if region.len() < 2 {
            self.state = ServerHandshakeState::Rejected;
            return Err(HandshakeError::Malformed(
                "handshake request is missing the piggyback length prefix".to_owned(),
            ));
        }
        let piggyback_len = usize::from(u16::from_le_bytes([region[0], region[1]]));
        let Some(padded) = region.get(2..2 + piggyback_len) else {
            self.state = ServerHandshakeState::Rejected;
            return Err(HandshakeError::Malformed(
                "piggyback length exceeds the padded region".to_owned(),
            ));
        };
        let piggyback = padded.to_vec();

        let suite = match negotiate_suite(&request.suites, &self.allowed_suites) {
            Some(suite) => suite,
            None => {
                debug!(
                    kind = HandshakeErrorKind::NoCommonSuite.as_str(),
                    user = auth.name(),
                    "no common suite"
                );
                let response = encode_response(
                    &envelope,
                    &HandshakeResponse::no_suite(),
                    self.session_id,
                    self.transport,
                    response_nonce,
                )?;
                self.state = ServerHandshakeState::NoCommonSuite;
                return Ok(ServerHandshakeResult::NoCommonSuite { response });
            }
        };

        let ephemeral = EphemeralKeyPair::generate()?;
        let server_salt = random_salt();
        let shared = ephemeral.compute_shared_secret(&request.eph_pub)?;
        let (c2s, s2c) = derive_session_keys_v4(
            &static_key,
            &request.client_salt,
            &server_salt,
            &shared,
            suite,
        )?;
        let response = HandshakeResponse::success(
            DEFAULT_PROTOCOL_VERSION,
            suite,
            *ephemeral.public_bytes(),
            server_salt,
        );
        let frame = encode_response(
            &envelope,
            &response,
            self.session_id,
            self.transport,
            response_nonce,
        )?;
        let user = auth.name().to_owned();

        // The ephemeral private key is zeroized here, before the result escapes.
        drop(ephemeral);
        self.state = ServerHandshakeState::Established;
        Ok(ServerHandshakeResult::Established {
            response: frame,
            early_c2s_key: Box::new(AeadKey::new(auth.suite(), early_c2s.as_slice())?),
            early_s2c_key: Box::new(AeadKey::new(auth.suite(), early_s2c.as_slice())?),
            session: Box::new(EstablishedHandshake {
                session_id: self.session_id,
                suite,
                c2s_key: AeadKey::new(suite, c2s.as_slice())?,
                s2c_key: AeadKey::new(suite, s2c.as_slice())?,
                early_c2s_key: AeadKey::new(auth.suite(), early_c2s.as_slice())?,
                early_s2c_key: AeadKey::new(auth.suite(), early_s2c.as_slice())?,
                piggyback: Vec::new(),
                user: Some(user.clone()),
            }),
            piggyback,
            user,
        })
    }
}

/// Pick the first suite of `server_order` that the client also offered.
///
/// An empty server list means "all suites in canonical order". The negotiated
/// key length is *not* constrained by the envelope suite.
#[must_use]
pub fn negotiate_suite(client: &[Suite], server_order: &[Suite]) -> Option<Suite> {
    let preferred: Vec<Suite> = if server_order.is_empty() {
        Suite::all_suites().to_vec()
    } else {
        server_order.to_vec()
    };
    preferred.into_iter().find(|suite| client.contains(suite))
}

/// Encrypt a 51-byte response with a random-length suffix with the envelope key.
fn encode_response(
    envelope: &AeadCipher,
    response: &HandshakeResponse,
    session_id: u32,
    transport: HandshakeTransport,
    nonce: WireNonce,
) -> Result<Vec<u8>, HandshakeError> {
    let payload = response.marshal();
    debug_assert_eq!(payload.len(), HANDSHAKE_RESPONSE_LEN);
    // A random-length suffix breaks the fixed-size response frame fingerprint.
    // The client decodes the variable part from the metadata suffix length.
    let suffix: Vec<u8> = if MAX_SUFFIX_PADDING == 0 {
        Vec::new()
    } else {
        let len = rand::random_range(0..=MAX_SUFFIX_PADDING);
        (0..len).map(|_| rand::random::<u8>()).collect()
    };
    let metadata = Metadata::session(
        TYPE_OPEN_SESSION_RESPONSE,
        session_id,
        0,
        payload_len(&payload)?,
        u8::try_from(suffix.len()).expect("suffix padding <= 32"),
    );
    let mut segment = shadowlemon_wire::Segment::new(metadata, nonce, payload.to_vec());
    segment.suffix_padding = suffix;
    let options = EncodeOptions {
        include_nonce: transport == HandshakeTransport::Datagram,
        payload_nonce: transport.payload_nonce(),
    };
    Ok(encode_segment(envelope, &segment, &options)?)
}

fn validate_suite_list(suites: &[Suite]) -> Result<(), HandshakeError> {
    if suites.is_empty() || suites.len() > MAX_HANDSHAKE_SUITES {
        return Err(HandshakeError::Configuration(format!(
            "expected 1..={MAX_HANDSHAKE_SUITES} suites, got {}",
            suites.len()
        )));
    }
    for (index, suite) in suites.iter().enumerate() {
        if !suite.is_valid() {
            return Err(HandshakeError::Configuration(format!(
                "invalid suite byte {}",
                suite.as_u8()
            )));
        }
        if suites[..index].contains(suite) {
            return Err(HandshakeError::Configuration(format!(
                "duplicate suite {}",
                suite.as_u8()
            )));
        }
    }
    Ok(())
}

fn payload_len(payload: &[u8]) -> Result<u16, HandshakeError> {
    u16::try_from(payload.len())
        .map_err(|_| HandshakeError::Malformed("handshake payload exceeds 65535 bytes".to_owned()))
}

fn random_wire_nonce() -> WireNonce {
    let mut nonce = [0u8; WIRE_NONCE_LEN];
    rand::rng().fill_bytes(&mut nonce);
    nonce
}

fn random_salt() -> [u8; 16] {
    let mut salt = [0u8; 16];
    rand::rng().fill_bytes(&mut salt);
    salt
}

#[cfg(test)]
mod tests {
    use super::*;
    use shadowlemon_crypto::AEAD_TAG_LEN;
    use shadowlemon_wire::frame_len;
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, DuplexStream};

    const USER: &str = "alice";
    const PASSWORD: &str = "s3cret";

    fn credential() -> [u8; 32] {
        hash_password(PASSWORD.as_bytes(), USER)
    }

    fn test_registry(_allowed: Vec<Suite>) -> (Arc<Registry>, Arc<AeadUserDecryptor>) {
        // The registry's suite list controls discovery order, not the server's
        // negotiation preference. Discovery must always try every suite.
        let user = User::from_password(USER, PASSWORD, vec![]).unwrap();
        build_registry([user], true)
    }

    fn envelope_suite_cipher(suite: Suite) -> AeadCipher {
        let key = derive_static_key(USER, &credential(), suite).unwrap();
        AeadCipher::new(AeadKey::new(suite, key.as_slice()).unwrap())
    }

    /// Read one complete frame from a stream underlay using the known envelope
    /// cipher to learn the total frame length from decrypted metadata.
    async fn read_frame<R: AsyncRead + Unpin>(
        io: &mut R,
        cipher: &AeadCipher,
        include_nonce: bool,
        implicit_nonce: WireNonce,
    ) -> Vec<u8> {
        let mut frame = Vec::new();
        if include_nonce {
            let mut nonce = [0u8; WIRE_NONCE_LEN];
            io.read_exact(&mut nonce).await.unwrap();
            frame.extend_from_slice(&nonce);
        }
        let mut meta = vec![0u8; META_BLOCK_LEN];
        io.read_exact(&mut meta).await.unwrap();
        frame.extend_from_slice(&meta);
        let nonce: WireNonce = if include_nonce {
            frame[..WIRE_NONCE_LEN].try_into().unwrap()
        } else {
            implicit_nonce
        };
        let meta_at = if include_nonce { WIRE_NONCE_LEN } else { 0 };
        let plain = cipher
            .open(&nonce, &frame[meta_at..meta_at + META_BLOCK_LEN])
            .unwrap();
        let meta = Metadata::parse(&plain).unwrap();
        let total = frame_len(
            usize::from(meta.prefix_len()),
            usize::from(meta.payload_len()),
            usize::from(meta.suffix_len()),
            include_nonce,
        );
        let mut tail = vec![0u8; total - frame.len()];
        io.read_exact(&mut tail).await.unwrap();
        frame.extend_from_slice(&tail);
        frame
    }

    #[test]
    fn suite_negotiation_follows_server_preference() {
        let client = [Suite::Aes128Gcm, Suite::XChaCha20Poly1305, Suite::Aes256Gcm];
        assert_eq!(
            negotiate_suite(&client, &[]),
            Some(Suite::XChaCha20Poly1305)
        );
        assert_eq!(
            negotiate_suite(&client, &[Suite::Aes256Gcm, Suite::Aes128Gcm]),
            Some(Suite::Aes256Gcm)
        );
        assert_eq!(
            negotiate_suite(&[Suite::XChaCha20Poly1305], &[Suite::Aes256Gcm]),
            None
        );
    }

    #[tokio::test]
    async fn handshake_round_trip_every_suite_and_piggyback() {
        for suite in Suite::all_suites() {
            let (registry, decryptor) = test_registry(vec![suite]);
            let mut client = ClientHandshake::with_password(
                USER,
                PASSWORD.as_bytes(),
                vec![suite],
                7,
                HandshakeTransport::Datagram,
            )
            .unwrap();
            let mut server = ServerHandshake::new(
                registry,
                decryptor,
                vec![suite],
                7,
                HandshakeTransport::Datagram,
                None,
            )
            .unwrap();

            let request = client.build_request(b"piggyback").unwrap();
            let result = server.accept(&request).unwrap();
            let (response, established) = match result {
                ServerHandshakeResult::Established {
                    response,
                    session,
                    piggyback,
                    user,
                    ..
                } => {
                    assert_eq!(piggyback, b"piggyback");
                    assert_eq!(user, USER);
                    (response, session)
                }
                _ => panic!("unexpected result"),
            };
            assert_eq!(established.suite, suite);
            match client.process_response(&response).unwrap() {
                ClientOutcome::Established(client_session) => {
                    assert_eq!(client_session.session_id, 7);
                    assert_eq!(client_session.suite, suite);
                    assert_eq!(
                        client_session.c2s_key.key_bytes(),
                        established.c2s_key.key_bytes()
                    );
                    assert_eq!(
                        client_session.s2c_key.key_bytes(),
                        established.s2c_key.key_bytes()
                    );
                }
                ClientOutcome::NoCommonSuite => panic!("unexpected no-suite response"),
            }
        }
    }

    #[test]
    fn datagram_handshake_response_carries_explicit_nonce() {
        let (registry, decryptor) = test_registry(vec![]);
        let mut client = ClientHandshake::with_password(
            USER,
            PASSWORD.as_bytes(),
            vec![Suite::XChaCha20Poly1305],
            42,
            HandshakeTransport::Datagram,
        )
        .unwrap();
        let mut server = ServerHandshake::new(
            registry,
            decryptor,
            vec![],
            42,
            HandshakeTransport::Datagram,
            None,
        )
        .unwrap();

        let request = client.build_request(b"").unwrap();
        // The piggyback region length is drawn from a wide interval, so the
        // first frame's length varies independently of the random suffix.
        let overhead = WIRE_NONCE_LEN + META_BLOCK_LEN + AEAD_TAG_LEN;
        let min = overhead + shadowlemon_wire::MAX_SESSION_PAYLOAD - PIGGYBACK_SLACK;
        let max = overhead + shadowlemon_wire::MAX_SESSION_PAYLOAD + MAX_SUFFIX_PADDING;
        assert!((min..=max).contains(&request.len()));
        let response = match server.accept(&request).unwrap() {
            ServerHandshakeResult::Established { response, .. } => response,
            _ => panic!("unexpected result"),
        };
        // In datagram mode every message carries its own explicit nonce. The
        // response has a random-length suffix, so its length varies.
        let base = WIRE_NONCE_LEN + META_BLOCK_LEN + HANDSHAKE_RESPONSE_LEN + AEAD_TAG_LEN;
        assert!((base..=base + MAX_SUFFIX_PADDING).contains(&response.len()));
        assert!(matches!(
            client.process_response(&response),
            Ok(ClientOutcome::Established(_))
        ));
    }

    #[test]
    fn handshake_timeout_is_classified_after_ten_seconds() {
        let client = ClientHandshake::with_password(
            USER,
            PASSWORD.as_bytes(),
            vec![Suite::XChaCha20Poly1305],
            10,
            HandshakeTransport::Datagram,
        )
        .unwrap();
        // Before the request is emitted there is no deadline to expire.
        assert!(client.deadline().is_none());
        assert!(client
            .check_timeout(Instant::now() + HANDSHAKE_TIMEOUT)
            .is_ok());
        let mut client = client;
        client.build_request(b"").unwrap();
        let deadline = client.deadline().expect("deadline after request");
        assert!(client
            .check_timeout(deadline - Duration::from_millis(1))
            .is_ok());
        let err = client.check_timeout(deadline).unwrap_err();
        assert_eq!(err.kind(), HandshakeErrorKind::Timeout);
    }

    #[tokio::test]
    async fn status_two_on_empty_intersection() {
        let (registry, decryptor) = test_registry(vec![Suite::Aes128Gcm]);
        let mut client = ClientHandshake::with_password(
            USER,
            PASSWORD.as_bytes(),
            vec![Suite::XChaCha20Poly1305],
            9,
            HandshakeTransport::Datagram,
        )
        .unwrap();
        let mut server = ServerHandshake::new(
            registry,
            decryptor,
            vec![Suite::Aes128Gcm],
            9,
            HandshakeTransport::Datagram,
            None,
        )
        .unwrap();
        let request = client.build_request(b"").unwrap();
        let response = match server.accept(&request).unwrap() {
            ServerHandshakeResult::NoCommonSuite { response } => response,
            _ => panic!("unexpected result"),
        };
        assert!(matches!(
            client.process_response(&response),
            Ok(ClientOutcome::NoCommonSuite)
        ));
        assert_eq!(client.state(), ClientHandshakeState::Failed);
    }

    #[test]
    fn malformed_and_legacy_requests_are_silently_dropped() {
        let (registry, decryptor) = test_registry(vec![]);
        let mut client = ClientHandshake::with_password(
            USER,
            PASSWORD.as_bytes(),
            vec![Suite::XChaCha20Poly1305],
            11,
            HandshakeTransport::Datagram,
        )
        .unwrap();
        let request = client.build_request(b"").unwrap();
        let mut corrupt = request.clone();
        corrupt[WIRE_NONCE_LEN + 1] ^= 0xff;
        let mut server = ServerHandshake::new(
            registry,
            decryptor,
            vec![],
            11,
            HandshakeTransport::Datagram,
            None,
        )
        .unwrap();
        let err = server.accept(&corrupt).unwrap_err();
        assert_eq!(err.kind(), HandshakeErrorKind::Authentication);
        assert_eq!(server.state(), ServerHandshakeState::Rejected);

        // A V0.1 version byte with an otherwise valid envelope is rejected
        // without any response bytes.
        let (registry, decryptor) = test_registry(vec![]);
        let cipher = envelope_suite_cipher(Suite::XChaCha20Poly1305);
        let mut legacy_payload = vec![3u8, 3, 1, 0];
        legacy_payload.extend_from_slice(&[0u8; 32]);
        legacy_payload.extend_from_slice(&[0u8; 16]);
        let metadata = Metadata::session(2, 12, 0, legacy_payload.len() as u16, 0);
        let mut legacy_nonce = [1u8; 24];
        write_user_hint(&mut legacy_nonce, USER.as_bytes());
        let segment = shadowlemon_wire::Segment::new(metadata, legacy_nonce, legacy_payload);
        let legacy_request = encode_segment(&cipher, &segment, &EncodeOptions::default()).unwrap();
        let mut server = ServerHandshake::new(
            registry,
            decryptor,
            vec![],
            12,
            HandshakeTransport::Datagram,
            None,
        )
        .unwrap();
        let err = server.accept(&legacy_request).unwrap_err();
        assert_eq!(err.kind(), HandshakeErrorKind::UnsupportedVersion);
        assert_eq!(server.state(), ServerHandshakeState::Rejected);
    }

    #[tokio::test]
    async fn duplex_transport_carries_both_handshake_messages() {
        let (mut client_io, mut server_io): (DuplexStream, DuplexStream) = tokio::io::duplex(4096);
        let (registry, decryptor) = test_registry(vec![]);
        let suite = Suite::Aes256Gcm;
        let mut client = ClientHandshake::with_password(
            USER,
            PASSWORD.as_bytes(),
            vec![suite],
            5,
            HandshakeTransport::Datagram,
        )
        .unwrap();
        let mut server = ServerHandshake::new(
            registry,
            decryptor,
            vec![],
            5,
            HandshakeTransport::Datagram,
            None,
        )
        .unwrap();

        let request = client.build_request(b"hi").unwrap();
        let cipher = envelope_suite_cipher(suite);
        server_io.write_all(&request).await.unwrap();
        server_io.flush().await.unwrap();
        let received = read_frame(&mut client_io, &cipher, true, [0u8; 24]).await;

        let response = match server.accept(&received).unwrap() {
            ServerHandshakeResult::Established { response, .. } => response,
            _ => panic!("unexpected result"),
        };
        client_io.write_all(&response).await.unwrap();
        client_io.flush().await.unwrap();
        let received = read_frame(&mut server_io, &cipher, true, [0u8; 24]).await;
        assert!(matches!(
            client.process_response(&received),
            Ok(ClientOutcome::Established(_))
        ));
    }
}
