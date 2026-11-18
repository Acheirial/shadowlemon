//! Data-plane session core for ShadowLemon V0.2 (spec §4, reference §2).
//!
//! A [`Session`] owns the two directional AEAD keys, the per-datagram UDP
//! nonce, the sliding window, the ACK and retransmission timers, CUBIC, RTT
//! estimation and one replay cache. It does not own a socket: the caller
//! drives it with [`Session::on_frame`], [`Session::tick`],
//! [`Session::poll_output`] and [`Session::send`], which keeps it usable by
//! the datagram underlay.
//!
//! Replay ordering is strict (spec §10): the signature is checked read-only
//! *before* any decryption, and it is recorded only after the metadata, the
//! payload tag and all structural/flow-control checks have passed. A forged
//! segment can never enter the cache.

use std::{
    collections::{BTreeMap, VecDeque},
    io,
    sync::Arc,
    time::{Duration, Instant},
};

use rand::{Rng, RngExt};
use shadowlemon_crypto::{aead::AeadKey, CryptoError, WireNonce};
use shadowlemon_wire::{decode_segment, encode_segment, increment_nonce, Cipher};
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    sync::{mpsc, Notify},
};
use tracing::debug;

use crate::{
    congestion::{retransmission_timeout, Cubic, RttStats, MAX_CWND, MIN_CWND},
    handshake::AeadCipher,
    replay::{ReplayCache, ReplayDecision, ReplayDomain, SourceTag},
    underlay::{MAX_PREFIX_PADDING, MAX_SUFFIX_PADDING},
};

/// Session identifier; zero is reserved and must never be used.
pub type SessionId = u32;

/// Minimum receive/send window, in segments.
pub const MIN_WINDOW_SIZE: u32 = MIN_CWND;
/// Maximum receive/send window, in segments.
pub const MAX_WINDOW_SIZE: u32 = MAX_CWND;
/// Capacity of the out-of-order receive buffer.
pub const SEGMENT_TREE_CAPACITY: usize = 4096;
/// Capacity of the send queue (backpressure starts here).
pub const SEGMENT_SEND_QUEUE_TREE_CAPACITY: usize = 1024;
/// Capacity of the plaintext channel handed to the application.
pub const SEGMENT_CHAN_CAPACITY: usize = 256;
/// Hard limit of undelivered segments before a session is closed.
pub const MAX_UNREAD_SEGMENTS: usize = 512;
/// Delayed ACK window for packet transport.
pub const PACKET_ACK_DELAY: Duration = Duration::from_millis(1);
/// Base heartbeat interval.
pub const SESSION_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);
/// Uniform base jitter, in milliseconds (`[-1000, +1000]`).
pub const SESSION_HEARTBEAT_JITTER_MS: i64 = 1000;
/// Probability denominator of the long-tail heartbeat jitter (one in eight).
pub const SESSION_HEARTBEAT_LONG_TAIL_DIVISOR: i32 = 8;
/// Long-tail jitter range, in milliseconds (`[1, 8000]`).
pub const SESSION_HEARTBEAT_LONG_TAIL_MS: i64 = 8000;
/// ACKs of this many consecutive segments trigger a proactive window update.
pub const ACK_WINDOW_UPDATE_THRESHOLD: u32 = 2048;
/// Duplicate ACKs that trigger early retransmission.
pub const EARLY_RETRANSMISSION: u32 = 3;
/// Early retransmission happens at most once (`tx_count <= 1`).
pub const EARLY_RETRANSMISSION_LIMIT: u32 = 1;
/// A segment is abandoned after this many transmissions.
pub const TX_COUNT_LIMIT: u32 = 20;
/// Largest data fragment for ordinary data segments.
pub const MAX_FRAGMENT: usize = shadowlemon_wire::MAX_FRAGMENT;
/// A low-entropy mode-1 frame can carry at most this many bytes per fragment.
pub const LOW_ENTROPY_MODE1_FRAGMENT: usize = 32764;

const TYPE_CLOSE_SESSION_REQUEST: u8 = 4;
const TYPE_CLOSE_SESSION_RESPONSE: u8 = 5;
const TYPE_DATA_C2S: u8 = 6;
const TYPE_DATA_S2C: u8 = 7;
const TYPE_ACK_C2S: u8 = 8;
const TYPE_ACK_S2C: u8 = 9;

/// Which peer owns the session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Direction {
    /// The client sends with the c2s key and expects s2c data.
    Client,
    /// The server sends with the s2c key and expects c2s data.
    Server,
}

impl Direction {
    /// Protocol type used for data sent by this peer.
    #[must_use]
    pub const fn data_type(self) -> u8 {
        match self {
            Self::Client => TYPE_DATA_C2S,
            Self::Server => TYPE_DATA_S2C,
        }
    }

    /// Protocol type used for ACKs sent by this peer.
    #[must_use]
    pub const fn ack_type(self) -> u8 {
        match self {
            Self::Client => TYPE_ACK_C2S,
            Self::Server => TYPE_ACK_S2C,
        }
    }

    /// Protocol type of data received by this peer.
    #[must_use]
    pub const fn peer_data_type(self) -> u8 {
        match self {
            Self::Client => TYPE_DATA_S2C,
            Self::Server => TYPE_DATA_C2S,
        }
    }

    /// Protocol type of ACKs received by this peer.
    #[must_use]
    pub const fn peer_ack_type(self) -> u8 {
        match self {
            Self::Client => TYPE_ACK_S2C,
            Self::Server => TYPE_ACK_C2S,
        }
    }

    fn replay_domain(self, mode: TransportMode) -> ReplayDomain {
        match (mode, self) {
            (TransportMode::Datagram, Self::Client) => ReplayDomain::UdpServerToClient,
            (TransportMode::Datagram, Self::Server) => ReplayDomain::UdpClientToServer,
        }
    }
}

/// Datagram (UDP) framing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportMode {
    /// Every datagram carries its own nonce.
    Datagram,
}

/// Session lifecycle. Transitions only move forward.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionState {
    /// Normal operation.
    Active,
    /// A close was requested; the close frame may still be in flight.
    Closing,
    /// Terminal state; all further work is suppressed.
    Closed,
}

/// Errors from the data plane.
#[derive(Debug, Error)]
pub enum SessionError {
    /// Wire framing/validation failed.
    #[error("wire error: {0}")]
    Wire(String),
    /// Cryptographic operation failed.
    #[error("crypto error: {0}")]
    Crypto(String),
    /// A replayed segment was rejected before decryption.
    #[error("replay rejected segment")]
    Replay,
    /// A protocol type this session will never send was received.
    #[error("invalid protocol type {0}")]
    InvalidType(u8),
    /// A segment was sent in the wrong direction.
    #[error("wrong direction for protocol type {0}")]
    WrongDirection(u8),
    /// A segment belongs to a different session.
    #[error("session id mismatch: got {got}, want {want}")]
    SessionMismatch {
        /// Received session id.
        got: u32,
        /// Expected session id.
        want: u32,
    },
    /// The application outran the 1024-fragment send queue.
    #[error("send queue is full")]
    Backpressure,
    /// Too many segments were left unread by the application.
    #[error("application left too many segments unread")]
    UnreadLimit,
    /// The session is already closed.
    #[error("session is closed")]
    Closed,
    /// A segment was lost more than twenty times.
    #[error("too many retransmissions")]
    TooManyRetransmissions,
    /// Invalid local configuration.
    #[error("invalid session configuration: {0}")]
    Configuration(String),
    /// Underlying I/O failed.
    #[error("I/O error: {0}")]
    Io(String),
}

impl From<shadowlemon_wire::WireError> for SessionError {
    fn from(err: shadowlemon_wire::WireError) -> Self {
        Self::Wire(err.to_string())
    }
}

impl From<CryptoError> for SessionError {
    fn from(err: CryptoError) -> Self {
        Self::Crypto(err.to_string())
    }
}

impl From<shadowlemon_wire::CipherError> for SessionError {
    fn from(err: shadowlemon_wire::CipherError) -> Self {
        Self::Crypto(err.to_string())
    }
}

impl From<io::Error> for SessionError {
    fn from(err: io::Error) -> Self {
        Self::Io(err.to_string())
    }
}

/// Parameters of a new [`Session`].
pub struct SessionConfig {
    /// Session id carried in all metadata (nonzero).
    pub session_id: SessionId,
    /// Local role.
    pub direction: Direction,
    /// Framing mode; always [`TransportMode::Datagram`] in this UDP-only build.
    pub mode: TransportMode,
    /// Client-to-server data key.
    pub c2s_key: AeadKey,
    /// Server-to-client data key.
    pub s2c_key: AeadKey,
    /// Low-entropy mode, when the (feature-gated) extension is configured.
    pub low_entropy_mode: Option<u8>,
    /// Source tag used by the UDP retransmission exemption.
    pub source_tag: SourceTag,
}

impl SessionConfig {
    /// Build a configuration with no low-entropy mode and no source tag.
    ///
    /// `mode` is retained for call-site stability but this build only supports
    /// [`TransportMode::Datagram`]; every datagram carries its own nonce.
    #[must_use]
    pub const fn new(
        session_id: SessionId,
        direction: Direction,
        mode: TransportMode,
        c2s_key: AeadKey,
        s2c_key: AeadKey,
    ) -> Self {
        Self {
            session_id,
            direction,
            mode,
            c2s_key,
            s2c_key,
            low_entropy_mode: None,
            source_tag: SourceTag::EMPTY,
        }
    }
}

struct Chain {
    cipher: AeadCipher,
    nonce: WireNonce,
    expects_explicit_nonce: bool,
    /// UDP datagrams always carry their own fresh nonce.
    always_explicit: bool,
}

impl Chain {
    fn new(key: AeadKey, always_explicit: bool) -> Self {
        Self {
            cipher: AeadCipher::new(key),
            nonce: random_nonce(),
            expects_explicit_nonce: true,
            always_explicit,
        }
    }

    /// Nonce to use for the next metadata block and whether it is on the wire.
    fn outgoing_nonce(&mut self) -> (WireNonce, bool) {
        let include_nonce = self.always_explicit || self.expects_explicit_nonce;
        if include_nonce {
            self.nonce = random_nonce();
            self.expects_explicit_nonce = false;
        }
        (self.nonce, include_nonce)
    }

    /// Advance past one metadata block and an optional payload block.
    fn advance(&mut self, has_payload: bool) {
        self.nonce = increment_nonce(&self.nonce);
        if has_payload {
            self.nonce = increment_nonce(&self.nonce);
        }
    }
}

#[derive(Clone, Debug)]
struct SentSegment {
    /// Complete wire frame, reused verbatim on retransmission.
    frame: Vec<u8>,
    /// Number of transmissions so far (1 for the first send).
    tx_count: u32,
    /// Consecutive duplicate ACKs seen for this segment.
    ack_count: u32,
    /// Time of the last transmission.
    tx_time: Instant,
    /// Current retransmission timeout.
    tx_timeout: Duration,
}

/// One data-plane session.
pub struct Session {
    id: SessionId,
    direction: Direction,
    mode: TransportMode,
    send_chain: Chain,
    recv_chain: Chain,
    next_send: u32,
    next_recv: u32,
    unack: u32,
    remote_unack: u32,
    remote_window: u16,
    recv_buf: BTreeMap<u32, Vec<u8>>,
    send_buf: BTreeMap<u32, SentSegment>,
    send_queue: VecDeque<(Vec<u8>, u8)>,
    outgoing: VecDeque<Vec<u8>>,
    pending_unread: VecDeque<Vec<u8>>,
    cubic: Arc<Cubic>,
    rtt: Arc<RttStats>,
    replay: ReplayCache,
    plaintext_tx: mpsc::Sender<Vec<u8>>,
    plaintext_rx: Option<mpsc::Receiver<Vec<u8>>>,
    space_notify: Notify,
    ack_deadline: Option<Instant>,
    heartbeat_at: Instant,
    segments_since_window_ack: u32,
    state: SessionState,
    low_entropy_mode: Option<u8>,
    source_tag: SourceTag,
}

impl Session {
    /// Replace the data-plane keys after the handshake completes.
    ///
    /// The session is created with 0-RTT early keys so the client can send
    /// application data in the first flight. Once the X25519 exchange finishes,
    /// both peers call this with the forward-secret session keys. UDP frames
    /// carry explicit nonces, so no nonce state needs to be rewritten here.
    pub fn upgrade_keys(&mut self, c2s_key: AeadKey, s2c_key: AeadKey) {
        let (send_key, recv_key) = match self.direction {
            Direction::Client => (c2s_key, s2c_key),
            Direction::Server => (s2c_key, c2s_key),
        };
        self.send_chain.cipher = AeadCipher::new(send_key);
        self.recv_chain.cipher = AeadCipher::new(recv_key);
    }

    /// Install the data-plane keys returned by a handshake.
    pub fn new(config: SessionConfig) -> Result<Self, SessionError> {
        if config.session_id == 0 {
            return Err(SessionError::Configuration(
                "session id 0 is reserved".to_owned(),
            ));
        }
        if let Some(mode) = config.low_entropy_mode {
            if !(1..=4).contains(&mode) {
                return Err(SessionError::Configuration(format!(
                    "invalid low entropy mode {mode}"
                )));
            }
        }
        let (send_key, recv_key) = match config.direction {
            Direction::Client => (config.c2s_key, config.s2c_key),
            Direction::Server => (config.s2c_key, config.c2s_key),
        };
        let replay_domain = config.direction.replay_domain(config.mode);
        let (plaintext_tx, plaintext_rx) = mpsc::channel(SEGMENT_CHAN_CAPACITY);
        let rtt = Arc::new(RttStats::new());
        Ok(Self {
            id: config.session_id,
            direction: config.direction,
            mode: config.mode,
            send_chain: Chain::new(send_key, config.mode == TransportMode::Datagram),
            recv_chain: Chain::new(recv_key, config.mode == TransportMode::Datagram),
            next_send: 0,
            next_recv: 0,
            unack: 0,
            remote_unack: 0,
            remote_window: MIN_WINDOW_SIZE as u16,
            recv_buf: BTreeMap::new(),
            send_buf: BTreeMap::new(),
            send_queue: VecDeque::new(),
            outgoing: VecDeque::new(),
            pending_unread: VecDeque::new(),
            cubic: Arc::new(Cubic::new(MIN_WINDOW_SIZE, MAX_WINDOW_SIZE)),
            rtt,
            replay: ReplayCache::new(replay_domain),
            plaintext_tx,
            plaintext_rx: Some(plaintext_rx),
            space_notify: Notify::new(),
            ack_deadline: None,
            heartbeat_at: Instant::now() + heartbeat_jitter(),
            segments_since_window_ack: 0,
            state: SessionState::Active,
            low_entropy_mode: config.low_entropy_mode,
            source_tag: config.source_tag,
        })
    }

    /// Session identifier.
    #[must_use]
    pub const fn id(&self) -> SessionId {
        self.id
    }

    /// Local role.
    #[must_use]
    pub const fn direction(&self) -> Direction {
        self.direction
    }

    /// Framing mode.
    #[must_use]
    pub const fn mode(&self) -> TransportMode {
        self.mode
    }

    /// Lifecycle state.
    #[must_use]
    pub const fn state(&self) -> SessionState {
        self.state
    }

    /// Whether the session is terminal.
    #[must_use]
    pub const fn is_closed(&self) -> bool {
        matches!(self.state, SessionState::Closed)
    }

    /// CUBIC state, exposed for diagnostics/tests.
    #[must_use]
    pub fn cubic(&self) -> &Cubic {
        &self.cubic
    }

    /// RTT estimator, exposed for diagnostics/tests.
    #[must_use]
    pub fn rtt_stats(&self) -> &RttStats {
        &self.rtt
    }

    /// The replay cache of this session's traffic domain.
    #[must_use]
    pub const fn replay_cache(&self) -> &ReplayCache {
        &self.replay
    }

    /// Number of segments currently awaiting retransmission.
    #[must_use]
    pub fn in_flight(&self) -> usize {
        self.send_buf.len()
    }

    /// Largest application fragment allowed by this session's mode.
    #[must_use]
    pub fn max_fragment(&self) -> usize {
        match self.low_entropy_mode {
            Some(1) => LOW_ENTROPY_MODE1_FRAGMENT,
            _ => MAX_FRAGMENT,
        }
    }

    /// Take the plaintext receiver; call this once before starting the driver.
    pub fn take_plaintext_rx(&mut self) -> Option<mpsc::Receiver<Vec<u8>>> {
        self.plaintext_rx.take()
    }

    /// Whether the next inbound frame carries an explicit nonce.
    #[must_use]
    pub fn expects_explicit_nonce(&self) -> bool {
        self.recv_chain.always_explicit || self.recv_chain.expects_explicit_nonce
    }

    /// Kill the session, optionally emitting a `closeSessionRequest`.
    pub fn close(&mut self, notify_peer: bool) -> Result<(), SessionError> {
        if self.state == SessionState::Closed {
            return Ok(());
        }
        self.state = SessionState::Closed;
        self.send_queue.clear();
        self.send_buf.clear();
        self.ack_deadline = None;
        if notify_peer {
            self.encode_control(TYPE_CLOSE_SESSION_REQUEST, Vec::new())?;
        }
        Ok(())
    }

    /// Enqueue application bytes for transmission.
    ///
    /// Returns the number of bytes accepted. Data is split into fragments of
    /// at most [`Self::max_fragment`] bytes; fragment numbers count down to
    /// zero for the last fragment. When the queue is full the caller should
    /// wait using [`Self::send`] rather than spin.
    pub fn try_send(&mut self, data: &[u8]) -> Result<usize, SessionError> {
        if self.state == SessionState::Closed {
            return Err(SessionError::Closed);
        }
        let limit = self.max_fragment();
        let chunks = data.chunks(limit.max(1)).collect::<Vec<_>>();
        if chunks.is_empty() {
            return Ok(0);
        }
        if self.send_queue.len() + chunks.len() > SEGMENT_SEND_QUEUE_TREE_CAPACITY {
            return Err(SessionError::Backpressure);
        }
        let count = chunks.len();
        for (index, chunk) in chunks.iter().enumerate() {
            let fragment = u8::try_from(count - 1 - index).unwrap_or(u8::MAX);
            self.send_queue.push_back((chunk.to_vec(), fragment));
        }
        Ok(data.len())
    }

    /// Async variant of [`Self::try_send`] that waits for queue space.
    pub async fn send(&mut self, data: &[u8]) -> Result<(), SessionError> {
        loop {
            match self.try_send(data) {
                Ok(_) => return Ok(()),
                Err(SessionError::Backpressure) => self.space_notify.notified().await,
                Err(err) => return Err(err),
            }
        }
    }

    /// Move queued fragments into frames, respecting both congestion and the
    /// peer's advertised window.
    pub fn pump(&mut self, now: Instant) -> Result<(), SessionError> {
        while self.can_send() && !self.send_queue.is_empty() {
            let (payload, fragment) = self
                .send_queue
                .pop_front()
                .ok_or_else(|| SessionError::Configuration("empty send queue".to_owned()))?;
            let frame = self.encode_data(&payload, fragment)?;
            let seq = self.next_send.wrapping_sub(1);
            let timeout = retransmission_timeout(self.rtt.rto(), 1);
            self.send_buf.insert(
                seq,
                SentSegment {
                    frame: frame.clone(),
                    tx_count: 1,
                    ack_count: 0,
                    tx_time: now,
                    tx_timeout: timeout,
                },
            );
            self.outgoing.push_back(frame);
            self.space_notify.notify_waiters();
        }
        Ok(())
    }

    fn can_send(&self) -> bool {
        if self.state == SessionState::Closed {
            return false;
        }
        let in_flight = self.send_buf.len() as u32;
        let available = self.cubic.cwnd().saturating_sub(in_flight);
        available > 0
            && in_flight < MAX_WINDOW_SIZE
            && u32::from(self.remote_window) > 0
            && self.recv_buf.len() < SEGMENT_TREE_CAPACITY
    }

    /// Earliest time at which [`Self::tick`] has work to do.
    #[must_use]
    pub fn next_timer(&self) -> Option<Instant> {
        if self.is_closed() {
            return None;
        }
        let mut deadlines = vec![self.heartbeat_at];
        if let Some(deadline) = self.ack_deadline {
            deadlines.push(deadline);
        }
        for segment in self.send_buf.values() {
            deadlines.push(segment.tx_time + segment.tx_timeout);
        }
        deadlines.into_iter().min()
    }

    /// Advance all timers at `now`: send queued data, delayed/window-update
    /// ACKs, retransmissions and heartbeats.
    pub fn tick(&mut self, now: Instant) -> Result<(), SessionError> {
        if self.is_closed() {
            return Ok(());
        }
        self.pump(now)?;

        if self.ack_deadline.is_some_and(|deadline| now >= deadline) {
            self.ack_deadline = None;
            self.encode_ack()?;
        }

        let mut loss = false;
        let mut timeout = false;
        for segment in self.send_buf.values_mut() {
            let early = segment.ack_count >= EARLY_RETRANSMISSION
                && segment.tx_count <= EARLY_RETRANSMISSION_LIMIT;
            let timed_out = now.saturating_duration_since(segment.tx_time) >= segment.tx_timeout;
            if early || timed_out {
                if segment.tx_count >= TX_COUNT_LIMIT {
                    self.close(false)?;
                    return Err(SessionError::TooManyRetransmissions);
                }
                segment.tx_count += 1;
                segment.ack_count = 0;
                segment.tx_time = now;
                segment.tx_timeout = retransmission_timeout(self.rtt.rto(), segment.tx_count);
                self.outgoing.push_back(segment.frame.clone());
                if early {
                    loss = true;
                } else {
                    timeout = true;
                }
            }
        }
        // Early retransmission and timeout feed CUBIC mutually exclusively.
        if loss {
            self.cubic.on_loss(now);
        } else if timeout {
            self.cubic.on_timeout();
        }

        if now >= self.heartbeat_at {
            self.encode_ack()?;
            self.heartbeat_at = now + heartbeat_jitter();
        }
        Ok(())
    }

    /// Pop the next frame ready for the transport.
    pub fn poll_output(&mut self) -> Option<Vec<u8>> {
        self.outgoing.pop_front()
    }

    /// Whether at least one frame is waiting for the transport.
    #[must_use]
    pub fn has_output(&self) -> bool {
        !self.outgoing.is_empty()
    }

    /// Non-blocking delivery of the next plaintext chunk to the application.
    pub fn try_recv(&mut self) -> Option<Vec<u8>> {
        self.flush_unread();
        self.plaintext_rx.as_mut()?.try_recv().ok()
    }

    /// Await the next plaintext chunk from the application channel.
    pub async fn recv(&mut self) -> Option<Vec<u8>> {
        self.flush_unread();
        match self.plaintext_rx.as_mut() {
            Some(rx) => rx.recv().await,
            None => None,
        }
    }

    /// Accept one complete inbound frame.
    ///
    /// The replay check is read-only and happens before any decryption; the
    /// signature is recorded only after all validation succeeds.
    pub fn on_frame(&mut self, frame: &[u8], now: Instant) -> Result<(), SessionError> {
        if self.is_closed() {
            return Err(SessionError::Closed);
        }
        let (nonce, include_nonce) = if self.expects_explicit_nonce() {
            if frame.len() < shadowlemon_wire::META_BLOCK_LEN + WIRE_LEN {
                return Err(SessionError::Wire(
                    "frame is shorter than its fixed part".to_owned(),
                ));
            }
            let mut nonce = [0u8; WIRE_LEN];
            nonce.copy_from_slice(&frame[..WIRE_LEN]);
            (nonce, true)
        } else {
            (self.recv_chain.nonce, false)
        };

        // Step 2 of spec §10: read-only replay check, before decryption.
        // Every UDP datagram carries its own nonce, so every frame is checked.
        let sig = self.replay.signature(&nonce);
        if include_nonce {
            match self.replay.check(sig, self.source_tag) {
                ReplayDecision::Fresh | ReplayDecision::Retransmission => {}
                ReplayDecision::Replay => return Err(SessionError::Replay),
            }
        }

        let payload_nonce = shadowlemon_wire::PayloadNonce::UdpFlip;
        let options = shadowlemon_wire::DecodeOptions {
            include_nonce,
            implicit_metadata_nonce: nonce,
            payload_nonce,
        };
        let segment = decode_segment(&self.recv_chain.cipher, frame, &options)?;
        let meta = segment.metadata;
        let has_payload = !segment.payload.is_empty();
        if meta.session_id() != self.id {
            return Err(SessionError::SessionMismatch {
                got: meta.session_id(),
                want: self.id,
            });
        }

        match meta.protocol_type() {
            TYPE_CLOSE_SESSION_REQUEST => {
                self.encode_control(TYPE_CLOSE_SESSION_RESPONSE, Vec::new())?;
                self.state = SessionState::Closed;
            }
            TYPE_CLOSE_SESSION_RESPONSE => {
                self.state = SessionState::Closed;
            }
            kind if kind == self.direction.peer_data_type() => {
                self.process_data(&meta, segment.payload, now)?;
            }
            kind if kind == self.direction.peer_ack_type() => {
                self.process_remote_window(meta.unack(), meta.window());
                self.process_ack(meta.unack(), now);
            }
            other => return Err(SessionError::WrongDirection(other)),
        }

        // Step 8 of spec §10: record only fully authenticated, validated data.
        if include_nonce {
            self.replay.record(sig, self.source_tag);
        }
        self.recv_chain.nonce = nonce;
        self.recv_chain.advance(has_payload);
        self.recv_chain.expects_explicit_nonce = self.recv_chain.always_explicit;
        Ok(())
    }

    /// Read one complete frame from a byte-oriented reader and process it.
    ///
    /// The fixed prefix is read first so the replay check can run before the
    /// metadata is decrypted. The length of the variable part comes from the
    /// authenticated metadata.
    pub async fn read_frame<R: AsyncRead + Unpin>(
        &mut self,
        reader: &mut R,
    ) -> Result<Vec<u8>, SessionError> {
        let (nonce, include_nonce) = if self.expects_explicit_nonce() {
            let mut nonce = [0u8; WIRE_LEN];
            reader.read_exact(&mut nonce).await?;
            (nonce, true)
        } else {
            (self.recv_chain.nonce, false)
        };
        // Read-only replay check before decrypting metadata; every datagram
        // carries its own nonce (see `on_frame`).
        let sig = self.replay.signature(&nonce);
        if include_nonce && self.replay.check(sig, self.source_tag).is_replay() {
            return Err(SessionError::Replay);
        }
        let mut frame = Vec::new();
        if include_nonce {
            frame.extend_from_slice(&nonce);
        }
        let mut fixed = vec![0u8; shadowlemon_wire::META_BLOCK_LEN];
        reader.read_exact(&mut fixed).await?;
        frame.extend_from_slice(&fixed);
        // Decrypt metadata with the recv-chain key to learn the frame length.
        // The replay check above already ran on this nonce.
        let plain = self.recv_chain.cipher.open(&nonce, &fixed[..])?;
        let metadata = shadowlemon_wire::Metadata::parse(&plain)?;
        let total = shadowlemon_wire::frame_len(
            usize::from(metadata.prefix_len()),
            usize::from(metadata.payload_len()),
            usize::from(metadata.suffix_len()),
            include_nonce,
        );
        if total < frame.len() {
            return Err(SessionError::Wire("frame length underflow".to_owned()));
        }
        let mut tail = vec![0u8; total - frame.len()];
        reader.read_exact(&mut tail).await?;
        frame.extend_from_slice(&tail);
        let now = Instant::now();
        self.on_frame(&frame, now)?;
        Ok(frame)
    }

    fn process_data(
        &mut self,
        meta: &shadowlemon_wire::Metadata,
        payload: Vec<u8>,
        now: Instant,
    ) -> Result<(), SessionError> {
        self.process_remote_window(meta.unack(), meta.window());
        self.request_ack(now);
        if payload.is_empty() {
            // ACK-like data segment with no body: only window information.
            return Ok(());
        }
        let seq = meta.sequence();
        let left = self.next_recv;
        if seq_lt(seq, left) || seq_ge(seq, left.wrapping_add(MAX_WINDOW_SIZE)) {
            // Outside the window: ignore, relying on the peer's retransmission.
            return Ok(());
        }
        if self.recv_buf.len() >= SEGMENT_TREE_CAPACITY {
            return Err(SessionError::Backpressure);
        }
        if seq == left {
            self.push_unread(payload)?;
            self.next_recv = self.next_recv.wrapping_add(1);
            self.unack = self.next_recv;
            while let Some(next) = self.recv_buf.remove(&self.next_recv) {
                self.push_unread(next)?;
                self.next_recv = self.next_recv.wrapping_add(1);
                self.unack = self.next_recv;
            }
            self.flush_unread();
        } else {
            self.recv_buf.insert(seq, payload);
        }
        Ok(())
    }

    fn process_remote_window(&mut self, unack: u32, window: u16) {
        if seq_ge(unack, self.remote_unack) {
            self.remote_unack = unack;
            self.remote_window = window;
        }
    }

    fn process_ack(&mut self, unack: u32, now: Instant) {
        let mut freed = Vec::new();
        let mut duplicated = Vec::new();
        for (&seq, segment) in &self.send_buf {
            if seq_lt(seq, unack) {
                freed.push((seq, segment.tx_count, segment.tx_time));
            } else if seq == unack {
                duplicated.push(seq);
            }
        }
        let freed_count = freed.len();
        for (seq, tx_count, tx_time) in freed {
            if self.send_buf.remove(&seq).is_some() {
                // Karn: only a segment sent exactly once yields an RTT sample.
                if tx_count == 1 {
                    self.rtt.update_rtt(now.saturating_duration_since(tx_time));
                }
            }
        }
        for seq in duplicated {
            if let Some(segment) = self.send_buf.get_mut(&seq) {
                segment.ack_count = segment.ack_count.saturating_add(1);
            }
        }
        if freed_count > 0 {
            let rtt = self.rtt.smoothed_rtt();
            self.cubic.on_ack(freed_count as u32, rtt, now);
        }
    }

    fn request_ack(&mut self, now: Instant) {
        if self.ack_deadline.is_none() {
            self.ack_deadline = Some(now + PACKET_ACK_DELAY);
        }
        if self.segments_since_window_ack >= ACK_WINDOW_UPDATE_THRESHOLD {
            self.segments_since_window_ack = 0;
            if let Err(err) = self.encode_ack() {
                debug!(%err, "failed to emit window update ACK");
            }
        }
    }

    fn push_unread(&mut self, data: Vec<u8>) -> Result<(), SessionError> {
        if self.pending_unread.len() >= MAX_UNREAD_SEGMENTS {
            self.close(false)?;
            return Err(SessionError::UnreadLimit);
        }
        self.pending_unread.push_back(data);
        self.segments_since_window_ack += 1;
        Ok(())
    }

    fn flush_unread(&mut self) {
        while let Some(data) = self.pending_unread.front() {
            match self.plaintext_tx.try_send(data.clone()) {
                Ok(()) => {
                    self.pending_unread.pop_front();
                }
                Err(_) => break,
            }
        }
    }

    fn receive_window(&self) -> u16 {
        MAX_WINDOW_SIZE
            .saturating_sub(self.recv_buf.len() as u32)
            .min(u16::MAX as u32) as u16
    }

    /// Random-length, random-byte unencrypted padding. A constant padding
    /// length would itself be a fingerprint, so the length is redrawn for every
    /// frame — including empty ACKs and close frames.
    fn random_padding(max: usize) -> Vec<u8> {
        if max == 0 {
            return Vec::new();
        }
        let len = rand::random_range(0..=max);
        (0..len).map(|_| rand::random::<u8>()).collect()
    }

    fn encode_data(&mut self, payload: &[u8], fragment: u8) -> Result<Vec<u8>, SessionError> {
        let seq = self.next_send;
        self.next_send = self.next_send.wrapping_add(1);
        let prefix = Self::random_padding(MAX_PREFIX_PADDING);
        let suffix = Self::random_padding(MAX_SUFFIX_PADDING);
        let metadata = shadowlemon_wire::Metadata::data(
            self.direction.data_type(),
            self.id,
            seq,
            self.next_recv,
            self.receive_window(),
            fragment,
            u8::try_from(prefix.len()).expect("prefix padding <= 32"),
            u16::try_from(payload.len()).map_err(|_| {
                SessionError::Configuration("data fragment exceeds 65535 bytes".to_owned())
            })?,
            u8::try_from(suffix.len()).expect("suffix padding <= 32"),
        );
        self.encode_segment(metadata, payload, prefix, suffix)
    }

    fn encode_ack(&mut self) -> Result<(), SessionError> {
        let seq = self.next_send.wrapping_sub(1);
        let prefix = Self::random_padding(MAX_PREFIX_PADDING);
        let suffix = Self::random_padding(MAX_SUFFIX_PADDING);
        let metadata = shadowlemon_wire::Metadata::data(
            self.direction.ack_type(),
            self.id,
            seq,
            self.next_recv,
            self.receive_window(),
            0,
            u8::try_from(prefix.len()).expect("prefix padding <= 32"),
            0,
            u8::try_from(suffix.len()).expect("suffix padding <= 32"),
        );
        let frame = self.encode_segment(metadata, &[], prefix, suffix)?;
        self.outgoing.push_back(frame);
        Ok(())
    }

    fn encode_control(&mut self, protocol_type: u8, payload: Vec<u8>) -> Result<(), SessionError> {
        let seq = self.next_send.wrapping_sub(1);
        let suffix = Self::random_padding(MAX_SUFFIX_PADDING);
        let metadata = shadowlemon_wire::Metadata::session(
            protocol_type,
            self.id,
            seq,
            u16::try_from(payload.len()).map_err(|_| {
                SessionError::Configuration("control payload exceeds 65535 bytes".to_owned())
            })?,
            u8::try_from(suffix.len()).expect("suffix padding <= 32"),
        );
        let frame = self.encode_segment(metadata, &payload, Vec::new(), suffix)?;
        self.outgoing.push_back(frame);
        Ok(())
    }

    fn encode_segment(
        &mut self,
        metadata: shadowlemon_wire::Metadata,
        payload: &[u8],
        prefix_padding: Vec<u8>,
        suffix_padding: Vec<u8>,
    ) -> Result<Vec<u8>, SessionError> {
        let (nonce, include_nonce) = self.send_chain.outgoing_nonce();
        let payload_nonce = shadowlemon_wire::PayloadNonce::UdpFlip;
        let mut segment = shadowlemon_wire::Segment::new(metadata, nonce, payload.to_vec());
        segment.prefix_padding = prefix_padding;
        segment.suffix_padding = suffix_padding;
        let options = shadowlemon_wire::EncodeOptions {
            include_nonce,
            payload_nonce,
        };
        let frame = encode_segment(&self.send_chain.cipher, &segment, &options)?;
        self.send_chain.advance(!payload.is_empty());
        Ok(frame)
    }
}

/// A wire nonce is always 24 bytes.
const WIRE_LEN: usize = shadowlemon_wire::WIRE_NONCE_LEN;

/// Serial-number comparison: `a < b` in wrapping 32-bit space.
#[must_use]
pub fn seq_lt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

/// Serial-number comparison: `a >= b` in wrapping 32-bit space.
#[must_use]
pub fn seq_ge(a: u32, b: u32) -> bool {
    !seq_lt(a, b)
}

/// Heartbeat jitter of reference §2.5: uniform `[-1000, 1000]` ms plus, with
/// probability 1/8, a long tail of `[1, 8000]` ms.
#[must_use]
pub fn heartbeat_jitter() -> Duration {
    heartbeat_jitter_with(&mut rand::rng())
}

/// Deterministic jitter helper used by tests and simulators.
#[must_use]
pub fn heartbeat_jitter_with<R: Rng + ?Sized>(rng: &mut R) -> Duration {
    let mut millis: i64 =
        rng.random_range(-SESSION_HEARTBEAT_JITTER_MS..=SESSION_HEARTBEAT_JITTER_MS);
    if rng.random_range(0..SESSION_HEARTBEAT_LONG_TAIL_DIVISOR) == 0 {
        millis += rng.random_range(1..=SESSION_HEARTBEAT_LONG_TAIL_MS);
    }
    if millis < 0 {
        SESSION_HEARTBEAT_INTERVAL.saturating_sub(Duration::from_millis(millis.unsigned_abs()))
    } else {
        SESSION_HEARTBEAT_INTERVAL.saturating_add(Duration::from_millis(millis as u64))
    }
}

fn random_nonce() -> WireNonce {
    let mut nonce = [0u8; WIRE_LEN];
    rand::rng().fill_bytes(&mut nonce);
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;
    use shadowlemon_crypto::suite::Suite;

    fn key(byte: u8) -> AeadKey {
        AeadKey::new(Suite::XChaCha20Poly1305, &[byte; 32]).unwrap()
    }

    fn pair(mode: TransportMode) -> (Session, Session) {
        let client = Session::new(SessionConfig::new(
            77,
            Direction::Client,
            mode,
            key(1),
            key(2),
        ))
        .unwrap();
        let server = Session::new(SessionConfig::new(
            77,
            Direction::Server,
            mode,
            key(1),
            key(2),
        ))
        .unwrap();
        (client, server)
    }

    fn pump_until_outgoing(session: &mut Session, now: Instant) -> Vec<u8> {
        session.tick(now).unwrap();
        session.poll_output().expect("expected an outbound frame")
    }

    #[test]
    fn serial_number_helpers_wrap() {
        assert!(seq_lt(u32::MAX, 0));
        assert!(seq_ge(0, u32::MAX));
        assert!(seq_lt(1, 2));
        assert!(!seq_lt(2, 1));
    }

    #[test]
    fn heartbeat_jitter_stays_within_bounds() {
        for _ in 0..1000 {
            let jitter = heartbeat_jitter();
            assert!(jitter >= Duration::from_millis(3000), "{jitter:?}");
            assert!(jitter <= Duration::from_secs(14), "{jitter:?}");
        }
    }

    #[test]
    fn data_exchanges_in_both_directions() {
        let (mut client, mut server) = pair(TransportMode::Datagram);
        let now = Instant::now();

        assert_eq!(client.try_send(b"hello").unwrap(), 5);
        let frame = pump_until_outgoing(&mut client, now);
        server.on_frame(&frame, now).unwrap();
        assert_eq!(server.try_recv(), Some(b"hello".to_vec()));

        // The delayed ACK fires once the 1ms ACK deadline expires.
        server.tick(now + PACKET_ACK_DELAY).unwrap();
        let ack = server.poll_output().expect("delayed ACK");
        client.on_frame(&ack, now + PACKET_ACK_DELAY).unwrap();

        assert_eq!(server.try_send(b"world").unwrap(), 5);
        let frame = pump_until_outgoing(&mut server, now);
        client.on_frame(&frame, now).unwrap();
        assert_eq!(client.try_recv(), Some(b"world".to_vec()));
    }

    #[test]
    fn padding_lengths_are_random_and_bounded() {
        let mut lengths = std::collections::HashSet::new();
        for _ in 0..256 {
            let padding = Session::random_padding(MAX_PREFIX_PADDING);
            assert!(padding.len() <= MAX_PREFIX_PADDING);
            lengths.insert(padding.len());
        }
        assert!(
            lengths.len() > 1,
            "padding length must not be constant (fingerprint)"
        );
        assert!(Session::random_padding(0).is_empty());
    }

    #[test]
    fn out_of_order_fragments_are_delivered_in_sequence() {
        // Datagrams carry their own nonce and may be delivered out of order.
        let (mut client, mut server) = pair(TransportMode::Datagram);
        let now = Instant::now();
        client.try_send(b"first").unwrap();
        client.try_send(b"second").unwrap();
        client.tick(now).unwrap();
        let first = client.poll_output().unwrap();
        let second = client.poll_output().unwrap();
        server.on_frame(&second, now).unwrap();
        assert_eq!(server.try_recv(), None);
        server.on_frame(&first, now).unwrap();
        assert_eq!(server.try_recv(), Some(b"first".to_vec()));
        assert_eq!(server.try_recv(), Some(b"second".to_vec()));
    }

    #[test]
    fn duplicate_datagram_is_rejected_by_replay_cache() {
        let (mut client, mut server) = pair(TransportMode::Datagram);
        let now = Instant::now();
        client.try_send(b"once").unwrap();
        let frame = pump_until_outgoing(&mut client, now);
        server.on_frame(&frame, now).unwrap();
        assert_eq!(server.try_recv(), Some(b"once".to_vec()));
        assert_eq!(server.replay_cache().sizes().0, 1);
        let err = server.on_frame(&frame, now).unwrap_err();
        assert!(matches!(err, SessionError::Replay));
        // The rejected duplicate never entered the cache.
        assert_eq!(server.replay_cache().sizes().0, 1);
    }

    #[test]
    fn retransmission_fires_after_timeout() {
        let (mut client, mut server) = pair(TransportMode::Datagram);
        let now = Instant::now();
        client.try_send(b"loss").unwrap();
        let first = pump_until_outgoing(&mut client, now);
        assert_eq!(client.in_flight(), 1);
        let timeout = retransmission_timeout(client.rtt_stats().rto(), 1);
        client
            .tick(now + timeout + Duration::from_millis(1))
            .unwrap();
        let retry = client.poll_output().expect("retransmitted frame");
        assert_eq!(retry, first);
        assert_eq!(client.send_buf.values().next().unwrap().tx_count, 2);
        server.on_frame(&retry, now).unwrap();
        assert_eq!(server.try_recv(), Some(b"loss".to_vec()));
    }

    #[test]
    fn heartbeat_fires_on_timer_without_sleeping() {
        let (mut client, _) = pair(TransportMode::Datagram);
        let deadline = client.next_timer().expect("heartbeat timer");
        client.tick(deadline).unwrap();
        assert!(client.has_output());
        let next = client.next_timer().expect("next heartbeat");
        assert!(next > deadline);
    }

    #[test]
    fn close_request_answers_with_close_response() {
        let (mut client, mut server) = pair(TransportMode::Datagram);
        let now = Instant::now();
        client.close(true).unwrap();
        let frame = client.poll_output().unwrap();
        server.on_frame(&frame, now).unwrap();
        let response = server.poll_output().expect("close response");
        assert!(server.is_closed());
        match shadowlemon_wire::decode_segment(
            &AeadCipher::new(key(2)),
            &response,
            &shadowlemon_wire::DecodeOptions {
                include_nonce: true,
                implicit_metadata_nonce: [0; WIRE_LEN],
                payload_nonce: shadowlemon_wire::PayloadNonce::UdpFlip,
            },
        )
        .unwrap()
        .metadata
        {
            shadowlemon_wire::Metadata::Session(meta) => {
                assert_eq!(meta.protocol_type, TYPE_CLOSE_SESSION_RESPONSE)
            }
            _ => panic!("close response must be session metadata"),
        }
    }

    #[test]
    fn fragmented_data_respects_low_entropy_mode_one_limit() {
        let mut config = SessionConfig::new(
            1,
            Direction::Client,
            TransportMode::Datagram,
            key(1),
            key(2),
        );
        config.low_entropy_mode = Some(1);
        let session = Session::new(config).unwrap();
        assert_eq!(session.max_fragment(), LOW_ENTROPY_MODE1_FRAGMENT);
    }
}
