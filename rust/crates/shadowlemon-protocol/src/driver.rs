//! Real V0.2 handshake/session adapters for the mux traits.
//!
//! This module is the integration point the hand-written mux in [`crate::mux`]
//! was designed for: it replaces the `PassthroughClientHandshake` /
//! `NoopServerHandshake` test adapters with implementations that actually run
//! the V0.2 handshake and encrypt every application byte.
//!
//! # UDP-only external transport
//!
//! The external transport is UDP-only. SOCKS5 `CONNECT` is still offered to
//! local clients, but the byte stream it needs is provided by the tunnel's
//! reliable datagram session (see [`crate::stream::DatagramStream`]); there is
//! no TCP transport handshake in this module.
//!
//! `mux::ClientHandshake::open_tcp` receives a resolved `target` plus an
//! optional original hostname. The driver encodes that pair as a SOCKS5
//! `CONNECT` request (`encode_request(CMD_CONNECT, address, port)`) and places
//! the resulting bytes in the `openSessionRequest` **piggyback** area, which
//! the handshake carries inside its authenticated envelope. The server parses
//! it with `read_request`, resolves a domain name with `lookup_host`, dials the
//! TCP target and relays the resulting byte stream through the datagram
//! session. Bytes that followed the SOCKS5 request in the piggyback are
//! written to the target before the relay starts.
//!
//! # 0-RTT early keys
//!
//! Both peers derive an early c2s/s2c key pair from the authenticated static
//! key, the session id and the envelope suite before any X25519 exchange
//! completes. The request piggyback (the SOCKS5 request plus any immediately
//! available application bytes that fit the handshake's capacity) is therefore
//! protected by the static-key envelope and can be acted on by the server in
//! the same flight that carries the handshake response. Early data has **no
//! forward secrecy**: only the post-handshake data keys do. The driver starts
//! each data-plane [`Session`](crate::session::Session) with the early keys and
//! swaps in the forward-secret keys once `openSessionResponse` has been
//! processed (client) or sent (server). Application bytes that arrive after the
//! first flight are held until the swap completes, so every data-plane frame
//! is encrypted with exactly one unambiguous key epoch.
//!
//! # UDP conventions
//!
//! UDP needs two extra, **driver-level** envelopes because the mux router only
//! sees opaque datagrams. These bytes are outside the frozen V0.2 wire format;
//! everything after the envelope header is a genuine V0.2 frame.
//!
//! 1. Routing envelope: `[kind: u8][session_id: u32be][wire frame ..]`, where
//!    `kind` is 1 = handshake request, 2 = handshake response, 3 = session
//!    data, 4 = session reply. The mux passes the whole datagram to
//!    `ServerHandshake::accept_udp` and sends its returned bytes back
//!    unchanged; the client undoes the envelope on receive. The session ID is
//!    therefore available for lookup **before** any AEAD key is known.
//! 2. Target convention: the handshake piggyback carries a SOCKS5 `CONNECT`
//!    (stream) or `UDP ASSOCIATE` (datagram) request for the destination. Every
//!    application datagram additionally carries a standard SOCKS5 UDP header
//!    (`0x00 0x00 0x00 ATYP DST.ADDR DST.PORT`) followed by the real payload,
//!    per `protocol-v0.2.md` §9. The server parses it with
//!    `parse_udp_datagram` and uses the address/port found there for that
//!    datagram, so a single association can talk to several peers.
//! 3. Application fragmentation: SOCKS5 datagrams are split to the MTU-derived
//!    capacity and each piece is prefixed with
//!    `[message_id: u32be][fragment_number: u8][fragment_count: u8]` before
//!    being handed to the V0.2 `Session`. Fragment numbers count down to zero,
//!    matching the wire metadata. Reassembly happens on both peers.

use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    io,
    net::{IpAddr, SocketAddr},
    sync::{
        atomic::{AtomicBool, AtomicU32, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use dashmap::DashMap;
use futures::future::BoxFuture;
use shadowlemon_crypto::suite::Suite;
use shadowlemon_socks5::{
    encode_request, encode_udp_header, parse_udp_datagram, read_request, Address, AsyncIo,
    Credential, DatagramSocket, EgressAction, EgressConfig, ATYP_DOMAIN, ATYP_IPV4, ATYP_IPV6,
    CMD_CONNECT, CMD_UDP_ASSOCIATE, MAX_UDP_DATAGRAM, VERSION,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    sync::{mpsc, oneshot, Mutex, Notify},
    time,
};
use tracing::{debug, warn};

use crate::{
    handshake::{
        build_registry, AeadUserDecryptor, ClientHandshake, ClientOutcome, HandshakeTransport,
        ServerHandshake, ServerHandshakeResult,
    },
    mux::{self, Endpoint, TransportKind},
    serveruser::{Registry, SourceKey, User},
    session::{Direction, Session, SessionConfig, TransportMode},
    stream::DatagramStream,
    underlay::{IpFamily, MtuBudget, MAX_PREFIX_PADDING, MAX_SUFFIX_PADDING},
    underlay_packet::PacketConfig,
};

/// Routing envelope: handshake request (client → mux server).
const UDP_KIND_HANDSHAKE_REQUEST: u8 = 1;
/// Routing envelope: handshake response (mux server → client).
const UDP_KIND_HANDSHAKE_RESPONSE: u8 = 2;
/// Routing envelope: encrypted session data.
const UDP_KIND_SESSION_DATA: u8 = 3;
/// Routing envelope: encrypted session reply/ACK.
const UDP_KIND_SESSION_REPLY: u8 = 4;
/// `[obfuscated kind][session id]` prefix length of the UDP routing envelope.
/// The kind byte is masked with a deterministic mix of the random session ID
/// so the prefix has no fixed, signature-matchable bytes.
const UDP_ENVELOPE_LEN: usize = 5;
/// `[message id][fragment number][fragment count]` application prefix.
const APP_FRAGMENT_HEADER_LEN: usize = 6;
/// How long a UDP relay waits for the first reply to a datagram.
const DEFAULT_UDP_REPLY_WAIT: Duration = Duration::from_millis(100);
/// Idle lifetime of a server-side UDP session.
const DEFAULT_UDP_SESSION_TTL: Duration = Duration::from_secs(180);
/// SOCKS5 method: no authentication.
const METHOD_NO_AUTH: u8 = 0;
/// SOCKS5 method: RFC 1929 username/password.
const METHOD_USERPASS: u8 = 2;
/// RFC 1929 sub-negotiation version.
const USERPASS_VERSION: u8 = 1;
/// RFC 1929 authentication success code.
const AUTH_SUCCESS: u8 = 0;

/// Partial application fragments, keyed by message id, with the highest
/// fragment number seen so far (numbers count down to zero).
type FragmentMap = HashMap<u32, (BTreeMap<u8, Vec<u8>>, u8)>;
/// Read half of a CONNECT-over-UDP target, owned by the reply relay task.
type TcpReadHalf = Box<dyn AsyncRead + Unpin + Send>;
/// Write half of a CONNECT-over-UDP target, owned by the session.
type TcpWriteHalf = Box<dyn AsyncWrite + Unpin + Send>;

fn io_err<E: std::fmt::Display>(err: E) -> io::Error {
    io::Error::other(err.to_string())
}

fn invalid_data(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.to_owned())
}

/// Source of the 32-byte user credential on the client side.
///
/// `Password` is hashed exactly like [`User::from_password`] does; `Credential`
/// is used when the active profile was created from a hex `hashedPassword`.
#[derive(Clone, Debug)]
pub enum ClientCredential {
    /// Raw password from `profile.user.password`.
    Password(String),
    /// Already hashed 32-byte credential from `profile.user.hashedPassword`.
    Credential([u8; 32]),
}

/// Configuration of [`RealClientHandshake`].
#[derive(Clone, Debug)]
pub struct RealClientConfig {
    /// User name from the active profile.
    pub username: String,
    /// Password or pre-hashed credential of that user.
    pub credential: ClientCredential,
    /// Wire cipher suites in client preference order (never empty).
    pub suites: Vec<Suite>,
    /// MTU and traffic pattern applied to UDP datagrams.
    pub packet: PacketConfig,
    /// Timeout for the handshake response.
    pub handshake_timeout: Duration,
}

impl RealClientConfig {
    /// Validate the suite list and MTU before any socket is opened.
    pub fn validate(&self) -> io::Result<()> {
        if self.username.is_empty() {
            return Err(invalid_data("client user name is empty"));
        }
        if self.suites.is_empty() || self.suites.len() > 4 {
            return Err(invalid_data(
                "client cipher suite list must have 1..=4 entries",
            ));
        }
        let mut seen = Vec::new();
        for suite in &self.suites {
            if !suite.is_valid() {
                return Err(invalid_data("invalid cipher suite in client profile"));
            }
            if seen.contains(suite) {
                return Err(invalid_data("duplicate cipher suite in client profile"));
            }
            seen.push(*suite);
        }
        crate::underlay::validate_l3_mtu(self.packet.mtu).map_err(io_err)?;
        self.packet
            .nonce_pattern_config
            .validate(&self.packet.nonce_pattern)
            .map_err(io_err)?;
        if self.handshake_timeout.is_zero() {
            return Err(invalid_data("handshake timeout must be positive"));
        }
        Ok(())
    }
}

/// Configuration of [`RealServerHandshake`].
#[derive(Clone, Debug)]
pub struct RealServerConfig {
    /// Registered users, hashed consistently with the client credential.
    pub users: Vec<User>,
    /// Whether a keyed user hint is required on the first packet.
    pub hint_mandatory: bool,
    /// Server suite preference; empty means accept all three suites.
    pub allowed_suites: Vec<Suite>,
    /// Egress policy applied when relaying to the target.
    pub egress: EgressConfig,
    /// MTU and traffic pattern applied to UDP datagrams.
    pub packet: PacketConfig,
    /// Time a UDP relay waits for a reply before returning to the mux.
    pub udp_reply_wait: Duration,
    /// Idle lifetime of UDP session state.
    pub udp_session_ttl: Duration,
}

impl Default for RealServerConfig {
    fn default() -> Self {
        Self {
            users: Vec::new(),
            hint_mandatory: true,
            allowed_suites: Vec::new(),
            egress: EgressConfig::new(),
            packet: PacketConfig::default(),
            udp_reply_wait: DEFAULT_UDP_REPLY_WAIT,
            udp_session_ttl: DEFAULT_UDP_SESSION_TTL,
        }
    }
}

impl RealServerConfig {
    /// Validate the MTU and nonce pattern configuration.
    pub fn validate(&self) -> io::Result<()> {
        crate::underlay::validate_l3_mtu(self.packet.mtu).map_err(io_err)?;
        self.packet
            .nonce_pattern_config
            .validate(&self.packet.nonce_pattern)
            .map_err(io_err)?;
        Ok(())
    }
}

/// The real client-side [`mux::ClientHandshake`] adapter.
pub struct RealClientHandshake {
    config: RealClientConfig,
    udp_sessions: DashMap<u32, Arc<UdpSessionHandle>>,
}

impl std::fmt::Debug for RealClientHandshake {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RealClientHandshake")
            .field("user", &self.config.username)
            .field("suites", &self.config.suites)
            .field("udp_sessions", &self.udp_sessions.len())
            .finish()
    }
}

impl RealClientHandshake {
    /// Build an adapter from a validated configuration.
    pub fn new(config: RealClientConfig) -> io::Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            udp_sessions: DashMap::new(),
        })
    }

    fn build_client_handshake(
        &self,
        session_id: u32,
        transport: HandshakeTransport,
    ) -> io::Result<ClientHandshake> {
        let result = match self.config.credential.clone() {
            ClientCredential::Password(password) => ClientHandshake::with_password(
                self.config.username.clone(),
                password.as_bytes(),
                self.config.suites.clone(),
                session_id,
                transport,
            ),
            ClientCredential::Credential(bytes) => ClientHandshake::new(
                self.config.username.clone(),
                bytes,
                self.config.suites.clone(),
                session_id,
                transport,
            ),
        };
        result.map_err(io_err)
    }

    async fn finish_udp_close(handle: Arc<UdpSessionHandle>) {
        handle.shutdown.notify_waiters();
        let mut frames = {
            let mut session = handle.session.lock().await;
            let _ = session.close(true);
            drain_output(&mut session)
        };
        for frame in frames.drain(..) {
            let packet = wrap_udp(UDP_KIND_SESSION_DATA, handle.session_id, &frame);
            let _ = handle.socket.send_to(&packet, handle.server).await;
        }
    }
}

impl mux::ClientHandshake for RealClientHandshake {
    fn open_tcp<'a>(
        &'a self,
        session_id: u32,
        endpoint: &'a Endpoint,
        target: SocketAddr,
        host: Option<&'a str>,
        _reuse: bool,
    ) -> BoxFuture<'a, io::Result<Box<dyn AsyncIo>>> {
        Box::pin(async move {
            let server = endpoint
                .address_for(TransportKind::Udp)
                .await
                .map_err(io_err)?;
            let bind: SocketAddr = if server.is_ipv4() {
                "0.0.0.0:0".parse().expect("literal address")
            } else {
                "[::]:0".parse().expect("literal address")
            };
            let socket = Arc::new(UdpSocket::bind(bind).await?);
            let address = match host {
                Some(name) if !name.is_empty() => Address::Domain(name.to_owned()),
                _ => Address::Ip(target.ip()),
            };
            // The SOCKS5 CONNECT request is the 0-RTT early data: it travels in
            // the authenticated handshake piggyback and the server forwards it
            // in the same flight that carries the response. `build_request`
            // enforces the piggyback capacity; there is no other application
            // data available at this layer yet.
            let piggyback = encode_request(CMD_CONNECT, &address, target.port());

            let mut handshake =
                self.build_client_handshake(session_id, HandshakeTransport::Datagram)?;
            let (early_c2s, early_s2c) = handshake.early_keys().map_err(io_err)?;
            let request = handshake.build_request(&piggyback).map_err(io_err)?;
            socket
                .send_to(
                    &wrap_udp(UDP_KIND_HANDSHAKE_REQUEST, session_id, &request),
                    server,
                )
                .await?;

            // The data plane starts on the early keys so the first flight is
            // protected without waiting for a round trip. A background task
            // swaps in the forward-secret keys once the response is processed.
            let session = Arc::new(Mutex::new(
                Session::new(SessionConfig::new(
                    session_id,
                    Direction::Client,
                    TransportMode::Datagram,
                    early_c2s,
                    early_s2c,
                ))
                .map_err(io_err)?,
            ));
            let max_fragment = MtuBudget::new(
                self.config.packet.mtu,
                IpFamily::from_addr(server.ip()),
                true,
            )
            .map_err(io_err)?
            .payload_capacity(MAX_PREFIX_PADDING, MAX_SUFFIX_PADDING)
            .saturating_sub(APP_FRAGMENT_HEADER_LEN);
            let handle = Arc::new(UdpSessionHandle {
                session_id,
                socket: Arc::clone(&socket),
                session: Arc::clone(&session),
                server,
                shutdown: Arc::new(Notify::new()),
            });
            self.udp_sessions.insert(session_id, Arc::clone(&handle));

            // A single reader demultiplexes the handshake response and the
            // session's encrypted replies, which share the same UDP socket.
            let inbound = Arc::new(UdpInbound::new(Arc::clone(&handle.shutdown)));
            let (response_tx, response_rx) = oneshot::channel();
            spawn_udp_reader(
                Arc::clone(&socket),
                server,
                session_id,
                response_tx,
                Arc::clone(&inbound),
                Arc::clone(&handle.shutdown),
            );
            let key_state = Arc::new(KeyUpgradeState::new());
            spawn_client_ticker(
                Arc::clone(&session),
                Arc::clone(&socket),
                server,
                session_id,
                Arc::clone(&handle.shutdown),
            );
            spawn_stream_key_upgrade(
                handshake,
                response_rx,
                Arc::clone(&session),
                Arc::clone(&key_state),
                handle,
                self.config.handshake_timeout,
            );

            // Return the byte stream immediately; data-plane I/O is gated on
            // the key swap so each frame uses exactly one unambiguous epoch.
            let tunnel: Box<dyn AsyncIo> = Box::new(DatagramStream::new(
                Box::new(TunnelDatagramSocket {
                    socket,
                    server,
                    session_id,
                    session,
                    target,
                    host: host.filter(|name| !name.is_empty()).map(str::to_owned),
                    max_fragment,
                    message_id: AtomicU32::new(1),
                    recv_lock: Mutex::new(()),
                    pending: Mutex::new(VecDeque::new()),
                    assembler: Mutex::new(HashMap::new()),
                    inbound: Some(inbound),
                    key_state: Some(key_state),
                }),
                target,
            ));
            debug!(session_id, "UDP stream session opened to StreamUnderlay{{");
            Ok(tunnel)
        })
    }

    fn open_udp<'a>(
        &'a self,
        session_id: u32,
        endpoint: &'a Endpoint,
        target: SocketAddr,
        host: Option<&'a str>,
        _reuse: bool,
    ) -> BoxFuture<'a, io::Result<Box<dyn DatagramSocket>>> {
        Box::pin(async move {
            let server = endpoint
                .address_for(TransportKind::Udp)
                .await
                .map_err(io_err)?;
            let bind: SocketAddr = if server.is_ipv4() {
                "0.0.0.0:0".parse().expect("literal address")
            } else {
                "[::]:0".parse().expect("literal address")
            };
            let socket = Arc::new(UdpSocket::bind(bind).await?);
            let address = match host {
                Some(name) if !name.is_empty() => Address::Domain(name.to_owned()),
                _ => Address::Ip(target.ip()),
            };
            let piggyback = encode_request(CMD_UDP_ASSOCIATE, &address, target.port());

            let mut handshake =
                self.build_client_handshake(session_id, HandshakeTransport::Datagram)?;
            let request = handshake.build_request(&piggyback).map_err(io_err)?;
            socket
                .send_to(
                    &wrap_udp(UDP_KIND_HANDSHAKE_REQUEST, session_id, &request),
                    server,
                )
                .await?;

            let mut buf = vec![0u8; MAX_UDP_DATAGRAM];
            let response = time::timeout(self.config.handshake_timeout, async {
                loop {
                    let (len, from) = socket.recv_from(&mut buf).await?;
                    if from != server {
                        continue;
                    }
                    let Some((kind, id, frame)) = unwrap_udp(&buf[..len]) else {
                        continue;
                    };
                    if kind == UDP_KIND_HANDSHAKE_RESPONSE && id == session_id {
                        return Ok::<Vec<u8>, io::Error>(frame.to_vec());
                    }
                }
            })
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "UDP handshake timed out"))??;

            let established = match handshake.process_response(&response).map_err(io_err)? {
                ClientOutcome::Established(established) => *established,
                ClientOutcome::NoCommonSuite => {
                    warn!("no common cipher suite with the server");
                    return Err(invalid_data("server rejected every offered cipher suite"));
                }
            };
            let session = Arc::new(Mutex::new(
                Session::new(SessionConfig::new(
                    session_id,
                    Direction::Client,
                    TransportMode::Datagram,
                    established.c2s_key,
                    established.s2c_key,
                ))
                .map_err(io_err)?,
            ));
            let max_fragment = MtuBudget::new(
                self.config.packet.mtu,
                IpFamily::from_addr(server.ip()),
                true,
            )
            .map_err(io_err)?
            .payload_capacity(MAX_PREFIX_PADDING, MAX_SUFFIX_PADDING)
            .saturating_sub(APP_FRAGMENT_HEADER_LEN);
            let handle = Arc::new(UdpSessionHandle {
                session_id,
                socket: Arc::clone(&socket),
                session: Arc::clone(&session),
                server,
                shutdown: Arc::new(Notify::new()),
            });
            spawn_client_ticker(
                Arc::clone(&session),
                Arc::clone(&socket),
                server,
                session_id,
                Arc::clone(&handle.shutdown),
            );
            self.udp_sessions.insert(session_id, handle);
            debug!(session_id, suite = %established.suite, "UDP session established to PacketUnderlay{{");
            let tunnel: Box<dyn DatagramSocket> = Box::new(TunnelDatagramSocket {
                socket,
                server,
                session_id,
                session,
                target,
                host: host.filter(|name| !name.is_empty()).map(str::to_owned),
                max_fragment,
                message_id: AtomicU32::new(1),
                recv_lock: Mutex::new(()),
                pending: Mutex::new(VecDeque::new()),
                assembler: Mutex::new(HashMap::new()),
                inbound: None,
                key_state: None,
            });
            Ok(tunnel)
        })
    }

    fn close_session(&self, session_id: u32) {
        if let Some((_, handle)) = self.udp_sessions.remove(&session_id) {
            tokio::spawn(Self::finish_udp_close(handle));
        }
    }
}

/// Server-side [`mux::ServerHandshake`] adapter.
pub struct RealServerHandshake {
    config: RealServerConfig,
    registry: Arc<Registry>,
    decryptor: Arc<AeadUserDecryptor>,
    udp_sessions: DashMap<(SocketAddr, u32), Arc<ServerUdpSession>>,
}

impl std::fmt::Debug for RealServerHandshake {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RealServerHandshake")
            .field("users", &self.registry.user_count())
            .field("hint_mandatory", &self.registry.hint_mandatory())
            .field("suites", &self.config.allowed_suites)
            .field("udp_sessions", &self.udp_sessions.len())
            .finish()
    }
}

impl RealServerHandshake {
    /// Build an adapter. The registry and decryptor share one keystore so the
    /// response can be sealed with the same envelope key that authenticated
    /// the request.
    pub fn new(config: RealServerConfig) -> io::Result<Self> {
        config.validate()?;
        if config.users.is_empty() {
            return Err(invalid_data("server needs at least one registered user"));
        }
        let (registry, decryptor) = build_registry(config.users.clone(), config.hint_mandatory);
        Ok(Self {
            config,
            registry,
            decryptor,
            udp_sessions: DashMap::new(),
        })
    }

    /// Build an adapter from an externally managed registry (useful for
    /// reloadable user tables).
    pub fn with_registry(
        config: RealServerConfig,
        registry: Arc<Registry>,
        decryptor: Arc<AeadUserDecryptor>,
    ) -> io::Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            registry,
            decryptor,
            udp_sessions: DashMap::new(),
        })
    }

    fn new_server_handshake(
        &self,
        session_id: u32,
        transport: HandshakeTransport,
        source: Option<SourceKey>,
    ) -> io::Result<ServerHandshake> {
        ServerHandshake::new(
            Arc::clone(&self.registry),
            Arc::clone(&self.decryptor),
            self.config.allowed_suites.clone(),
            session_id,
            transport,
            source,
        )
        .map_err(io_err)
    }

    async fn dial_target(
        &self,
        address: &Address,
        port: u16,
        raw_request: &[u8],
    ) -> io::Result<Box<dyn AsyncIo>> {
        let (ip, host) = resolve_address(address).await?;
        let decision = self.config.egress.find_action(Some(ip), host.as_deref());
        if decision.action == EgressAction::Reject {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "egress rejected",
            ));
        }
        if decision.action == EgressAction::Proxy {
            let proxy = decision
                .proxy
                .ok_or_else(|| invalid_data("egress proxy is missing"))?;
            let proxy_ip = resolve_host(&proxy.host).await?;
            let mut stream = TcpStream::connect(SocketAddr::new(proxy_ip, proxy.port)).await?;
            socks5_client_handshake(&mut stream, proxy.credential.as_ref()).await?;
            stream.write_all(raw_request).await?;
            stream.flush().await?;
            let mut reply = [0u8; 4];
            stream.read_exact(&mut reply).await?;
            read_socks5_address_tail(&mut stream, reply[3]).await?;
            return Ok(Box::new(stream));
        }
        Ok(Box::new(
            TcpStream::connect(SocketAddr::new(ip, port)).await?,
        ))
    }

    fn udp_peer(&self, source: SocketAddr, session_id: u32) -> io::Result<Arc<ServerUdpSession>> {
        self.udp_sessions
            .get(&(source, session_id))
            .map(|entry| Arc::clone(entry.value()))
            .ok_or_else(|| invalid_data("unknown UDP session"))
    }

    fn expire_udp_sessions(&self) {
        let ttl = self.config.udp_session_ttl;
        self.udp_sessions
            .retain(|_, state| state.created.elapsed() < ttl && !state.is_closed());
    }
}

impl mux::ServerHandshake for RealServerHandshake {
    fn accept_udp<'a>(
        &'a self,
        datagram: Vec<u8>,
        source: SocketAddr,
        reply_socket: Arc<UdpSocket>,
    ) -> BoxFuture<'a, io::Result<Vec<Vec<u8>>>> {
        Box::pin(async move {
            let Some((kind, session_id, frame)) = unwrap_udp(&datagram) else {
                return Err(invalid_data("malformed UDP routing envelope"));
            };
            self.expire_udp_sessions();
            match kind {
                UDP_KIND_HANDSHAKE_REQUEST => {
                    let source_key = source_key(source);
                    let mut handshake = self.new_server_handshake(
                        session_id,
                        HandshakeTransport::Datagram,
                        Some(source_key),
                    )?;
                    let result = handshake.accept(frame).map_err(io_err)?;
                    match result {
                        ServerHandshakeResult::NoCommonSuite { response } => Ok(vec![wrap_udp(
                            UDP_KIND_HANDSHAKE_RESPONSE,
                            session_id,
                            &response,
                        )]),
                        ServerHandshakeResult::Established {
                            response,
                            session,
                            early_c2s_key,
                            early_s2c_key,
                            piggyback,
                            ..
                        } => {
                            let suite = session.suite;
                            // Both peers derive the same early keys from the
                            // authenticated static key, session id and suite.
                            let (c2s, s2c) = (session.c2s_key, session.s2c_key);

                            let mut bytes = &piggyback[..];
                            let mut target = None;
                            let mut tcp = None;
                            if !piggyback.is_empty() {
                                let (request, raw) =
                                    read_request(&mut bytes).await.map_err(io_err)?;
                                let (ip, host) = resolve_address(&request.address).await?;
                                let addr = SocketAddr::new(ip, request.port);
                                match request.command {
                                    CMD_UDP_ASSOCIATE => {
                                        target = Some((addr, host));
                                    }
                                    CMD_CONNECT => {
                                        // CONNECT-over-UDP: the handshake
                                        // piggyback carries a SOCKS5 CONNECT and
                                        // its early data. Dial the TCP target and
                                        // relay its byte stream through the
                                        // datagram session. Splitting the stream
                                        // keeps the reply reader from blocking
                                        // writes to the target.
                                        let outbound = self
                                            .dial_target(
                                                &request.address,
                                                request.port,
                                                &piggyback[..raw.len()],
                                            )
                                            .await?;
                                        let (read_half, mut write_half) =
                                            tokio::io::split(outbound);
                                        let initial = &piggyback[raw.len()..];
                                        if !initial.is_empty() {
                                            write_half.write_all(initial).await?;
                                            write_half.flush().await?;
                                        }
                                        tcp = Some((
                                            Box::new(write_half) as TcpWriteHalf,
                                            Box::new(read_half) as TcpReadHalf,
                                            addr,
                                        ));
                                        target = Some((addr, host));
                                    }
                                    _ => {
                                        return Err(invalid_data(
                                            "piggyback must be a SOCKS5 CONNECT or UDP ASSOCIATE request",
                                        ));
                                    }
                                }
                            }
                            let state = Arc::new(ServerUdpSession::new(
                                session_id,
                                *early_c2s_key,
                                *early_s2c_key,
                                target,
                                tcp,
                                MtuBudget::new(
                                    self.config.packet.mtu,
                                    IpFamily::from_addr(source.ip()),
                                    true,
                                )
                                .map_err(io_err)?
                                .payload_capacity(MAX_PREFIX_PADDING, MAX_SUFFIX_PADDING)
                                .saturating_sub(APP_FRAGMENT_HEADER_LEN),
                                ReplyContext {
                                    client: source,
                                    socket: Arc::clone(&reply_socket),
                                },
                            ));
                            self.udp_sessions
                                .insert((source, session_id), Arc::clone(&state));
                            // The mux sends the returned response immediately;
                            // move the data plane to the forward-secret keys as
                            // part of completing this handshake.
                            {
                                let mut guard = state.session.lock().await;
                                guard.upgrade_keys(c2s, s2c);
                            }
                            // Start the background reply flusher so large
                            // responses flow without waiting for more client
                            // datagrams.
                            state.spawn_reply_flusher();
                            debug!(session_id, %source, suite = %suite, "server UDP session established");
                            Ok(vec![wrap_udp(
                                UDP_KIND_HANDSHAKE_RESPONSE,
                                session_id,
                                &response,
                            )])
                        }
                    }
                }
                UDP_KIND_SESSION_DATA => {
                    let state = self.udp_peer(source, session_id)?;
                    let plaintext_chunks = {
                        let mut session = state.session.lock().await;
                        session.on_frame(frame, Instant::now()).map_err(io_err)?;
                        let chunks: Vec<Vec<u8>> =
                            std::iter::from_fn(|| session.try_recv()).collect();
                        for ack in drain_output(&mut session) {
                            state
                                .push_frame(wrap_udp(UDP_KIND_SESSION_REPLY, session_id, &ack))
                                .await;
                        }
                        chunks
                    };
                    // Processing the inbound frame may have advanced the send
                    // window via ACKs; wake the flusher to emit more reply data.
                    state.flusher_wake.notify_one();
                    for chunk in plaintext_chunks {
                        let Some((id, number, count, piece)) = split_app_fragment(&chunk) else {
                            return Err(invalid_data("malformed application fragment"));
                        };
                        let Some(datagram) = state.assemble(id, number, count, piece).await else {
                            continue;
                        };
                        let parsed = parse_udp_datagram(&datagram).map_err(io_err)?;
                        let (ip, _) = resolve_address(&parsed.address).await?;
                        let target = SocketAddr::new(ip, parsed.port);
                        state.send_payload(target, &parsed.payload).await?;
                    }
                    // Reply payloads are encoded and sent by the background
                    // reply flusher; only the ACKs generated while processing
                    // this datagram are returned to the mux here.
                    Ok(state.drain_frames().await)
                }
                _ => Err(invalid_data("unexpected UDP routing envelope kind")),
            }
        })
    }
}

/// Shared handle to a client UDP session, kept so `close_session` can terminate
/// it when the mux reports a closed session.
struct UdpSessionHandle {
    session_id: u32,
    socket: Arc<UdpSocket>,
    session: Arc<Mutex<Session>>,
    server: SocketAddr,
    /// Wakes the handshake-response demultiplexer when the session closes.
    shutdown: Arc<Notify>,
}

/// Gate that holds 0-RTT data-plane I/O until the key swap completes.
///
/// Data frames are never sent with early keys after the response has been
/// processed (or received with final keys before it): ambiguous key epochs
/// would make decryption fail nondeterministically. The CONNECT request itself
/// is still sent in the first flight as handshake piggyback.
struct KeyUpgradeState {
    ready: AtomicBool,
    failed: AtomicBool,
    notify: Notify,
}

impl KeyUpgradeState {
    fn new() -> Self {
        Self {
            ready: AtomicBool::new(false),
            failed: AtomicBool::new(false),
            notify: Notify::new(),
        }
    }

    fn succeed(&self) {
        self.ready.store(true, Ordering::Release);
        self.notify.notify_waiters();
    }

    fn fail(&self) {
        self.failed.store(true, Ordering::Release);
        self.notify.notify_waiters();
    }

    async fn wait(&self) -> io::Result<()> {
        loop {
            if self.ready.load(Ordering::Acquire) {
                return Ok(());
            }
            if self.failed.load(Ordering::Acquire) {
                return Err(invalid_data("UDP stream handshake did not complete"));
            }
            self.notify.notified().await;
        }
    }
}

/// Session-reply frames waiting to be decrypted by the tunnel socket.
struct UdpInbound {
    frames: Mutex<VecDeque<Vec<u8>>>,
    ready: Notify,
    shutdown: Arc<Notify>,
}

impl UdpInbound {
    fn new(shutdown: Arc<Notify>) -> Self {
        Self {
            frames: Mutex::new(VecDeque::new()),
            ready: Notify::new(),
            shutdown,
        }
    }

    async fn push(&self, frame: Vec<u8>) {
        self.frames.lock().await.push_back(frame);
        self.ready.notify_one();
    }

    async fn pop(&self) -> Option<Vec<u8>> {
        loop {
            if let Some(frame) = self.frames.lock().await.pop_front() {
                return Some(frame);
            }
            tokio::select! {
                _ = self.ready.notified() => {}
                _ = self.shutdown.notified() => return None,
            }
        }
    }
}

/// Demultiplex one socket's inbound datagrams between the handshake response
/// and the session's encrypted replies. Without this, the key-upgrade task and
/// the data-plane reader would race to consume the same UDP datagrams.
fn spawn_udp_reader(
    socket: Arc<UdpSocket>,
    server: SocketAddr,
    session_id: u32,
    response_tx: oneshot::Sender<Vec<u8>>,
    inbound: Arc<UdpInbound>,
    shutdown: Arc<Notify>,
) {
    tokio::spawn(async move {
        let mut response_tx = Some(response_tx);
        let mut buf = vec![0u8; MAX_UDP_DATAGRAM];
        loop {
            let (len, from) = tokio::select! {
                received = socket.recv_from(&mut buf) => match received {
                    Ok(result) => result,
                    Err(_) => break,
                },
                _ = shutdown.notified() => break,
            };
            if from != server {
                continue;
            }
            let Some((kind, id, frame)) = unwrap_udp(&buf[..len]) else {
                continue;
            };
            if id != session_id {
                continue;
            }
            match kind {
                UDP_KIND_HANDSHAKE_RESPONSE => {
                    if let Some(tx) = response_tx.take() {
                        let _ = tx.send(frame.to_vec());
                    }
                }
                UDP_KIND_SESSION_REPLY => inbound.push(frame.to_vec()).await,
                _ => {}
            }
        }
    });
}

/// Periodically drive a client session's timers so delayed ACKs and
/// retransmissions are emitted. Frames are sent directly on the client's UDP
/// socket. The loop exits when the session closes or the socket is gone.
fn spawn_client_ticker(
    session: Arc<Mutex<Session>>,
    socket: Arc<UdpSocket>,
    server: SocketAddr,
    session_id: u32,
    shutdown: Arc<Notify>,
) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_millis(2));
        loop {
            tokio::select! {
                _ = shutdown.notified() => break,
                _ = ticker.tick() => {
                    let frames = {
                        let mut guard = session.lock().await;
                        if guard.is_closed() {
                            break;
                        }
                        let _ = guard.tick(Instant::now());
                        drain_output(&mut guard)
                    };
                    for frame in frames {
                        let wire = wrap_udp(UDP_KIND_SESSION_DATA, session_id, &frame);
                        if let Err(err) = socket.send_to(&wire, server).await {
                            debug!(%err, "client ticker send failed");
                            break;
                        }
                    }
                }
            }
        }
    });
}

/// Await the handshake response, install the forward-secret keys into the very
/// same `Session` the stream is already using, and unblock data-plane I/O.
fn spawn_stream_key_upgrade(
    mut handshake: ClientHandshake,
    response_rx: oneshot::Receiver<Vec<u8>>,
    session: Arc<Mutex<Session>>,
    key_state: Arc<KeyUpgradeState>,
    handle: Arc<UdpSessionHandle>,
    timeout: Duration,
) {
    let session_id = handle.session_id;
    tokio::spawn(async move {
        let response = match time::timeout(timeout, response_rx).await {
            Ok(Ok(frame)) => frame,
            _ => {
                warn!(session_id, "UDP stream handshake response timed out");
                key_state.fail();
                RealClientHandshake::finish_udp_close(handle).await;
                return;
            }
        };
        match handshake.process_response(&response) {
            Ok(ClientOutcome::Established(established)) => {
                {
                    let mut guard = session.lock().await;
                    // Cross-file API: Session::upgrade_keys(c2s, s2c).
                    guard.upgrade_keys(established.c2s_key, established.s2c_key);
                }
                debug!(session_id, suite = %established.suite, "UDP stream handshake completed");
                key_state.succeed();
            }
            Ok(ClientOutcome::NoCommonSuite) => {
                warn!("no common cipher suite with the server");
                key_state.fail();
                RealClientHandshake::finish_udp_close(handle).await;
            }
            Err(err) => {
                warn!(session_id, %err, "UDP stream handshake failed");
                key_state.fail();
                RealClientHandshake::finish_udp_close(handle).await;
            }
        }
    });
}

/// Drain frames queued by a session without ticking its timers.
fn drain_output(session: &mut Session) -> Vec<Vec<u8>> {
    std::iter::from_fn(|| session.poll_output()).collect()
}

/// Mix a random session ID into a single byte. This is the MurmurHash3 finalizer
/// resized to 8 bits; it is an obfuscation against fixed-byte DPI signatures,
/// not encryption — a protocol-aware observer can still invert it. Real
/// confidentiality of the routing metadata requires a negotiated secret key.
fn envelope_mask(session_id: u32) -> u8 {
    let mut x = session_id;
    x ^= x >> 16;
    x = x.wrapping_mul(0x7feb_352d);
    x ^= x >> 15;
    x = x.wrapping_mul(0x846c_a68b);
    x ^= x >> 16;
    (x & 0xff) as u8
}

fn wrap_udp(kind: u8, session_id: u32, frame: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(UDP_ENVELOPE_LEN + frame.len());
    out.push(kind ^ envelope_mask(session_id));
    out.extend_from_slice(&session_id.to_be_bytes());
    out.extend_from_slice(frame);
    out
}

fn unwrap_udp(datagram: &[u8]) -> Option<(u8, u32, &[u8])> {
    if datagram.len() < UDP_ENVELOPE_LEN {
        return None;
    }
    let id = u32::from_be_bytes(datagram[1..5].try_into().ok()?);
    let kind = datagram[0] ^ envelope_mask(id);
    // Reject packets whose masked kind is not one of the four legal values;
    // this also drops unrelated UDP noise before it reaches the handshake.
    if !(UDP_KIND_HANDSHAKE_REQUEST..=UDP_KIND_SESSION_REPLY).contains(&kind) {
        return None;
    }
    Some((kind, id, &datagram[UDP_ENVELOPE_LEN..]))
}

fn split_app_fragment(chunk: &[u8]) -> Option<(u32, u8, u8, Vec<u8>)> {
    if chunk.len() < APP_FRAGMENT_HEADER_LEN {
        return None;
    }
    let id = u32::from_be_bytes(chunk[..4].try_into().ok()?);
    Some((
        id,
        chunk[4],
        chunk[5],
        chunk[APP_FRAGMENT_HEADER_LEN..].to_vec(),
    ))
}

/// Reassemble descending-numbered application fragments.
fn assemble_fragment(
    map: &mut FragmentMap,
    id: u32,
    number: u8,
    count: u8,
    piece: Vec<u8>,
) -> Option<Vec<u8>> {
    if count == 0 || number >= count {
        return None;
    }
    let entry = map.entry(id).or_insert((BTreeMap::new(), 0));
    entry.1 = entry.1.max(count);
    let total = entry.1;
    entry.0.insert(number, piece);
    if entry.0.len() != usize::from(total) || (0..total).any(|n| !entry.0.contains_key(&n)) {
        return None;
    }
    let parts = map.remove(&id)?.0;
    let mut out = Vec::new();
    for number in (0..total).rev() {
        out.extend_from_slice(&parts[&number]);
    }
    Some(out)
}

/// Split a datagram into MTU-sized encrypted application fragments.
fn fragment_payload(data: &[u8], max_fragment: usize, id: u32) -> io::Result<Vec<Vec<u8>>> {
    if max_fragment == 0 {
        return Err(invalid_data("UDP MTU leaves no room for application data"));
    }
    let pieces: Vec<&[u8]> = data.chunks(max_fragment).collect();
    if pieces.len() > u8::MAX as usize + 1 {
        return Err(invalid_data("UDP datagram needs too many fragments"));
    }
    let count = pieces.len() as u8;
    Ok(pieces
        .into_iter()
        .enumerate()
        .map(|(index, piece)| {
            let number = count - 1 - index as u8;
            let mut out = Vec::with_capacity(APP_FRAGMENT_HEADER_LEN + piece.len());
            out.extend_from_slice(&id.to_be_bytes());
            out.push(number);
            out.push(count);
            out.extend_from_slice(piece);
            out
        })
        .collect())
}

/// Socket returned by `RealClientHandshake::open_udp` and `open_tcp`.
struct TunnelDatagramSocket {
    socket: Arc<UdpSocket>,
    server: SocketAddr,
    session_id: u32,
    session: Arc<Mutex<Session>>,
    target: SocketAddr,
    host: Option<String>,
    max_fragment: usize,
    message_id: AtomicU32,
    recv_lock: Mutex<()>,
    pending: Mutex<VecDeque<(Vec<u8>, SocketAddr)>>,
    assembler: Mutex<FragmentMap>,
    /// Set on the 0-RTT stream path: a shared reader has already consumed the
    /// handshake response, so session replies arrive through this queue.
    inbound: Option<Arc<UdpInbound>>,
    /// Set on the 0-RTT stream path: data-plane I/O waits for the key swap.
    key_state: Option<Arc<KeyUpgradeState>>,
}

impl TunnelDatagramSocket {
    /// Decrypt one session-reply frame, send any ACKs it produced, and return
    /// the reassembled application chunks.
    async fn process_reply(&self, frame: &[u8]) -> io::Result<Vec<Vec<u8>>> {
        let chunks = {
            let mut session = self.session.lock().await;
            session.on_frame(frame, Instant::now()).map_err(io_err)?;
            let chunks: Vec<Vec<u8>> = std::iter::from_fn(|| session.try_recv()).collect();
            for ack in drain_output(&mut session) {
                self.socket
                    .send_to(
                        &wrap_udp(UDP_KIND_SESSION_DATA, self.session_id, &ack),
                        self.server,
                    )
                    .await?;
            }
            chunks
        };
        Ok(chunks)
    }
}

impl DatagramSocket for TunnelDatagramSocket {
    fn send_to<'a>(
        &'a self,
        data: &'a [u8],
        target: SocketAddr,
    ) -> BoxFuture<'a, io::Result<usize>> {
        Box::pin(async move {
            if let Some(key_state) = &self.key_state {
                key_state.wait().await?;
            }
            let address = match &self.host {
                Some(host) if target == self.target => Address::Domain(host.clone()),
                _ => Address::Ip(target.ip()),
            };
            let mut datagram = encode_udp_header(&address, target.port());
            datagram.extend_from_slice(data);
            let id = self.message_id.fetch_add(1, Ordering::Relaxed);
            let fragments = fragment_payload(&datagram, self.max_fragment, id)?;
            let mut session = self.session.lock().await;
            for fragment in fragments {
                session.send(&fragment).await.map_err(io_err)?;
            }
            session.tick(Instant::now()).map_err(io_err)?;
            for frame in drain_output(&mut session) {
                self.socket
                    .send_to(
                        &wrap_udp(UDP_KIND_SESSION_DATA, self.session_id, &frame),
                        self.server,
                    )
                    .await?;
            }
            Ok(data.len())
        })
    }

    fn recv_from<'a>(
        &'a self,
        buf: &'a mut [u8],
    ) -> BoxFuture<'a, io::Result<(usize, SocketAddr)>> {
        Box::pin(async move {
            let _guard = self.recv_lock.lock().await;
            loop {
                let pending_item = {
                    let mut pending = self.pending.lock().await;
                    pending.pop_front()
                };
                if let Some((payload, source)) = pending_item {
                    let len = buf.len().min(payload.len());
                    buf[..len].copy_from_slice(&payload[..len]);
                    // A reassembled datagram may be larger than the caller's
                    // buffer. Keep the remainder queued instead of dropping it.
                    if len < payload.len() {
                        self.pending
                            .lock()
                            .await
                            .push_front((payload[len..].to_vec(), source));
                    }
                    return Ok((len, source));
                }
                let chunks = if let Some(inbound) = &self.inbound {
                    if let Some(key_state) = &self.key_state {
                        key_state.wait().await?;
                    }
                    match inbound.pop().await {
                        Some(frame) => self.process_reply(&frame).await?,
                        None => {
                            return Err(io::Error::new(
                                io::ErrorKind::BrokenPipe,
                                "UDP stream session closed",
                            ))
                        }
                    }
                } else {
                    let mut wire = vec![0u8; MAX_UDP_DATAGRAM];
                    let (len, from) = self.socket.recv_from(&mut wire).await?;
                    if from != self.server {
                        continue;
                    }
                    let Some((kind, id, frame)) = unwrap_udp(&wire[..len]) else {
                        continue;
                    };
                    if kind != UDP_KIND_SESSION_REPLY || id != self.session_id {
                        continue;
                    }
                    self.process_reply(frame).await?
                };
                for chunk in chunks {
                    let Some((message, number, count, piece)) = split_app_fragment(&chunk) else {
                        return Err(invalid_data("malformed application fragment"));
                    };
                    if let Some(datagram) = assemble_fragment(
                        &mut *self.assembler.lock().await,
                        message,
                        number,
                        count,
                        piece,
                    ) {
                        let parsed = parse_udp_datagram(&datagram).map_err(io_err)?;
                        let source = SocketAddr::new(
                            match parsed.address {
                                Address::Ip(ip) => ip,
                                Address::Domain(_) => {
                                    return Err(invalid_data("domain reply address"))
                                }
                            },
                            parsed.port,
                        );
                        self.pending
                            .lock()
                            .await
                            .push_back((parsed.payload, source));
                    }
                }
            }
        })
    }
}

/// Direct reply path to a UDP client, shared from the listener socket.
struct ReplyContext {
    client: SocketAddr,
    socket: Arc<UdpSocket>,
}

/// Server-side state of one UDP session.
struct ServerUdpSession {
    session: Arc<Mutex<Session>>,
    session_id: u32,
    client: SocketAddr,
    reply_socket: Arc<UdpSocket>,
    target: Mutex<Option<(SocketAddr, Option<String>)>>,
    outbound: Mutex<Option<Arc<UdpSocket>>>,
    /// CONNECT-over-UDP egress: the write half of the dialed TCP stream.
    tcp_outbound: Mutex<Option<TcpWriteHalf>>,
    assembler: Mutex<FragmentMap>,
    replies: Mutex<mpsc::UnboundedReceiver<Vec<u8>>>,
    reply_tx: mpsc::UnboundedSender<Vec<u8>>,
    pending_frames: Mutex<VecDeque<Vec<u8>>>,
    /// Woken when an inbound frame (ACK) may unblock more reply frames.
    flusher_wake: Notify,
    created: Instant,
    max_fragment: usize,
}

impl ServerUdpSession {
    fn new(
        session_id: u32,
        c2s_key: shadowlemon_crypto::aead::AeadKey,
        s2c_key: shadowlemon_crypto::aead::AeadKey,
        target: Option<(SocketAddr, Option<String>)>,
        tcp: Option<(TcpWriteHalf, TcpReadHalf, SocketAddr)>,
        max_fragment: usize,
        reply: ReplyContext,
    ) -> Self {
        let client = reply.client;
        let reply_socket = reply.socket;
        let (reply_tx, replies) = mpsc::unbounded_channel();
        let tcp_outbound = tcp.map(|(write_half, read_half, source)| {
            spawn_tcp_reply_reader(read_half, source, reply_tx.clone());
            write_half
        });
        Self {
            session: Arc::new(Mutex::new(
                Session::new(SessionConfig::new(
                    session_id,
                    Direction::Server,
                    TransportMode::Datagram,
                    c2s_key,
                    s2c_key,
                ))
                .expect("valid UDP session configuration"),
            )),
            session_id,
            client,
            reply_socket,
            target: Mutex::new(target),
            outbound: Mutex::new(None),
            tcp_outbound: Mutex::new(tcp_outbound),
            assembler: Mutex::new(HashMap::new()),
            replies: Mutex::new(replies),
            reply_tx,
            pending_frames: Mutex::new(VecDeque::new()),
            flusher_wake: Notify::new(),
            created: Instant::now(),
            max_fragment,
        }
    }

    fn is_closed(&self) -> bool {
        // The lock is held only briefly; this is called from the mux cleanup.
        self.session
            .try_lock()
            .is_ok_and(|session| session.is_closed())
    }

    async fn assemble(&self, id: u32, number: u8, count: u8, piece: Vec<u8>) -> Option<Vec<u8>> {
        let mut assembler = self.assembler.lock().await;
        assemble_fragment(&mut assembler, id, number, count, piece)
    }

    async fn push_frame(&self, frame: Vec<u8>) {
        self.pending_frames.lock().await.push_back(frame);
    }

    async fn drain_frames(&self) -> Vec<Vec<u8>> {
        self.pending_frames.lock().await.drain(..).collect()
    }

    /// Encode one plaintext reply into the session's send queue and flush every
    /// frame the session is currently willing to emit straight to the client.
    async fn flush_reply(&self, datagram: &[u8]) {
        let id = {
            let mut counter = 0u32;
            for byte in datagram {
                counter = counter.wrapping_mul(31).wrapping_add(u32::from(*byte));
            }
            counter
        };
        let fragments = match fragment_payload(datagram, self.max_fragment, id) {
            Ok(f) => f,
            Err(_) => return,
        };
        let mut session = self.session.lock().await;
        for fragment in fragments {
            let _ = session.send(&fragment).await;
        }
        let _ = session.tick(Instant::now());
        for frame in drain_output(&mut session) {
            let wire = wrap_udp(UDP_KIND_SESSION_REPLY, self.session_id, &frame);
            if let Err(err) = self.reply_socket.send_to(&wire, self.client).await {
                debug!(%err, "background UDP reply send failed");
            }
        }
    }

    /// Flush any frames the session can emit now (e.g. after an ACK advanced
    /// the send window), without new plaintext input.
    async fn flush_pending_output(&self) {
        let mut session = self.session.lock().await;
        let _ = session.tick(Instant::now());
        for frame in drain_output(&mut session) {
            let wire = wrap_udp(UDP_KIND_SESSION_REPLY, self.session_id, &frame);
            if let Err(err) = self.reply_socket.send_to(&wire, self.client).await {
                debug!(%err, "background UDP reply send failed");
            }
        }
    }

    /// Start a background task that turns queued plaintext replies into
    /// encrypted frames and sends them straight to the client on the shared
    /// listener socket. It also flushes on each inbound ACK so large responses
    /// keep flowing as the client's receive window advances.
    fn spawn_reply_flusher(self: &Arc<Self>) {
        let state = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    datagram = async {
                        let mut replies = state.replies.lock().await;
                        replies.recv().await
                    } => {
                        let Some(datagram) = datagram else { break };
                        state.flush_reply(&datagram).await;
                    }
                    _ = state.flusher_wake.notified() => {
                        state.flush_pending_output().await;
                    }
                }
            }
        });
    }

    async fn send_payload(&self, target: SocketAddr, payload: &[u8]) -> io::Result<()> {
        if let Some(stream) = self.tcp_outbound.lock().await.as_mut() {
            stream.write_all(payload).await?;
            stream.flush().await?;
            return Ok(());
        }
        let socket = {
            let mut outbound = self.outbound.lock().await;
            if let Some(socket) = outbound.as_ref() {
                Arc::clone(socket)
            } else {
                let bind: SocketAddr = if target.is_ipv4() {
                    "0.0.0.0:0".parse().expect("literal address")
                } else {
                    "[::]:0".parse().expect("literal address")
                };
                let socket = Arc::new(UdpSocket::bind(bind).await?);
                *outbound = Some(Arc::clone(&socket));
                spawn_udp_reply_reader(Arc::clone(&socket), self.reply_tx.clone());
                socket
            }
        };
        socket.send_to(payload, target).await?;
        let mut guard = self.target.lock().await;
        if guard.is_none() {
            *guard = Some((
                target, None, // per-datagram hostname is carried in the SOCKS5 header
            ));
        }
        Ok(())
    }
}

/// Forward plaintext SOCKS5 reply datagrams into the session's reply queue.
///
/// Encryption is performed only in `collect_replies`, which is called from the
/// mux's `accept_udp` when it can return the encrypted bytes to the client.
fn spawn_udp_reply_reader(socket: Arc<UdpSocket>, tx: mpsc::UnboundedSender<Vec<u8>>) {
    tokio::spawn(async move {
        let mut buf = vec![0u8; MAX_UDP_DATAGRAM];
        loop {
            let (len, source) = match socket.recv_from(&mut buf).await {
                Ok(result) => result,
                Err(error) => {
                    warn!(%error, "UDP relay receive failed");
                    break;
                }
            };
            let mut datagram = encode_udp_header(&Address::Ip(source.ip()), source.port());
            datagram.extend_from_slice(&buf[..len]);
            if tx.send(datagram).is_err() {
                break;
            }
        }
    });
}

/// Relay the read half of a dialed TCP target into the CONNECT-over-UDP reply
/// queue. Bytes are wrapped in a SOCKS5 UDP header so the client side's
/// datagram socket can hand them to the byte-stream facade as ordinary
/// application data. The write half stays with the session; the two halves are
/// independent so a blocking read never stalls outgoing writes.
fn spawn_tcp_reply_reader(
    mut stream: TcpReadHalf,
    source: SocketAddr,
    tx: mpsc::UnboundedSender<Vec<u8>>,
) {
    tokio::spawn(async move {
        let mut buf = vec![0u8; MAX_UDP_DATAGRAM];
        loop {
            let len = match stream.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(len) => len,
            };
            let mut datagram = encode_udp_header(&Address::Ip(source.ip()), source.port());
            datagram.extend_from_slice(&buf[..len]);
            if tx.send(datagram).is_err() {
                break;
            }
        }
    });
}

fn source_key(source: SocketAddr) -> SourceKey {
    match source.ip() {
        IpAddr::V4(ip) => SourceKey::from_ipv4(ip.octets()),
        IpAddr::V6(ip) => SourceKey::from_ipv6(ip.octets()),
    }
}

async fn resolve_address(address: &Address) -> io::Result<(IpAddr, Option<String>)> {
    match address {
        Address::Ip(ip) => Ok((*ip, None)),
        Address::Domain(host) => Ok((resolve_host(host).await?, Some(host.clone()))),
    }
}

async fn resolve_host(host: &str) -> io::Result<IpAddr> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(ip);
    }
    tokio::net::lookup_host((host, 0))
        .await?
        .next()
        .map(|addr| addr.ip())
        .ok_or_else(|| invalid_data("host did not resolve to an address"))
}

/// Minimal SOCKS5 client authentication used for egress proxies.
async fn socks5_client_handshake(
    stream: &mut TcpStream,
    credential: Option<&Credential>,
) -> io::Result<()> {
    if credential.is_some() {
        stream.write_all(&[VERSION, 1, METHOD_USERPASS]).await?;
    } else {
        stream.write_all(&[VERSION, 1, METHOD_NO_AUTH]).await?;
    }
    stream.flush().await?;
    let mut method = [0u8; 2];
    stream.read_exact(&mut method).await?;
    if method[0] != VERSION {
        return Err(invalid_data("egress proxy spoke a different SOCKS version"));
    }
    if let Some(credential) = credential {
        if method[1] != METHOD_USERPASS {
            return Err(invalid_data("egress proxy refused username/password"));
        }
        let user = credential.username.as_bytes();
        let password = credential.password.as_bytes();
        if user.len() > 255 || password.len() > 255 {
            return Err(invalid_data("egress proxy credentials are too long"));
        }
        let mut auth = Vec::with_capacity(user.len() + password.len() + 3);
        auth.extend_from_slice(&[USERPASS_VERSION, user.len() as u8]);
        auth.extend_from_slice(user);
        auth.push(password.len() as u8);
        auth.extend_from_slice(password);
        stream.write_all(&auth).await?;
        stream.flush().await?;
        let mut reply = [0u8; 2];
        stream.read_exact(&mut reply).await?;
        if reply[1] != AUTH_SUCCESS {
            return Err(invalid_data("egress proxy authentication failed"));
        }
    } else if method[1] != METHOD_NO_AUTH {
        return Err(invalid_data("egress proxy required authentication"));
    }
    Ok(())
}

/// Read the variable part of a SOCKS5 reply after its four-byte header.
async fn read_socks5_address_tail(stream: &mut TcpStream, address_type: u8) -> io::Result<()> {
    let len = match address_type {
        ATYP_IPV4 => 4,
        ATYP_IPV6 => 16,
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            usize::from(len[0])
        }
        other => {
            return Err(invalid_data(
                format!("unknown SOCKS5 address type {other}").as_str(),
            ))
        }
    };
    let mut tail = vec![0u8; len + 2];
    stream.read_exact(&mut tail).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use shadowlemon_crypto::{
        kdf::{derive_static_key, hash_password},
        WireNonce,
    };

    fn user(name: &str, password: &str) -> User {
        User::from_password(name, password, Vec::new()).expect("valid user")
    }

    #[test]
    fn client_and_server_derive_the_same_static_key() {
        let name = "alice@example.com";
        let password = "s3cret";
        let client_credential = hash_password(password.as_bytes(), name);
        let server_user = user(name, password);
        assert_eq!(server_user.credential(), &client_credential);
        for suite in Suite::all_suites() {
            let from_client = derive_static_key(name, &client_credential, suite).unwrap();
            let from_server =
                derive_static_key(server_user.name(), server_user.credential(), suite).unwrap();
            assert_eq!(from_client.as_slice(), from_server.as_slice());
        }
    }

    #[test]
    fn udp_envelope_round_trip() {
        let frame = wrap_udp(UDP_KIND_SESSION_DATA, 42, b"encrypted frame");
        assert_eq!(
            unwrap_udp(&frame),
            Some((UDP_KIND_SESSION_DATA, 42, &b"encrypted frame"[..]))
        );
        assert!(unwrap_udp(&frame[..UDP_ENVELOPE_LEN - 1]).is_none());
    }

    #[test]
    fn udp_envelope_kind_byte_is_obfuscated_and_varies_with_session() {
        // A passive observer must not find the old fixed 1/2/3/4 prefix.
        let mut first_bytes = std::collections::HashSet::new();
        for id in [1u32, 2, 3, 42, 10_000, u32::MAX] {
            let frame = wrap_udp(UDP_KIND_SESSION_DATA, id, b"x");
            assert_ne!(frame[0], UDP_KIND_SESSION_DATA);
            first_bytes.insert(frame[0]);
        }
        assert!(first_bytes.len() > 1);
        // Garbage is rejected before reaching the handshake dispatcher.
        let mut garbage = wrap_udp(UDP_KIND_SESSION_DATA, 7, b"x");
        garbage[0] ^= 0xff;
        assert!(unwrap_udp(&garbage).is_none());
    }

    #[test]
    fn application_fragments_reassemble_in_descending_order() {
        let data: Vec<u8> = (0..40u8).collect();
        let pieces = fragment_payload(&data, 16, 9).unwrap();
        assert_eq!(pieces.len(), 3);
        let mut map = HashMap::new();
        let mut result = None;
        for piece in pieces {
            let (id, number, count, chunk) = split_app_fragment(&piece).unwrap();
            result = assemble_fragment(&mut map, id, number, count, chunk);
        }
        assert_eq!(result.unwrap(), data);
    }

    #[test]
    fn client_config_validates_suites_and_mtu() {
        let config = RealClientConfig {
            username: "alice".to_owned(),
            credential: ClientCredential::Password("secret".to_owned()),
            suites: vec![Suite::XChaCha20Poly1305],
            packet: PacketConfig::default(),
            handshake_timeout: Duration::from_secs(10),
        };
        assert!(config.validate().is_ok());
        let bad = RealClientConfig {
            suites: Vec::new(),
            ..config
        };
        assert!(bad.validate().is_err());
    }

    #[allow(dead_code)]
    fn assert_wire_nonce(_nonce: WireNonce) {}
}
