//! Real V0.2 handshake/session adapters for the mux traits.
//!
//! This module is the integration point the hand-written mux in [`crate::mux`]
//! was designed for: it replaces the `PassthroughClientHandshake` /
//! `NoopServerHandshake` test adapters with implementations that actually run
//! the 1-RTT handshake and encrypt every application byte.
//!
//! # TCP target convention
//!
//! `mux::ClientHandshake::open_tcp` receives a resolved `target` plus an
//! optional original hostname. The driver encodes that pair as a SOCKS5
//! `CONNECT` request (`proto::encode_request(CMD_CONNECT, address, port)`) and
//! places the resulting bytes in the `openSessionRequest` **piggyback** area,
//! which the V0.2 handshake carries inside its authenticated envelope and the
//! server handshake returns as `piggyback`. The server parses it with
//! `proto::read_request`; a domain name is resolved with `lookup_host` before
//! dialing. Bytes that followed the SOCKS5 request in the piggyback (no-wait
//! style handshakes) are written to the target before the relay starts.
//!
//! # UDP conventions
//!
//! UDP needs two extra, **driver-level** envelopes because the mux router only
//! sees opaque datagrams. These bytes are outside the frozen V0.2 wire format;
//! everything after the envelope header is a genuine V0.2 frame.
//!
//! 1. Routing envelope: `[kind: u8][session_id: u32be][wire frame ..]`, where
//!    `kind` is 1 = handshake request, 2 = session data, 3 = handshake
//!    response, 4 = session reply. The mux passes the whole datagram to
//!    `ServerHandshake::accept_udp` and sends its returned bytes back
//!    unchanged; the client undoes the envelope on receive. The session ID is
//!    therefore available for lookup **before** any AEAD key is known.
//! 2. Target convention: the handshake piggyback carries a SOCKS5
//!    `UDP ASSOCIATE` request for the destination. The first (and every)
//!    application datagram additionally carries a standard SOCKS5 UDP header
//!    (`0x00 0x00 0x00 ATYP DST.ADDR DST.PORT`) followed by the real payload,
//!    per `protocol-v0.2.md` §9. The server parses it with
//!    `proto::parse_udp_datagram` and uses the address/port found there for
//!    that datagram, so a single association can talk to several peers.
//! 3. Application fragmentation: SOCKS5 datagrams are split to the MTU-derived
//!    capacity and each piece is prefixed with
//!    `[message_id: u32be][fragment_number: u8][fragment_count: u8]` before
//!    being handed to the V0.2 `Session`. Fragment numbers count down to zero,
//!    matching the wire metadata. Reassembly happens on both peers.
//!
//! # Key installation
//!
//! A V0.2 [`Session`](crate::session::Session) owns two independent directional
//! AEAD keys and its own framing state, so the established c2s/s2c keys are
//! installed into a `Session` and driven by [`TcpSessionStream`]. On the stream
//! path a [`StreamUnderlay`] is also configured and its cipher chain installed
//! (it is the framing primitive used by raw-underlay deployments); the raw I/O
//! object is then handed to `TcpSessionStream`, which owns the data-plane
//! framing so the two layers never double-encrypt.

use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    io,
    net::{IpAddr, SocketAddr},
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use dashmap::DashMap;
use futures::future::BoxFuture;
use shadowlemon_crypto::{
    aead::AeadKey, kdf::derive_static_key, suite::Suite, HANDSHAKE_RESPONSE_LEN,
};
use shadowlemon_socks5::{
    encode_request, encode_udp_header, parse_udp_datagram, read_request, Address, AsyncIo,
    Credential, DatagramSocket, EgressAction, EgressConfig, ATYP_DOMAIN, ATYP_IPV4, ATYP_IPV6,
    CMD_CONNECT, CMD_UDP_ASSOCIATE, MAX_UDP_DATAGRAM, VERSION,
};
use shadowlemon_wire::{
    payload_block_len, Metadata, META_BLOCK_LEN, NONCE_AND_META_LEN, TAG_LEN, WIRE_NONCE_LEN,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    sync::{mpsc, Mutex},
    time,
};
use tracing::{debug, warn};

use crate::{
    handshake::{
        build_registry, AeadUserDecryptor, ClientHandshake, ClientOutcome, HandshakeTransport,
        ServerHandshake, ServerHandshakeResult, TYPE_OPEN_SESSION_REQUEST,
    },
    mux::{self, Endpoint, TransportKind},
    serveruser::{Registry, SourceKey, User},
    session::{Direction, Session, SessionConfig, TransportMode},
    stream::TcpSessionStream,
    underlay::{IpFamily, MtuBudget, Underlay},
    underlay_packet::PacketConfig,
    underlay_stream::{StreamConfig, StreamUnderlay},
};

/// Routing envelope: handshake request (client → mux server).
const UDP_KIND_HANDSHAKE_REQUEST: u8 = 1;
/// Routing envelope: handshake response (mux server → client).
const UDP_KIND_HANDSHAKE_RESPONSE: u8 = 2;
/// Routing envelope: encrypted session data.
const UDP_KIND_SESSION_DATA: u8 = 3;
/// Routing envelope: encrypted session reply/ACK.
const UDP_KIND_SESSION_REPLY: u8 = 4;
/// `[kind][session id]` prefix length of the UDP routing envelope.
const UDP_ENVELOPE_LEN: usize = 5;
/// `[message id][fragment number][fragment count]` application prefix.
const APP_FRAGMENT_HEADER_LEN: usize = 6;
/// Stream handshake response frame: encrypted metadata + fixed payload + tag.
const STREAM_HANDSHAKE_RESPONSE_LEN: usize = META_BLOCK_LEN + HANDSHAKE_RESPONSE_LEN + TAG_LEN;
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
    /// Traffic pattern applied to TCP nonces.
    pub stream: StreamConfig,
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

    fn credential_bytes(&self) -> [u8; 32] {
        match &self.credential {
            ClientCredential::Password(password) => {
                shadowlemon_crypto::kdf::hash_password(password.as_bytes(), &self.username)
            }
            ClientCredential::Credential(bytes) => *bytes,
        }
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
    /// Traffic pattern applied to TCP nonces.
    pub stream: StreamConfig,
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
            stream: StreamConfig::default(),
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
        mut stream: Box<dyn AsyncIo>,
        session_id: u32,
        _endpoint: &'a Endpoint,
        target: SocketAddr,
        host: Option<&'a str>,
    ) -> BoxFuture<'a, io::Result<Box<dyn AsyncIo>>> {
        Box::pin(async move {
            let address = match host {
                Some(name) if !name.is_empty() => Address::Domain(name.to_owned()),
                _ => Address::Ip(target.ip()),
            };
            let piggyback = encode_request(CMD_CONNECT, &address, target.port());

            let mut handshake =
                self.build_client_handshake(session_id, HandshakeTransport::Stream)?;
            let request = handshake.build_request(&piggyback).map_err(io_err)?;
            stream.write_all(&request).await?;
            stream.flush().await?;

            let mut response = vec![0u8; STREAM_HANDSHAKE_RESPONSE_LEN];
            stream.read_exact(&mut response).await?;
            let established = match handshake.process_response(&response).map_err(io_err)? {
                ClientOutcome::Established(established) => *established,
                ClientOutcome::NoCommonSuite => {
                    warn!("no common cipher suite with the server");
                    return Err(invalid_data("server rejected every offered cipher suite"));
                }
            };

            // Install the envelope chain in the stream underlay (the framing
            // primitive used by raw-underlay deployments), then hand the raw
            // I/O to the session stream, which owns data-plane framing.
            let static_key = derive_static_key(
                &self.config.username,
                &self.config.credential_bytes(),
                self.config.suites[0],
            )
            .map_err(io_err)?;
            let envelope_key =
                AeadKey::new(self.config.suites[0], static_key.as_slice()).map_err(io_err)?;
            let mut underlay =
                StreamUnderlay::new(stream, envelope_key, self.config.stream.clone());
            let session_cipher =
                AeadKey::new(established.suite, established.c2s_key.key_bytes()).map_err(io_err)?;
            underlay.install_session_cipher(session_cipher);
            let transport = underlay.into_inner();

            let session = Session::new(SessionConfig::new(
                session_id,
                Direction::Client,
                TransportMode::Stream,
                established.c2s_key,
                established.s2c_key,
            ))
            .map_err(io_err)?;
            let tunnel: Box<dyn AsyncIo> = Box::new(TcpSessionStream::new(session, transport));
            debug!(session_id, suite = %established.suite, "TCP session established to StreamUnderlay{{");
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
            .payload_capacity(0, 0)
            .saturating_sub(APP_FRAGMENT_HEADER_LEN);
            let handle = Arc::new(UdpSessionHandle {
                session_id,
                socket: Arc::clone(&socket),
                session: Arc::clone(&session),
                server,
            });
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

    async fn relay_tcp(
        &self,
        mut tunnel: TcpSessionStream<Box<dyn AsyncIo>>,
        mut outbound: Box<dyn AsyncIo>,
        initial: &[u8],
    ) -> io::Result<()> {
        if !initial.is_empty() {
            outbound.write_all(initial).await?;
            outbound.flush().await?;
        }
        let (mut tunnel_read, mut tunnel_write) = tokio::io::split(&mut tunnel);
        let (mut outbound_read, mut outbound_write) = tokio::io::split(&mut *outbound);
        let up = async {
            let result = tokio::io::copy(&mut tunnel_read, &mut outbound_write).await;
            let _ = outbound_write.shutdown().await;
            result
        };
        let down = async {
            let result = tokio::io::copy(&mut outbound_read, &mut tunnel_write).await;
            let _ = tunnel_write.shutdown().await;
            result
        };
        let (up, down) = tokio::join!(up, down);
        up?;
        down?;
        Ok(())
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
    fn accept_tcp<'a>(
        &'a self,
        mut stream: Box<dyn AsyncIo>,
        source: SocketAddr,
    ) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(async move {
            let source_key = source_key(source);
            // Read the fixed part first to learn the authenticated frame length
            // from the encrypted metadata (spec §10, step 1/5).
            let mut fixed = [0u8; NONCE_AND_META_LEN];
            stream.read_exact(&mut fixed).await?;
            let nonce: shadowlemon_crypto::WireNonce = fixed[..WIRE_NONCE_LEN]
                .try_into()
                .expect("fixed part has nonce length");
            let auth = self
                .registry
                .discover(&nonce, &fixed[WIRE_NONCE_LEN..], Some(source_key))
                .map_err(io_err)?;
            let metadata = Metadata::parse(auth.plaintext()).map_err(io_err)?;
            if metadata.protocol_type() != TYPE_OPEN_SESSION_REQUEST || metadata.session_id() == 0 {
                auth.record(&self.registry);
                return Err(invalid_data("unexpected handshake request metadata"));
            }
            let variable_len = usize::from(metadata.prefix_len())
                + payload_block_len(usize::from(metadata.payload_len()))
                + usize::from(metadata.suffix_len());
            let mut variable = vec![0u8; variable_len];
            stream.read_exact(&mut variable).await?;
            let mut frame = fixed.to_vec();
            frame.extend_from_slice(&variable);

            let session_id = metadata.session_id();
            let mut handshake = self.new_server_handshake(
                session_id,
                HandshakeTransport::Stream,
                Some(source_key),
            )?;
            let result = handshake.accept(&frame).map_err(io_err)?;
            match result {
                ServerHandshakeResult::NoCommonSuite { response } => {
                    stream.write_all(&response).await?;
                    stream.flush().await?;
                    Ok(())
                }
                ServerHandshakeResult::Established {
                    response,
                    session,
                    piggyback,
                    ..
                } => {
                    stream.write_all(&response).await?;
                    stream.flush().await?;

                    let mut request_bytes = &piggyback[..];
                    let (request, raw) = read_request(&mut request_bytes).await.map_err(io_err)?;
                    if request.command != CMD_CONNECT {
                        return Err(invalid_data("piggyback must be a SOCKS5 CONNECT request"));
                    }
                    let outbound = self
                        .dial_target(&request.address, request.port, &piggyback)
                        .await?;
                    let initial = &piggyback[raw.len()..];

                    let state = Session::new(SessionConfig::new(
                        session_id,
                        Direction::Server,
                        TransportMode::Stream,
                        session.c2s_key,
                        session.s2c_key,
                    ))
                    .map_err(io_err)?;
                    let tunnel = TcpSessionStream::new(state, stream);
                    debug!(session_id, %source, suite = %session.suite, "server TCP session established");
                    self.relay_tcp(tunnel, outbound, initial).await
                }
            }
        })
    }

    fn accept_udp<'a>(
        &'a self,
        datagram: Vec<u8>,
        source: SocketAddr,
    ) -> BoxFuture<'a, io::Result<Option<Vec<u8>>>> {
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
                        ServerHandshakeResult::NoCommonSuite { response } => Ok(Some(wrap_udp(
                            UDP_KIND_HANDSHAKE_RESPONSE,
                            session_id,
                            &response,
                        ))),
                        ServerHandshakeResult::Established {
                            response,
                            session,
                            piggyback,
                            ..
                        } => {
                            let mut bytes = &piggyback[..];
                            let target = if piggyback.is_empty() {
                                None
                            } else {
                                let (request, _) =
                                    read_request(&mut bytes).await.map_err(io_err)?;
                                if request.command != CMD_UDP_ASSOCIATE {
                                    return Err(invalid_data("piggyback must be UDP ASSOCIATE"));
                                }
                                let (ip, host) = resolve_address(&request.address).await?;
                                Some((SocketAddr::new(ip, request.port), host))
                            };
                            let state = Arc::new(ServerUdpSession::new(
                                session_id,
                                session.c2s_key,
                                session.s2c_key,
                                target,
                                MtuBudget::new(
                                    self.config.packet.mtu,
                                    IpFamily::from_addr(source.ip()),
                                    true,
                                )
                                .map_err(io_err)?
                                .payload_capacity(0, 0)
                                .saturating_sub(APP_FRAGMENT_HEADER_LEN),
                            ));
                            self.udp_sessions
                                .insert((source, session_id), Arc::clone(&state));
                            debug!(session_id, %source, suite = %session.suite, "server UDP session established");
                            Ok(Some(wrap_udp(
                                UDP_KIND_HANDSHAKE_RESPONSE,
                                session_id,
                                &response,
                            )))
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
                    // Drain anything the relay already produced, waiting briefly
                    // for a fast reply so the mux can answer this datagram.
                    let wait = self.config.udp_reply_wait;
                    state
                        .collect_replies(session_id, wait, time::Instant::now() + wait)
                        .await;
                    Ok(state.pop_frame().await)
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
}

/// Drain frames queued by a session without ticking its timers.
fn drain_output(session: &mut Session) -> Vec<Vec<u8>> {
    std::iter::from_fn(|| session.poll_output()).collect()
}

fn wrap_udp(kind: u8, session_id: u32, frame: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(UDP_ENVELOPE_LEN + frame.len());
    out.push(kind);
    out.extend_from_slice(&session_id.to_be_bytes());
    out.extend_from_slice(frame);
    out
}

fn unwrap_udp(datagram: &[u8]) -> Option<(u8, u32, &[u8])> {
    if datagram.len() < UDP_ENVELOPE_LEN {
        return None;
    }
    let id = u32::from_be_bytes(datagram[1..5].try_into().ok()?);
    Some((datagram[0], id, &datagram[UDP_ENVELOPE_LEN..]))
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

/// Socket returned by `RealClientHandshake::open_udp`.
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
}

impl DatagramSocket for TunnelDatagramSocket {
    fn send_to<'a>(
        &'a self,
        data: &'a [u8],
        target: SocketAddr,
    ) -> BoxFuture<'a, io::Result<usize>> {
        Box::pin(async move {
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
                if let Some((payload, source)) = self.pending.lock().await.pop_front() {
                    let len = buf.len().min(payload.len());
                    buf[..len].copy_from_slice(&payload[..len]);
                    return Ok((len, source));
                }
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

/// Server-side state of one UDP session.
struct ServerUdpSession {
    session: Arc<Mutex<Session>>,
    target: Mutex<Option<(SocketAddr, Option<String>)>>,
    outbound: Mutex<Option<Arc<UdpSocket>>>,
    assembler: Mutex<FragmentMap>,
    replies: Mutex<mpsc::UnboundedReceiver<Vec<u8>>>,
    reply_tx: mpsc::UnboundedSender<Vec<u8>>,
    pending_frames: Mutex<VecDeque<Vec<u8>>>,
    created: Instant,
    max_fragment: usize,
}

impl ServerUdpSession {
    fn new(
        session_id: u32,
        c2s_key: shadowlemon_crypto::aead::AeadKey,
        s2c_key: shadowlemon_crypto::aead::AeadKey,
        target: Option<(SocketAddr, Option<String>)>,
        max_fragment: usize,
    ) -> Self {
        let (reply_tx, replies) = mpsc::unbounded_channel();
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
            target: Mutex::new(target),
            outbound: Mutex::new(None),
            assembler: Mutex::new(HashMap::new()),
            replies: Mutex::new(replies),
            reply_tx,
            pending_frames: Mutex::new(VecDeque::new()),
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

    async fn pop_frame(&self) -> Option<Vec<u8>> {
        self.pending_frames.lock().await.pop_front()
    }

    async fn send_payload(&self, target: SocketAddr, payload: &[u8]) -> io::Result<()> {
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

    async fn collect_replies(&self, session_id: u32, wait: Duration, deadline: time::Instant) {
        loop {
            let received = {
                let mut replies = self.replies.lock().await;
                if let Ok(datagram) = replies.try_recv() {
                    Some(datagram)
                } else if time::Instant::now() < deadline {
                    match time::timeout(wait, replies.recv()).await {
                        Ok(Some(datagram)) => Some(datagram),
                        _ => None,
                    }
                } else {
                    None
                }
            };
            let Some(datagram) = received else { break };
            let id = {
                let mut counter = 0u32;
                // Derive a stable-enough message id from the reply content: a
                // short rolling hash keeps the assembler key independent of
                // the request side's message ids.
                for byte in &datagram {
                    counter = counter.wrapping_mul(31).wrapping_add(u32::from(*byte));
                }
                counter
            };
            let fragments = match fragment_payload(&datagram, self.max_fragment, id) {
                Ok(fragments) => fragments,
                Err(_) => break,
            };
            let mut session = self.session.lock().await;
            for fragment in fragments {
                let _ = session.send(&fragment).await;
            }
            let _ = session.tick(Instant::now());
            for frame in drain_output(&mut session) {
                self.push_frame(wrap_udp(UDP_KIND_SESSION_REPLY, session_id, &frame))
                    .await;
            }
            if self.pending_frames.lock().await.len() >= 8 {
                break;
            }
        }
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
    use shadowlemon_crypto::{kdf::hash_password, WireNonce};

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
            stream: StreamConfig::default(),
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
