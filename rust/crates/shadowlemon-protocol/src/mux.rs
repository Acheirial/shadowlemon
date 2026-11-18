//! Connection and session multiplexing for ShadowLemon V0.2
//! (`reference-go-v3.md` §3).
//!
//! # Client
//!
//! [`ClientMux`] owns a pool of UDP underlays to the configured server
//! endpoints. It allocates non-zero session IDs, chooses endpoints round
//! robin, applies the configured connection-reuse policy, and delegates the
//! actual 1-RTT V0.2 handshake to a [`ClientHandshake`]. It implements
//! `shadowlemon_socks5::ProxyDialer` so a SOCKS5 ingress can use it directly.
//!
//! # Server
//!
//! [`ServerMux`] listens on the configured UDP port bindings, applies a
//! per-source-IP token bucket (burst 2048, refill 512/s), caps concurrent
//! underlays at 4096, expires idle server underlays after three minutes, and
//! runs a five-second cleaner. Every accepted `openSessionRequest` is passed
//! to a [`ServerHandshake`] which owns the handshake/session logic.
//!
//! # Integration with the concurrently written handshake/session modules
//!
//! To keep this module independent of the concurrently written handshake
//! crate module, it does not reference `crate::handshake` directly. Instead
//! the two narrow traits below define the minimal interface the mux needs.
//! The integrator should implement them by forwarding to the V0.2 handshake
//! and session layers. [`PassthroughClientHandshake`] and
//! [`NoopServerHandshake`] are provided as deterministic wiring adapters for
//! tests; they do **not** perform any cryptographic handshake and must not be
//! used in production.

use std::{
    io,
    net::{IpAddr, SocketAddr},
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use dashmap::DashMap;
use futures::future::BoxFuture;
use shadowlemon_crypto::{aead::AeadKey, suite::Suite};
use shadowlemon_socks5::{AsyncIo, DatagramSocket, ProxyDialer, TokioDatagramSocket};
use tokio::{
    sync::{Mutex, Notify},
    task::JoinHandle,
    time,
};
use tracing::{debug, warn};

use crate::{
    underlay::{IpFamily, UnderlayError, UnderlayKind, UnderlayResult, DEFAULT_MTU},
    underlay_packet::PacketConfig,
};

/// Default maximum number of concurrent underlays (spec §3.1).
pub const DEFAULT_MAX_UNDERLAYS: usize = 4096;
/// Default server underlay TTL (spec §3.1).
pub const DEFAULT_UNDERLAY_TTL: Duration = Duration::from_secs(3 * 60);
/// Default underlay cleanup interval (spec §3.1).
pub const DEFAULT_CLEANUP_INTERVAL: Duration = Duration::from_secs(5);
/// Default per-source accept burst (spec §3.3).
pub const DEFAULT_ACCEPT_BURST: usize = 2048;
/// Default per-source token refill rate (spec §3.3).
pub const DEFAULT_ACCEPT_REFILL_PER_SECOND: u64 = 512;
/// Default maximum number of cached source buckets (spec §3.3).
pub const DEFAULT_MAX_SOURCES: usize = 4096;
/// Default source bucket idle timeout (spec §3.3).
pub const DEFAULT_SOURCE_IDLE_TIMEOUT: Duration = Duration::from_secs(10 * 60);
/// Handshake response timeout (reference §1.1).
pub const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Transport of a configured port binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransportKind {
    /// Datagrams.
    Udp,
}

/// One port binding of an endpoint or listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PortBindingSpec {
    /// UDP port number.
    pub port: u16,
    /// Transport protocol.
    pub protocol: TransportKind,
}

impl PortBindingSpec {
    /// Build a binding.
    #[must_use]
    pub const fn new(port: u16, protocol: TransportKind) -> Self {
        Self { port, protocol }
    }
}

/// A configured ShadowLemon server endpoint (`ipAddress`/`domainName` plus
/// `portBindings`) independent of the serde config crate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    /// Literal IP address; ignored when `domain_name` is set.
    pub ip_address: Option<String>,
    /// Domain name, which takes precedence over `ip_address`.
    pub domain_name: Option<String>,
    /// Port/protocol bindings this endpoint serves.
    pub port_bindings: Vec<PortBindingSpec>,
}

impl Endpoint {
    /// Build an endpoint from a literal host string.
    #[must_use]
    pub fn new(host: impl Into<String>, port_bindings: Vec<PortBindingSpec>) -> Self {
        Self {
            ip_address: Some(host.into()),
            domain_name: None,
            port_bindings,
        }
    }

    /// Build an endpoint from a domain name.
    #[must_use]
    pub fn with_domain(domain: impl Into<String>, port_bindings: Vec<PortBindingSpec>) -> Self {
        Self {
            ip_address: None,
            domain_name: Some(domain.into()),
            port_bindings,
        }
    }

    /// Resolve every binding to concrete socket addresses.
    ///
    /// Literal IPs short-circuit DNS; domain names use `lookup_host`. IPv4
    /// results are sorted before IPv6 ones, matching the config layer's
    /// default dual-stack preference.
    pub async fn resolve(&self) -> UnderlayResult<Vec<SocketAddr>> {
        let host = self
            .domain_name
            .as_deref()
            .or(self.ip_address.as_deref())
            .ok_or_else(|| UnderlayError::InvalidEndpoint("missing host".to_owned()))?;
        if self.port_bindings.is_empty() {
            return Err(UnderlayError::InvalidEndpoint(
                "no port bindings".to_owned(),
            ));
        }
        let mut out = Vec::new();
        if let Ok(ip) = host.parse::<IpAddr>() {
            for binding in &self.port_bindings {
                out.push(SocketAddr::new(ip, binding.port));
            }
        } else {
            for binding in &self.port_bindings {
                let resolved = tokio::net::lookup_host((host, binding.port)).await?;
                out.extend(resolved);
            }
        }
        out.sort_by_key(|addr| (!addr.is_ipv4(), *addr));
        out.dedup();
        if out.is_empty() {
            return Err(UnderlayError::InvalidEndpoint(format!(
                "host {host:?} resolved to no addresses"
            )));
        }
        Ok(out)
    }

    /// First resolved address for a given transport.
    pub async fn address_for(&self, protocol: TransportKind) -> UnderlayResult<SocketAddr> {
        let mut addrs = self.resolve().await?;
        addrs.retain(|addr| {
            self.port_bindings
                .iter()
                .any(|b| b.protocol == protocol && b.port == addr.port())
        });
        addrs.into_iter().next().ok_or_else(|| {
            UnderlayError::InvalidEndpoint(format!("no {protocol:?} binding in endpoint"))
        })
    }
}

/// Multiplexing level controlling how aggressively existing underlays are
/// reused (spec §3.2: factor ∈ 0..3).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum Multiplexing {
    /// Always open a new underlay.
    Off,
    /// Reuse existing underlays occasionally.
    Low,
    /// Reuse underlays moderately.
    #[default]
    Middle,
    /// Reuse underlays aggressively.
    High,
}

impl Multiplexing {
    /// Reuse factor used in the `active * factor` vs. one-new-slot lottery.
    #[must_use]
    pub const fn reuse_factor(self) -> usize {
        match self {
            Self::Off => 0,
            Self::Low => 1,
            Self::Middle => 2,
            Self::High => 3,
        }
    }
}

/// Limits and timers for both mux sides. Every field is configurable so tests
/// can use small limits without waiting for the production TTLs.
#[derive(Debug, Clone)]
pub struct MuxConfig {
    /// Maximum number of simultaneous underlays.
    pub max_underlays: usize,
    /// Idle server-underlay TTL.
    pub underlay_ttl: Duration,
    /// Underlay/session cleaner interval.
    pub cleanup_interval: Duration,
    /// Per-source accept burst.
    pub accept_burst: usize,
    /// Per-source token refill rate (tokens per second).
    pub accept_refill_per_second: u64,
    /// Maximum number of tracked source IPs.
    pub max_sources: usize,
    /// Idle timeout for a source token bucket.
    pub source_idle_timeout: Duration,
    /// Initial listener rebuild delay.
    pub rebuild_initial: Duration,
    /// Maximum listener rebuild delay.
    pub rebuild_max: Duration,
    /// Connection reuse policy.
    pub multiplexing: Multiplexing,
    /// L3 MTU used by UDP underlays.
    pub mtu: u16,
    /// IP family used for MTU budgeting.
    pub ip_family: IpFamily,
    /// Handshake response timeout.
    pub handshake_timeout: Duration,
    /// Number of base-connection attempts before giving up on a dial.
    pub reconnect_attempts: u32,
}

impl Default for MuxConfig {
    fn default() -> Self {
        Self {
            max_underlays: DEFAULT_MAX_UNDERLAYS,
            underlay_ttl: DEFAULT_UNDERLAY_TTL,
            cleanup_interval: DEFAULT_CLEANUP_INTERVAL,
            accept_burst: DEFAULT_ACCEPT_BURST,
            accept_refill_per_second: DEFAULT_ACCEPT_REFILL_PER_SECOND,
            max_sources: DEFAULT_MAX_SOURCES,
            source_idle_timeout: DEFAULT_SOURCE_IDLE_TIMEOUT,
            rebuild_initial: Duration::from_secs(1),
            rebuild_max: Duration::from_secs(30),
            multiplexing: Multiplexing::default(),
            mtu: DEFAULT_MTU,
            ip_family: IpFamily::V4,
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
            reconnect_attempts: 3,
        }
    }
}

impl MuxConfig {
    /// Validate the configurable limits.
    pub fn validate(&self) -> UnderlayResult<()> {
        crate::underlay::validate_l3_mtu(self.mtu)?;
        if self.max_underlays == 0 || self.max_sources == 0 {
            return Err(UnderlayError::LimitReached("limits must be positive"));
        }
        if self.accept_burst == 0 {
            return Err(UnderlayError::LimitReached("accept burst must be positive"));
        }
        if self.cleanup_interval.is_zero() || self.handshake_timeout.is_zero() {
            return Err(UnderlayError::InvalidEndpoint(
                "durations must be positive".to_owned(),
            ));
        }
        Ok(())
    }

    /// Listener rebuild delay with `[delay/2, delay]` jitter.
    #[must_use]
    pub fn rebuild_delay(&self, attempt: u32) -> Duration {
        let mut delay = self.rebuild_initial;
        let mut tries = attempt;
        while tries > 0 && delay < self.rebuild_max {
            delay *= 2;
            tries -= 1;
        }
        if delay > self.rebuild_max {
            delay = self.rebuild_max;
        }
        let half = delay / 2;
        let nanos = half.as_nanos().min(u64::MAX as u128) as u64;
        half + Duration::from_nanos(rand::random_range(0..nanos))
    }

    /// Packet-underlay configuration derived from this mux config.
    #[must_use]
    pub fn packet_config(&self) -> PacketConfig {
        PacketConfig {
            mtu: self.mtu,
            family: self.ip_family,
            ..PacketConfig::default()
        }
    }
}

/// Minimal client-side handshake interface needed by [`ClientMux`].
///
/// The integrator should forward these calls to the V0.2 handshake module:
/// perform a 1-RTT `openSessionRequest`/`openSessionResponse` exchange over a
/// UDP underlay, derive the session keys, install them with
/// `Underlay::install_session_cipher`, and return an I/O object that carries
/// only this session's application bytes. `session_id` is allocated by the mux
/// and must be carried in the request metadata. Both methods are backed by UDP;
/// `open_tcp` wraps the session in a byte stream for SOCKS5 CONNECT.
pub trait ClientHandshake: Send + Sync + std::fmt::Debug {
    /// Establish a byte-stream session to `endpoint` for `target` over UDP.
    ///
    /// `session_id` is allocated by the mux and must be used in the handshake
    /// request metadata so that mux bookkeeping matches the live session.
    /// `reuse` tells the driver whether the mux's reuse policy selected an
    /// existing packet underlay instead of a fresh one.
    fn open_tcp<'a>(
        &'a self,
        session_id: u32,
        endpoint: &'a Endpoint,
        target: SocketAddr,
        host: Option<&'a str>,
        reuse: bool,
    ) -> BoxFuture<'a, io::Result<Box<dyn AsyncIo>>>;

    /// Establish a datagram session to `endpoint` for `target`.
    ///
    /// `session_id` is allocated by the mux and must be used in the handshake
    /// request metadata so that mux bookkeeping matches the live session.
    /// `reuse` tells the driver whether the mux's reuse policy selected an
    /// existing packet underlay instead of a fresh one.
    fn open_udp<'a>(
        &'a self,
        session_id: u32,
        endpoint: &'a Endpoint,
        target: SocketAddr,
        host: Option<&'a str>,
        reuse: bool,
    ) -> BoxFuture<'a, io::Result<Box<dyn DatagramSocket>>>;

    /// Notify the handshake layer that a session closed.
    fn close_session(&self, session_id: u32);
}

/// Minimal server-side handshake interface needed by [`ServerMux`].
///
/// The integrator should forward `accept_udp` to the UDP `openSessionRequest`
/// dispatcher. Every returned payload is sent back to `source` unchanged, in
/// order, within the same inbound-datagram turn; an empty vector sends nothing.
pub trait ServerHandshake: Send + Sync + std::fmt::Debug {
    /// Process one UDP datagram, returning zero or more reply payloads.
    fn accept_udp<'a>(
        &'a self,
        datagram: Vec<u8>,
        source: SocketAddr,
    ) -> BoxFuture<'a, io::Result<Vec<Vec<u8>>>>;
}

/// Test adapter that skips the cryptographic handshake and returns the
/// underlying socket unchanged. **Not for production use.**
#[derive(Debug, Default, Clone, Copy)]
pub struct PassthroughClientHandshake;

impl ClientHandshake for PassthroughClientHandshake {
    fn open_tcp<'a>(
        &'a self,
        _session_id: u32,
        _endpoint: &'a Endpoint,
        _target: SocketAddr,
        _host: Option<&'a str>,
        _reuse: bool,
    ) -> BoxFuture<'a, io::Result<Box<dyn AsyncIo>>> {
        // Tests using this adapter only exercise mux bookkeeping, not the
        // byte-stream path; the real driver provides the UDP-backed stream.
        Box::pin(async {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "PassthroughClientHandshake::open_tcp is not implemented",
            ))
        })
    }

    fn open_udp<'a>(
        &'a self,
        _session_id: u32,
        _endpoint: &'a Endpoint,
        target: SocketAddr,
        _host: Option<&'a str>,
        _reuse: bool,
    ) -> BoxFuture<'a, io::Result<Box<dyn DatagramSocket>>> {
        Box::pin(async move {
            let bind: SocketAddr = if target.is_ipv4() {
                "0.0.0.0:0".parse().unwrap()
            } else {
                "[::]:0".parse().unwrap()
            };
            let socket: Box<dyn DatagramSocket> = Box::new(TokioDatagramSocket::bind(bind).await?);
            Ok(socket)
        })
    }

    fn close_session(&self, _session_id: u32) {}
}

/// Test adapter that accepts everything without responding. **Not for
/// production use.**
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopServerHandshake;

impl ServerHandshake for NoopServerHandshake {
    fn accept_udp<'a>(
        &'a self,
        _datagram: Vec<u8>,
        _source: SocketAddr,
    ) -> BoxFuture<'a, io::Result<Vec<Vec<u8>>>> {
        Box::pin(async { Ok(vec![]) })
    }
}

fn io_error(error: UnderlayError) -> io::Error {
    io::Error::other(error.to_string())
}

/// Metadata for one live client session.
#[derive(Debug, Clone, Copy)]
pub struct SessionInfo {
    /// Transport used by the session.
    pub kind: UnderlayKind,
    /// When the session was opened.
    pub opened_at: Instant,
}

struct ClientMuxInner {
    config: MuxConfig,
    endpoints: Vec<Endpoint>,
    handshake: Box<dyn ClientHandshake>,
    upstream: Mutex<Option<Arc<dyn ProxyDialer>>>,
    next_endpoint: AtomicUsize,
    active: AtomicUsize,
    stopped: AtomicBool,
    sessions: DashMap<u32, SessionInfo>,
}

/// Client-side multiplexer implementing `ProxyDialer`.
#[derive(Clone)]
pub struct ClientMux {
    inner: Arc<ClientMuxInner>,
}

impl std::fmt::Debug for ClientMux {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientMux")
            .field("endpoints", &self.inner.endpoints.len())
            .field("active", &self.active_underlays())
            .finish()
    }
}

impl ClientMux {
    /// Build a mux over `endpoints`, delegating handshakes to `handshake`.
    pub fn new(
        config: MuxConfig,
        endpoints: Vec<Endpoint>,
        handshake: Box<dyn ClientHandshake>,
    ) -> UnderlayResult<Self> {
        config.validate()?;
        if endpoints.is_empty() {
            return Err(UnderlayError::InvalidEndpoint(
                "client mux needs at least one endpoint".to_owned(),
            ));
        }
        Ok(Self {
            inner: Arc::new(ClientMuxInner {
                config,
                endpoints,
                handshake,
                upstream: Mutex::new(None),
                next_endpoint: AtomicUsize::new(0),
                active: AtomicUsize::new(0),
                stopped: AtomicBool::new(false),
                sessions: DashMap::new(),
            }),
        })
    }

    /// Install an upstream dialer (for example another SOCKS5 proxy).
    pub async fn set_upstream(&self, upstream: Arc<dyn ProxyDialer>) {
        *self.inner.upstream.lock().await = Some(upstream);
    }

    /// Mux configuration.
    #[must_use]
    pub fn config(&self) -> &MuxConfig {
        &self.inner.config
    }

    /// Configured endpoints.
    #[must_use]
    pub fn endpoints(&self) -> &[Endpoint] {
        &self.inner.endpoints
    }

    /// Underlays currently in use.
    #[must_use]
    pub fn active_underlays(&self) -> usize {
        self.inner.active.load(Ordering::Relaxed)
    }

    /// Live sessions.
    #[must_use]
    pub fn session_count(&self) -> usize {
        self.inner.sessions.len()
    }

    /// Whether `stop` was called.
    #[must_use]
    pub fn is_stopped(&self) -> bool {
        self.inner.stopped.load(Ordering::Relaxed)
    }

    /// Allocate a non-zero, unpredictable session ID.
    ///
    /// Sequential IDs are a stable traffic fingerprint: the session ID is
    /// visible in the UDP routing envelope, where an observer can correlate it
    /// across packet lengths and timing. Draw a random 32-bit value instead,
    /// retrying on the reserved value 0 and on a rare collision with a live
    /// session.
    pub fn allocate_session_id(&self) -> UnderlayResult<u32> {
        for _ in 0..8 {
            let id = rand::random::<u32>();
            if id != 0 && !self.inner.sessions.contains_key(&id) {
                return Ok(id);
            }
        }
        Err(UnderlayError::LimitReached("session IDs"))
    }

    /// Try to reserve an underlay slot.
    pub fn try_reserve_underlay(&self) -> UnderlayResult<()> {
        let max = self.inner.config.max_underlays;
        let mut current = self.inner.active.load(Ordering::Relaxed);
        loop {
            if current >= max {
                return Err(UnderlayError::LimitReached("underlays"));
            }
            match self.inner.active.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Ok(()),
                Err(actual) => current = actual,
            }
        }
    }

    /// Release an underlay slot (handshake drivers should call this when a
    /// session closes).
    pub fn release_underlay(&self) {
        let mut current = self.active_underlays();
        while current > 0 {
            match self.inner.active.compare_exchange_weak(
                current,
                current - 1,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return,
                Err(actual) => current = actual,
            }
        }
    }

    /// Whether the reuse policy selects an existing packet underlay.
    #[must_use]
    pub fn should_reuse_packet(&self) -> bool {
        let factor = self.inner.config.multiplexing.reuse_factor();
        if factor == 0 {
            return false;
        }
        let active = self.active_underlays().min(usize::MAX / factor);
        let reuse_slots = active.saturating_mul(factor);
        if reuse_slots == 0 {
            return false;
        }
        // Slots: `reuse_slots` reuse + 1 new slot.
        rand::random_range(0..=reuse_slots) < reuse_slots
    }

    fn next_endpoint(&self) -> &Endpoint {
        let index = self.inner.next_endpoint.fetch_add(1, Ordering::Relaxed);
        &self.inner.endpoints[index % self.inner.endpoints.len()]
    }

    /// Drop all sessions and reset endpoint rotation (reconnection).
    pub fn reconnect(&self) {
        self.inner.sessions.clear();
        self.inner.active.store(0, Ordering::Release);
        self.inner.next_endpoint.store(0, Ordering::Release);
        self.inner.stopped.store(false, Ordering::Release);
    }

    /// Close one session and release its underlay slot.
    pub fn close_session(&self, session_id: u32) {
        if self.inner.sessions.remove(&session_id).is_some() {
            self.inner.handshake.close_session(session_id);
            self.release_underlay();
        }
    }

    /// Stop all dialing and clear session state.
    pub fn stop(&self) {
        self.inner.stopped.store(true, Ordering::Release);
        for entry in self.inner.sessions.iter() {
            self.inner.handshake.close_session(*entry.key());
        }
        self.inner.sessions.clear();
        self.inner.active.store(0, Ordering::Release);
    }

    /// Dial a byte-stream session through the UDP tunnel (SOCKS5 CONNECT
    /// equivalent). The handshake adapter owns the UDP socket and returns a
    /// byte stream carrying only this session's application data.
    pub fn open_tcp<'a>(
        &'a self,
        target: SocketAddr,
        host: Option<&'a str>,
    ) -> BoxFuture<'a, io::Result<Box<dyn AsyncIo>>> {
        Box::pin(async move {
            if self.is_stopped() {
                return Err(io::Error::new(io::ErrorKind::Interrupted, "mux stopped"));
            }
            let endpoint = self.next_endpoint();
            let server_addr = endpoint
                .address_for(TransportKind::Udp)
                .await
                .map_err(io_error)?;
            let session_id = self.allocate_session_id().map_err(io_error)?;
            self.try_reserve_underlay().map_err(io_error)?;
            let reuse = self.should_reuse_packet();
            debug!(session_id, reuse, %server_addr, "opening stream-over-UDP session");

            let handshake = time::timeout(
                self.inner.config.handshake_timeout,
                self.inner
                    .handshake
                    .open_tcp(session_id, endpoint, target, host, reuse),
            )
            .await;
            match handshake {
                Ok(Ok(stream)) => {
                    self.inner.sessions.insert(
                        session_id,
                        SessionInfo {
                            kind: UnderlayKind::Packet,
                            opened_at: Instant::now(),
                        },
                    );
                    Ok(stream)
                }
                Ok(Err(error)) => {
                    self.release_underlay();
                    Err(error)
                }
                Err(_) => {
                    self.release_underlay();
                    Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "handshake timed out",
                    ))
                }
            }
        })
    }

    /// Dial a datagram session through the tunnel (SOCKS5 UDP ASSOCIATE
    /// equivalent).
    pub fn open_udp<'a>(
        &'a self,
        target: SocketAddr,
        host: Option<&'a str>,
    ) -> BoxFuture<'a, io::Result<Box<dyn DatagramSocket>>> {
        Box::pin(async move {
            if self.is_stopped() {
                return Err(io::Error::new(io::ErrorKind::Interrupted, "mux stopped"));
            }
            let endpoint = self.next_endpoint();
            let session_id = self.allocate_session_id().map_err(io_error)?;
            self.try_reserve_underlay().map_err(io_error)?;
            let reuse = self.should_reuse_packet();
            debug!(session_id, reuse, "opening UDP session");

            let handshake = time::timeout(
                self.inner.config.handshake_timeout,
                self.inner
                    .handshake
                    .open_udp(session_id, endpoint, target, host, reuse),
            )
            .await;
            match handshake {
                Ok(Ok(socket)) => {
                    self.inner.sessions.insert(
                        session_id,
                        SessionInfo {
                            kind: UnderlayKind::Packet,
                            opened_at: Instant::now(),
                        },
                    );
                    Ok(socket)
                }
                Ok(Err(error)) => {
                    self.release_underlay();
                    Err(error)
                }
                Err(_) => {
                    self.release_underlay();
                    Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "handshake timed out",
                    ))
                }
            }
        })
    }
}

impl ProxyDialer for ClientMux {
    fn dial_tcp<'a>(
        &'a self,
        addr: SocketAddr,
        host: Option<&'a str>,
    ) -> BoxFuture<'a, io::Result<Box<dyn AsyncIo>>> {
        self.open_tcp(addr, host)
    }

    fn dial_udp<'a>(
        &'a self,
        addr: SocketAddr,
        host: Option<&'a str>,
    ) -> BoxFuture<'a, io::Result<Box<dyn DatagramSocket>>> {
        self.open_udp(addr, host)
    }
}

/// Per-source token bucket state.
#[derive(Debug, Clone)]
pub struct TokenBucket {
    tokens: f64,
    last: Instant,
    burst: usize,
    refill_per_second: f64,
}

impl TokenBucket {
    /// Create a full bucket.
    #[must_use]
    pub fn new(burst: usize, refill_per_second: u64) -> Self {
        Self {
            tokens: burst as f64,
            last: Instant::now(),
            burst,
            refill_per_second: refill_per_second as f64,
        }
    }

    /// Consume one token, refilling with elapsed wall time first.
    pub fn allow(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + elapsed * self.refill_per_second).min(self.burst as f64);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Tokens currently available.
    #[must_use]
    pub fn tokens(&self) -> f64 {
        self.tokens
    }
}

#[derive(Debug)]
struct SourceState {
    bucket: TokenBucket,
    last_seen: Instant,
}

#[derive(Debug)]
struct UnderlayRecord {
    kind: UnderlayKind,
    sessions: usize,
    last_seen: Instant,
}

struct ServerMuxInner {
    config: MuxConfig,
    listen_ip: IpAddr,
    bindings: Vec<PortBindingSpec>,
    handshake: Arc<dyn ServerHandshake>,
    sources: DashMap<IpAddr, SourceState>,
    underlays: DashMap<u64, UnderlayRecord>,
    next_underlay_id: AtomicU64,
    stopped: AtomicBool,
    started: AtomicBool,
    tasks: Mutex<Vec<JoinHandle<()>>>,
    notify: Notify,
}

/// Server-side multiplexer.
#[derive(Clone)]
pub struct ServerMux {
    inner: Arc<ServerMuxInner>,
}

impl std::fmt::Debug for ServerMux {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerMux")
            .field("listen_ip", &self.inner.listen_ip)
            .field("bindings", &self.inner.bindings.len())
            .field("underlays", &self.active_underlays())
            .finish()
    }
}

impl ServerMux {
    /// Build a server mux listening on `listen_ip` and `bindings`.
    pub fn new(
        config: MuxConfig,
        listen_ip: IpAddr,
        bindings: Vec<PortBindingSpec>,
        handshake: Arc<dyn ServerHandshake>,
    ) -> UnderlayResult<Self> {
        config.validate()?;
        if bindings.is_empty() {
            return Err(UnderlayError::InvalidEndpoint(
                "server mux needs at least one port binding".to_owned(),
            ));
        }
        Ok(Self {
            inner: Arc::new(ServerMuxInner {
                config,
                listen_ip,
                bindings,
                handshake,
                sources: DashMap::new(),
                underlays: DashMap::new(),
                next_underlay_id: AtomicU64::new(1),
                stopped: AtomicBool::new(false),
                started: AtomicBool::new(false),
                tasks: Mutex::new(Vec::new()),
                notify: Notify::new(),
            }),
        })
    }

    /// Mux configuration.
    #[must_use]
    pub fn config(&self) -> &MuxConfig {
        &self.inner.config
    }

    /// Number of tracked underlays.
    #[must_use]
    pub fn active_underlays(&self) -> usize {
        self.inner.underlays.len()
    }

    /// Number of source buckets.
    #[must_use]
    pub fn source_count(&self) -> usize {
        self.inner.sources.len()
    }

    /// Whether the mux is running.
    #[must_use]
    pub fn is_running(&self) -> bool {
        self.inner.started.load(Ordering::Acquire) && !self.inner.stopped.load(Ordering::Acquire)
    }

    /// Start listeners and the cleaner. Calling `start` twice is a no-op.
    pub async fn start(&self) -> UnderlayResult<()> {
        if self
            .inner
            .started
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
        {
            return Ok(());
        }
        self.inner.stopped.store(false, Ordering::Release);
        let mut tasks = self.inner.tasks.lock().await;
        tasks.push(tokio::spawn(cleanup_task(Arc::clone(&self.inner))));
        for binding in &self.inner.bindings {
            tasks.push(tokio::spawn(udp_listener_task(
                Arc::clone(&self.inner),
                binding.port,
            )));
        }
        Ok(())
    }

    /// Stop all listeners, abort their tasks and clear rate-limit state.
    pub async fn stop(&self) {
        self.inner.stopped.store(true, Ordering::Release);
        self.inner.notify.notify_waiters();
        let mut tasks = self.inner.tasks.lock().await;
        for task in tasks.drain(..) {
            task.abort();
        }
        self.inner.underlays.clear();
        self.inner.sources.clear();
    }

    /// Apply per-source accept limiting. Hosts without a valid IP are allowed.
    ///
    /// Exposed so deployments/tests can share the listener's rate limiter.
    pub fn allow_source(&self, ip: IpAddr) -> bool {
        self.inner.allow_source(ip)
    }
}

impl ServerMuxInner {
    fn allow_source(&self, ip: IpAddr) -> bool {
        if ip.is_unspecified() {
            return true;
        }
        let now = Instant::now();
        if let Some(mut state) = self.sources.get_mut(&ip) {
            state.last_seen = now;
            return state.bucket.allow();
        }
        if self.sources.len() >= self.config.max_sources {
            self.evict_oldest_source();
        }
        let mut bucket = TokenBucket::new(
            self.config.accept_burst,
            self.config.accept_refill_per_second,
        );
        let allowed = bucket.allow();
        self.sources.insert(
            ip,
            SourceState {
                bucket,
                last_seen: now,
            },
        );
        allowed
    }

    fn evict_oldest_source(&self) {
        let oldest = self
            .sources
            .iter()
            .min_by_key(|entry| entry.value().last_seen)
            .map(|entry| *entry.key());
        if let Some(ip) = oldest {
            self.sources.remove(&ip);
        }
    }

    fn register_underlay(&self, kind: UnderlayKind) -> UnderlayResult<u64> {
        if self.underlays.len() >= self.config.max_underlays {
            return Err(UnderlayError::LimitReached("underlays"));
        }
        let id = self.next_underlay_id.fetch_add(1, Ordering::Relaxed);
        self.underlays.insert(
            id,
            UnderlayRecord {
                kind,
                sessions: 1,
                last_seen: Instant::now(),
            },
        );
        Ok(id)
    }
}

async fn udp_listener_task(inner: Arc<ServerMuxInner>, port: u16) {
    let addr = SocketAddr::new(inner.listen_ip, port);
    let mut underlay = match crate::underlay_packet::PacketUnderlay::bind(
        addr,
        AeadKey::new(Suite::XChaCha20Poly1305, &[0u8; 32]).expect("zero key is valid"),
        inner.config.packet_config(),
    )
    .await
    {
        Ok(underlay) => underlay,
        Err(error) => {
            warn!(%addr, %error, "failed to bind UDP underlay listener");
            return;
        }
    };
    let mut attempt = 0u32;
    loop {
        if inner.stopped.load(Ordering::Acquire) {
            break;
        }
        match underlay.recv_raw().await {
            Ok((datagram, source)) => {
                attempt = 0;
                if !inner.allow_source(source.ip()) {
                    debug!(%source, "source rate limit exceeded");
                    continue;
                }
                if inner.underlays.len() >= inner.config.max_underlays {
                    debug!(%source, "underlay limit reached");
                    continue;
                }
                let id = match inner.register_underlay(UnderlayKind::Packet) {
                    Ok(id) => id,
                    Err(_) => continue,
                };
                let handshake = Arc::clone(&inner.handshake);
                let timeout = inner.config.handshake_timeout;
                let response = time::timeout(timeout, handshake.accept_udp(datagram, source)).await;
                inner.underlays.remove(&id);
                match response {
                    Ok(Ok(replies)) => {
                        for reply in replies {
                            if let Err(error) = underlay.send_to(&reply, source).await {
                                warn!(%source, %error, "failed to send UDP reply");
                            }
                        }
                    }
                    Ok(Err(error)) => debug!(%source, %error, "UDP handshake failed"),
                    Err(_) => debug!(%source, "UDP handshake timed out"),
                }
            }
            Err(error) => {
                warn!(%addr, %error, "UDP socket error; rebuilding listener");
                attempt += 1;
                let delay = inner.config.rebuild_delay(attempt);
                tokio::select! {
                    _ = time::sleep(delay) => {}
                    _ = inner.notify.notified() => break,
                }
                if let Err(error) = underlay.rebind().await {
                    warn!(%addr, %error, "UDP listener rebuild failed");
                }
            }
        }
    }
}

async fn cleanup_task(inner: Arc<ServerMuxInner>) {
    let mut ticker = time::interval(inner.config.cleanup_interval);
    loop {
        tokio::select! {
            _ = inner.notify.notified() => break,
            _ = ticker.tick() => {
                let ttl = inner.config.underlay_ttl;
                let idle = inner.config.source_idle_timeout;
                inner.underlays.retain(|id, record| {
                    let keep = record.sessions > 0 || record.last_seen.elapsed() < ttl;
                    if !keep {
                        debug!(id, kind = %record.kind, "expiring idle underlay");
                    }
                    keep
                });
                inner.sources.retain(|_, state| state.last_seen.elapsed() < idle);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint() -> Vec<Endpoint> {
        vec![Endpoint::new(
            "127.0.0.1",
            vec![PortBindingSpec::new(2012, TransportKind::Udp)],
        )]
    }

    #[tokio::test]
    async fn client_resolves_endpoint_and_allocates_nonzero_ids() {
        let mux = ClientMux::new(
            MuxConfig::default(),
            endpoint(),
            Box::new(PassthroughClientHandshake),
        )
        .unwrap();
        let udp = mux.endpoints()[0]
            .address_for(TransportKind::Udp)
            .await
            .unwrap();
        assert_eq!(udp.port(), 2012);
        let mut seen = std::collections::HashSet::new();
        for _ in 0..10 {
            let id = mux.allocate_session_id().unwrap();
            assert_ne!(id, 0);
            seen.insert(id);
        }
        assert_eq!(seen.len(), 10);
    }

    #[tokio::test]
    async fn client_enforces_small_underlay_limit() {
        let config = MuxConfig {
            max_underlays: 2,
            ..MuxConfig::default()
        };
        let mux = ClientMux::new(config, endpoint(), Box::new(PassthroughClientHandshake)).unwrap();
        mux.try_reserve_underlay().unwrap();
        mux.try_reserve_underlay().unwrap();
        assert!(matches!(
            mux.try_reserve_underlay().unwrap_err(),
            UnderlayError::LimitReached("underlays")
        ));
        assert_eq!(mux.active_underlays(), 2);
        mux.release_underlay();
        mux.try_reserve_underlay().unwrap();
        mux.stop();
        assert!(mux.is_stopped());
        assert_eq!(mux.active_underlays(), 0);
    }

    #[tokio::test]
    async fn multiplexing_level_controls_reuse() {
        for (level, factor) in [
            (Multiplexing::Off, 0),
            (Multiplexing::Low, 1),
            (Multiplexing::Middle, 2),
            (Multiplexing::High, 3),
        ] {
            assert_eq!(level.reuse_factor(), factor);
            let mux = ClientMux::new(
                MuxConfig {
                    multiplexing: level,
                    ..MuxConfig::default()
                },
                endpoint(),
                Box::new(PassthroughClientHandshake),
            )
            .unwrap();
            if factor == 0 {
                for _ in 0..20 {
                    assert!(!mux.should_reuse_packet());
                }
            }
        }
    }

    #[test]
    fn token_bucket_uses_burst_and_refill() {
        let mut bucket = TokenBucket::new(3, 10);
        assert!(bucket.allow());
        assert!(bucket.allow());
        assert!(bucket.allow());
        assert!(!bucket.allow());
        std::thread::sleep(Duration::from_millis(120));
        assert!(bucket.allow());
    }

    #[tokio::test]
    async fn server_mux_enforces_source_limit_and_start_stop() {
        let config = MuxConfig {
            max_sources: 2,
            accept_burst: 1,
            cleanup_interval: Duration::from_millis(10),
            underlay_ttl: Duration::from_millis(20),
            ..MuxConfig::default()
        };
        let mux = ServerMux::new(
            config,
            "127.0.0.1".parse().unwrap(),
            vec![PortBindingSpec::new(0, TransportKind::Udp)],
            Arc::new(NoopServerHandshake),
        )
        .unwrap();
        assert!(mux.allow_source("10.0.0.1".parse().unwrap()));
        assert!(mux.allow_source("10.0.0.2".parse().unwrap()));
        assert!(!mux.allow_source("10.0.0.1".parse().unwrap()));
        assert!(mux.allow_source("10.0.0.3".parse().unwrap()));
        assert!(mux.source_count() <= 2);

        mux.start().await.unwrap();
        assert!(mux.is_running());
        mux.start().await.unwrap(); // idempotent
        time::sleep(Duration::from_millis(30)).await;
        mux.stop().await;
        assert!(!mux.is_running());
    }
}
