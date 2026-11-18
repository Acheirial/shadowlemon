//! SOCKS5 server: handshake, CONNECT, UDP ASSOCIATE and relaying.

use std::{
    collections::HashMap,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex},
    time::Duration,
};

use tokio::{
    io::{split, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufStream},
    net::{TcpListener, UdpSocket},
    time::timeout,
};

use crate::{
    auth::{authenticate, client_handshake},
    egress::EgressAction,
    proto::{
        encode_error_reply, encode_reply, parse_udp_datagram, read_reply, read_request, Address,
        Request, MAX_UDP_DATAGRAM, REP_COMMAND_NOT_SUPPORTED, REP_CONNECTION_REFUSED,
        REP_HOST_UNREACHABLE, REP_NETWORK_UNREACHABLE, REP_NOT_ALLOWED, REP_SUCCESS,
    },
    resolve_target,
};
use crate::{Credential, EgressConfig, Error, ProxyDialer, Resolver, Result, SystemResolver};

/// Default handshake timeout (greeting, authentication and request).
pub const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum concurrent UDP associations per authenticated user.
pub const MAX_UDP_ASSOCIATIONS_PER_USER: usize = 32;

/// Server configuration.
///
/// Use [`Config::new`] with the injected [`ProxyDialer`], then adjust the
/// public fields or chain the `with_*` builder methods.
pub struct Config {
    /// Credentials for incoming USERNAME/PASSWORD authentication. When this
    /// list is empty, NO_AUTH is accepted and USERNAME/PASSWORD is refused.
    pub credentials: Vec<Credential>,
    /// Timeout for the greeting, authentication and request. Zero means no
    /// timeout.
    pub handshake_timeout: Duration,
    /// Custom resolver. `None` selects [`SystemResolver`].
    pub resolver: Option<Arc<dyn Resolver>>,
    /// The dialer used for all outbound TCP and UDP connections.
    pub dialer: Arc<dyn ProxyDialer>,
    /// Egress policy applied to every request (and to every UDP datagram).
    pub egress: EgressConfig,
    /// When true, the server sends the CONNECT success reply immediately and
    /// tolerates application data piggybacked after the SOCKS5 request. The
    /// buffered stream always preserves such bytes. For PROXY egress rules it
    /// also suppresses the downstream proxy's reply, matching the Go
    /// `HandshakeNoWait` behaviour.
    pub no_wait: bool,
}

impl Config {
    /// Creates a configuration with sensible defaults and the given dialer.
    pub fn new(dialer: Arc<dyn ProxyDialer>) -> Self {
        Self {
            credentials: Vec::new(),
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
            resolver: None,
            dialer,
            egress: EgressConfig::new(),
            no_wait: false,
        }
    }

    /// Sets the ingress credentials.
    pub fn with_credentials(mut self, credentials: Vec<Credential>) -> Self {
        self.credentials = credentials;
        self
    }

    /// Sets the handshake timeout.
    pub fn with_handshake_timeout(mut self, timeout: Duration) -> Self {
        self.handshake_timeout = timeout;
        self
    }

    /// Sets a custom resolver.
    pub fn with_resolver(mut self, resolver: Arc<dyn Resolver>) -> Self {
        self.resolver = Some(resolver);
        self
    }

    /// Sets the egress policy.
    pub fn with_egress(mut self, egress: EgressConfig) -> Self {
        self.egress = egress;
        self
    }

    /// Enables or disables no-wait handshake handling.
    pub fn with_no_wait(mut self, no_wait: bool) -> Self {
        self.no_wait = no_wait;
        self
    }
}

struct Inner {
    config: Config,
    resolver: Arc<dyn Resolver>,
    udp_associations: Mutex<HashMap<String, usize>>,
}

/// A shareable SOCKS5 server instance.
#[derive(Clone)]
pub struct Server {
    inner: Arc<Inner>,
}

impl Server {
    /// Creates a server from the given configuration.
    pub fn new(config: Config) -> Self {
        let resolver = config
            .resolver
            .clone()
            .unwrap_or_else(|| Arc::new(SystemResolver));
        Self {
            inner: Arc::new(Inner {
                config,
                resolver,
                udp_associations: Mutex::new(HashMap::new()),
            }),
        }
    }

    /// Serves a single connection until it closes or errors.
    ///
    /// Accepts any tokio async stream; `listen_and_serve` passes accepted
    /// `TcpStream`s, while tests may pass in-memory duplex streams.
    pub async fn serve<S>(&self, stream: S) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        self.serve_io(stream).await
    }

    /// Binds `addr` and serves connections forever, one task per connection.
    pub async fn listen_and_serve(&self, addr: &str) -> io::Result<()> {
        let listener = TcpListener::bind(addr).await?;
        loop {
            let (stream, _) = listener.accept().await?;
            let server = self.clone();
            tokio::spawn(async move {
                if let Err(err) = server.serve(stream).await {
                    tracing::debug!("SOCKS5 connection closed with error: {err}");
                }
            });
        }
    }

    async fn serve_io<S>(&self, io: S) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let mut stream = BufStream::new(io);
        let (user, request, raw_request) = {
            let config = &self.inner.config;
            let handshake = async {
                let user = authenticate(&mut stream, &config.credentials).await?;
                let (request, raw) = read_request(&mut stream).await?;
                Ok::<_, Error>((user, request, raw))
            };
            if config.handshake_timeout.is_zero() {
                handshake.await?
            } else {
                match timeout(config.handshake_timeout, handshake).await {
                    Ok(result) => result?,
                    Err(_) => return Err(Error::HandshakeTimeout),
                }
            }
        };

        match request.command {
            crate::CMD_CONNECT => {
                self.handle_connect(&mut stream, &request, &raw_request)
                    .await
            }
            crate::CMD_UDP_ASSOCIATE => {
                self.handle_udp_associate(&mut stream, &request, &user)
                    .await
            }
            crate::CMD_BIND => {
                send_reply(&mut stream, REP_COMMAND_NOT_SUPPORTED).await?;
                Err(Error::UnsupportedCommand(crate::CMD_BIND))
            }
            other => {
                send_reply(&mut stream, REP_COMMAND_NOT_SUPPORTED).await?;
                Err(Error::UnsupportedCommand(other))
            }
        }
    }

    async fn handle_connect<S>(
        &self,
        stream: &mut S,
        request: &Request,
        raw_request: &[u8],
    ) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let (ip, host) = match resolve_target(&request.address, self.inner.resolver.as_ref()).await
        {
            Ok(result) => result,
            Err(err) => {
                send_reply(stream, REP_HOST_UNREACHABLE).await?;
                return Err(err);
            }
        };

        let decision = self
            .inner
            .config
            .egress
            .find_action(Some(ip), host.as_deref());
        if decision.action == EgressAction::Reject {
            send_reply(stream, REP_NOT_ALLOWED).await?;
            return Err(Error::Rejected);
        }

        if decision.action == EgressAction::Proxy {
            let proxy = decision.proxy.clone().ok_or(Error::NoEgressProxy)?;
            let (proxy_ip, _) = resolve_target(
                &Address::Domain(proxy.host.clone()),
                self.inner.resolver.as_ref(),
            )
            .await?;
            let proxy_addr = SocketAddr::new(proxy_ip, proxy.port);
            let mut downstream = self.dial_tcp(proxy_addr, Some(&proxy.host)).await?;
            client_handshake(&mut downstream, proxy.credential.as_ref()).await?;
            downstream.write_all(raw_request).await?;
            downstream.flush().await?;

            if self.inner.config.no_wait {
                // Fabricate success for the local client and consume the real
                // downstream reply so it is not mistaken for application data.
                stream
                    .write_all(&encode_reply(
                        REP_SUCCESS,
                        &Address::Ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
                        0,
                    ))
                    .await?;
                stream.flush().await?;
                read_reply(&mut downstream).await?;
            }
            return relay(stream, &mut downstream).await;
        }

        let target = SocketAddr::new(ip, request.port);
        let mut outbound = match self.dial_tcp(target, host.as_deref()).await {
            Ok(stream) => stream,
            Err(err) => {
                let reply = map_dial_error(&err);
                send_reply(stream, reply).await?;
                return Err(err);
            }
        };

        stream
            .write_all(&encode_reply(
                REP_SUCCESS,
                &Address::Ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
                0,
            ))
            .await?;
        stream.flush().await?;

        relay(stream, &mut outbound).await
    }

    async fn handle_udp_associate<S>(
        &self,
        stream: &mut S,
        request: &Request,
        user: &str,
    ) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        if !self.acquire_udp_association(user) {
            send_reply(stream, REP_NOT_ALLOWED).await?;
            return Err(Error::TooManyUdpAssociations);
        }
        let result = self.udp_associate_inner(stream, request).await;
        self.release_udp_association(user);
        result
    }

    async fn udp_associate_inner<S>(&self, stream: &mut S, request: &Request) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let relay_socket = UdpSocket::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))).await?;
        let bind_port = relay_socket.local_addr()?.port();
        stream
            .write_all(&encode_reply(
                REP_SUCCESS,
                &Address::Ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
                bind_port,
            ))
            .await?;
        stream.flush().await?;

        let host = request.address.host();
        let outbound = self
            .dial_udp(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)), host)
            .await?;

        let declared_client_ip = request.address.ip().filter(|ip| !ip.is_unspecified());
        let mut client_addr: Option<SocketAddr> = None;
        // Maps a responder address to the verbatim header of the request that
        // created it, so the response uses the address type the client expects.
        let mut headers: HashMap<SocketAddr, Vec<u8>> = HashMap::new();
        // Fallback keyed by destination port for pass-through (domain) targets.
        let mut reply_headers: HashMap<u16, Vec<u8>> = HashMap::new();
        let mut from_client = vec![0u8; MAX_UDP_DATAGRAM];
        let mut from_outbound = vec![0u8; MAX_UDP_DATAGRAM];
        let mut control = [0u8; 1];

        loop {
            tokio::select! {
                received = relay_socket.recv_from(&mut from_client) => {
                    let (length, source) = received?;
                    match client_addr {
                        Some(expected) if source != expected => continue,
                        None => {
                            if declared_client_ip.is_some_and(|ip| ip != source.ip()) {
                                continue;
                            }
                            client_addr = Some(source);
                        }
                        _ => {}
                    }

                    let datagram = match parse_udp_datagram(&from_client[..length]) {
                        Ok(datagram) => datagram,
                        Err(err) => {
                            tracing::debug!("dropping invalid SOCKS5 UDP datagram: {err}");
                            continue;
                        }
                    };
                    let (ip, host) =
                        match resolve_target(&datagram.address, self.inner.resolver.as_ref()).await {
                            Ok(result) => result,
                            Err(err) => {
                                tracing::debug!("dropping UDP datagram: {err}");
                                continue;
                            }
                        };
                    let decision = self.inner.config.egress.find_action(Some(ip), host.as_deref());
                    if decision.action == EgressAction::Reject {
                        tracing::debug!("UDP datagram to {ip} rejected by egress policy");
                        continue;
                    }
                    let target = SocketAddr::new(ip, datagram.port);
                    if let Err(err) = outbound
                        .send_to_host(&datagram.payload, target, host.as_deref())
                        .await
                    {
                        tracing::debug!("outbound UDP send failed: {err}");
                        continue;
                    }
                    // With a pass-through resolver `ip` is a loopback
                    // placeholder while the real responder reports its actual
                    // IP on reply, so the exact-key lookup below would miss.
                    // Index by port as a fallback; UDP association ports are
                    // unique per destination in the common case.
                    reply_headers.insert(datagram.port, datagram.header.clone());
                    headers.insert(target, datagram.header);
                }

                received = outbound.recv_from(&mut from_outbound) => {
                    let (length, source) = match received {
                        Ok(result) => result,
                        Err(err) => {
                            tracing::debug!("outbound UDP receive failed: {err}");
                            continue;
                        }
                    };
                    let header = headers
                        .get(&source)
                        .or_else(|| reply_headers.get(&source.port()));
                    let (Some(header), Some(client)) = (header, client_addr) else {
                        // Off-path datagram: never inject it into the client.
                        continue;
                    };
                    let packet = crate::proto::encode_udp_datagram(header, &from_outbound[..length]);
                    if let Err(err) = relay_socket.send_to(&packet, client).await {
                        tracing::debug!("UDP response to client failed: {err}");
                    }
                }

                control_result = stream.read(&mut control) => {
                    match control_result {
                        Ok(0) | Err(_) => break,
                        // Any data on the control channel is discarded; the
                        // association ends when the TCP connection closes.
                        Ok(_) => continue,
                    }
                }
            }
        }
        Ok(())
    }

    async fn dial_tcp(
        &self,
        addr: SocketAddr,
        host: Option<&str>,
    ) -> Result<Box<dyn crate::AsyncIo>> {
        let future = self.inner.config.dialer.dial_tcp(addr, host);
        if self.inner.config.handshake_timeout.is_zero() {
            future.await.map_err(|err| Error::Dial(err.to_string()))
        } else {
            match timeout(self.inner.config.handshake_timeout, future).await {
                Ok(result) => result.map_err(|err| Error::Dial(err.to_string())),
                Err(_) => Err(Error::Dial("outbound TCP dial timed out".to_owned())),
            }
        }
    }

    async fn dial_udp(
        &self,
        addr: SocketAddr,
        host: Option<&str>,
    ) -> Result<Box<dyn crate::DatagramSocket>> {
        let future = self.inner.config.dialer.dial_udp(addr, host);
        if self.inner.config.handshake_timeout.is_zero() {
            future.await.map_err(|err| Error::Dial(err.to_string()))
        } else {
            match timeout(self.inner.config.handshake_timeout, future).await {
                Ok(result) => result.map_err(|err| Error::Dial(err.to_string())),
                Err(_) => Err(Error::Dial("outbound UDP dial timed out".to_owned())),
            }
        }
    }

    fn acquire_udp_association(&self, user: &str) -> bool {
        let mut associations = self.inner.udp_associations.lock().unwrap();
        let count = associations.entry(user.to_owned()).or_insert(0);
        if *count >= MAX_UDP_ASSOCIATIONS_PER_USER {
            false
        } else {
            *count += 1;
            true
        }
    }

    fn release_udp_association(&self, user: &str) {
        let mut associations = self.inner.udp_associations.lock().unwrap();
        let should_remove = match associations.get_mut(user) {
            Some(count) => {
                *count -= 1;
                *count == 0
            }
            None => false,
        };
        if should_remove {
            associations.remove(user);
        }
    }
}

async fn send_reply<S>(stream: &mut S, reply: u8) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    stream.write_all(&encode_error_reply(reply)).await?;
    stream.flush().await?;
    Ok(())
}

fn map_dial_error(err: &Error) -> u8 {
    let message = err.to_string().to_ascii_lowercase();
    if message.contains("refused") {
        REP_CONNECTION_REFUSED
    } else if message.contains("network is unreachable") {
        REP_NETWORK_UNREACHABLE
    } else {
        REP_HOST_UNREACHABLE
    }
}

/// Copies bytes in both directions until both sides close or an error occurs.
async fn relay<A, B>(a: &mut A, b: &mut B) -> Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    let (mut a_read, mut a_write) = split(&mut *a);
    let (mut b_read, mut b_write) = split(&mut *b);

    let a_to_b = async {
        let result = tokio::io::copy(&mut a_read, &mut b_write).await;
        let _ = b_write.shutdown().await;
        result
    };
    let b_to_a = async {
        let result = tokio::io::copy(&mut b_read, &mut a_write).await;
        let _ = a_write.shutdown().await;
        result
    };

    let (first, second) = tokio::join!(a_to_b, b_to_a);
    first?;
    second?;
    Ok(())
}
