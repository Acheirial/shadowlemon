//! Foreground client/server runtimes and the optional upstream SOCKS5 dialer.

use std::{
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::{atomic::AtomicI32, Arc},
    time::Duration,
};

use futures::future::BoxFuture;
use shadowlemon_config::{
    ClientConfig, ClientDialer, PortBinding, ServerConfig, TransportProtocol,
};
use shadowlemon_protocol::{
    mux::{ClientMux, Endpoint, PortBindingSpec, ServerMux, TransportKind},
    RealClientHandshake, RealServerHandshake,
};
use shadowlemon_socks5::{
    encode_request, Address, AsyncIo, Credential, DatagramSocket, PassThroughResolver, ProxyDialer,
    Server, ATYP_DOMAIN, ATYP_IPV4, ATYP_IPV6, CMD_CONNECT, VERSION,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tracing::{debug, info, warn};

use crate::{
    config::{
        active_profile, client_driver_config, client_mux_config, load_client, load_server,
        server_driver_config, server_mux_config, socks_credentials,
    },
    platform::{self, PidFile},
    AppError, Mode,
};

const METHOD_NO_AUTH: u8 = 0;
const METHOD_USERPASS: u8 = 2;
const USERPASS_VERSION: u8 = 1;

/// Run the SOCKS5 ingress in the foreground until a shutdown signal arrives.
pub async fn run_client(path: PathBuf, stop: &'static AtomicI32) -> Result<(), AppError> {
    let _pidfile = PidFile::acquire(Mode::Client)?;
    let config: ClientConfig = load_client(&path)?;
    let profile = active_profile(&config)?;
    let driver_config = client_driver_config(profile)?;
    let suites = driver_config.suites.clone();
    info!(
        user = %driver_config.username,
        suites = ?suites,
        "ShadowLemon V0.2 cipher suite configuration loaded"
    );

    let endpoints = profile
        .servers
        .iter()
        .filter_map(endpoint_from_config)
        .collect::<Vec<_>>();
    if endpoints.is_empty() {
        return Err(AppError::Config(
            "active profile has no usable server endpoints".to_owned(),
        ));
    }
    let mux = ClientMux::new(
        client_mux_config(profile),
        endpoints,
        Box::new(RealClientHandshake::new(driver_config).map_err(AppError::Io)?),
    )
    .map_err(|error| AppError::Config(error.to_string()))?;
    if let Some(dialer) = profile.dialer.as_ref() {
        mux.set_upstream(Arc::new(UpstreamSocks5::new(dialer)?))
            .await;
    }

    // Never resolve SOCKS5 target domains locally: that would leak them through
    // the client's DNS. The tunnel carries Address::Domain to the server, which
    // performs the real lookup at its egress; this resolver only supplies a
    // harmless placeholder IP for local bookkeeping.
    let mut socks_config = shadowlemon_socks5::Config::new(Arc::new(mux.clone()))
        .with_credentials(socks_credentials(&config))
        .with_resolver(Arc::new(PassThroughResolver));
    if matches!(
        profile.handshake_mode,
        Some(shadowlemon_config::HandshakeMode::HandshakeNoWait)
    ) {
        socks_config = socks_config.with_no_wait(true);
    }
    let server = Server::new(socks_config);
    let port = u16::try_from(config.socks5_port.unwrap_or(1080))
        .map_err(|_| AppError::Config("socks5Port is out of range".to_owned()))?;
    let listen_ip = if config.socks5_listen_lan {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    } else {
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    };
    let listener = TcpListener::bind(SocketAddr::new(listen_ip, port)).await?;
    info!(address = %listener.local_addr()?, "SOCKS5 ingress listening");

    loop {
        tokio::select! {
            _ = wait_for_shutdown(stop) => break,
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, peer)) => {
                        // SOCKS5 relays many small reads/writes; Nagle plus the
                        // peer's delayed ACK would add a ~40 ms stall per burst.
                        if let Err(error) = stream.set_nodelay(true) {
                            warn!(%error, "failed to set TCP_NODELAY on SOCKS5 ingress");
                        }
                        let server = server.clone();
                        tokio::spawn(async move {
                            if let Err(error) = server.serve(stream).await {
                                debug!(%peer, %error, "SOCKS5 connection closed");
                            }
                        });
                    }
                    Err(error) => warn!(%error, "SOCKS5 accept failed"),
                }
            }
        }
    }
    mux.stop();
    info!("client shutdown complete");
    Ok(())
}

/// Run the tunnel listeners in the foreground until a shutdown signal arrives.
pub async fn run_server(path: PathBuf, stop: &'static AtomicI32) -> Result<(), AppError> {
    let _pidfile = PidFile::acquire(Mode::Server)?;
    let config: ServerConfig = load_server(&path)?;
    let driver_config = server_driver_config(&config)?;
    info!(
        users = driver_config.users.len(),
        suites = ?driver_config.allowed_suites,
        hint_mandatory = driver_config.hint_mandatory,
        "ShadowLemon V0.2 cipher suite configuration loaded"
    );
    let mux_config = server_mux_config(&config)?;
    let listen_ip = match config.listen_ip_address.as_deref() {
        Some(text) if !text.is_empty() => text.parse::<IpAddr>().map_err(|error| {
            AppError::Config(format!("invalid listenIPAddress {text:?}: {error}"))
        })?,
        _ => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
    };
    let bindings = config
        .port_bindings
        .iter()
        .flat_map(port_bindings)
        .collect::<Vec<_>>();
    if bindings.is_empty() {
        return Err(AppError::Config(
            "server config has no usable port bindings".to_owned(),
        ));
    }
    let mux = ServerMux::new(
        mux_config,
        listen_ip,
        bindings,
        Arc::new(RealServerHandshake::new(driver_config).map_err(AppError::Io)?),
    )
    .map_err(|error| AppError::Config(error.to_string()))?;
    mux.start()
        .await
        .map_err(|error| AppError::Config(error.to_string()))?;
    info!(%listen_ip, "ShadowLemon server listeners started");

    wait_for_shutdown(stop).await;
    mux.stop().await;
    info!("server shutdown complete");
    Ok(())
}

async fn wait_for_shutdown(flag: &AtomicI32) {
    while !platform::shutdown_requested(flag) {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn endpoint_from_config(server: &shadowlemon_config::ServerEndpoint) -> Option<Endpoint> {
    let bindings = server
        .port_bindings
        .iter()
        .flat_map(port_bindings)
        .collect::<Vec<_>>();
    if bindings.is_empty() {
        return None;
    }
    if let Some(domain) = server
        .domain_name
        .as_deref()
        .filter(|name| !name.is_empty())
    {
        Some(Endpoint::with_domain(domain, bindings))
    } else {
        let ip = server.ip_address.as_deref().filter(|ip| !ip.is_empty())?;
        Some(Endpoint::new(ip, bindings))
    }
}

fn port_bindings(binding: &PortBinding) -> Vec<PortBindingSpec> {
    // The external transport is UDP-only. TCP bindings are rejected during
    // config validation; if one reaches here, skip it defensively.
    let protocol = match binding.protocol {
        TransportProtocol::Udp => TransportKind::Udp,
        _ => return Vec::new(),
    };
    let mut ports = Vec::new();
    if let Some(port) = binding.port {
        if let Ok(port) = u16::try_from(port) {
            ports.push(port);
        }
    }
    if let Some((begin, end)) = binding
        .port_range
        .as_deref()
        .and_then(shadowlemon_config::parse_port_range)
    {
        ports.extend(begin..=end);
    }
    ports
        .into_iter()
        .map(|port| PortBindingSpec::new(port, protocol))
        .collect()
}

/// Upstream SOCKS5 proxy used to reach the ShadowLemon server itself.
struct UpstreamSocks5 {
    proxy: SocketAddr,
    credential: Option<Credential>,
    udp_enabled: bool,
}

impl UpstreamSocks5 {
    fn new(config: &ClientDialer) -> Result<Self, AppError> {
        let host = config
            .host
            .as_deref()
            .filter(|host| !host.is_empty())
            .ok_or_else(|| AppError::Config("upstream dialer needs a host".to_owned()))?;
        let port = u16::try_from(config.port.unwrap_or(0))
            .map_err(|_| AppError::Config("upstream dialer needs a valid port".to_owned()))?;
        let proxy = match host.parse::<IpAddr>() {
            Ok(ip) => SocketAddr::new(ip, port),
            Err(_) => {
                let ip = std::net::ToSocketAddrs::to_socket_addrs(&(host, port))
                    .map_err(|error| AppError::Config(format!("cannot resolve {host}: {error}")))?
                    .next()
                    .map(|addr| addr.ip())
                    .ok_or_else(|| {
                        AppError::Config(format!("upstream host {host} did not resolve"))
                    })?;
                SocketAddr::new(ip, port)
            }
        };
        let credential = config.socks5_authentication.as_ref().and_then(|auth| {
            Some(Credential::new(
                auth.user.as_deref()?,
                auth.password.as_deref()?,
            ))
        });
        Ok(Self {
            proxy,
            credential,
            udp_enabled: config.socks5_udp_associate,
        })
    }

    async fn connect(&self) -> io::Result<TcpStream> {
        let mut stream = TcpStream::connect(self.proxy).await?;
        if self.credential.is_some() {
            stream.write_all(&[VERSION, 1, METHOD_USERPASS]).await?;
        } else {
            stream.write_all(&[VERSION, 1, METHOD_NO_AUTH]).await?;
        }
        stream.flush().await?;
        let mut method = [0u8; 2];
        stream.read_exact(&mut method).await?;
        if method[0] != VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "bad SOCKS version",
            ));
        }
        if let Some(credential) = &self.credential {
            if method[1] != METHOD_USERPASS {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "proxy refused auth",
                ));
            }
            let user = credential.username.as_bytes();
            let password = credential.password.as_bytes();
            let mut auth = vec![USERPASS_VERSION, user.len() as u8];
            auth.extend_from_slice(user);
            auth.push(password.len() as u8);
            auth.extend_from_slice(password);
            stream.write_all(&auth).await?;
            stream.flush().await?;
            let mut reply = [0u8; 2];
            stream.read_exact(&mut reply).await?;
            if reply[1] != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "proxy auth failed",
                ));
            }
        } else if method[1] != METHOD_NO_AUTH {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "proxy needs auth",
            ));
        }
        Ok(stream)
    }
}

impl ProxyDialer for UpstreamSocks5 {
    fn dial_tcp<'a>(
        &'a self,
        addr: SocketAddr,
        host: Option<&'a str>,
    ) -> BoxFuture<'a, io::Result<Box<dyn AsyncIo>>> {
        Box::pin(async move {
            let mut stream = self.connect().await?;
            let address = match host {
                Some(name) if !name.is_empty() => Address::Domain(name.to_owned()),
                _ => Address::Ip(addr.ip()),
            };
            stream
                .write_all(&encode_request(CMD_CONNECT, &address, addr.port()))
                .await?;
            stream.flush().await?;
            let mut reply = [0u8; 4];
            stream.read_exact(&mut reply).await?;
            if reply[1] != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    "proxy CONNECT failed",
                ));
            }
            let tail_len = match reply[3] {
                ATYP_IPV4 => 6,
                ATYP_IPV6 => 18,
                ATYP_DOMAIN => {
                    let mut len = [0u8; 1];
                    stream.read_exact(&mut len).await?;
                    usize::from(len[0]) + 2
                }
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "bad proxy reply",
                    ))
                }
            };
            let mut tail = vec![0u8; tail_len];
            stream.read_exact(&mut tail).await?;
            Ok(Box::new(stream) as Box<dyn AsyncIo>)
        })
    }

    fn dial_udp<'a>(
        &'a self,
        _addr: SocketAddr,
        _host: Option<&'a str>,
    ) -> BoxFuture<'a, io::Result<Box<dyn DatagramSocket>>> {
        let _ = self.udp_enabled;
        Box::pin(async {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "upstream SOCKS5 UDP ASSOCIATE is not implemented; use a direct UDP dialer",
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_bindings_expand_ranges_and_filter_unknown_protocols() {
        let binding = PortBinding {
            port: None,
            port_range: Some("2012-2014".to_owned()),
            protocol: TransportProtocol::Udp,
        };
        let ports = port_bindings(&binding);
        assert_eq!(ports.len(), 3);
        assert_eq!(ports[0].port, 2012);
        assert_eq!(ports[2].port, 2014);
        let unknown = PortBinding {
            port: Some(2012),
            port_range: None,
            protocol: TransportProtocol::UnknownTransportProtocol,
        };
        assert!(port_bindings(&unknown).is_empty());
    }
}
