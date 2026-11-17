//! RFC 1928 SOCKS5 ingress proxy for ShadowLemon V0.2.
//!
//! This crate accepts SOCKS5 connections from a local client, performs
//! greeting/method negotiation (NO_AUTH and USERNAME/PASSWORD), applies a
//! configurable egress policy, and relays traffic through an injected
//! [`ProxyDialer`] (normally implemented by the ShadowLemon protocol layer).
//!
//! It supports the three interesting parts of RFC 1928:
//!
//! * `CONNECT` with IPv4, IPv6 and DOMAINNAME destination types,
//! * `UDP ASSOCIATE` with strict SOCKS5 UDP framing (FRAG must be zero),
//! * `BIND` is explicitly rejected with `COMMAND_NOT_SUPPORTED`.
//!
//! # Public dialer contract (for the protocol crate)
//!
//! The protocol crate implements [`ProxyDialer`] and [`DatagramSocket`] and
//! hands an `Arc<dyn ProxyDialer>` to [`Config::new`]. The exact signatures are:
//!
//! ```rust,ignore
//! pub trait AsyncIo:
//!     tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send
//! {}
//!
//! pub trait ProxyDialer: Send + Sync {
//!     fn dial_tcp<'a>(
//!         &'a self,
//!         addr: std::net::SocketAddr,
//!         host: Option<&'a str>,
//!     ) -> futures::future::BoxFuture<'a, std::io::Result<Box<dyn AsyncIo>>>;
//!
//!     fn dial_udp<'a>(
//!         &'a self,
//!         addr: std::net::SocketAddr,
//!         host: Option<&'a str>,
//!     ) -> futures::future::BoxFuture<'a, std::io::Result<Box<dyn DatagramSocket>>>;
//! }
//!
//! pub trait DatagramSocket: Send + Sync {
//!     fn send_to<'a>(
//!         &'a self,
//!         data: &'a [u8],
//!         target: std::net::SocketAddr,
//!     ) -> futures::future::BoxFuture<'a, std::io::Result<usize>>;
//!
//!     fn recv_from<'a>(
//!         &'a self,
//!         buf: &'a mut [u8],
//!     ) -> futures::future::BoxFuture<'a, std::io::Result<(usize, std::net::SocketAddr)>>;
//! }
//! ```
//!
//! Important details for implementors:
//!
//! * The I/O traits above are **tokio's** `AsyncRead`/`AsyncWrite`, not the
//!   `futures::io` ones. `tokio::net::TcpStream` and the usual tunnel wrappers
//!   satisfy [`AsyncIo`] directly through a blanket impl.
//! * `addr` is the concrete endpoint to dial. `host`, when present, is the
//!   original hostname from the SOCKS5 request; pass it through when the
//!   tunnel supports name-based routing, otherwise it may be ignored.
//! * `dial_udp` is called once per UDP association with the unspecified
//!   address `0.0.0.0:0` (and the request host when available). The returned
//!   socket must be able to `send_to` arbitrary `target` addresses and report
//!   the responder's address from `recv_from`. [`TokioDatagramSocket`] is a
//!   ready-to-use implementation backed by `tokio::net::UdpSocket`.
//! * All futures are boxed with `futures::future::BoxFuture`; use
//!   `Box::pin(async move { ... })` in your implementation.
//!
//! Because the generic [`AsyncIo`] trait object does not expose a local
//! address, the TCP `CONNECT` success reply uses the unspecified bind address
//! `0.0.0.0:0`, which is valid RFC 1928 behaviour for `CONNECT`. The UDP
//! `ASSOCIATE` success reply carries the real local UDP port.
//!
//! On egress decisions: a `REJECT` rule sends `NOT_ALLOWED`. A `PROXY` rule
//! dials the selected downstream SOCKS5 proxy through the injected dialer,
//! negotiates authentication and forwards the original request. For UDP,
//! every datagram still honours `REJECT`, while `PROXY` datagrams are sent
//! directly through the injected UDP dialer (the downstream SOCKS5 UDP relay
//! handshake is intentionally not performed). A `PROXY` rule whose proxy
//! names do not resolve to a configured proxy falls back to `DIRECT`.
//!
//! # Example
//!
//! ```rust,no_run
//! use std::sync::Arc;
//! use shadowlemon_socks5::{Config, Credential, Server};
//! # use shadowlemon_socks5::{AsyncIo, DatagramSocket, ProxyDialer};
//! # use futures::future::BoxFuture;
//! # use std::{io, net::SocketAddr};
//! # struct MyDialer;
//! # impl ProxyDialer for MyDialer {
//! #     fn dial_tcp<'a>(&'a self, _: SocketAddr, _: Option<&'a str>)
//! #         -> BoxFuture<'a, io::Result<Box<dyn AsyncIo>>> { todo!() }
//! #     fn dial_udp<'a>(&'a self, _: SocketAddr, _: Option<&'a str>)
//! #         -> BoxFuture<'a, io::Result<Box<dyn DatagramSocket>>> { todo!() }
//! # }
//! # async fn example() {
//! let config = Config::new(Arc::new(MyDialer))
//!     .with_credentials(vec![Credential::new("alice", "secret")]);
//! let server = Server::new(config);
//! server.listen_and_serve("127.0.0.1:1080").await.unwrap();
//! # }
//! ```

#![forbid(unsafe_code)]

mod auth;
mod dialer;
mod egress;
mod proto;
mod resolver;
mod server;

pub use auth::Credential;
pub use dialer::{AsyncIo, DatagramSocket, ProxyDialer, TokioDatagramSocket};
pub use egress::{EgressAction, EgressConfig, EgressDecision, EgressProxy, EgressRule};
pub use proto::{
    encode_address, encode_error_reply, encode_reply, encode_request, encode_udp_datagram,
    encode_udp_header, parse_udp_datagram, read_reply, read_request, Address, Request, UdpDatagram,
    ATYP_DOMAIN, ATYP_IPV4, ATYP_IPV6, CMD_BIND, CMD_CONNECT, CMD_UDP_ASSOCIATE, MAX_UDP_DATAGRAM,
    REP_ADDR_TYPE_NOT_SUPPORTED, REP_COMMAND_NOT_SUPPORTED, REP_CONNECTION_REFUSED,
    REP_HOST_UNREACHABLE, REP_NETWORK_UNREACHABLE, REP_NOT_ALLOWED, REP_SUCCESS, VERSION,
};
pub use resolver::{resolve_target, Resolver, SystemResolver};
pub use server::{Config, Server, DEFAULT_HANDSHAKE_TIMEOUT, MAX_UDP_ASSOCIATIONS_PER_USER};

/// Errors produced by the SOCKS5 server.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// An underlying I/O operation failed.
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    /// The greeting used an unsupported SOCKS version.
    #[error("unsupported SOCKS version {0}")]
    UnsupportedVersion(u8),
    /// The client offered no mutually supported authentication method.
    #[error("no acceptable authentication method")]
    NoAcceptableMethod,
    /// Username/password authentication failed.
    #[error("authentication failed")]
    AuthenticationFailed,
    /// A command other than CONNECT / UDP ASSOCIATE was requested.
    #[error("unsupported SOCKS command {0}")]
    UnsupportedCommand(u8),
    /// An unsupported address type was present in a request or datagram.
    #[error("unsupported address type {0}")]
    UnsupportedAddressType(u8),
    /// A UDP datagram had a non-zero fragment number.
    #[error("fragmented UDP datagrams are not supported")]
    FragmentedDatagram,
    /// The handshake (greeting, auth and request) exceeded the timeout.
    #[error("SOCKS5 handshake timed out")]
    HandshakeTimeout,
    /// The egress policy rejected the destination.
    #[error("destination rejected by egress policy")]
    Rejected,
    /// Name resolution failed.
    #[error("name resolution failed: {0}")]
    Resolution(String),
    /// Dialing the outbound connection failed.
    #[error("dial failed: {0}")]
    Dial(String),
    /// A PROXY egress rule selected a proxy that is not configured.
    #[error("PROXY egress action has no available proxy")]
    NoEgressProxy,
    /// The user exceeded the concurrent UDP association limit.
    #[error("too many concurrent UDP associations")]
    TooManyUdpAssociations,
}

/// Convenience result alias for this crate.
pub type Result<T> = std::result::Result<T, Error>;
