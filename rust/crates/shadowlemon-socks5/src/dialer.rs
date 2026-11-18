//! Public dialer and datagram abstractions used by the ingress server.
//!
//! These traits are intended to be implemented by the ShadowLemon protocol
//! crate. See the crate-level documentation in `lib.rs` for the full contract.

use std::{io, net::SocketAddr};

use futures::future::BoxFuture;
use tokio::net::UdpSocket;

/// A byte stream returned by [`ProxyDialer::dial_tcp`].
///
/// This is a marker trait: any type implementing tokio's `AsyncRead` and
/// `AsyncWrite` (plus `Unpin + Send`) satisfies it automatically. Tokio's
/// `TcpStream`, `DuplexStream` and the usual tunnel wrappers all qualify.
pub trait AsyncIo: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}

impl<T> AsyncIo for T where T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + ?Sized {}

/// Creates outbound TCP and UDP connections, normally through the ShadowLemon
/// tunnel.
///
/// All methods return boxed futures so the trait is object safe and can be
/// injected as `Arc<dyn ProxyDialer>`.
pub trait ProxyDialer: Send + Sync {
    /// Dials a TCP connection to `addr`.
    ///
    /// `host`, when present, is the original SOCKS5 hostname. Implementations
    /// that support name-based routing should forward it; others may ignore it.
    fn dial_tcp<'a>(
        &'a self,
        addr: SocketAddr,
        host: Option<&'a str>,
    ) -> BoxFuture<'a, io::Result<Box<dyn AsyncIo>>>;

    /// Creates a UDP (datagram) socket through the tunnel.
    ///
    /// The SOCKS5 server calls this once per UDP association with the
    /// unspecified address `0.0.0.0:0` and the request hostname (if any). The
    /// returned socket must be able to send to arbitrary targets via
    /// [`DatagramSocket::send_to`] and report the responder via
    /// [`DatagramSocket::recv_from`].
    fn dial_udp<'a>(
        &'a self,
        addr: SocketAddr,
        host: Option<&'a str>,
    ) -> BoxFuture<'a, io::Result<Box<dyn DatagramSocket>>>;
}

/// A minimal datagram socket capable of sending to and receiving from
/// arbitrary endpoints while preserving datagram boundaries.
pub trait DatagramSocket: Send + Sync {
    /// Sends one datagram to `target`, returning the number of bytes sent.
    fn send_to<'a>(
        &'a self,
        data: &'a [u8],
        target: SocketAddr,
    ) -> BoxFuture<'a, io::Result<usize>>;

    /// Send a datagram whose destination was a domain name.
    ///
    /// When the local SOCKS5 ingress deliberately avoids resolving domains
    /// (to keep the hostname inside the encrypted tunnel), the resolved
    /// `target` is only a placeholder. Implementations that understand named
    /// destinations should override this and forward `host`; the default
    /// ignores it and falls back to [`Self::send_to`].
    fn send_to_host<'a>(
        &'a self,
        data: &'a [u8],
        target: SocketAddr,
        host: Option<&'a str>,
    ) -> BoxFuture<'a, io::Result<usize>> {
        let _ = host;
        self.send_to(data, target)
    }

    /// Receives one datagram into `buf`, returning its length and source.
    fn recv_from<'a>(&'a self, buf: &'a mut [u8])
        -> BoxFuture<'a, io::Result<(usize, SocketAddr)>>;
}

/// A [`DatagramSocket`] backed by a tokio UDP socket.
///
/// This is useful for tests and for running the SOCKS5 ingress without a
/// tunnel (direct UDP mode).
#[derive(Debug)]
pub struct TokioDatagramSocket {
    socket: UdpSocket,
}

impl TokioDatagramSocket {
    /// Wraps an existing UDP socket.
    pub fn new(socket: UdpSocket) -> Self {
        Self { socket }
    }

    /// Binds a new UDP socket and wraps it.
    pub async fn bind(addr: SocketAddr) -> io::Result<Self> {
        Ok(Self {
            socket: UdpSocket::bind(addr).await?,
        })
    }

    /// Returns the underlying socket's local address.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Returns a shared reference to the underlying socket.
    pub fn inner(&self) -> &UdpSocket {
        &self.socket
    }
}

impl DatagramSocket for TokioDatagramSocket {
    fn send_to<'a>(
        &'a self,
        data: &'a [u8],
        target: SocketAddr,
    ) -> BoxFuture<'a, io::Result<usize>> {
        Box::pin(async move { self.socket.send_to(data, target).await })
    }

    fn recv_from<'a>(
        &'a self,
        buf: &'a mut [u8],
    ) -> BoxFuture<'a, io::Result<(usize, SocketAddr)>> {
        Box::pin(async move { self.socket.recv_from(buf).await })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn tokio_datagram_socket_preserves_boundaries() {
        let receiver = TokioDatagramSocket::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let addr = receiver.local_addr().unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
            .await
            .unwrap();

        sender.send_to(b"first", addr).await.unwrap();
        sender.send_to(b"second datagram", addr).await.unwrap();

        let mut buf = [0u8; 64];
        let (n, from) = receiver.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"first");
        assert_eq!(from, sender.local_addr().unwrap());
        let (n, _) = receiver.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"second datagram");
    }
}
