//! Byte-stream facade over the UDP tunnel's reliable datagram session.
//!
//! External transport is UDP-only in this build. SOCKS5 `CONNECT` still needs
//! an ordered, reliable byte stream; that stream is provided by the tunnel's
//! existing CUBIC/ARQ layer, which reassembles datagrams into ordered
//! plaintext. [`DatagramStream`] maps `AsyncRead`/`AsyncWrite` onto a
//! [`DatagramSocket`] via a driver task, so no second reliability layer is
//! introduced and no datagram is lost if a future is cancelled.

use std::{
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use shadowlemon_socks5::{AsyncIo, DatagramSocket};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::mpsc,
};

/// Channel depth between the stream handle and its driver task.
const CHAN_CAPACITY: usize = 256;
/// Maximum bytes handed to `send_to` in one call. The tunnel fragments larger
/// writes internally, so this only bounds a single datagram.
const WRITE_CHUNK: usize = 60 * 1024;

type ReserveFuture = Pin<
    Box<dyn Future<Output = Result<mpsc::OwnedPermit<Vec<u8>>, mpsc::error::SendError<()>>> + Send>,
>;

/// An ordered byte stream backed by a reliable datagram socket.
pub struct DatagramStream {
    app_tx: Option<mpsc::Sender<Vec<u8>>>,
    plaintext_rx: mpsc::Receiver<Vec<u8>>,
    reserve: Option<ReserveFuture>,
    read_buf: Vec<u8>,
}

impl std::fmt::Debug for DatagramStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DatagramStream")
            .field("shutdown", &self.app_tx.is_none())
            .finish_non_exhaustive()
    }
}

impl DatagramStream {
    /// Wrap a reliable datagram socket as a byte stream directed at `target`.
    #[must_use]
    pub fn new(socket: Box<dyn DatagramSocket>, target: SocketAddr) -> Self {
        let (app_tx, app_rx) = mpsc::channel(CHAN_CAPACITY);
        let (plain_tx, plain_rx) = mpsc::channel(CHAN_CAPACITY);
        tokio::spawn(drive(Arc::from(socket), target, app_rx, plain_tx));
        Self {
            app_tx: Some(app_tx),
            plaintext_rx: plain_rx,
            reserve: None,
            read_buf: Vec::new(),
        }
    }
}

/// Pump writes to the tunnel and reassembled reads back to the stream handle.
async fn drive(
    socket: Arc<Box<dyn DatagramSocket>>,
    target: SocketAddr,
    mut app_rx: mpsc::Receiver<Vec<u8>>,
    plain_tx: mpsc::Sender<Vec<u8>>,
) {
    loop {
        tokio::select! {
            biased;
            outgoing = app_rx.recv() => {
                match outgoing {
                    Some(data) => {
                        if let Err(err) = socket.send_to(&data, target).await {
                            tracing::debug!(%err, "datagram stream write failed");
                            break;
                        }
                    }
                    None => break,
                }
            }
            incoming = async {
                let mut buf = vec![0u8; WRITE_CHUNK];
                let result = socket.recv_from(&mut buf).await;
                result.map(|(len, addr)| (addr, buf[..len].to_vec()))
            } => {
                match incoming {
                    Ok((_addr, data)) => {
                        if plain_tx.send(data).await.is_err() {
                            break;
                        }
                    }
                    Err(err) => {
                        tracing::debug!(%err, "datagram stream read failed");
                        break;
                    }
                }
            }
        }
    }
}

impl AsyncRead for DatagramStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if !this.read_buf.is_empty() {
                let len = buf.remaining().min(this.read_buf.len());
                buf.put_slice(&this.read_buf[..len]);
                this.read_buf.drain(..len);
                return Poll::Ready(Ok(()));
            }
            match Pin::new(&mut this.plaintext_rx).poll_recv(cx) {
                Poll::Ready(Some(data)) => this.read_buf = data,
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for DatagramStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let Some(sender) = this.app_tx.as_ref() else {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "datagram stream is shut down",
            )));
        };
        if this.reserve.is_none() {
            let sender = sender.clone();
            this.reserve = Some(Box::pin(async move { sender.reserve_owned().await }));
        }
        match this
            .reserve
            .as_mut()
            .expect("reserve future was just installed")
            .as_mut()
            .poll(cx)
        {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(_)) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "datagram stream driver stopped",
            ))),
            Poll::Ready(Ok(permit)) => {
                this.reserve = None;
                let n = buf.len().min(WRITE_CHUNK);
                permit.send(buf[..n].to_vec());
                Poll::Ready(Ok(n))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.reserve = None;
        this.app_tx = None;
        Poll::Ready(Ok(()))
    }
}

// The facade satisfies the marker trait used by the SOCKS5 ingress.
const _: fn() = || {
    fn assert_async_io<T: AsyncIo>() {}
    assert_async_io::<DatagramStream>();
};
