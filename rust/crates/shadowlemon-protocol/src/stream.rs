//! `AsyncRead`/`AsyncWrite` adapter for a TCP [`Session`].
//!
//! The SOCKS5 relay wants a plain byte stream, while [`Session`] speaks frames.
//! `TcpSessionStream` bridges the two by spawning one driver task per stream:
//! the driver reads complete frames from the transport, feeds them to the
//! session, runs its retransmission/ACK/heartbeat timers and writes generated
//! frames back. The public handle only owns two bounded tokio channels: one
//! for application writes and one for received plaintext.
//!
//! # Transport choice
//!
//! The constructor uses a generic `AsyncRead + AsyncWrite + Unpin + Send + 'static`
//! bound instead of defining another `Underlay` trait. That lets callers pass a
//! `tokio::net::TcpStream`, a `tokio::io::DuplexStream` (tests) or any adapter
//! that exposes a byte stream; the crate's segment-oriented
//! [`Underlay`](crate::underlay::Underlay) implementations can be adapted to
//! that bound by their owner without introducing a redundant abstraction here.
//!
//! The write channel is bounded (256 fragments), so a slow session applies
//! backpressure to the application instead of buffering without limit.

use std::{
    future::Future,
    io,
    marker::PhantomData,
    pin::Pin,
    task::{Context, Poll},
    time::Instant,
};

use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf},
    sync::mpsc::{self, error::SendError, OwnedPermit},
};
use tracing::debug;

use crate::session::{Session, SessionError, SEGMENT_CHAN_CAPACITY};

type ReserveFuture =
    Pin<Box<dyn Future<Output = Result<OwnedPermit<Vec<u8>>, SendError<()>>> + Send>>;

/// An application-facing byte stream backed by a TCP [`Session`].
pub struct TcpSessionStream<T> {
    app_tx: Option<mpsc::Sender<Vec<u8>>>,
    plaintext_rx: mpsc::Receiver<Vec<u8>>,
    reserve: Option<ReserveFuture>,
    read_buf: Vec<u8>,
    _transport: PhantomData<T>,
}

impl<T> TcpSessionStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    /// Attach `session` to `transport` and start its I/O driver.
    ///
    /// # Panics
    /// Panics if the session's plaintext receiver was already taken.
    #[must_use]
    pub fn new(mut session: Session, transport: T) -> Self {
        let plaintext_rx = session
            .take_plaintext_rx()
            .expect("session plaintext receiver must be taken exactly once");
        let (app_tx, app_rx) = mpsc::channel(SEGMENT_CHAN_CAPACITY);
        tokio::spawn(drive(session, transport, app_rx));
        Self {
            app_tx: Some(app_tx),
            plaintext_rx,
            reserve: None,
            read_buf: Vec::new(),
            _transport: PhantomData,
        }
    }

    /// Whether the application-facing side has been shut down.
    #[must_use]
    pub fn is_shutdown(&self) -> bool {
        self.app_tx.is_none()
    }
}

/// Run until the transport closes, the session closes or the writer goes away.
async fn drive<T>(mut session: Session, transport: T, mut app_rx: mpsc::Receiver<Vec<u8>>)
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut reader, mut writer) = tokio::io::split(transport);
    let stop_reason: Option<&'static str> = loop {
        if session.is_closed() {
            break Some("session closed");
        }
        let deadline = session.next_timer();
        let timer = async move {
            match deadline {
                Some(at) => tokio::time::sleep_until(tokio::time::Instant::from_std(at)).await,
                None => std::future::pending::<()>().await,
            }
        };
        tokio::select! {
            biased;
            incoming = app_rx.recv() => {
                match incoming {
                    Some(data) => {
                        if let Err(err) = session.send(&data).await {
                            debug!(%err, "session rejected application write");
                            break Some("write rejected");
                        }
                    }
                    None => {
                        // The application handle was dropped or shut down:
                        // best-effort close notification, then stop.
                        let _ = session.close(true);
                        break Some("application shutdown");
                    }
                }
            }
            frame = session.read_frame(&mut reader) => {
                if let Err(err) = frame {
                    if !matches!(err, SessionError::Closed) {
                        debug!(%err, "session stopped reading");
                    }
                    break Some("transport read failed");
                }
            }
            _ = timer => {}
        }

        if let Err(err) = session.tick(Instant::now()) {
            debug!(%err, "session timer failed");
            break Some("session timer failed");
        }
        while let Some(frame) = session.poll_output() {
            if let Err(err) = writer.write_all(&frame).await {
                debug!(%err, "session failed to write a frame");
                break;
            }
        }
        if writer.flush().await.is_err() {
            break Some("transport write failed");
        }
    };

    if !session.is_closed() {
        let _ = session.close(false);
        while let Some(frame) = session.poll_output() {
            if writer.write_all(&frame).await.is_err() {
                break;
            }
        }
        let _ = writer.flush().await;
    }
    if let Some(reason) = stop_reason {
        debug!(reason, "TCP session stream driver stopped");
    }
}

impl<T: Unpin> AsyncRead for TcpSessionStream<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.read_buf.is_empty() {
            match Pin::new(&mut this.plaintext_rx).poll_recv(cx) {
                Poll::Ready(Some(data)) => this.read_buf = data,
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            }
        }
        let len = buf.remaining().min(this.read_buf.len());
        buf.put_slice(&this.read_buf[..len]);
        this.read_buf.drain(..len);
        Poll::Ready(Ok(()))
    }
}

impl<T: Unpin> AsyncWrite for TcpSessionStream<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let Some(sender) = this.app_tx.as_ref() else {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "session stream is shut down",
            )));
        };
        if this.reserve.is_none() {
            let sender = sender.clone();
            this.reserve = Some(Box::pin(async move { sender.reserve_owned().await }));
        }
        let result = this
            .reserve
            .as_mut()
            .expect("reserve future was just installed")
            .as_mut()
            .poll(cx);
        match result {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(_)) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "session driver stopped",
            ))),
            Poll::Ready(Ok(permit)) => {
                this.reserve = None;
                permit.send(buf.to_vec());
                Poll::Ready(Ok(buf.len()))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Writes are handed to the driver synchronously in `poll_write`; the
        // driver flushes the transport after every batch of generated frames.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.reserve = None;
        this.app_tx = None;
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::{Direction, SessionConfig, TransportMode};
    use shadowlemon_crypto::{aead::AeadKey, suite::Suite};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::time::{timeout, Duration};

    fn key(byte: u8) -> AeadKey {
        AeadKey::new(Suite::XChaCha20Poly1305, &[byte; 32]).unwrap()
    }

    fn session(id: u32, direction: Direction) -> Session {
        Session::new(SessionConfig::new(
            id,
            direction,
            TransportMode::Stream,
            key(1),
            key(2),
        ))
        .unwrap()
    }

    #[tokio::test]
    async fn bytes_flow_both_ways_over_a_duplex_stream() {
        let (client_io, server_io) = tokio::io::duplex(8192);
        let mut client = TcpSessionStream::new(session(31, Direction::Client), client_io);
        let mut server = TcpSessionStream::new(session(31, Direction::Server), server_io);

        timeout(Duration::from_secs(3), client.write_all(b"client bytes"))
            .await
            .unwrap()
            .unwrap();
        timeout(Duration::from_secs(3), client.flush())
            .await
            .unwrap()
            .unwrap();
        let mut received = [0u8; 12];
        timeout(Duration::from_secs(3), server.read_exact(&mut received))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&received, b"client bytes");

        timeout(Duration::from_secs(3), server.write_all(b"server bytes"))
            .await
            .unwrap()
            .unwrap();
        let mut received = [0u8; 12];
        timeout(Duration::from_secs(3), client.read_exact(&mut received))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&received, b"server bytes");
    }

    #[tokio::test]
    async fn partial_reads_preserve_byte_order() {
        let (client_io, server_io) = tokio::io::duplex(8192);
        let mut client = TcpSessionStream::new(session(32, Direction::Client), client_io);
        let mut server = TcpSessionStream::new(session(32, Direction::Server), server_io);

        timeout(Duration::from_secs(3), client.write_all(b"0123456789"))
            .await
            .unwrap()
            .unwrap();
        let mut first = [0u8; 4];
        let mut second = [0u8; 6];
        timeout(Duration::from_secs(3), server.read_exact(&mut first))
            .await
            .unwrap()
            .unwrap();
        timeout(Duration::from_secs(3), server.read_exact(&mut second))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&first, b"0123");
        assert_eq!(&second, b"456789");
    }
}
