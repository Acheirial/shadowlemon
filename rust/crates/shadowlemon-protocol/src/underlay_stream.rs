//! Tokio TCP underlay for ShadowLemon V0.2 (spec §4.3, §10).
//!
//! A frame is read in two steps: the fixed 72-byte part (24-byte nonce + 32
//! bytes of encrypted metadata + 16-byte tag) for the first message of a
//! cipher chain, then only the fixed 48 bytes for later messages whose nonce
//! is implicit. Metadata is decrypted first so the prefix/payload/suffix
//! lengths are known before the variable part is read (spec §10 step 5).
//!
//! Each direction keeps its own 24-byte big-endian [`NonceChain`]. A handshake
//! cipher switch resets both chains via [`Underlay::install_session_cipher`],
//! so the first message under the session key again carries an explicit
//! randomly generated nonce.

use std::net::SocketAddr;

use futures::future::BoxFuture;
use shadowlemon_crypto::aead::AeadKey;
use shadowlemon_wire::{
    decode_segment, encode_segment, Cipher, DecodeOptions, EncodeOptions, Metadata, PayloadNonce,
    Segment, META_BLOCK_LEN, NONCE_AND_META_LEN, WIRE_NONCE_LEN,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};

use crate::underlay::{
    apply_nonce_pattern_random, new_wire_nonce, NonceChain, NoncePattern, NoncePatternConfig,
    Underlay, UnderlayError, UnderlayKind, UnderlayResult, WireCipher,
};

/// Configuration of a stream underlay.
#[derive(Debug, Clone)]
pub struct StreamConfig {
    /// Traffic pattern applied when a fresh nonce is generated (chain start).
    pub nonce_pattern: NoncePattern,
    /// Length range and UDP applicability of the pattern.
    pub nonce_pattern_config: NoncePatternConfig,
}

impl Default for StreamConfig {
    fn default() -> Self {
        Self {
            nonce_pattern: NoncePattern::Random,
            nonce_pattern_config: NoncePatternConfig::default(),
        }
    }
}

/// A TCP (or duplex) underlay, generic over the concrete Tokio I/O object so
/// tests can drive it with `tokio::io::duplex`.
#[derive(Debug)]
pub struct StreamUnderlay<S = TcpStream> {
    io: S,
    cipher: WireCipher,
    send_chain: NonceChain,
    recv_chain: NonceChain,
    config: StreamConfig,
    closed: bool,
}

/// Concrete TCP underlay used by the client and server muxes.
pub type TcpUnderlay = StreamUnderlay<TcpStream>;

impl<S> StreamUnderlay<S> {
    /// Wrap an already connected stream.
    #[must_use]
    pub fn new(io: S, key: AeadKey, config: StreamConfig) -> Self {
        Self {
            io,
            cipher: WireCipher::new(key),
            send_chain: NonceChain::fresh(Some(&config.nonce_pattern)),
            recv_chain: NonceChain::fresh(Some(&config.nonce_pattern)),
            config,
            closed: false,
        }
    }

    /// Borrow the underlying I/O object.
    #[must_use]
    pub const fn io(&self) -> &S {
        &self.io
    }

    /// Mutably borrow the underlying I/O object.
    #[must_use]
    pub fn io_mut(&mut self) -> &mut S {
        &mut self.io
    }

    /// Consume the underlay and return the I/O object.
    #[must_use]
    pub fn into_inner(self) -> S {
        self.io
    }

    /// Fresh nonce for a new cipher chain, with the traffic pattern applied.
    fn fresh_chain_nonce(&self) -> shadowlemon_crypto::WireNonce {
        let mut nonce = new_wire_nonce(Some(&self.config.nonce_pattern));
        apply_nonce_pattern_random(
            &mut nonce,
            &self.config.nonce_pattern,
            &self.config.nonce_pattern_config,
        );
        nonce
    }
}

impl StreamUnderlay<TcpStream> {
    /// Connect to a TCP endpoint and install a stream underlay over it.
    pub async fn connect(
        addr: SocketAddr,
        key: AeadKey,
        config: StreamConfig,
    ) -> UnderlayResult<Self> {
        let stream = TcpStream::connect(addr).await?;
        Ok(Self::new(stream, key, config))
    }

    /// Remote address of the TCP connection.
    pub fn peer_addr(&self) -> UnderlayResult<SocketAddr> {
        Ok(self.io.peer_addr()?)
    }

    /// Local address of the TCP connection.
    pub fn local_addr(&self) -> UnderlayResult<SocketAddr> {
        Ok(self.io.local_addr()?)
    }
}

/// Read exactly `len` bytes.
///
/// EOF before the first byte is reported as a clean close (`None`); EOF
/// mid-frame is a protocol error. No polling loop is involved.
async fn read_part<S: AsyncRead + Unpin>(
    io: &mut S,
    len: usize,
) -> UnderlayResult<Option<Vec<u8>>> {
    let mut buf = vec![0u8; len];
    let mut filled = 0;
    while filled < len {
        let read = io.read(&mut buf[filled..]).await?;
        if read == 0 {
            if filled == 0 {
                return Ok(None);
            }
            return Err(UnderlayError::TruncatedFrame {
                got: filled,
                want: len,
            });
        }
        filled += read;
    }
    Ok(Some(buf))
}

impl<S> Underlay for StreamUnderlay<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    fn kind(&self) -> UnderlayKind {
        UnderlayKind::Stream
    }

    fn mtu(&self) -> Option<u16> {
        None
    }

    fn send_segment(&mut self, mut segment: Segment) -> BoxFuture<'_, UnderlayResult<()>> {
        Box::pin(async move {
            if self.closed {
                return Err(UnderlayError::Shutdown);
            }
            let include_nonce = self.send_chain.should_include_nonce();
            if include_nonce {
                // Rewriting changes the AEAD nonce for XChaCha20-Poly1305 too,
                // so reseed the chain with the bytes actually put on the wire.
                let mut nonce = *self.send_chain.current();
                apply_nonce_pattern_random(
                    &mut nonce,
                    &self.config.nonce_pattern,
                    &self.config.nonce_pattern_config,
                );
                self.send_chain.reset(nonce);
            }
            segment.wire_nonce = self.send_chain.send_metadata_nonce();
            let has_payload = usize::from(segment.metadata.payload_len()) > 0;
            let frame = encode_segment(
                &self.cipher,
                &segment,
                &EncodeOptions {
                    include_nonce,
                    payload_nonce: PayloadNonce::TcpIncrement,
                },
            )?;
            self.io.write_all(&frame).await?;
            self.io.flush().await?;
            if has_payload {
                self.send_chain.advance_payload();
            }
            Ok(())
        })
    }

    fn recv_segment(&mut self) -> BoxFuture<'_, UnderlayResult<Segment>> {
        Box::pin(async move {
            if self.closed {
                return Err(UnderlayError::Shutdown);
            }
            let include_nonce = self.recv_chain.should_include_nonce();
            let fixed_len = if include_nonce {
                NONCE_AND_META_LEN
            } else {
                META_BLOCK_LEN
            };
            let fixed = match read_part(&mut self.io, fixed_len).await? {
                Some(bytes) => bytes,
                None => return Err(UnderlayError::Closed),
            };
            let explicit = if include_nonce {
                let mut nonce = [0u8; WIRE_NONCE_LEN];
                nonce.copy_from_slice(&fixed[..WIRE_NONCE_LEN]);
                Some(nonce)
            } else {
                None
            };
            let metadata_nonce = self.recv_chain.recv_metadata_nonce(explicit);

            // Decrypt metadata before reading the variable-length part (§10).
            let meta_block_start = if include_nonce { WIRE_NONCE_LEN } else { 0 };
            let metadata_plain = self
                .cipher
                .open(&metadata_nonce, &fixed[meta_block_start..fixed_len])?;
            let metadata = Metadata::parse(&metadata_plain)?;

            let prefix_len = usize::from(metadata.prefix_len());
            let suffix_len = usize::from(metadata.suffix_len());
            let payload_len = usize::from(metadata.payload_len());
            let variable_len =
                prefix_len + shadowlemon_wire::payload_block_len(payload_len) + suffix_len;
            let variable = match read_part(&mut self.io, variable_len).await? {
                Some(bytes) => bytes,
                None => {
                    return Err(UnderlayError::TruncatedFrame {
                        got: 0,
                        want: variable_len,
                    })
                }
            };

            let mut frame = Vec::with_capacity(fixed_len + variable_len);
            frame.extend_from_slice(&fixed);
            frame.extend_from_slice(&variable);
            let segment = decode_segment(
                &self.cipher,
                &frame,
                &DecodeOptions {
                    include_nonce,
                    implicit_metadata_nonce: metadata_nonce,
                    payload_nonce: PayloadNonce::TcpIncrement,
                },
            )?;
            if payload_len > 0 {
                self.recv_chain.advance_payload();
            }
            Ok(segment)
        })
    }

    fn install_session_cipher(&mut self, key: AeadKey) {
        self.cipher.replace(key);
        self.send_chain.reset(self.fresh_chain_nonce());
        self.recv_chain.reset(self.fresh_chain_nonce());
    }

    fn shutdown(&mut self) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            self.closed = true;
            let _ = self.io.shutdown().await;
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shadowlemon_crypto::{suite::Suite, WireNonce};
    use shadowlemon_wire::increment_nonce;

    const KEY: [u8; 32] = [3u8; 32];

    fn key() -> AeadKey {
        AeadKey::new(Suite::XChaCha20Poly1305, &KEY).unwrap()
    }

    fn data_segment(session: u32, sequence: u32, body: &[u8]) -> Segment {
        Segment::new(
            Metadata::data(6, session, sequence, 0, 16, 0, 0, body.len() as u16, 0),
            [0u8; WIRE_NONCE_LEN],
            body.to_vec(),
        )
    }

    #[tokio::test]
    async fn tcp_round_trip_over_duplex() {
        let (a, b) = tokio::io::duplex(8192);
        let mut sender = StreamUnderlay::new(a, key(), StreamConfig::default());
        let mut receiver = StreamUnderlay::new(b, key(), StreamConfig::default());

        sender
            .send_segment(data_segment(1, 7, b"hello underlay"))
            .await
            .unwrap();
        let got = receiver.recv_segment().await.unwrap();
        assert_eq!(got.metadata, Metadata::data(6, 1, 7, 0, 16, 0, 0, 14, 0));
        assert_eq!(got.payload, b"hello underlay");
    }

    #[tokio::test]
    async fn multiple_sessions_interleaved_on_one_underlay() {
        let (a, b) = tokio::io::duplex(16 * 1024);
        let mut sender = StreamUnderlay::new(a, key(), StreamConfig::default());
        let mut receiver = StreamUnderlay::new(b, key(), StreamConfig::default());

        for i in 0..8u32 {
            let session = i % 3 + 1;
            let body = format!("session-{session}-seq-{i}").into_bytes();
            sender
                .send_segment(data_segment(session, i, &body))
                .await
                .unwrap();
        }
        for i in 0..8u32 {
            let got = receiver.recv_segment().await.unwrap();
            let session = i % 3 + 1;
            assert_eq!(got.metadata.session_id(), session);
            assert_eq!(got.metadata.sequence(), i);
            assert_eq!(
                got.payload,
                format!("session-{session}-seq-{i}").into_bytes()
            );
        }
    }

    #[tokio::test]
    async fn second_frame_omits_the_explicit_nonce() {
        let (a, mut raw) = tokio::io::duplex(4096);
        let mut sender = StreamUnderlay::new(a, key(), StreamConfig::default());

        // Empty payloads make the two frames exactly 72 and 48 bytes.
        sender.send_segment(data_segment(1, 0, b"")).await.unwrap();
        sender.send_segment(data_segment(1, 1, b"")).await.unwrap();

        let mut first = vec![0u8; NONCE_AND_META_LEN];
        raw.read_exact(&mut first).await.unwrap();
        let mut second = vec![0u8; META_BLOCK_LEN];
        raw.read_exact(&mut second).await.unwrap();

        let first_nonce: WireNonce = first[..WIRE_NONCE_LEN].try_into().unwrap();
        let mut expected_second_nonce = first_nonce;
        expected_second_nonce = increment_nonce(&expected_second_nonce);

        let cipher = WireCipher::new(key());
        let first_segment = decode_segment(&cipher, &first, &DecodeOptions::default()).unwrap();
        let second_segment = decode_segment(
            &cipher,
            &second,
            &DecodeOptions {
                include_nonce: false,
                implicit_metadata_nonce: expected_second_nonce,
                payload_nonce: PayloadNonce::TcpIncrement,
            },
        )
        .unwrap();
        assert_eq!(first_segment.metadata.sequence(), 0);
        assert_eq!(second_segment.metadata.sequence(), 1);
        assert_eq!(second_segment.wire_nonce, expected_second_nonce);
    }

    #[tokio::test]
    async fn eof_and_truncation_are_reportable() {
        // Dropping the peer before any byte is a clean close.
        let (reader, peer) = tokio::io::duplex(256);
        drop(peer);
        let mut receiver = StreamUnderlay::new(reader, key(), StreamConfig::default());
        assert!(matches!(
            receiver.recv_segment().await.unwrap_err(),
            UnderlayError::Closed
        ));

        // A half-written frame is a truncation error.
        let (reader, mut peer) = tokio::io::duplex(256);
        peer.write_all(&[0u8; 10]).await.unwrap();
        drop(peer);
        let mut receiver = StreamUnderlay::new(reader, key(), StreamConfig::default());
        assert!(matches!(
            receiver.recv_segment().await.unwrap_err(),
            UnderlayError::TruncatedFrame { got: 10, want: 72 }
        ));
    }
}
