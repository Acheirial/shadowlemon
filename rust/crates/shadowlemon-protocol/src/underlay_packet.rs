//! Tokio UDP underlay for ShadowLemon V0.2 (spec §4.2, §4.4, §10).
//!
//! Every datagram carries its own 24-byte `wireNonce`; the payload is sealed
//! with the byte-16-flipped nonce returned by the crypto crate's
//! `udp_payload_nonce`. Sockets are created through `socket2` so `SO_REUSEADDR`
//! can be set before `bind` on Unix. On Windows the option is deliberately a
//! no-op (`platform-notes.md` §a.1), because `SO_REUSEADDR` there permits port
//! hijacking.
//!
//! The listener rebuild delay follows `reference-go-v3.md` §3.4: 1, 2, 4, 8,
//! 16, 30 seconds with `[delay/2, delay]` jitter.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use futures::future::BoxFuture;
use shadowlemon_crypto::aead::AeadKey;
use shadowlemon_wire::{
    decode_segment, encode_segment, DecodeOptions, EncodeOptions, PayloadNonce, Segment,
};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;

use crate::underlay::{
    apply_nonce_pattern_random, derive_udp_payload_nonce, new_wire_nonce, IpFamily, MtuBudget,
    NoncePattern, NoncePatternConfig, Underlay, UnderlayError, UnderlayKind, UnderlayResult,
    WireCipher, DEFAULT_MTU, MAX_DATAGRAM_LEN,
};

/// Maximum listener rebuild delay (spec §3.4).
pub const REBUILD_BACKOFF_MAX: Duration = Duration::from_secs(30);
/// Initial listener rebuild delay (spec §3.4).
pub const REBUILD_BACKOFF_INITIAL: Duration = Duration::from_secs(1);

/// Configuration of a datagram underlay.
#[derive(Debug, Clone)]
pub struct PacketConfig {
    /// L3 MTU in bytes, validated against `1280..=1500`.
    pub mtu: u16,
    /// IP family used to subtract the IP/UDP header overhead.
    pub family: IpFamily,
    /// Traffic pattern applied to the nonce prefix.
    pub nonce_pattern: NoncePattern,
    /// Length range and UDP applicability of the pattern.
    pub nonce_pattern_config: NoncePatternConfig,
}

impl Default for PacketConfig {
    fn default() -> Self {
        Self {
            mtu: DEFAULT_MTU,
            family: IpFamily::V4,
            nonce_pattern: NoncePattern::Random,
            nonce_pattern_config: NoncePatternConfig::default(),
        }
    }
}

/// Set socket options before binding.
#[cfg(unix)]
fn apply_socket_options(socket: &Socket) -> std::io::Result<()> {
    socket.set_reuse_address(true)
}

/// Windows intentionally does not set `SO_REUSEADDR` (`platform-notes.md` §a.1).
#[cfg(not(unix))]
fn apply_socket_options(_socket: &Socket) -> std::io::Result<()> {
    Ok(())
}

fn bind_socket(addr: SocketAddr) -> std::io::Result<UdpSocket> {
    let domain = match addr {
        SocketAddr::V4(_) => Domain::IPV4,
        SocketAddr::V6(_) => Domain::IPV6,
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    apply_socket_options(&socket)?;
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    let std_socket: std::net::UdpSocket = socket.into();
    UdpSocket::from_std(std_socket)
}

/// Exponential rebuild delay with jitter, in `[delay/2, delay]`.
///
/// `rand_below(n)` returns a uniform value in `0..n`; passing `|_| 0` makes
/// the result deterministic for tests.
#[must_use]
pub fn rebuild_backoff(attempt: u32, rand_below: impl Fn(u64) -> u64) -> Duration {
    let mut delay = REBUILD_BACKOFF_INITIAL;
    let mut tries = attempt;
    while tries > 0 && delay < REBUILD_BACKOFF_MAX {
        delay *= 2;
        tries -= 1;
    }
    if delay > REBUILD_BACKOFF_MAX {
        delay = REBUILD_BACKOFF_MAX;
    }
    let half = delay / 2;
    half + Duration::from_nanos(rand_below(half.as_nanos() as u64))
}

/// Convenience wrapper for [`rebuild_backoff`] using thread-local RNG.
#[must_use]
pub fn rebuild_backoff_random(attempt: u32) -> Duration {
    rebuild_backoff(attempt, |n| rand::random_range(0..n))
}

/// A UDP underlay bound to a local address.
#[derive(Debug)]
pub struct PacketUnderlay {
    socket: Arc<UdpSocket>,
    cipher: WireCipher,
    budget: MtuBudget,
    config: PacketConfig,
    bind_addr: SocketAddr,
    peer: Option<SocketAddr>,
    nonce_pattern_applied: bool,
    closed: bool,
}

impl PacketUnderlay {
    /// Bind a UDP socket to `addr`, applying platform socket options.
    pub async fn bind(
        addr: SocketAddr,
        key: AeadKey,
        config: PacketConfig,
    ) -> UnderlayResult<Self> {
        config
            .nonce_pattern_config
            .validate(&config.nonce_pattern)?;
        let family = IpFamily::from_addr(addr.ip());
        let budget = MtuBudget::new(config.mtu, family, true)?;
        let socket = bind_socket(addr)?;
        let bind_addr = socket.local_addr()?;
        Ok(Self {
            socket: Arc::new(socket),
            cipher: WireCipher::new(key),
            budget,
            config,
            bind_addr,
            peer: None,
            nonce_pattern_applied: false,
            closed: false,
        })
    }

    /// Bind an ephemeral UDP socket on loopback (convenience for clients/tests).
    pub async fn bind_ephemeral(key: AeadKey, config: PacketConfig) -> UnderlayResult<Self> {
        let addr = match config.family {
            IpFamily::V4 => SocketAddr::from(([127, 0, 0, 1], 0)),
            IpFamily::V6 => SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, 0)),
        };
        Self::bind(addr, key, config).await
    }

    /// Local socket address.
    pub fn local_addr(&self) -> UnderlayResult<SocketAddr> {
        Ok(self.socket.local_addr()?)
    }

    /// Shared handle to the listening socket, used by server-side sessions to
    /// send queued reply frames directly without waiting for a new inbound
    /// datagram on the listener loop.
    #[must_use]
    pub fn socket_handle(&self) -> Arc<UdpSocket> {
        Arc::clone(&self.socket)
    }

    /// Destination used by [`Underlay::send_segment`].
    #[must_use]
    pub const fn peer(&self) -> Option<SocketAddr> {
        self.peer
    }

    /// Set the destination for outgoing datagrams.
    pub fn set_peer(&mut self, peer: SocketAddr) {
        self.peer = Some(peer);
    }

    /// MTU-derived frame budget.
    #[must_use]
    pub const fn budget(&self) -> &MtuBudget {
        &self.budget
    }

    /// Rebuild the listening socket after a fatal socket error.
    ///
    /// Callers should sleep for [`rebuild_backoff`] before retrying.
    pub async fn rebind(&mut self) -> UnderlayResult<()> {
        self.closed = false;
        self.socket = Arc::new(bind_socket(self.bind_addr)?);
        self.bind_addr = self.socket.local_addr()?;
        Ok(())
    }

    /// Generate the per-datagram nonce, applying the pattern when due.
    fn next_nonce(&mut self) -> shadowlemon_crypto::WireNonce {
        let mut nonce = new_wire_nonce(None);
        let apply = self.config.nonce_pattern_config.apply_to_all_udp_packets
            || !self.nonce_pattern_applied;
        if apply {
            apply_nonce_pattern_random(
                &mut nonce,
                &self.config.nonce_pattern,
                &self.config.nonce_pattern_config,
            );
            self.nonce_pattern_applied = true;
        }
        nonce
    }

    /// Send an already-encoded datagram to `target` (used to reply on the
    /// listening socket without changing the stored peer).
    pub async fn send_to(&self, bytes: &[u8], target: SocketAddr) -> UnderlayResult<usize> {
        if bytes.len() > MAX_DATAGRAM_LEN {
            return Err(UnderlayError::DatagramTooLarge {
                got: bytes.len(),
                want: MAX_DATAGRAM_LEN,
            });
        }
        Ok(self.socket.send_to(bytes, target).await?)
    }

    /// Receive one raw datagram, returning the source address.
    pub async fn recv_raw(&self) -> UnderlayResult<(Vec<u8>, SocketAddr)> {
        let mut buf = vec![0u8; MAX_DATAGRAM_LEN];
        let (len, from) = self.socket.recv_from(&mut buf).await?;
        buf.truncate(len);
        Ok((buf, from))
    }
}

impl Underlay for PacketUnderlay {
    fn kind(&self) -> UnderlayKind {
        UnderlayKind::Packet
    }

    fn mtu(&self) -> Option<u16> {
        Some(self.config.mtu)
    }

    fn send_segment(&mut self, mut segment: Segment) -> BoxFuture<'_, UnderlayResult<()>> {
        Box::pin(async move {
            if self.closed {
                return Err(UnderlayError::Shutdown);
            }
            let peer = self.peer.ok_or(UnderlayError::NoPeer)?;
            segment.wire_nonce = self.next_nonce();
            if !self.budget.fits(&segment) {
                let len = shadowlemon_wire::frame_len(
                    segment.prefix_padding.len(),
                    segment.payload.len(),
                    segment.suffix_padding.len(),
                    true,
                );
                return Err(UnderlayError::DatagramTooLarge {
                    got: len,
                    want: self.budget.frame_budget,
                });
            }
            // Byte 16 of the wire nonce is XORed with 0x01 by the crypto
            // crate; it is inside the AES-GCM nonce but outside the
            // traffic-pattern prefix and the user hint.
            let payload_nonce = derive_udp_payload_nonce(&segment.wire_nonce);
            let frame = encode_segment(
                &self.cipher,
                &segment,
                &EncodeOptions {
                    include_nonce: true,
                    payload_nonce: PayloadNonce::Explicit(payload_nonce),
                },
            )?;
            self.socket.send_to(&frame, peer).await?;
            Ok(())
        })
    }

    fn recv_segment(&mut self) -> BoxFuture<'_, UnderlayResult<Segment>> {
        Box::pin(async move {
            if self.closed {
                return Err(UnderlayError::Shutdown);
            }
            let mut buf = vec![0u8; MAX_DATAGRAM_LEN];
            let (len, from) = self.socket.recv_from(&mut buf).await?;
            buf.truncate(len);
            self.peer = Some(from);
            let mut metadata_nonce = [0u8; shadowlemon_wire::WIRE_NONCE_LEN];
            if buf.len() < shadowlemon_wire::WIRE_NONCE_LEN {
                return Err(shadowlemon_wire::WireError::FrameTooShort {
                    got: buf.len(),
                    want: shadowlemon_wire::NONCE_AND_META_LEN,
                }
                .into());
            }
            metadata_nonce.copy_from_slice(&buf[..shadowlemon_wire::WIRE_NONCE_LEN]);
            let payload_nonce = derive_udp_payload_nonce(&metadata_nonce);
            let segment = decode_segment(
                &self.cipher,
                &buf,
                &DecodeOptions {
                    include_nonce: true,
                    implicit_metadata_nonce: metadata_nonce,
                    payload_nonce: PayloadNonce::Explicit(payload_nonce),
                },
            )?;
            Ok(segment)
        })
    }

    fn install_session_cipher(&mut self, key: AeadKey) {
        self.cipher.replace(key);
        self.nonce_pattern_applied = false;
    }

    fn shutdown(&mut self) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            self.closed = true;
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::underlay::{derive_udp_payload_nonce, fragment_with_numbers, FragmentReassembler};
    use shadowlemon_crypto::suite::Suite;
    use shadowlemon_wire::Metadata;

    const KEY: [u8; 32] = [11u8; 32];

    fn key() -> AeadKey {
        AeadKey::new(Suite::XChaCha20Poly1305, &KEY).unwrap()
    }

    fn config() -> PacketConfig {
        PacketConfig {
            mtu: 1280,
            family: IpFamily::V4,
            nonce_pattern: NoncePattern::Random,
            nonce_pattern_config: NoncePatternConfig::default(),
        }
    }

    #[tokio::test]
    async fn udp_datagram_round_trip_uses_per_datagram_nonce() {
        let mut server = PacketUnderlay::bind_ephemeral(key(), config())
            .await
            .unwrap();
        let mut client = PacketUnderlay::bind_ephemeral(key(), config())
            .await
            .unwrap();
        client.set_peer(server.local_addr().unwrap());
        server.set_peer(client.local_addr().unwrap());

        let mut nonces = Vec::new();
        for i in 0..4u32 {
            client
                .send_segment(Segment::new(
                    Metadata::data(6, 9, i, 0, 16, 0, 0, 4, 0),
                    [0u8; shadowlemon_wire::WIRE_NONCE_LEN],
                    vec![i as u8; 4],
                ))
                .await
                .unwrap();
            let got = server.recv_segment().await.unwrap();
            assert_eq!(got.payload, vec![i as u8; 4]);
            assert!(!nonces.contains(&got.wire_nonce));
            assert_ne!(derive_udp_payload_nonce(&got.wire_nonce), got.wire_nonce);
            nonces.push(got.wire_nonce);
        }
    }

    #[tokio::test]
    async fn udp_fragmentation_and_reassembly_within_mtu() {
        let mut server = PacketUnderlay::bind_ephemeral(key(), config())
            .await
            .unwrap();
        let mut client = PacketUnderlay::bind_ephemeral(key(), config())
            .await
            .unwrap();
        client.set_peer(server.local_addr().unwrap());

        let capacity = client.budget().payload_capacity(0, 0);
        let payload: Vec<u8> = (0..(capacity * 3 - 7)).map(|i| (i % 251) as u8).collect();
        let pieces = fragment_with_numbers(&payload, capacity).unwrap();
        assert_eq!(pieces.len(), 3);

        let mut reassembler = FragmentReassembler::new(64 * 1024);
        let mut assembled = None;
        for (number, piece) in pieces {
            let len = piece.len();
            client
                .send_segment(Segment::new(
                    Metadata::data(6, 42, 1, 0, 16, number, 0, len as u16, 0),
                    [0u8; 24],
                    piece,
                ))
                .await
                .unwrap();
            let got = server.recv_segment().await.unwrap();
            assembled = reassembler
                .insert((42u32, 1u32), got.metadata.fragment(), got.payload)
                .unwrap();
        }
        assert_eq!(assembled.unwrap(), payload);
    }

    #[tokio::test]
    async fn udp_enforces_mtu_budget() {
        let mut client = PacketUnderlay::bind_ephemeral(key(), config())
            .await
            .unwrap();
        client.set_peer(client.local_addr().unwrap());
        let too_big = client.budget().payload_capacity(0, 0) + 1;
        let segment = Segment::new(
            Metadata::data(6, 1, 0, 0, 16, 0, 0, 0, 0),
            [0u8; 24],
            vec![0u8; too_big],
        );
        assert!(matches!(
            client.send_segment(segment).await.unwrap_err(),
            UnderlayError::DatagramTooLarge { .. }
        ));
    }

    #[test]
    fn rebuild_backoff_is_bounded_and_jittered() {
        assert_eq!(rebuild_backoff(0, |_| 0), Duration::from_millis(500));
        assert_eq!(rebuild_backoff(1, |_| 0), Duration::from_secs(1));
        assert_eq!(rebuild_backoff(2, |_| 0), Duration::from_secs(2));
        assert_eq!(rebuild_backoff(3, |_| 0), Duration::from_secs(4));
        assert_eq!(rebuild_backoff(4, |_| 0), Duration::from_secs(8));
        assert_eq!(rebuild_backoff(5, |_| 0), Duration::from_secs(15));
        assert_eq!(rebuild_backoff(6, |_| 0), Duration::from_secs(15));
        assert_eq!(rebuild_backoff(100, |_| 0), Duration::from_secs(15));
        let jittered = rebuild_backoff(3, |n| n - 1);
        assert!(jittered >= Duration::from_secs(4) && jittered < Duration::from_secs(8));
    }

    #[tokio::test]
    async fn invalid_mtu_is_rejected() {
        let bad = PacketConfig {
            mtu: 1501,
            ..config()
        };
        assert!(matches!(
            PacketUnderlay::bind_ephemeral(key(), bad)
                .await
                .unwrap_err(),
            UnderlayError::InvalidMtu(1501)
        ));
    }
}
