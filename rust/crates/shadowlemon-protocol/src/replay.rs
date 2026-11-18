//! Replay protection for the two V0.2 traffic classes.
//!
//! Each direction gets its own [`ReplayCache`]: UDP c2s (domain 1) and UDP s2c
//! (domain 2). Signatures are 64-bit FNV-1a hashes of
//! `u32be(length) || domain || wire_nonce` (spec §8.1). The cache has two
//! generations of `GENERATION_CAPACITY` signatures and rotates after a
//! generation fills up or after `GENERATION_TTL` seconds.
//!
//! [`ReplayCache::check`] is strictly read-only and safe to call on data that
//! has not been authenticated; only [`ReplayCache::record`] changes state and
//! it must be called after a successful authentication.

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Mutex,
    },
    time::Instant,
};

/// Signatures kept in each generation.
pub const GENERATION_CAPACITY: u64 = 65_536;
/// A generation expires after six minutes (360 seconds).
pub const GENERATION_TTL: std::time::Duration = std::time::Duration::from_secs(360);
/// Number of shards; the index uses the high bits of the signature.
pub const SHARD_COUNT: usize = 16;

/// Traffic class a replay cache belongs to (spec §8.1).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum ReplayDomain {
    /// UDP client-to-server datagrams.
    UdpClientToServer = 1,
    /// UDP server-to-client datagrams.
    UdpServerToClient = 2,
}

impl ReplayDomain {
    /// Numeric domain byte used in the signature hash.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Source of a packet, used for the retransmission exemption.
///
/// A non-empty tag from the same source grants a retransmission exemption; an
/// empty tag never does. The wire form is `family || ip || u16be(port)`, at
/// most 19 bytes.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct SourceTag {
    bytes: [u8; 19],
    len: u8,
}

impl SourceTag {
    /// A tag with no source; it cannot grant a retransmission exemption.
    pub const EMPTY: Self = Self {
        bytes: [0; 19],
        len: 0,
    };

    /// Build a tag from its wire bytes. Returns `None` for more than 19 bytes.
    #[must_use]
    pub fn new(bytes: &[u8]) -> Option<Self> {
        if bytes.len() > 19 {
            return None;
        }
        let mut tag = Self::EMPTY;
        tag.bytes[..bytes.len()].copy_from_slice(bytes);
        tag.len = bytes.len() as u8;
        Some(tag)
    }

    /// Build the wire tag of an IPv4 source address.
    #[must_use]
    pub fn from_ipv4(ip: [u8; 4], port: u16) -> Self {
        let mut bytes = [0u8; 7];
        bytes[0] = 4;
        bytes[1..5].copy_from_slice(&ip);
        bytes[5..7].copy_from_slice(&port.to_be_bytes());
        Self::new(&bytes).expect(" IPv4 tag fits in 19 bytes")
    }

    /// Build the wire tag of an IPv6 source address.
    #[must_use]
    pub fn from_ipv6(ip: [u8; 16], port: u16) -> Self {
        let mut bytes = [0u8; 19];
        bytes[0] = 6;
        bytes[1..17].copy_from_slice(&ip);
        bytes[17..19].copy_from_slice(&port.to_be_bytes());
        Self::new(&bytes).expect(" IPv6 tag fits in 19 bytes")
    }

    /// Build a tag from a socket address.
    #[must_use]
    pub fn from_socket_addr(addr: SocketAddr) -> Self {
        match addr.ip() {
            std::net::IpAddr::V4(ip) => Self::from_ipv4(ip.octets(), addr.port()),
            std::net::IpAddr::V6(ip) => Self::from_ipv6(ip.octets(), addr.port()),
        }
    }

    /// Whether this tag carries no source.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Wire bytes of the tag.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }
}

/// Outcome of a read-only replay check.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplayDecision {
    /// The signature is not in either generation.
    Fresh,
    /// A duplicate from the same non-empty source: a legitimate retransmission.
    Retransmission,
    /// A duplicate that must be rejected.
    Replay,
}

impl ReplayDecision {
    /// Whether the packet must be rejected.
    #[must_use]
    pub const fn is_replay(self) -> bool {
        matches!(self, Self::Replay)
    }
}

/// FNV-1a 64-bit signature of `u32be(data.len()) || domain || data`.
#[must_use]
pub fn compute_signature(domain: ReplayDomain, data: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in (data.len() as u32).to_be_bytes() {
        hash = (hash ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3);
    }
    hash = (hash ^ u64::from(domain.as_u8())).wrapping_mul(0x0100_0000_01b3);
    for &byte in data {
        hash = (hash ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3);
    }
    hash
}

fn can_retransmit(recorded: SourceTag, tag: SourceTag) -> bool {
    !tag.is_empty() && recorded == tag
}

#[derive(Debug, Default)]
struct Shard {
    current: HashMap<u64, SourceTag>,
    previous: HashMap<u64, SourceTag>,
}

/// A two-generation replay cache for one traffic domain.
#[derive(Debug)]
pub struct ReplayCache {
    domain: ReplayDomain,
    shards: Vec<Mutex<Shard>>,
    rotate_lock: Mutex<()>,
    capacity: u64,
    count: AtomicU64,
    /// Expiry, in nanoseconds since `base`.
    expire_at_ns: AtomicU64,
    expire_interval_ns: u64,
    base: Instant,
}

impl ReplayCache {
    /// Create an empty cache for `domain`.
    #[must_use]
    pub fn new(domain: ReplayDomain) -> Self {
        let base = Instant::now();
        let expire_interval_ns = GENERATION_TTL.as_nanos() as u64;
        Self {
            domain,
            shards: (0..SHARD_COUNT)
                .map(|_| Mutex::new(Shard::default()))
                .collect(),
            rotate_lock: Mutex::new(()),
            capacity: GENERATION_CAPACITY,
            count: AtomicU64::new(0),
            expire_at_ns: AtomicU64::new(expire_interval_ns),
            expire_interval_ns,
            base,
        }
    }

    /// Domain this cache belongs to.
    #[must_use]
    pub const fn domain(&self) -> ReplayDomain {
        self.domain
    }

    /// Signature of `data` in this cache's domain.
    #[must_use]
    pub fn signature(&self, data: &[u8]) -> u64 {
        compute_signature(self.domain, data)
    }

    /// Read-only check of `sig` against both generations.
    ///
    /// This never inserts, refreshes a tag or rotates the cache. A duplicate
    /// with the same non-empty source tag is a [`ReplayDecision::Retransmission`].
    #[must_use]
    pub fn check(&self, sig: u64, tag: SourceTag) -> ReplayDecision {
        if self.capacity == 0 {
            return ReplayDecision::Fresh;
        }
        let shard = self
            .shard(sig)
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(recorded) = shard.current.get(&sig) {
            return if can_retransmit(*recorded, tag) {
                ReplayDecision::Retransmission
            } else {
                ReplayDecision::Replay
            };
        }
        if let Some(recorded) = shard.previous.get(&sig) {
            return if can_retransmit(*recorded, tag) {
                ReplayDecision::Retransmission
            } else {
                ReplayDecision::Replay
            };
        }
        ReplayDecision::Fresh
    }

    /// Insert a signature after successful authentication.
    ///
    /// Overwrites the source tag of an existing current-generation entry; a
    /// signature that lives only in the previous generation is promoted by
    /// being inserted into the current one.
    pub fn record(&self, sig: u64, tag: SourceTag) {
        if self.capacity == 0 {
            return;
        }
        if self.count.load(Ordering::Relaxed) >= self.capacity
            || self.now_ns() > self.expire_at_ns.load(Ordering::Relaxed)
        {
            self.rotate();
        }
        let mut shard = self
            .shard(sig)
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !shard.current.contains_key(&sig) {
            self.count.fetch_add(1, Ordering::Relaxed);
        }
        shard.current.insert(sig, tag);
    }

    /// Number of signatures in the current and previous generations.
    #[must_use]
    pub fn sizes(&self) -> (u64, u64) {
        let mut current = 0;
        let mut previous = 0;
        for shard in &self.shards {
            let shard = shard
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            current += shard.current.len() as u64;
            previous += shard.previous.len() as u64;
        }
        (current, previous)
    }

    /// Drop every recorded signature.
    pub fn clear(&self) {
        let _guard = self
            .rotate_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for shard in &self.shards {
            let mut shard = shard
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            shard.current.clear();
            shard.previous.clear();
        }
        self.count.store(0, Ordering::Relaxed);
    }

    fn shard(&self, sig: u64) -> &Mutex<Shard> {
        &self.shards[((sig >> 60) as usize) & (SHARD_COUNT - 1)]
    }

    fn now_ns(&self) -> u64 {
        self.base.elapsed().as_nanos() as u64
    }

    fn rotate(&self) {
        let _guard = self
            .rotate_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let now = self.now_ns();
        let expire_at = self.expire_at_ns.load(Ordering::Relaxed);
        let interval = self.expire_interval_ns;

        if now.saturating_sub(expire_at) > interval {
            // Both generations are stale: drop them entirely.
            for shard in &self.shards {
                let mut shard = shard
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let removed = shard.current.len() as u64;
                shard.current.clear();
                shard.previous.clear();
                self.count.fetch_sub(removed, Ordering::Relaxed);
            }
            self.expire_at_ns
                .store(now.saturating_add(interval), Ordering::Relaxed);
            return;
        }

        if self.count.load(Ordering::Relaxed) < self.capacity && now <= expire_at {
            // Another writer performed the rotation already.
            return;
        }

        // Current becomes previous; the new current generation starts empty.
        for shard in &self.shards {
            let mut shard = shard
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let removed = shard.current.len() as u64;
            shard.previous = std::mem::take(&mut shard.current);
            self.count.fetch_sub(removed, Ordering::Relaxed);
        }
        self.expire_at_ns
            .store(now.saturating_add(interval), Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sig(n: u64) -> u64 {
        // Spread signatures across shards while keeping them deterministic.
        n.rotate_left(60) | (n << 4)
    }

    #[test]
    fn signature_is_domain_separated_and_length_prefixed() {
        let nonce = [0x11u8; 24];
        let a = compute_signature(ReplayDomain::UdpClientToServer, &nonce);
        let b = compute_signature(ReplayDomain::UdpServerToClient, &nonce);
        assert_ne!(a, b);
        assert_ne!(
            a,
            compute_signature(ReplayDomain::UdpClientToServer, &nonce[..23])
        );

        // FNV-1a over u32be(24), domain=1, then 24 identical bytes.
        let mut expected = 0xcbf2_9ce4_8422_2325_u64;
        for byte in 24_u32.to_be_bytes() {
            expected = (expected ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3);
        }
        expected = (expected ^ u64::from(ReplayDomain::UdpClientToServer.as_u8()))
            .wrapping_mul(0x0100_0000_01b3);
        for byte in nonce {
            expected = (expected ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3);
        }
        assert_eq!(a, expected);
    }

    #[test]
    fn check_is_read_only_and_forged_packets_are_never_recorded() {
        let cache = ReplayCache::new(ReplayDomain::UdpClientToServer);
        let tag = SourceTag::from_ipv4([10, 0, 0, 1], 1234);
        let signature = compute_signature(ReplayDomain::UdpClientToServer, &[7u8; 24]);

        // A forged packet only ever runs `check`: nothing is stored.
        assert_eq!(cache.check(signature, tag), ReplayDecision::Fresh);
        assert_eq!(
            cache.check(signature, SourceTag::EMPTY),
            ReplayDecision::Fresh
        );
        assert_eq!(cache.sizes(), (0, 0));

        // After authentication the signature is recorded, but repeating the
        // read-only check does not refresh its generation or source tag.
        cache.record(signature, tag);
        assert_eq!(cache.sizes(), (1, 0));
        for _ in 0..3 {
            assert_eq!(
                cache.check(signature, SourceTag::EMPTY),
                ReplayDecision::Replay
            );
            assert_eq!(cache.sizes(), (1, 0));
        }
        cache.record(signature, SourceTag::EMPTY);
        assert_eq!(cache.sizes(), (1, 0));
        assert_eq!(cache.check(signature, tag), ReplayDecision::Replay);
    }

    #[test]
    fn rotation_keeps_previous_generation_then_forgets_it() {
        let mut cache = ReplayCache::new(ReplayDomain::UdpClientToServer);
        let old = sig(1);
        cache.record(old, SourceTag::EMPTY);
        assert_eq!(cache.check(old, SourceTag::EMPTY), ReplayDecision::Replay);

        // Force a capacity rotation.
        cache
            .expire_at_ns
            .store(cache.now_ns() + 10, Ordering::Relaxed);
        for i in 0..GENERATION_CAPACITY {
            cache.record(sig(i + 2), SourceTag::EMPTY);
        }
        assert_eq!(cache.sizes(), (GENERATION_CAPACITY, 1));
        assert_eq!(cache.check(old, SourceTag::EMPTY), ReplayDecision::Replay);

        // A second rotation drops the old generation entirely.
        for i in 0..GENERATION_CAPACITY {
            cache.record(sig(i + 2), SourceTag::EMPTY);
        }
        assert_eq!(cache.check(old, SourceTag::EMPTY), ReplayDecision::Fresh);
        assert_eq!(
            cache.check(sig(2), SourceTag::EMPTY),
            ReplayDecision::Replay
        );

        // Time-based rotation after a full TTL of staleness clears both maps.
        cache.base -= std::time::Duration::from_secs(721);
        cache.record(sig(u64::MAX), SourceTag::EMPTY);
        assert_eq!(cache.sizes(), (1, 0));
        assert_eq!(cache.check(sig(2), SourceTag::EMPTY), ReplayDecision::Fresh);
    }

    #[test]
    fn udp_same_source_is_exempt_but_empty_and_cross_source_are_not() {
        let cache = ReplayCache::new(ReplayDomain::UdpClientToServer);
        let a = SourceTag::from_ipv4([192, 0, 2, 1], 5000);
        let b = SourceTag::from_ipv4([192, 0, 2, 2], 5000);
        let signature = compute_signature(ReplayDomain::UdpClientToServer, &[9u8; 24]);

        cache.record(signature, a);
        assert_eq!(cache.check(signature, a), ReplayDecision::Retransmission);
        assert_eq!(cache.check(signature, b), ReplayDecision::Replay);
        assert_eq!(
            cache.check(signature, SourceTag::EMPTY),
            ReplayDecision::Replay
        );

        // Overwriting the tag with an authenticated record from another source
        // transfers the exemption to that source only.
        cache.record(signature, b);
        assert_eq!(cache.check(signature, b), ReplayDecision::Retransmission);
        assert_eq!(cache.check(signature, a), ReplayDecision::Replay);
        assert_eq!(
            cache.check(signature, SourceTag::EMPTY),
            ReplayDecision::Replay
        );
    }

    #[test]
    fn empty_tag_has_no_exemption() {
        let cache = ReplayCache::new(ReplayDomain::UdpClientToServer);
        let signature = cache.signature(&[3u8; 24]);
        cache.record(signature, SourceTag::EMPTY);
        assert_eq!(
            cache.check(signature, SourceTag::EMPTY),
            ReplayDecision::Replay
        );
        assert!(cache.check(signature, SourceTag::EMPTY).is_replay());
        // A lookup with an empty tag never grants an exemption, even when the
        // recorded tag came from a real source.
        cache.record(signature, SourceTag::from_ipv6([1; 16], 42));
        assert_eq!(
            cache.check(signature, SourceTag::EMPTY),
            ReplayDecision::Replay
        );
    }

    #[test]
    fn hint_length_matches_signature_input_contract() {
        // The signature input is the full 24-byte wire nonce; the user hint is
        // its last four bytes. This guards a common integration mistake.
        assert_eq!(shadowlemon_crypto::HINT_LEN, 4);
        assert_eq!(shadowlemon_crypto::WIRE_NONCE_LEN, 24);
    }
}
