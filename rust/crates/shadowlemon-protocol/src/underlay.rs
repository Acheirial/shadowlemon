//! Core abstractions for the ShadowLemon V0.2 UDP underlay transport.
//!
//! This module owns the parts of the data plane shared by the wire and driver
//! layers (spec `protocol-v0.2.md` §4, §10; `reference-go-v3.md` §7):
//!
//! * [`Underlay`] – the async read/write interface implemented by the UDP
//!   underlay, which draws a fresh nonce per datagram.
//! * [`WireCipher`] – adapts the crypto crate's `AeadKey` to the wire crate's
//!   `Cipher` trait (the AEAD nonce is always the *suffix* of the wire nonce).
//! * [`NoncePattern`] – traffic-pattern rewriting of at most 12 leading nonce
//!   bytes. Bytes `wireNonce[12:24]` are **never** rewritten, so AES-GCM never
//!   sees a deterministic nonce.
//! * MTU budgeting – [`udp_payload_budget`] subtracts 28 (IPv4) or 48 (IPv6)
//!   bytes from the configured L3 MTU; [`MtuBudget`] turns that into a maximum
//!   application fragment size via the wire crate's `frame_len` helpers.
//! * [`fragment`] / [`FragmentReassembler`] – application-data fragmentation
//!   across datagrams, using the metadata fragment counter that counts down to
//!   `0` for the final fragment.
//!
//! The concrete Tokio transport lives in [`crate::underlay_packet`].

use std::{
    collections::{BTreeMap, HashMap},
    fmt,
    hash::Hash,
    io,
    net::IpAddr,
};

use futures::future::BoxFuture;
use shadowlemon_crypto::{aead::AeadKey, WireNonce};
use shadowlemon_wire::{
    frame_len, Cipher, CipherError, Segment, META_BLOCK_LEN, NONCE_AND_META_LEN, WIRE_NONCE_LEN,
};

/// Default L3 MTU from `reference-go-v3.md` §0 (`DefaultMTU`).
pub const DEFAULT_MTU: u16 = 1400;
/// Smallest accepted L3 MTU (spec §4.4).
pub const MIN_MTU: u16 = 1280;
/// Largest accepted L3 MTU (spec §4.4).
pub const MAX_MTU: u16 = 1500;
/// IPv4 header (20) + UDP header (8).
pub const IPV4_OVERHEAD: usize = 28;
/// IPv6 header (40) + UDP header (8).
pub const IPV6_OVERHEAD: usize = 48;
/// Plaintext routing envelope prepended by the driver to every UDP datagram.
/// It must be reserved from the MTU budget so the IP packet never exceeds the
/// configured L3 MTU.
pub const UDP_ROUTING_ENVELOPE_LEN: usize = 5;
/// Maximum random prefix padding added to a frame. Combined with the suffix
/// budget this breaks the deterministic frame-length fingerprint.
pub const MAX_PREFIX_PADDING: usize = 32;
/// Maximum random suffix padding added to a frame.
pub const MAX_SUFFIX_PADDING: usize = 32;
/// Largest possible UDP datagram payload.
pub const MAX_DATAGRAM_LEN: usize = 65_535;
/// A traffic pattern may only rewrite the first 12 nonce bytes so that the
/// AES-GCM nonce (`wireNonce[12:24]`) stays unpredictable (spec §2.3, §10.2).
pub const MAX_NONCE_PATTERN_LEN: usize = WIRE_NONCE_LEN - 12;
/// Highest usable metadata fragment number; `0` is the final fragment.
pub const MAX_FRAGMENT_NUMBER: u8 = u8::MAX;

/// Errors reported by an underlay transport.
#[derive(Debug, thiserror::Error)]
pub enum UnderlayError {
    /// An underlying I/O operation failed.
    #[error("underlay I/O error: {0}")]
    Io(#[from] io::Error),
    /// The wire codec rejected a frame.
    #[error("wire codec error: {0}")]
    Wire(#[from] shadowlemon_wire::WireError),
    /// The AEAD rejected a block.
    #[error("cipher error: {0}")]
    Cipher(#[from] CipherError),
    /// The peer closed the connection before any byte of a frame arrived.
    #[error("connection closed")]
    Closed,
    /// A partial frame was followed by EOF.
    #[error("truncated frame: read {got} of {want} bytes")]
    TruncatedFrame {
        /// Bytes actually read.
        got: usize,
        /// Bytes required.
        want: usize,
    },
    /// A datagram exceeded the configured MTU budget.
    #[error("datagram of {got} bytes exceeds MTU budget of {want} bytes")]
    DatagramTooLarge {
        /// Datagram length.
        got: usize,
        /// Maximum permitted length.
        want: usize,
    },
    /// The configured L3 MTU was outside `1280..=1500`.
    #[error("invalid L3 MTU {0} (want {min}..={max})", min = MIN_MTU, max = MAX_MTU)]
    InvalidMtu(u16),
    /// A nonce-pattern configuration was inconsistent.
    #[error("invalid nonce pattern: {0}")]
    InvalidNoncePattern(String),
    /// No destination peer was configured for a datagram underlay.
    #[error("no UDP peer configured")]
    NoPeer,
    /// Too many fragments for the one-byte fragment counter.
    #[error("application data requires {got} fragments (limit {want})", want = MAX_FRAGMENT_NUMBER as usize + 1)]
    TooManyFragments {
        /// Number of fragments required.
        got: usize,
        /// Maximum number of fragments.
        want: usize,
    },
    /// A reassembly buffer grew past its configured limit.
    #[error("reassembly buffer exceeded {0} bytes")]
    ReassemblyTooLarge(usize),
    /// A session/underlay limit was reached.
    #[error("mux limit reached: {0}")]
    LimitReached(&'static str),
    /// A configured endpoint was incomplete or unresolvable.
    #[error("invalid endpoint: {0}")]
    InvalidEndpoint(String),
    /// The underlay was shut down.
    #[error("underlay is shut down")]
    Shutdown,
    /// A handshake layer was not wired into the mux.
    #[error("handshake layer is not configured")]
    NoHandshakeDriver,
}

/// Result alias used throughout the underlay and mux modules.
pub type UnderlayResult<T> = Result<T, UnderlayError>;

/// Transport kind of an underlay.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UnderlayKind {
    /// Unreliable datagrams (UDP).
    Packet,
}

impl fmt::Display for UnderlayKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Packet => "UDP",
        })
    }
}

/// Async read/write interface for the UDP underlay.
///
/// The underlay draws a fresh nonce per datagram. `install_session_cipher` is
/// called once the V0.2 handshake completes (spec §4.3).
pub trait Underlay: Send {
    /// Transport kind.
    fn kind(&self) -> UnderlayKind;

    /// Configured L3 MTU for the datagram underlay.
    fn mtu(&self) -> Option<u16>;

    /// Send one encrypted segment, updating the outbound nonce state.
    fn send_segment(&mut self, segment: Segment) -> BoxFuture<'_, UnderlayResult<()>>;

    /// Receive one encrypted segment, updating the inbound nonce state.
    fn recv_segment(&mut self) -> BoxFuture<'_, UnderlayResult<Segment>>;

    /// Replace the handshake (static-key) cipher with the session cipher.
    fn install_session_cipher(&mut self, key: AeadKey);

    /// Flush and close the underlying transport.
    fn shutdown(&mut self) -> BoxFuture<'_, ()>;
}

/// Adapts [`AeadKey`] to the wire crate's AEAD-agnostic [`Cipher`] trait.
///
/// `AeadKey` already performs the suite-specific nonce truncation
/// (`wireNonce[12:24]` for AES-GCM), so the adapter is a thin error mapping.
pub struct WireCipher {
    key: AeadKey,
}

impl fmt::Debug for WireCipher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("WireCipher(<redacted>)")
    }
}

impl WireCipher {
    /// Wrap a key.
    #[must_use]
    pub const fn new(key: AeadKey) -> Self {
        Self { key }
    }

    /// Borrow the underlying key.
    #[must_use]
    pub const fn key(&self) -> &AeadKey {
        &self.key
    }

    /// Consume the adapter and return the key.
    #[must_use]
    pub fn into_key(self) -> AeadKey {
        self.key
    }

    /// Replace the key (used at the handshake cipher-chain switch).
    pub fn replace(&mut self, key: AeadKey) {
        self.key = key;
    }
}

impl Cipher for WireCipher {
    fn seal(&self, wire_nonce: &WireNonce, plaintext: &[u8]) -> Result<Vec<u8>, CipherError> {
        self.key
            .seal(wire_nonce, plaintext)
            .map_err(CipherError::failed)
    }

    fn open(&self, wire_nonce: &WireNonce, ciphertext: &[u8]) -> Result<Vec<u8>, CipherError> {
        self.key
            .open(wire_nonce, ciphertext)
            .map_err(CipherError::failed)
    }
}

impl From<AeadKey> for WireCipher {
    fn from(key: AeadKey) -> Self {
        Self::new(key)
    }
}

/// Traffic-pattern nonce-prefix strategy (`reference-go-v3.md` §10.2).
///
/// Every variant is constrained to `wireNonce[0..12]`; the AEAD nonce region
/// `wireNonce[12..24]` (including the UDP payload flip at byte 16) is left
/// untouched. The `Fixed` variant stores raw prefix candidates (at most 12
/// bytes each) as decoded bytes, not hex strings.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum NoncePattern {
    /// Leave the random prefix alone (the default).
    #[default]
    Random,
    /// Rewrite the prefix with printable ASCII bytes `0x20..=0x7e`.
    Printable,
    /// Rewrite the prefix with the common 64-character printable subset.
    PrintableSubset,
    /// Copy one of the supplied fixed prefixes.
    Fixed(Vec<Vec<u8>>),
}

/// Rewriting lengths and UDP applicability of a [`NoncePattern`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NoncePatternConfig {
    /// Minimum number of prefix bytes to rewrite.
    pub min_len: usize,
    /// Maximum number of prefix bytes to rewrite (clamped to 12).
    pub max_len: usize,
    /// Rewrite every UDP datagram instead of only the first one.
    pub apply_to_all_udp_packets: bool,
}

impl Default for NoncePatternConfig {
    fn default() -> Self {
        Self {
            min_len: 6,
            max_len: MAX_NONCE_PATTERN_LEN,
            apply_to_all_udp_packets: true,
        }
    }
}

impl NoncePatternConfig {
    /// Validate `min_len <= max_len <= 12` and every fixed prefix length.
    pub fn validate(&self, pattern: &NoncePattern) -> UnderlayResult<()> {
        if self.min_len > self.max_len || self.max_len > MAX_NONCE_PATTERN_LEN {
            return Err(UnderlayError::InvalidNoncePattern(format!(
                "length range {}..={} outside 0..={}",
                self.min_len, self.max_len, MAX_NONCE_PATTERN_LEN
            )));
        }
        if let NoncePattern::Fixed(prefixes) = pattern {
            if prefixes.iter().any(|p| p.len() > MAX_NONCE_PATTERN_LEN) {
                return Err(UnderlayError::InvalidNoncePattern(format!(
                    "fixed prefix longer than {} bytes",
                    MAX_NONCE_PATTERN_LEN
                )));
            }
        }
        Ok(())
    }

    /// Choose a rewrite length in `min_len..=max_len` via `rand_below`.
    #[must_use]
    pub fn choose_len(&self, mut rand_below: impl FnMut(usize) -> usize) -> usize {
        if self.min_len >= self.max_len {
            return self.max_len.min(MAX_NONCE_PATTERN_LEN);
        }
        let span = self.max_len - self.min_len + 1;
        self.min_len + rand_below(span).min(span - 1)
    }
}

/// The printable subset used by `NONCE_TYPE_PRINTABLE_SUBSET`.
pub const PRINTABLE_SUBSET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Apply a traffic pattern to the leading bytes of `wire_nonce`.
///
/// `rand_below(n)` must return a uniform value in `0..n` and `rand_byte()`
/// an arbitrary byte. Supplying them as closures keeps this function
/// deterministic in tests. Only indices `0..12` are ever written.
pub fn apply_nonce_pattern(
    wire_nonce: &mut WireNonce,
    pattern: &NoncePattern,
    config: &NoncePatternConfig,
    mut rand_below: impl FnMut(usize) -> usize,
    mut rand_byte: impl FnMut() -> u8,
) {
    let len = config
        .choose_len(&mut rand_below)
        .min(MAX_NONCE_PATTERN_LEN);
    if len == 0 {
        return;
    }
    match pattern {
        NoncePattern::Random => {}
        NoncePattern::Printable => {
            for byte in wire_nonce.iter_mut().take(len) {
                *byte = 0x20 + (rand_below(0x5f).min(0x5e) as u8);
            }
        }
        NoncePattern::PrintableSubset => {
            for byte in wire_nonce.iter_mut().take(len) {
                *byte = PRINTABLE_SUBSET[rand_below(PRINTABLE_SUBSET.len())];
            }
        }
        NoncePattern::Fixed(prefixes) => {
            if prefixes.is_empty() {
                return;
            }
            let idx = rand_below(prefixes.len());
            let prefix = &prefixes[idx];
            let copy_len = len.min(prefix.len()).min(MAX_NONCE_PATTERN_LEN);
            wire_nonce[..copy_len].copy_from_slice(&prefix[..copy_len]);
        }
    }
    // The unused prefix bytes stay random; `rand_byte` exists so callers can
    // feed the same RNG used elsewhere without reseeding it here.
    if matches!(pattern, NoncePattern::Fixed(_)) {
        let _ = rand_byte();
    }
}

/// Convenience wrapper for [`apply_nonce_pattern`] using thread-local RNG.
pub fn apply_nonce_pattern_random(
    wire_nonce: &mut WireNonce,
    pattern: &NoncePattern,
    config: &NoncePatternConfig,
) {
    apply_nonce_pattern(
        wire_nonce,
        pattern,
        config,
        |n| rand::random_range(0..n),
        rand::random,
    );
}

/// Generate a fresh 24-byte wire nonce, applying a traffic pattern if any.
#[must_use]
pub fn new_wire_nonce(pattern: Option<&NoncePattern>) -> WireNonce {
    let mut nonce = [0u8; WIRE_NONCE_LEN];
    for byte in &mut nonce {
        *byte = rand::random();
    }
    if let Some(pattern) = pattern {
        apply_nonce_pattern_random(&mut nonce, pattern, &NoncePatternConfig::default());
    }
    nonce
}

/// Derive the UDP payload nonce from a metadata nonce.
///
/// This delegates to the crypto crate's `udp_payload_nonce` (byte 16 XOR
/// `0x01`) instead of duplicating the rule. It is kept as an underlay-level
/// helper so both transports and their tests use one entry point.
#[must_use]
pub fn derive_udp_payload_nonce(metadata_nonce: &WireNonce) -> WireNonce {
    shadowlemon_crypto::aead::udp_payload_nonce(metadata_nonce)
}

/// IP family whose header size is subtracted from the L3 MTU.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpFamily {
    /// IPv4: 20-byte IP header + 8-byte UDP header.
    V4,
    /// IPv6: 40-byte IP header + 8-byte UDP header.
    V6,
}

impl IpFamily {
    /// Classify an address (IPv4-mapped IPv6 addresses count as IPv6).
    #[must_use]
    pub const fn from_addr(addr: IpAddr) -> Self {
        match addr {
            IpAddr::V4(_) => Self::V4,
            IpAddr::V6(_) => Self::V6,
        }
    }

    /// Bytes subtracted from the L3 MTU for this family.
    #[must_use]
    pub const fn header_overhead(self) -> usize {
        match self {
            Self::V4 => IPV4_OVERHEAD,
            Self::V6 => IPV6_OVERHEAD,
        }
    }
}

/// Validate an L3 MTU against the configured `1280..=1500` range.
pub fn validate_l3_mtu(mtu: u16) -> UnderlayResult<()> {
    if (MIN_MTU..=MAX_MTU).contains(&mtu) {
        Ok(())
    } else {
        Err(UnderlayError::InvalidMtu(mtu))
    }
}

/// Maximum UDP payload (encrypted segment) size for an L3 MTU and family.
pub fn udp_payload_budget(mtu: u16, family: IpFamily) -> UnderlayResult<usize> {
    validate_l3_mtu(mtu)?;
    Ok(usize::from(mtu) - family.header_overhead() - UDP_ROUTING_ENVELOPE_LEN)
}

/// Turn an L3 MTU into a per-fragment application-payload capacity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MtuBudget {
    /// Maximum encrypted segment length that fits in one datagram.
    pub frame_budget: usize,
    /// Whether frames carry an explicit nonce (always true for UDP).
    pub include_nonce: bool,
}

impl MtuBudget {
    /// Build a budget, validating the MTU (spec §4.4).
    pub fn new(mtu: u16, family: IpFamily, include_nonce: bool) -> UnderlayResult<Self> {
        Ok(Self {
            frame_budget: udp_payload_budget(mtu, family)?,
            include_nonce,
        })
    }

    /// Largest application payload that fits with the given padding lengths.
    #[must_use]
    pub fn payload_capacity(&self, prefix_len: usize, suffix_len: usize) -> usize {
        let fixed = if self.include_nonce {
            NONCE_AND_META_LEN
        } else {
            META_BLOCK_LEN
        };
        let available = self
            .frame_budget
            .saturating_sub(fixed + prefix_len + suffix_len);
        // A non-empty payload always carries a 16-byte tag.
        available.saturating_sub(shadowlemon_wire::TAG_LEN)
    }

    /// Whether `segment` fits in one datagram.
    #[must_use]
    pub fn fits(&self, segment: &Segment) -> bool {
        let len = frame_len(
            segment.prefix_padding.len(),
            segment.payload.len(),
            segment.suffix_padding.len(),
            self.include_nonce,
        );
        len <= self.frame_budget && len <= MAX_DATAGRAM_LEN
    }
}

/// Split application data into fragments of at most `max_fragment` bytes.
///
/// An empty input yields no fragments. Callers should emit a single empty
/// payload themselves when they need a control frame.
#[must_use]
pub fn fragment(data: &[u8], max_fragment: usize) -> Vec<Vec<u8>> {
    if data.is_empty() || max_fragment == 0 {
        return Vec::new();
    }
    data.chunks(max_fragment).map(<[u8]>::to_vec).collect()
}

/// Fragment data and attach the metadata fragment numbers.
///
/// Numbers count down from `count - 1` to `0`; `0` marks the final fragment
/// (spec §6.2). Returns [`UnderlayError::TooManyFragments`] if more than 256
/// fragments are needed.
pub fn fragment_with_numbers(
    data: &[u8],
    max_fragment: usize,
) -> UnderlayResult<Vec<(u8, Vec<u8>)>> {
    let chunks = fragment(data, max_fragment);
    if chunks.len() > usize::from(MAX_FRAGMENT_NUMBER) + 1 {
        return Err(UnderlayError::TooManyFragments {
            got: chunks.len(),
            want: usize::from(MAX_FRAGMENT_NUMBER) + 1,
        });
    }
    let count = chunks.len();
    Ok(chunks
        .into_iter()
        .enumerate()
        .map(|(i, chunk)| ((count - 1 - i) as u8, chunk))
        .collect())
}

/// Reassemble fragments keyed by `(session ID, sequence)` or any other key.
///
/// Fragment numbers count down to `0`, so the highest number seen reveals the
/// total count. Completion requires every number `0..total` exactly once.
#[derive(Debug)]
pub struct FragmentReassembler<K: Eq + Hash> {
    parts: HashMap<K, BTreeMap<u8, Vec<u8>>>,
    total: HashMap<K, usize>,
    max_total_bytes: usize,
}

impl<K: Eq + Hash + Clone> FragmentReassembler<K> {
    /// Create a reassembler that refuses a single message larger than
    /// `max_total_bytes`.
    #[must_use]
    pub fn new(max_total_bytes: usize) -> Self {
        Self {
            parts: HashMap::new(),
            total: HashMap::new(),
            max_total_bytes,
        }
    }

    /// Insert one fragment. Returns the completed byte stream once every
    /// fragment of the message has arrived.
    pub fn insert(
        &mut self,
        key: K,
        fragment_number: u8,
        data: Vec<u8>,
    ) -> UnderlayResult<Option<Vec<u8>>> {
        let total = usize::from(fragment_number) + 1;
        if total > usize::from(MAX_FRAGMENT_NUMBER) + 1 {
            return Err(UnderlayError::TooManyFragments {
                got: total,
                want: usize::from(MAX_FRAGMENT_NUMBER) + 1,
            });
        }
        let entry = self.total.entry(key.clone()).or_insert(0);
        *entry = (*entry).max(total);
        let total = *entry;

        let parts = self.parts.entry(key.clone()).or_default();
        parts.insert(fragment_number, data);

        let bytes: usize = parts.values().map(Vec::len).sum();
        if bytes > self.max_total_bytes {
            self.parts.remove(&key);
            self.total.remove(&key);
            return Err(UnderlayError::ReassemblyTooLarge(self.max_total_bytes));
        }
        if parts.len() != total || (0..total).any(|i| !parts.contains_key(&(i as u8))) {
            return Ok(None);
        }

        let parts = self.parts.remove(&key).expect("entry was inserted above");
        self.total.remove(&key);
        let mut out = Vec::with_capacity(bytes);
        for number in (0..total).rev() {
            let part = parts.get(&(number as u8)).expect("completeness checked");
            out.extend_from_slice(part);
        }
        Ok(Some(out))
    }

    /// Discard all fragments for a message (e.g. after a timeout).
    pub fn remove(&mut self, key: &K) {
        self.parts.remove(key);
        self.total.remove(key);
    }

    /// Number of messages currently being reassembled.
    #[must_use]
    pub fn len(&self) -> usize {
        self.parts.len()
    }

    /// Whether no message is being reassembled.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.parts.is_empty()
    }

    /// Total bytes currently buffered across all messages.
    #[must_use]
    pub fn buffered_bytes(&self) -> usize {
        self.parts
            .values()
            .flat_map(|m| m.values())
            .map(Vec::len)
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shadowlemon_wire::{payload_block_len, Metadata};

    #[test]
    fn traffic_pattern_never_touches_aead_nonce_region() {
        for pattern in [
            NoncePattern::Printable,
            NoncePattern::PrintableSubset,
            NoncePattern::Fixed(vec![vec![0xAA; 12], vec![0x01, 0x02]]),
        ] {
            let config = NoncePatternConfig {
                min_len: 0,
                max_len: 12,
                apply_to_all_udp_packets: true,
            };
            config.validate(&pattern).unwrap();
            let mut nonce = [0x5au8; WIRE_NONCE_LEN];
            let suffix = nonce[12..].to_vec();
            for len in 0..40 {
                apply_nonce_pattern(&mut nonce, &pattern, &config, |n| len % n.max(1), || 0xff);
                assert_eq!(&nonce[12..], suffix.as_slice());
            }
            assert_eq!(derive_udp_payload_nonce(&nonce)[16], suffix[4] ^ 0x01);
        }
    }

    #[test]
    fn invalid_nonce_patterns_are_rejected() {
        let config = NoncePatternConfig {
            min_len: 10,
            max_len: 13,
            apply_to_all_udp_packets: true,
        };
        assert!(config.validate(&NoncePattern::Random).is_err());
        let config = NoncePatternConfig::default();
        assert!(config
            .validate(&NoncePattern::Fixed(vec![vec![0u8; 13]]))
            .is_err());
    }

    #[test]
    fn mtu_budget_matches_spec_headers() {
        assert_eq!(udp_payload_budget(1400, IpFamily::V4).unwrap(), 1367);
        assert_eq!(udp_payload_budget(1400, IpFamily::V6).unwrap(), 1347);
        assert!(validate_l3_mtu(1279).is_err());
        assert!(validate_l3_mtu(1501).is_err());
        validate_l3_mtu(1280).unwrap();
        validate_l3_mtu(1500).unwrap();

        let budget = MtuBudget::new(1400, IpFamily::V4, true).unwrap();
        let segment = Segment::new(
            Metadata::data(6, 1, 0, 0, 16, 0, 2, 100, 3),
            [1u8; WIRE_NONCE_LEN],
            vec![0xaa; 100],
        );
        assert!(budget.fits(&segment));
        assert_eq!(budget.payload_capacity(2, 3), 1367 - 72 - 2 - 3 - 16);
        let big = Segment::new(
            Metadata::data(6, 1, 0, 0, 16, 0, 0, 32768, 0),
            [1u8; WIRE_NONCE_LEN],
            vec![0u8; 32768],
        );
        assert!(!budget.fits(&big));
    }

    #[test]
    fn fragmentation_numbers_count_down_and_reassemble() {
        let data: Vec<u8> = (0..250u8).collect();
        let pieces = fragment_with_numbers(&data, 100).unwrap();
        assert_eq!(pieces.len(), 3);
        assert_eq!(pieces[0].0, 2);
        assert_eq!(pieces[2].0, 0);

        let mut reassembler = FragmentReassembler::new(1024);
        let mut out = None;
        // Fragments arrive in wire order: highest number first, zero last.
        for (number, piece) in pieces {
            out = reassembler.insert((1u32, 0u32), number, piece).unwrap();
        }
        assert_eq!(out.unwrap(), data);
        assert!(reassembler.is_empty());

        let too_many = vec![0u8; 257];
        assert!(matches!(
            fragment_with_numbers(&too_many, 1),
            Err(UnderlayError::TooManyFragments { .. })
        ));
    }

    #[test]
    fn reassembler_detects_gaps_and_oversize() {
        let mut r = FragmentReassembler::new(16);
        assert!(r.insert(1u32, 2u8, vec![9]).unwrap().is_none());
        assert!(r.insert(1u32, 0u8, vec![8]).unwrap().is_none());
        assert!(r.insert(1u32, 1u8, vec![7]).unwrap().is_some());
        assert!(r.is_empty());

        assert!(r.insert(2u32, 1u8, vec![0; 20]).is_err());
        assert!(r.is_empty());
    }

    #[test]
    fn wire_helpers_are_reachable() {
        assert_eq!(META_BLOCK_LEN, 48);
        assert_eq!(NONCE_AND_META_LEN, 72);
        assert_eq!(payload_block_len(0), 0);
        assert_eq!(frame_len(0, 0, 0, true), 72);
    }
}
