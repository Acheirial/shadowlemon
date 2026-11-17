//! Server-side user discovery for a registry shared by many users.
//!
//! A config user is reduced to its 32-byte credential (`HashPassword` of the
//! password, or a decoded `hashedPassword`) plus its discovery suite order.
//! The four-byte user hint of spec §2.4 is computed per packet from the wire
//! nonce; it only narrows the set of users whose AEAD tag is tried and never
//! authenticates anything.
//!
//! Discovery order:
//! 1. cached source bindings whose hint matches (cached suite tried first),
//! 2. remaining registry users whose hint matches,
//! 3. cached bindings with a non-matching hint, if hints are optional,
//! 4. every remaining user, if hints are optional.
//!
//! AEAD verification is supplied by the caller through [`UserDecryptor`], so
//! this module is independently testable with a fake decryptor.

use std::{
    collections::{HashMap, HashSet},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

use dashmap::DashMap;
use shadowlemon_crypto::{
    hint::check_user_hint, kdf::hash_password, suite::Suite, WireNonce, HINT_LEN, KEY_LEN,
};
use thiserror::Error;

/// Maximum accepted user name length, in bytes.
pub const MAX_USER_NAME_LEN: usize = 64;
/// Lifetime of a successful source-to-user binding.
pub const SOURCE_CACHE_TTL: Duration = Duration::from_secs(600);
/// Lifetime of a negative `(source, hint)` entry.
pub const NEGATIVE_CACHE_TTL: Duration = Duration::from_secs(10);
/// Maximum users retained per source in the positive cache.
const MAX_BINDINGS_PER_SOURCE: usize = 16;

/// Errors while turning a config entry into a registry user.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum UserError {
    /// The user name is empty.
    #[error("user name is empty")]
    EmptyName,
    /// The user name is longer than 64 bytes.
    #[error("user name exceeds {MAX_USER_NAME_LEN} bytes")]
    NameTooLong,
    /// `hashedPassword` was not valid hexadecimal.
    #[error("hashed password is not valid hexadecimal")]
    InvalidHex,
    /// `hashedPassword` did not decode to exactly 32 bytes.
    #[error("hashed password must decode to 32 bytes, got {0}")]
    InvalidCredentialLength(usize),
}

/// Canonical source identity: an IP address without port or zone.
///
/// IPv4 addresses are stored in IPv4-mapped IPv6 form, matching the Go
/// `SourceFromAddr` key, so an IPv4 address and its mapped IPv6 form share a
/// cache entry.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SourceKey([u8; 16]);

impl SourceKey {
    /// Build a source key from raw canonical bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Build a source key from an IPv4 address.
    #[must_use]
    pub const fn from_ipv4(ip: [u8; 4]) -> Self {
        let mut bytes = [0u8; 16];
        bytes[10] = 0xff;
        bytes[11] = 0xff;
        bytes[12] = ip[0];
        bytes[13] = ip[1];
        bytes[14] = ip[2];
        bytes[15] = ip[3];
        Self(bytes)
    }

    /// Build a source key from an IPv6 address.
    #[must_use]
    pub const fn from_ipv6(ip: [u8; 16]) -> Self {
        Self(ip)
    }

    /// Canonical key bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// One server user compiled from a config entry.
#[derive(Clone, Debug)]
pub struct User {
    name: String,
    credential: [u8; KEY_LEN],
    suites: Vec<Suite>,
}

impl User {
    /// Build a user from a raw 32-byte credential.
    ///
    /// An empty `suites` list is expanded to all supported suites in the
    /// canonical discovery order `0, 1, 2`; unknown and duplicate suites are
    /// dropped.
    pub fn new(
        name: impl Into<String>,
        credential: [u8; KEY_LEN],
        suites: Vec<Suite>,
    ) -> Result<Self, UserError> {
        let name = name.into();
        if name.is_empty() {
            return Err(UserError::EmptyName);
        }
        if name.len() > MAX_USER_NAME_LEN {
            return Err(UserError::NameTooLong);
        }
        let mut discovery_suites = Vec::with_capacity(suites.len().max(3));
        for suite in suites {
            if suite.is_valid() && !discovery_suites.contains(&suite) {
                discovery_suites.push(suite);
            }
        }
        if discovery_suites.is_empty() {
            discovery_suites.extend_from_slice(&Suite::all_suites());
        }
        Ok(Self {
            name,
            credential,
            suites: discovery_suites,
        })
    }

    /// Build a user from a plain password: `SHA256(password || 0x00 || name)`.
    pub fn from_password(
        name: impl Into<String>,
        password: &str,
        suites: Vec<Suite>,
    ) -> Result<Self, UserError> {
        let name = name.into();
        let credential = hash_password(password.as_bytes(), &name);
        Self::new(name, credential, suites)
    }

    /// Build a user from a config `hashedPassword` hexadecimal string.
    pub fn from_hashed_password(
        name: impl Into<String>,
        hashed_password: &str,
        suites: Vec<Suite>,
    ) -> Result<Self, UserError> {
        let credential = decode_credential(hashed_password)?;
        Self::new(name, credential, suites)
    }

    /// User name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// 32-byte credential used to derive static keys.
    #[must_use]
    pub fn credential(&self) -> &[u8; KEY_LEN] {
        &self.credential
    }

    /// Cipher suite discovery order.
    #[must_use]
    pub fn suites(&self) -> &[Suite] {
        &self.suites
    }
}

fn decode_credential(hex: &str) -> Result<[u8; KEY_LEN], UserError> {
    if hex.len() != KEY_LEN * 2 || hex.len() % 2 != 0 {
        return Err(UserError::InvalidCredentialLength(hex.len() / 2));
    }
    let mut out = [0u8; KEY_LEN];
    let bytes = hex.as_bytes();
    for (chunk, slot) in bytes.chunks_exact(2).zip(out.iter_mut()) {
        let high = hex_nibble(chunk[0]).ok_or(UserError::InvalidHex)?;
        let low = hex_nibble(chunk[1]).ok_or(UserError::InvalidHex)?;
        *slot = (high << 4) | low;
    }
    Ok(out)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Result of a successful AEAD trial: the suite that authenticated and the
/// decrypted envelope.
#[derive(Debug)]
pub struct Decryption {
    /// Suite whose static key verified the tag.
    pub suite: Suite,
    /// Decrypted metadata (or other envelope plaintext).
    pub plaintext: Vec<u8>,
}

/// AEAD verification hook.
///
/// Implementations derive a static key from `user.credential()` for each
/// candidate suite and return `Some` only when the authentication tag
/// verifies. A wrong suite hint costs one extra trial; the hint itself is
/// never an authentication result.
pub trait UserDecryptor: std::fmt::Debug + Send + Sync {
    /// Try the supplied suites in order for `user`; return the first success.
    fn try_decrypt(
        &self,
        user: &User,
        suites: &[Suite],
        nonce: &WireNonce,
        ciphertext: &[u8],
    ) -> Option<Decryption>;
}

/// Registry of server users, hint lookup and source caches.
#[derive(Debug)]
pub struct Registry {
    users: Vec<RegisteredUser>,
    hint_mandatory: AtomicBool,
    decryptor: Arc<dyn UserDecryptor>,
    source_cache: DashMap<[u8; 16], Vec<Binding>>,
    fail_cache: Mutex<HashMap<FailCacheKey, Instant>>,
}

/// Key of a negative-cache entry: canonical source plus four-byte hint.
type FailCacheKey = ([u8; 16], [u8; HINT_LEN]);

#[derive(Debug)]
struct RegisteredUser {
    id: u32,
    user: User,
}

#[derive(Clone, Debug)]
struct Binding {
    user_id: u32,
    suite: Suite,
    seen: Instant,
}

/// Why a discovery attempt failed.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum DiscoveryError {
    /// No usable users were configured.
    #[error("no server user found")]
    NoUsers,
    /// The negative cache suppressed this `(source, hint)` pair.
    #[error("user hint is suppressed by the source failure cache")]
    Suppressed,
    /// No user/suite combination authenticated the envelope.
    #[error("authentication failed for all users and suites")]
    NoMatch,
}

/// A pending successful authentication. Retain it only until the envelope has
/// been structurally validated; then call [`Authentication::record`].
#[derive(Debug)]
pub struct Authentication {
    user_id: u32,
    name: String,
    suite: Suite,
    plaintext: Vec<u8>,
    source: Option<[u8; 16]>,
}

impl Authentication {
    /// Numeric id of the authenticated user (starts at 1).
    #[must_use]
    pub const fn user_id(&self) -> u32 {
        self.user_id
    }

    /// Name of the authenticated user.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Suite whose tag authenticated the envelope.
    #[must_use]
    pub const fn suite(&self) -> Suite {
        self.suite
    }

    /// Decrypted envelope bytes.
    #[must_use]
    pub fn plaintext(&self) -> &[u8] {
        &self.plaintext
    }

    /// Store the successful `(source, user, suite)` binding. No-op when the
    /// discovery had no source address.
    pub fn record(&self, registry: &Registry) {
        if let Some(key) = self.source {
            registry.record_binding(key, self.user_id, self.suite);
        }
        registry.clear_failure(self.source);
    }
}

impl Registry {
    /// Compile a registry from config users. Users are sorted by name and
    /// assigned dense ids starting at 1; duplicate names are skipped.
    #[must_use]
    pub fn new(
        users: impl IntoIterator<Item = User>,
        hint_mandatory: bool,
        decryptor: Arc<dyn UserDecryptor>,
    ) -> Self {
        let mut users: Vec<User> = users.into_iter().collect();
        users.sort_by(|a, b| a.name.cmp(&b.name));
        users.dedup_by(|a, b| a.name == b.name);
        let users = users
            .into_iter()
            .enumerate()
            .map(|(index, user)| RegisteredUser {
                id: (index + 1) as u32,
                user,
            })
            .collect();
        Self {
            users,
            hint_mandatory: AtomicBool::new(hint_mandatory),
            decryptor,
            source_cache: DashMap::new(),
            fail_cache: Mutex::new(HashMap::new()),
        }
    }

    /// Whether a matching user hint is currently required.
    #[must_use]
    pub fn hint_mandatory(&self) -> bool {
        self.hint_mandatory.load(Ordering::Relaxed)
    }

    /// Change the hint requirement (e.g. on a config reload).
    pub fn set_hint_mandatory(&self, mandatory: bool) {
        self.hint_mandatory.store(mandatory, Ordering::Relaxed);
    }

    /// Whether any usable user is registered.
    #[must_use]
    pub fn has_users(&self) -> bool {
        !self.users.is_empty()
    }

    /// Number of registered users.
    #[must_use]
    pub fn user_count(&self) -> usize {
        self.users.len()
    }

    /// Discover the user whose static key authenticates `ciphertext`.
    ///
    /// `nonce` is the full 24-byte wire nonce carrying the keyed user hint in
    /// its last four bytes. `source` enables the positive/negative source
    /// caches; pass `None` when no source address is available. The negative
    /// cache is consulted and written only when hints are mandatory.
    pub fn discover(
        &self,
        nonce: &WireNonce,
        ciphertext: &[u8],
        source: Option<SourceKey>,
    ) -> Result<Authentication, DiscoveryError> {
        if self.users.is_empty() {
            return Err(DiscoveryError::NoUsers);
        }
        let hint: [u8; HINT_LEN] = nonce[nonce.len() - HINT_LEN..]
            .try_into()
            .expect("wire nonce is at least four bytes");
        let mandatory = self.hint_mandatory.load(Ordering::Relaxed);
        let source_bytes = source.map(|s| s.0);

        if let Some(key) = source_bytes {
            if mandatory && self.is_suppressed(key, hint) {
                return Err(DiscoveryError::Suppressed);
            }
        }

        let mut candidates: Vec<(usize, Option<Suite>)> = Vec::new();
        let cached = source_bytes.and_then(|key| self.cached_bindings(key));

        // Phase 1 and 3: users remembered for this source, most recent first.
        for (id, suite) in cached.into_iter().flatten() {
            if let Some(index) = self.index_by_id(id) {
                let matches = self.hint_matches(index, nonce);
                if matches || !mandatory {
                    candidates.push((index, Some(suite)));
                }
            }
        }
        // Phase 2 and 4: the full registry. With mandatory hints only hint
        // matches are worth an AEAD trial.
        for index in 0..self.users.len() {
            if !mandatory || self.hint_matches(index, nonce) {
                candidates.push((index, None));
            }
        }

        let mut attempted = HashSet::new();
        for (index, suite_hint) in candidates {
            if !attempted.insert(index) {
                continue;
            }
            let registered = &self.users[index];
            let mut order = Vec::with_capacity(registered.user.suites.len() + 1);
            if let Some(suite) = suite_hint {
                if registered.user.suites.contains(&suite) {
                    order.push(suite);
                }
            }
            for suite in &registered.user.suites {
                if !order.contains(suite) {
                    order.push(*suite);
                }
            }
            if let Some(result) =
                self.decryptor
                    .try_decrypt(&registered.user, &order, nonce, ciphertext)
            {
                if mandatory {
                    self.clear_failure(source_bytes);
                }
                return Ok(Authentication {
                    user_id: registered.id,
                    name: registered.user.name.clone(),
                    suite: result.suite,
                    plaintext: result.plaintext,
                    source: source_bytes,
                });
            }
        }

        if mandatory {
            if let Some(key) = source_bytes {
                self.record_failure(key, hint);
            }
        }
        Err(DiscoveryError::NoMatch)
    }

    fn hint_matches(&self, index: usize, nonce: &WireNonce) -> bool {
        check_user_hint(self.users[index].user.name.as_bytes(), nonce)
    }

    fn index_by_id(&self, id: u32) -> Option<usize> {
        if id == 0 {
            return None;
        }
        let index = (id - 1) as usize;
        self.users
            .get(index)
            .and_then(|entry| (entry.id == id).then_some(index))
    }

    fn cached_bindings(&self, key: [u8; 16]) -> Option<Vec<(u32, Suite)>> {
        let entry = self.source_cache.get(&key)?;
        let now = Instant::now();
        let mut bindings: Vec<&Binding> = entry
            .value()
            .iter()
            .filter(|binding| now.saturating_duration_since(binding.seen) < SOURCE_CACHE_TTL)
            .collect();
        bindings.sort_by_key(|b| std::cmp::Reverse(b.seen));
        Some(bindings.into_iter().map(|b| (b.user_id, b.suite)).collect())
    }

    fn record_binding(&self, key: [u8; 16], user_id: u32, suite: Suite) {
        let mut entry = self.source_cache.entry(key).or_default();
        let bindings = entry.value_mut();
        let now = Instant::now();
        bindings.retain(|b| now.saturating_duration_since(b.seen) < SOURCE_CACHE_TTL);
        match bindings.iter_mut().find(|b| b.user_id == user_id) {
            Some(binding) => {
                binding.suite = suite;
                binding.seen = now;
            }
            None => {
                if bindings.len() == MAX_BINDINGS_PER_SOURCE {
                    bindings.remove(0);
                }
                bindings.push(Binding {
                    user_id,
                    suite,
                    seen: now,
                });
            }
        }
    }

    fn is_suppressed(&self, key: [u8; 16], hint: [u8; HINT_LEN]) -> bool {
        let mut cache = self
            .fail_cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match cache.get(&(key, hint)) {
            Some(failed_at) if failed_at.elapsed() < NEGATIVE_CACHE_TTL => true,
            Some(_) => {
                cache.remove(&(key, hint));
                false
            }
            None => false,
        }
    }

    fn record_failure(&self, key: [u8; 16], hint: [u8; HINT_LEN]) {
        let mut cache = self
            .fail_cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        cache.insert((key, hint), Instant::now());
    }

    fn clear_failure(&self, source: Option<[u8; 16]>) {
        if let Some(key) = source {
            let mut cache = self
                .fail_cache
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            cache.retain(|(failed_key, _), _| *failed_key != key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shadowlemon_crypto::hint::write_user_hint;
    use std::thread;

    #[derive(Debug)]
    struct FakeDecryptor {
        accepted: Mutex<HashSet<String>>,
        attempts: Mutex<Vec<String>>,
    }

    impl FakeDecryptor {
        fn accepting(names: &[&str]) -> Arc<Self> {
            Arc::new(Self {
                accepted: Mutex::new(names.iter().map(|name| (*name).to_owned()).collect()),
                attempts: Mutex::new(Vec::new()),
            })
        }

        fn take_attempts(&self) -> Vec<String> {
            std::mem::take(&mut self.attempts.lock().expect("attempts lock"))
        }
    }

    impl UserDecryptor for FakeDecryptor {
        fn try_decrypt(
            &self,
            user: &User,
            suites: &[Suite],
            _nonce: &WireNonce,
            ciphertext: &[u8],
        ) -> Option<Decryption> {
            self.attempts
                .lock()
                .expect("attempts lock")
                .push(user.name().to_owned());
            if !self
                .accepted
                .lock()
                .expect("accepted lock")
                .contains(user.name())
            {
                return None;
            }
            Some(Decryption {
                suite: suites[0],
                plaintext: ciphertext.to_vec(),
            })
        }
    }

    fn user(name: &str) -> User {
        User::from_password(name, "password", Vec::new()).expect("valid user")
    }

    fn nonce_for(name: Option<&str>) -> WireNonce {
        let mut nonce = [0x5a; 24];
        if let Some(name) = name {
            write_user_hint(&mut nonce, name.as_bytes());
        }
        nonce
    }

    fn registry(names: &[&str], mandatory: bool, fake: Arc<FakeDecryptor>) -> Registry {
        Registry::new(names.iter().map(|name| user(name)), mandatory, fake)
    }

    #[test]
    fn credential_sources_and_hint_lookup() {
        let hashed = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
        let from_hash = User::from_hashed_password("hash", hashed, Vec::new()).unwrap();
        assert_eq!(&from_hash.credential()[..2], &[1, 2]);
        assert_eq!(from_hash.suites(), &Suite::all_suites());
        assert!(User::from_hashed_password("hash", "zz", Vec::new()).is_err());
        assert!(User::from_password("", "p", Vec::new()).is_err());

        let fake = FakeDecryptor::accepting(&["bob"]);
        let reg = registry(&["alice", "bob", "carol"], true, Arc::clone(&fake));
        let auth = reg
            .discover(&nonce_for(Some("bob")), b"envelope", None)
            .unwrap();
        assert_eq!(auth.name(), "bob");
        assert_eq!(auth.user_id(), 2);
        assert_eq!(auth.plaintext(), b"envelope");
        assert_eq!(auth.suite(), Suite::XChaCha20Poly1305);
        assert_eq!(reg.user_count(), 3);

        // Only the hint-matching user reached the AEAD trial.
        assert_eq!(fake.take_attempts(), vec!["bob"]);

        // No user matches a random hint, so mandatory discovery fails.
        let fake2 = FakeDecryptor::accepting(&["alice", "bob", "carol"]);
        let reg2 = registry(&["alice", "bob", "carol"], true, fake2);
        assert_eq!(
            reg2.discover(&nonce_for(None), b"x", None).unwrap_err(),
            DiscoveryError::NoMatch
        );
    }

    #[test]
    fn negative_cache_expires_after_ten_seconds() {
        let key = SourceKey::from_ipv4([10, 1, 2, 3]);
        let registry = registry(&["alice"], true, FakeDecryptor::accepting(&[]));
        let nonce = nonce_for(Some("alice"));
        assert_eq!(
            registry.discover(&nonce, b"x", Some(key)).unwrap_err(),
            DiscoveryError::NoMatch
        );
        assert_eq!(
            registry.discover(&nonce, b"x", Some(key)).unwrap_err(),
            DiscoveryError::Suppressed
        );

        let hint: [u8; HINT_LEN] = nonce[nonce.len() - HINT_LEN..].try_into().unwrap();
        let mut cache = registry
            .fail_cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        cache.insert(
            (*key.as_bytes(), hint),
            Instant::now() - NEGATIVE_CACHE_TTL - Duration::from_secs(1),
        );
        drop(cache);

        assert_eq!(
            registry.discover(&nonce, b"x", Some(key)).unwrap_err(),
            DiscoveryError::NoMatch
        );
    }

    #[test]
    fn fallback_to_full_set_when_hint_is_optional() {
        let key = SourceKey::from_ipv4([10, 4, 5, 6]);
        let fake = FakeDecryptor::accepting(&["bob"]);
        let reg = registry(&["alice", "bob"], true, Arc::clone(&fake));
        assert_eq!(
            reg.discover(&nonce_for(None), b"x", Some(key)).unwrap_err(),
            DiscoveryError::NoMatch
        );
        assert!(!reg.fail_cache.lock().unwrap().is_empty());

        reg.set_hint_mandatory(false);
        let auth = reg.discover(&nonce_for(None), b"x", Some(key)).unwrap();
        assert_eq!(auth.name(), "bob");
        auth.record(&reg);

        // The negative cache is neither consulted nor written when hints are
        // optional; a failed attempt leaves it untouched.
        let failing = registry(&["alice"], false, FakeDecryptor::accepting(&[]));
        assert_eq!(
            failing
                .discover(&nonce_for(Some("alice")), b"x", Some(key))
                .unwrap_err(),
            DiscoveryError::NoMatch
        );
        assert!(failing.fail_cache.lock().unwrap().is_empty());
    }

    #[test]
    fn cached_source_binding_is_tried_first_without_a_hint() {
        let key =
            SourceKey::from_ipv6([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let fake = FakeDecryptor::accepting(&["alice", "bob"]);
        let registry = registry(&["alice", "bob"], false, Arc::clone(&fake));
        let auth = registry
            .discover(&nonce_for(Some("alice")), b"x", Some(key))
            .unwrap();
        auth.record(&registry);

        fake.take_attempts();
        // A nonce carrying no hint falls back to the full set, but the cached
        // user is tried before the uncached one.
        let auth = registry
            .discover(&nonce_for(None), b"y", Some(key))
            .unwrap();
        assert_eq!(auth.name(), "alice");
        assert_eq!(fake.take_attempts(), vec!["alice"]);
    }

    #[test]
    fn concurrent_discovery_is_safe() {
        let registry = Arc::new(registry(
            &["alice", "bob", "carol"],
            false,
            FakeDecryptor::accepting(&["alice", "bob", "carol"]),
        ));
        let mut handles = Vec::new();
        for index in 0u8..8 {
            let registry = Arc::clone(&registry);
            handles.push(thread::spawn(move || {
                let key = SourceKey::from_ipv4([127, 0, 0, index]);
                let name = ["alice", "bob", "carol"][index as usize % 3];
                let auth = registry
                    .discover(&nonce_for(Some(name)), b"x", Some(key))
                    .expect("concurrent discovery succeeds");
                auth.record(&registry);
                auth.user_id()
            }));
        }
        for handle in handles {
            assert!(handle.join().expect("worker did not panic") >= 1);
        }
        assert_eq!(registry.source_cache.len(), 8);
    }
}
