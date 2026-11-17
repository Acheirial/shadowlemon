//! serde schema for client and server configuration.
//!
//! Field names intentionally mirror the Go V0.1 JSON shape documented in
//! `rust/docs/config-v0.2.md`. `rename_all = "camelCase"` covers most fields;
//! the handful of names whose capitalization differs (for example
//! `socks5ListenLAN` and `allowPrivateIP`) use an explicit `rename`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::enums::{
    CipherSuite, DualStack, EgressAction, HandshakeMode, LoggingLevel, LowEntropyMaskRotation,
    LowEntropyMode, MultiplexingLevel, NonceType, ProxyProtocol, TransportProtocol,
};

fn default_true() -> bool {
    true
}

/// Top-level client configuration (`configs/examples/client_config*.json`).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(default, rename_all = "camelCase")]
pub struct ClientConfig {
    /// Known client profiles.
    pub profiles: Vec<ClientProfile>,
    /// Name of the active profile; must match one of `profiles`.
    pub active_profile: Option<String>,
    /// Port the local socks5 proxy listens on.
    pub socks5_port: Option<i32>,
    /// Logging level.
    pub logging_level: LoggingLevel,
    /// Listen on LAN instead of localhost.
    #[serde(rename = "socks5ListenLAN")]
    pub socks5_listen_lan: bool,
    /// Accounts allowed to authenticate to the local socks5 proxy.
    pub socks5_authentication: Vec<Auth>,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            profiles: Vec::new(),
            active_profile: None,
            // Matches the value used in configs/examples/client_config*.json.
            socks5_port: Some(1080),
            logging_level: LoggingLevel::Default,
            socks5_listen_lan: false,
            socks5_authentication: Vec::new(),
        }
    }
}

/// A named set of client connection parameters.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(default, rename_all = "camelCase")]
pub struct ClientProfile {
    /// Profile name. Required for export and validation.
    pub profile_name: Option<String>,
    /// Proxy account used to authenticate to the server.
    pub user: Option<User>,
    /// Servers this profile can connect to.
    pub servers: Vec<ServerEndpoint>,
    /// L3 MTU used for UDP egress, in the range `1280..=1500`.
    pub mtu: Option<i32>,
    /// Connection multiplexing behavior.
    pub multiplexing: Option<MultiplexingConfig>,
    /// Handshake mode.
    pub handshake_mode: Option<HandshakeMode>,
    /// Traffic-shape fine tuning.
    pub traffic_pattern: Option<TrafficPattern>,
    /// Optional upstream proxy used to reach the ShadowLemon server.
    pub dialer: Option<ClientDialer>,
    /// Ordered cipher-suite preferences (config enum names).
    pub cipher_suites: Vec<CipherSuite>,
}

impl Default for ClientProfile {
    fn default() -> Self {
        Self {
            profile_name: None,
            user: None,
            servers: Vec::new(),
            // Documented L3 MTU default (see configs/examples/*.json).
            mtu: Some(1400),
            multiplexing: None,
            handshake_mode: None,
            traffic_pattern: None,
            dialer: None,
            cipher_suites: Vec::new(),
        }
    }
}

/// An upstream proxy the client dials before reaching a ShadowLemon server.
#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq)]
#[serde(default, rename_all = "camelCase")]
pub struct ClientDialer {
    /// Proxy protocol.
    pub protocol: ProxyProtocol,
    /// Proxy IP address or domain name.
    pub host: Option<String>,
    /// Proxy port.
    pub port: Option<i32>,
    /// Whether UDP underlays use socks5 UDP ASSOCIATE.
    #[serde(rename = "socks5UDPAssociate")]
    pub socks5_udp_associate: bool,
    /// Credentials for a socks5 upstream proxy.
    pub socks5_authentication: Option<Auth>,
}

/// One ShadowLemon server endpoint.
#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq)]
#[serde(default, rename_all = "camelCase")]
pub struct ServerEndpoint {
    /// Server IP address (v4 or v6). Ignored when `domain_name` is set.
    #[serde(rename = "ipAddress")]
    pub ip_address: Option<String>,
    /// Server fully-qualified domain name; takes precedence over `ip_address`.
    pub domain_name: Option<String>,
    /// Port/protocol bindings of the server.
    pub port_bindings: Vec<PortBinding>,
}

/// A single port or an inclusive port range, together with its transport.
///
/// `port` and `port_range` are mutually exclusive; exactly one must be set for
/// a binding that is actually used.
#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq)]
#[serde(default, rename_all = "camelCase")]
pub struct PortBinding {
    /// A single port number.
    pub port: Option<i32>,
    /// An inclusive range such as `"2012-2022"`.
    pub port_range: Option<String>,
    /// Transport protocol.
    pub protocol: TransportProtocol,
}

/// Multiplexing behavior.
#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq)]
#[serde(default, rename_all = "camelCase")]
pub struct MultiplexingConfig {
    /// How frequently a connection is reused.
    pub level: MultiplexingLevel,
}

/// Top-level server configuration (`configs/examples/server_config*.json`).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(default, rename_all = "camelCase")]
pub struct ServerConfig {
    /// Listening port/protocol bindings.
    pub port_bindings: Vec<PortBinding>,
    /// Registered users.
    pub users: Vec<User>,
    /// IP address to listen on; empty means all interfaces.
    #[serde(rename = "listenIPAddress")]
    pub listen_ip_address: Option<String>,
    /// Advanced server settings.
    pub advanced_settings: Option<ServerAdvancedSettings>,
    /// Logging level.
    pub logging_level: LoggingLevel,
    /// L3 MTU used for UDP egress, in the range `1280..=1500`.
    pub mtu: Option<i32>,
    /// Egress proxies and rules.
    pub egress: Option<Egress>,
    /// Domain-name resolution settings.
    pub dns: Option<DNS>,
    /// Traffic-shape fine tuning.
    pub traffic_pattern: Option<TrafficPattern>,
    /// Cipher suites the server accepts, in preference order.
    pub cipher_suites: Vec<CipherSuite>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            port_bindings: Vec::new(),
            users: Vec::new(),
            listen_ip_address: None,
            advanced_settings: None,
            logging_level: LoggingLevel::Default,
            mtu: Some(1400),
            egress: None,
            dns: None,
            traffic_pattern: None,
            cipher_suites: Vec::new(),
        }
    }
}

/// Advanced server settings (`userHintIsMandatory` defaults to `true`).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(default, rename_all = "camelCase")]
pub struct ServerAdvancedSettings {
    /// Require clients to send a keyed user hint on the first packet.
    #[serde(default = "default_true")]
    pub user_hint_is_mandatory: bool,
}

impl Default for ServerAdvancedSettings {
    fn default() -> Self {
        Self {
            user_hint_is_mandatory: true,
        }
    }
}

/// Proxy account. `password` and `hashedPassword` are alternatives.
#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq)]
#[serde(default, rename_all = "camelCase")]
pub struct User {
    /// User name, also used as the user ID (typically an email address).
    pub name: Option<String>,
    /// Raw password.
    pub password: Option<String>,
    /// Hex-encoded hashed password.
    pub hashed_password: Option<String>,
    /// Permit private-IP destinations (server side only).
    #[serde(rename = "allowPrivateIP")]
    pub allow_private_ip: bool,
    /// Permit loopback-IP destinations (server side only).
    #[serde(rename = "allowLoopbackIP")]
    pub allow_loopback_ip: bool,
}

/// A username/password credential.
#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq)]
#[serde(default, rename_all = "camelCase")]
pub struct Auth {
    /// Authentication user name.
    pub user: Option<String>,
    /// Authentication password.
    pub password: Option<String>,
}

/// Egress proxy list and ordered rules.
#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq)]
#[serde(default, rename_all = "camelCase")]
pub struct Egress {
    /// Available egress proxies.
    pub proxies: Vec<EgressProxy>,
    /// Rules evaluated in order; unmatched traffic goes `DIRECT`.
    pub rules: Vec<EgressRule>,
}

/// An egress proxy.
#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq)]
#[serde(default, rename_all = "camelCase")]
pub struct EgressProxy {
    /// Proxy name referenced by `EgressRule::proxy_names`.
    pub name: Option<String>,
    /// Proxy protocol.
    pub protocol: ProxyProtocol,
    /// Proxy IP address or domain name.
    pub host: Option<String>,
    /// Proxy port.
    pub port: Option<i32>,
    /// Credentials for a socks5 proxy.
    pub socks5_authentication: Option<Auth>,
}

/// A rule matching destination IPs and/or domain names.
#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq)]
#[serde(default, rename_all = "camelCase")]
pub struct EgressRule {
    /// CIDR strings; `"*"` matches all IP addresses.
    pub ip_ranges: Vec<String>,
    /// Domain names; `"*"` matches all domain names.
    pub domain_names: Vec<String>,
    /// Action to take when the rule matches.
    pub action: EgressAction,
    /// Proxy names referenced when `action` is `PROXY`.
    pub proxy_names: Vec<String>,
}

/// Domain-name resolution settings.
#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq)]
#[serde(default, rename_all = "camelCase")]
pub struct DNS {
    /// IP version preference.
    pub dual_stack: DualStack,
    /// Static domain-to-IP mappings, like `/etc/hosts`.
    ///
    /// A `BTreeMap` keeps serialization deterministic (required by the binary
    /// payload used for `shadowlemon://` URLs).
    pub hosts: BTreeMap<String, String>,
}

/// Traffic-shape fine tuning, shared by client and server.
#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq)]
#[serde(default, rename_all = "camelCase")]
pub struct TrafficPattern {
    /// Seed used to derive implicit traffic patterns.
    pub seed: Option<i32>,
    /// Allow implicit patterns to use all available options.
    pub unlock_all: Option<bool>,
    /// Extra TCP fragmentation.
    pub tcp_fragment: Option<TCPFragment>,
    /// Nonce-prefix manipulation.
    pub nonce: Option<NoncePattern>,
    /// Padding behavior.
    pub padding: Option<PaddingPattern>,
    /// Feature-gated low-entropy behavior (default OFF).
    pub low_entropy: Option<LowEntropyPattern>,
}

/// Extra TCP fragmentation settings.
#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq)]
#[serde(default, rename_all = "camelCase")]
pub struct TCPFragment {
    /// Enable additional TCP fragmentation.
    pub enable: Option<bool>,
    /// Upper bound (milliseconds) for sleeps between fragments; at most 100.
    pub max_sleep_ms: Option<i32>,
}

/// Nonce-prefix manipulation settings.
#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq)]
#[serde(default, rename_all = "camelCase")]
pub struct NoncePattern {
    /// Manipulation strategy; JSON field name is `type`.
    #[serde(rename = "type")]
    pub nonce_type: NonceType,
    /// Apply the pattern to every UDP packet, not just the first.
    #[serde(rename = "applyToAllUDPPacket")]
    pub apply_to_all_udp_packet: bool,
    /// Minimum number of prefix bytes to manipulate.
    pub min_len: Option<i32>,
    /// Maximum number of prefix bytes to manipulate; at most 12.
    pub max_len: Option<i32>,
    /// Hex strings (no `0x`) describing fixed nonce prefixes, at most 12 bytes each.
    pub custom_hex_strings: Vec<String>,
}

/// Padding length settings. Zero disables the corresponding padding.
#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq)]
#[serde(default, rename_all = "camelCase")]
pub struct PaddingPattern {
    /// Maximum middle padding length, in `0..=255`.
    pub max_middle_padding_len: Option<i32>,
    /// Maximum end padding length, in `0..=255`.
    pub max_end_padding_len: Option<i32>,
}

/// Feature-gated low-entropy behavior.
#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq)]
#[serde(default, rename_all = "camelCase")]
pub struct LowEntropyPattern {
    /// Amount of entropy reduction; `LOW_ENTROPY_MODE_OFF` disables it.
    pub mode: LowEntropyMode,
    /// Mask rotation between adjacent 64-bit chunks.
    pub mask_rotation: LowEntropyMaskRotation,
}

/// Parse a `"begin-end"` inclusive port range into `(begin, end)`.
///
/// Returns `None` for malformed or out-of-range input. Both endpoints must be
/// valid TCP/UDP ports and `begin <= end`.
#[must_use]
pub fn parse_port_range(text: &str) -> Option<(u16, u16)> {
    let (begin, end) = text.trim().split_once('-')?;
    let begin = begin.trim().parse::<u16>().ok()?;
    let end = end.trim().parse::<u16>().ok()?;
    if begin == 0 || end == 0 || begin > end {
        return None;
    }
    Some((begin, end))
}

/// Validate that a number is a usable port (`1..=65535`).
#[must_use]
pub const fn is_valid_port(port: i32) -> bool {
    port >= 1 && port <= 65535
}
