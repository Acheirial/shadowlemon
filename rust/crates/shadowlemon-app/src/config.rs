//! Configuration discovery, environment compatibility and driver translation.
//!
//! The JSON file names come from `shadowlemon_config` (`client.json` /
//! `server.json`). Existing deployments may point at a different file with
//! `SHADOWLEMON_{CLIENT,SERVER}_CONFIG_JSON_FILE`; the older
//! `SHADOWLEMON_{CLIENT,SERVER}_CONFIG_FILE` variable is still recognised but a
//! protobuf payload is rejected with an actionable error instead of being
//! silently mis-parsed as JSON.

use std::{
    fs,
    path::{Path, PathBuf},
};

use crate::AppError;
use shadowlemon_config::{
    config_dir, config_suite_to_wire, load_json, CipherSuite, ClientConfig, ClientProfile, Egress,
    LoggingLevel, MultiplexingLevel, ServerConfig, TrafficPattern,
};
use shadowlemon_crypto::suite::Suite;
use shadowlemon_protocol::serveruser::User;
use shadowlemon_protocol::{
    mux::{Multiplexing, MuxConfig},
    underlay::{IpFamily, NoncePattern, NoncePatternConfig},
    underlay_packet::PacketConfig,
    underlay_stream::StreamConfig,
    ClientCredential, RealClientConfig, RealServerConfig,
};
use shadowlemon_socks5::{Credential, EgressAction, EgressConfig, EgressProxy, EgressRule};

/// Which command set is active.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode {
    /// Local SOCKS5 ingress process.
    Client,
    /// Remote tunnel endpoint process.
    Server,
}

impl Mode {
    /// Lower-case command name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Client => "client",
            Self::Server => "server",
        }
    }
}

/// Resolve the configuration path, honouring the deployment environment
/// variables described in the module docs.
pub fn config_path(mode: Mode) -> Result<PathBuf, AppError> {
    let (json_var, legacy_var) = match mode {
        Mode::Client => (
            "SHADOWLEMON_CLIENT_CONFIG_JSON_FILE",
            "SHADOWLEMON_CLIENT_CONFIG_FILE",
        ),
        Mode::Server => (
            "SHADOWLEMON_SERVER_CONFIG_JSON_FILE",
            "SHADOWLEMON_SERVER_CONFIG_FILE",
        ),
    };
    if let Some(path) = std::env::var_os(json_var) {
        if !path.is_empty() {
            return Ok(PathBuf::from(path));
        }
    }
    if let Some(path) = std::env::var_os(legacy_var) {
        if !path.is_empty() {
            let path = PathBuf::from(path);
            match fs::read(&path) {
                Ok(bytes) if !looks_like_json(&bytes) => {
                    return Err(AppError::Config(format!(
                        "{legacy_var} points at {}: protobuf configuration is no longer \
                         supported; convert it to JSON (see configs/examples)",
                        path.display()
                    )));
                }
                Ok(_) => return Ok(path),
                // A missing legacy path is handled by the normal loader, which
                // reports the canonical "file not found" error.
                Err(_) => return Ok(path),
            }
        }
    }
    Ok(match mode {
        Mode::Client => shadowlemon_config::client_config_path()?,
        Mode::Server => shadowlemon_config::server_config_path()?,
    })
}

fn looks_like_json(bytes: &[u8]) -> bool {
    let trimmed = bytes
        .iter()
        .copied()
        .find(|byte| !byte.is_ascii_whitespace());
    trimmed == Some(b'{')
}

/// Load a client config from `path` (already selected by [`config_path`]).
pub fn load_client(path: &Path) -> Result<ClientConfig, AppError> {
    Ok(load_json::<ClientConfig>(path)?)
}

/// Load a server config from `path`.
pub fn load_server(path: &Path) -> Result<ServerConfig, AppError> {
    Ok(load_json::<ServerConfig>(path)?)
}

/// Pick the active profile from a client config.
pub fn active_profile(config: &ClientConfig) -> Result<&ClientProfile, AppError> {
    let name = config
        .active_profile
        .as_deref()
        .ok_or_else(|| AppError::Config("client config has no activeProfile".to_owned()))?;
    config
        .profiles
        .iter()
        .find(|profile| profile.profile_name.as_deref() == Some(name))
        .ok_or_else(|| AppError::Config(format!("activeProfile {name:?} has no matching profile")))
}

fn wire_suites(suites: &[CipherSuite], fallback: Option<Suite>) -> Result<Vec<Suite>, AppError> {
    let mut out = Vec::new();
    for suite in suites {
        let wire = config_suite_to_wire(suite.clone()).ok_or_else(|| {
            AppError::Config(format!("cipher suite {suite} has no wire representation"))
        })?;
        let wire = Suite::from_u8(wire).ok_or_else(|| {
            AppError::Config(format!(
                "cipher suite {suite} maps to an unsupported wire suite"
            ))
        })?;
        if !out.contains(&wire) {
            out.push(wire);
        }
    }
    if out.is_empty() {
        out.extend(fallback);
    }
    Ok(out)
}

fn map_multiplexing(level: &MultiplexingLevel) -> Multiplexing {
    match level {
        MultiplexingLevel::MultiplexingOff => Multiplexing::Off,
        MultiplexingLevel::MultiplexingLow => Multiplexing::Low,
        MultiplexingLevel::MultiplexingHigh => Multiplexing::High,
        MultiplexingLevel::MultiplexingMiddle | MultiplexingLevel::MultiplexingDefault => {
            Multiplexing::Middle
        }
        _ => Multiplexing::Middle,
    }
}

fn decode_hex(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    if bytes.len() % 2 != 0 {
        return None;
    }
    let nibble = |byte: u8| match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    };
    bytes
        .chunks_exact(2)
        .map(|pair| Some(nibble(pair[0])? << 4 | nibble(pair[1])?))
        .collect()
}

fn traffic_pattern(pattern: Option<&TrafficPattern>) -> (NoncePattern, NoncePatternConfig) {
    let Some(pattern) = pattern else {
        return (NoncePattern::Random, NoncePatternConfig::default());
    };
    let Some(nonce) = pattern.nonce.as_ref() else {
        return (NoncePattern::Random, NoncePatternConfig::default());
    };
    let strategy = match &nonce.nonce_type {
        shadowlemon_config::NonceType::NonceTypePrintable => NoncePattern::Printable,
        shadowlemon_config::NonceType::NonceTypePrintableSubset => NoncePattern::PrintableSubset,
        shadowlemon_config::NonceType::NonceTypeFixed => NoncePattern::Fixed(
            nonce
                .custom_hex_strings
                .iter()
                .filter_map(|text| decode_hex(text))
                .filter(|prefix| prefix.len() <= 12)
                .collect(),
        ),
        _ => NoncePattern::Random,
    };
    let min_len = usize::try_from(nonce.min_len.unwrap_or(6))
        .unwrap_or(6)
        .min(12);
    let max_len = usize::try_from(nonce.max_len.unwrap_or(12))
        .unwrap_or(12)
        .min(12);
    let config = NoncePatternConfig {
        min_len: min_len.min(max_len),
        max_len,
        apply_to_all_udp_packets: nonce.apply_to_all_udp_packet,
    };
    (strategy, config)
}

/// Translate an active client profile into the real handshake driver config.
pub fn client_driver_config(profile: &ClientProfile) -> Result<RealClientConfig, AppError> {
    let user = profile
        .user
        .as_ref()
        .ok_or_else(|| AppError::Config("active profile has no user".to_owned()))?;
    let name = user
        .name
        .as_deref()
        .filter(|name| !name.is_empty())
        .ok_or_else(|| AppError::Config("active profile user has no name".to_owned()))?;
    let credential = if let Some(password) = user.password.as_deref() {
        ClientCredential::Password(password.to_owned())
    } else if let Some(hash) = user.hashed_password.as_deref() {
        let bytes = decode_hex(hash)
            .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
            .ok_or_else(|| {
                AppError::Config("hashedPassword must be 32 hex-encoded bytes".to_owned())
            })?;
        ClientCredential::Credential(bytes)
    } else {
        return Err(AppError::Config(
            "active profile user needs password or hashedPassword".to_owned(),
        ));
    };
    let suites = wire_suites(&profile.cipher_suites, Some(Suite::XChaCha20Poly1305))?;
    let (nonce, nonce_config) = traffic_pattern(profile.traffic_pattern.as_ref());
    let mtu = u16::try_from(profile.mtu.unwrap_or(1400))
        .map_err(|_| AppError::Config("profile MTU is out of range".to_owned()))?;
    let handshake_timeout = shadowlemon_protocol::handshake::HANDSHAKE_TIMEOUT;
    let config = RealClientConfig {
        username: name.to_owned(),
        credential,
        suites,
        stream: StreamConfig {
            nonce_pattern: nonce.clone(),
            nonce_pattern_config: nonce_config,
        },
        packet: PacketConfig {
            mtu,
            family: IpFamily::V4,
            nonce_pattern: nonce,
            nonce_pattern_config: nonce_config,
        },
        handshake_timeout,
    };
    config
        .validate()
        .map_err(|error| AppError::Config(error.to_string()))?;
    Ok(config)
}

/// Mux limits/timers derived from a client profile.
pub fn client_mux_config(profile: &ClientProfile) -> MuxConfig {
    let mut config = MuxConfig::default();
    if let Ok(mtu) = u16::try_from(profile.mtu.unwrap_or(1400)) {
        config.mtu = mtu;
    }
    config.multiplexing = profile
        .multiplexing
        .as_ref()
        .map(|m| map_multiplexing(&m.level))
        .unwrap_or(Multiplexing::Middle);
    config
}

/// SOCKS5 ingress credentials from `socks5Authentication`.
pub fn socks_credentials(config: &ClientConfig) -> Vec<Credential> {
    config
        .socks5_authentication
        .iter()
        .filter_map(|auth| {
            let user = auth.user.as_deref()?;
            let password = auth.password.as_deref()?;
            Some(Credential::new(user, password))
        })
        .collect()
}

/// Translate a server config into the real server handshake driver config.
pub fn server_driver_config(config: &ServerConfig) -> Result<RealServerConfig, AppError> {
    let suites = wire_suites(&config.cipher_suites, None)?;
    let mut users = Vec::new();
    for entry in &config.users {
        let name = entry
            .name
            .as_deref()
            .filter(|name| !name.is_empty())
            .ok_or_else(|| AppError::Config("server user has no name".to_owned()))?;
        let user = if let Some(password) = entry.password.as_deref() {
            // Hash exactly like `ClientHandshake::with_password` does; both
            // sides then feed the same credential into `derive_static_key`.
            User::from_password(name, password, suites.clone())
        } else if let Some(hash) = entry.hashed_password.as_deref() {
            User::from_hashed_password(name, hash, suites.clone())
        } else {
            return Err(AppError::Config(format!(
                "server user {name:?} needs password or hashedPassword"
            )));
        }
        .map_err(|error| AppError::Config(format!("invalid server user {name:?}: {error}")))?;
        users.push(user);
    }
    let (nonce, nonce_config) = traffic_pattern(config.traffic_pattern.as_ref());
    let mtu = u16::try_from(config.mtu.unwrap_or(1400))
        .map_err(|_| AppError::Config("server MTU is out of range".to_owned()))?;
    let driver = RealServerConfig {
        users,
        hint_mandatory: config
            .advanced_settings
            .as_ref()
            .map(|settings| settings.user_hint_is_mandatory)
            .unwrap_or(true),
        allowed_suites: suites,
        egress: egress_config(config.egress.as_ref())?,
        stream: StreamConfig {
            nonce_pattern: nonce.clone(),
            nonce_pattern_config: nonce_config,
        },
        packet: PacketConfig {
            mtu,
            family: IpFamily::V4,
            nonce_pattern: nonce,
            nonce_pattern_config: nonce_config,
        },
        ..RealServerConfig::default()
    };
    driver
        .validate()
        .map_err(|error| AppError::Config(error.to_string()))?;
    Ok(driver)
}

pub fn server_mux_config(config: &ServerConfig) -> Result<MuxConfig, AppError> {
    let mux = MuxConfig {
        mtu: u16::try_from(config.mtu.unwrap_or(1400))
            .map_err(|_| AppError::Config("server MTU is out of range".to_owned()))?,
        ..MuxConfig::default()
    };
    mux.validate()
        .map_err(|error| AppError::Config(error.to_string()))?;
    Ok(mux)
}

fn egress_config(egress: Option<&Egress>) -> Result<EgressConfig, AppError> {
    let mut out = EgressConfig::new();
    let Some(egress) = egress else {
        return Ok(out);
    };
    for proxy in &egress.proxies {
        let name = proxy
            .name
            .as_deref()
            .filter(|name| !name.is_empty())
            .ok_or_else(|| AppError::Config("egress proxy needs a name".to_owned()))?;
        let host = proxy
            .host
            .as_deref()
            .filter(|host| !host.is_empty())
            .ok_or_else(|| AppError::Config(format!("egress proxy {name:?} needs a host")))?;
        let port = u16::try_from(proxy.port.unwrap_or(0))
            .map_err(|_| AppError::Config(format!("egress proxy {name:?} has an invalid port")))?;
        let credential = proxy.socks5_authentication.as_ref().and_then(|auth| {
            Some(Credential::new(
                auth.user.as_deref()?,
                auth.password.as_deref()?,
            ))
        });
        let mut proxy = EgressProxy::new(name, host, port);
        proxy.credential = credential;
        out = out.with_proxy(proxy);
    }
    for rule in &egress.rules {
        let action = match rule.action {
            shadowlemon_config::EgressAction::Proxy => EgressAction::Proxy,
            shadowlemon_config::EgressAction::Direct => EgressAction::Direct,
            shadowlemon_config::EgressAction::Reject => EgressAction::Reject,
            _ => return Err(AppError::Config("unknown egress action".to_owned())),
        };
        out = out.with_rule(EgressRule::new(
            rule.ip_ranges.iter().map(String::as_str),
            rule.domain_names.iter().map(String::as_str),
            action,
            rule.proxy_names.iter().map(String::as_str),
        ));
    }
    Ok(out)
}

/// Translate the configured logging level to a `tracing` level.
pub fn tracing_level(level: &LoggingLevel) -> tracing::Level {
    match level {
        LoggingLevel::Fatal => tracing::Level::ERROR,
        LoggingLevel::Error => tracing::Level::ERROR,
        LoggingLevel::Warn => tracing::Level::WARN,
        LoggingLevel::Info => tracing::Level::INFO,
        LoggingLevel::Debug => tracing::Level::DEBUG,
        LoggingLevel::Trace => tracing::Level::TRACE,
        LoggingLevel::Default | LoggingLevel::Unknown(_) => tracing::Level::INFO,
    }
}

/// Directory used for per-user daemon state (including the client pidfile).
pub fn state_dir() -> Result<PathBuf, AppError> {
    Ok(config_dir()?)
}
