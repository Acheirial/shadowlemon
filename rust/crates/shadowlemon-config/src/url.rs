//! `shadowlemon://` and `shadowlemons://` URL import/export.
//!
//! Binary encoding choice: the V0.2 spec allows any deterministic equivalent
//! binary encoding in place of Go's protobuf bytes. We use the UTF-8 bytes of
//! the canonical `serde_json` serialization of the config. Struct field order
//! is fixed and `DNS::hosts` is a `BTreeMap`, so the byte sequence is stable;
//! the bytes are then encoded with standard, padded base64 (the equivalent of
//! Go's `base64.StdEncoding`).

use std::borrow::Cow;

use base64::{engine::general_purpose::STANDARD, Engine};
use url::{Host, Url};

use crate::{
    enums::{CipherSuite, HandshakeMode, MultiplexingLevel, TransportProtocol},
    error::{ConfigError, Result},
    schema::{
        is_valid_port, parse_port_range, ClientConfig, ClientProfile, MultiplexingConfig,
        PortBinding, ServerEndpoint, User,
    },
    validate::Validate,
};

const FULL_PREFIX: &str = "shadowlemon://";
const SIMPLE_SCHEME: &str = "shadowlemons";

fn invalid(message: impl Into<String>) -> ConfigError {
    ConfigError::invalid("url", message)
}

/// Percent-encode a URL component using RFC 3986 unreserved characters only.
fn encode_component(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for &byte in value.as_bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// Export the whole `ClientConfig` as a `shadowlemon://` URL.
pub fn export_full_url(config: &ClientConfig) -> Result<String> {
    config.validate()?;
    let bytes = serde_json::to_vec(config)?;
    Ok(format!("{FULL_PREFIX}{}", STANDARD.encode(bytes)))
}

/// Import a `shadowlemon://` URL into a fully validated `ClientConfig`.
pub fn import_full_url(url: &str) -> Result<ClientConfig> {
    // The base64 payload may contain '/', so strip the literal prefix instead
    // of letting a URL parser split the payload into host and path.
    let payload = url
        .strip_prefix(FULL_PREFIX)
        .ok_or_else(|| invalid(format!("expected the '{FULL_PREFIX}' prefix")))?;
    if payload.is_empty() {
        return Err(invalid("empty base64 payload"));
    }
    if payload.contains('?') || payload.contains('#') {
        return Err(invalid(
            "the config payload must not contain a query or fragment",
        ));
    }
    let bytes = STANDARD.decode(payload)?;
    let config: ClientConfig = serde_json::from_slice(&bytes)?;
    config.validate()?;
    Ok(config)
}

/// Export one human-readable `shadowlemons://` URL per server in a profile.
pub fn export_simple_urls(config: &ClientConfig) -> Result<Vec<String>> {
    config.validate()?;
    let mut urls = Vec::new();
    for profile in &config.profiles {
        urls.extend(export_profile_urls(profile)?);
    }
    Ok(urls)
}

fn export_profile_urls(profile: &ClientProfile) -> Result<Vec<String>> {
    let profile_name = required(&profile.profile_name, "profileName")?;
    let user = profile
        .user
        .as_ref()
        .ok_or_else(|| invalid(format!("profile '{profile_name}' has no user")))?;
    let user_name = required(&user.name, "user.name")?;
    // A hashed-only account cannot be embedded in a shareable URL.
    let password = required(&user.password, "user.password")?;

    let mut common: Vec<(String, String)> = vec![("profile".into(), profile_name.to_owned())];
    if let Some(mtu) = profile.mtu {
        common.push(("mtu".into(), mtu.to_string()));
    }
    if let Some(mux) = &profile.multiplexing {
        let name = mux
            .level
            .as_str()
            .ok_or_else(|| invalid("unknown multiplexing level"))?;
        common.push(("multiplexing".into(), name.to_owned()));
    }
    if let Some(handshake) = &profile.handshake_mode {
        let name = handshake
            .as_str()
            .ok_or_else(|| invalid("unknown handshake mode"))?;
        common.push(("handshake-mode".into(), name.to_owned()));
    }
    if !profile.cipher_suites.is_empty() {
        let mut names = Vec::with_capacity(profile.cipher_suites.len());
        for suite in &profile.cipher_suites {
            let name = suite
                .as_str()
                .filter(|_| crate::enums::config_suite_to_wire(suite.clone()).is_some())
                .ok_or_else(|| invalid("cannot export an unusable cipher suite"))?;
            names.push(name);
        }
        common.push(("cipher-suites".into(), names.join(",")));
    }
    if profile.servers.is_empty() {
        return Err(invalid(format!("profile '{profile_name}' has no servers")));
    }
    let mut urls = Vec::with_capacity(profile.servers.len());
    for server in &profile.servers {
        let host = server
            .domain_name
            .as_deref()
            .filter(|domain| !domain.is_empty())
            .or_else(|| server.ip_address.as_deref().filter(|ip| !ip.is_empty()))
            .ok_or_else(|| {
                invalid(format!(
                    "profile '{profile_name}' has a server without a host"
                ))
            })?;

        if server.port_bindings.is_empty() {
            return Err(invalid(format!(
                "profile '{profile_name}' has a server without port bindings"
            )));
        }
        let mut pairs = common.clone();
        for binding in &server.port_bindings {
            let port = match (&binding.port, &binding.port_range) {
                (Some(port), None) => port.to_string(),
                (None, Some(range)) => range.clone(),
                _ => {
                    return Err(invalid(
                        "each port binding needs exactly one of port/portRange",
                    ))
                }
            };
            let protocol = binding
                .protocol
                .as_str()
                .ok_or_else(|| invalid("unknown transport protocol"))?;
            pairs.push(("port".into(), port));
            pairs.push(("protocol".into(), protocol.to_owned()));
        }

        let host_part = if host.parse::<std::net::Ipv6Addr>().is_ok() {
            format!("[{host}]")
        } else {
            host.to_owned()
        };
        let mut url = Url::parse(&format!(
            "{SIMPLE_SCHEME}://{}:{}@{host_part}/",
            encode_component(user_name),
            encode_component(password)
        ))?;
        url.query_pairs_mut()
            .extend_pairs(pairs.iter().map(|(k, v)| (k.as_str(), v.as_str())));
        urls.push(url.to_string());
    }
    Ok(urls)
}

fn required<'a>(value: &'a Option<String>, field: &str) -> Result<&'a str> {
    value
        .as_deref()
        .filter(|v| !v.is_empty())
        .ok_or_else(|| invalid(format!("{field} is required to export a URL")))
}

/// Import a `shadowlemons://` URL into a single-profile `ClientConfig`.
///
/// Cipher-suite names are parsed strictly: an unknown name is an error, never
/// a silent fallback to a default suite.
pub fn import_simple_url(url: &str) -> Result<ClientConfig> {
    let url = Url::parse(url)?;
    if url.scheme() != SIMPLE_SCHEME {
        return Err(invalid(format!("expected the '{SIMPLE_SCHEME}://' scheme")));
    }
    let user_name = url.username();
    if user_name.is_empty() {
        return Err(invalid("URL must contain a user name"));
    }
    let password = url
        .password()
        .filter(|p| !p.is_empty())
        .ok_or_else(|| invalid("URL must contain a password"))?;
    let host = url
        .host()
        .ok_or_else(|| invalid("URL must contain a host"))?;

    let pairs: Vec<(Cow<'_, str>, Cow<'_, str>)> = url.query_pairs().collect();
    let find = |key: &str| -> Option<&str> {
        pairs
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_ref())
    };
    let profile_name = find("profile")
        .filter(|v| !v.is_empty())
        .ok_or_else(|| invalid("query parameter 'profile' is required"))?;

    let cipher_suites = match find("cipher-suites") {
        Some(raw) if !raw.is_empty() => {
            let mut suites = Vec::new();
            for name in raw.split(',') {
                let suite = CipherSuite::from_name(name);
                if !suite.is_known() || suite == CipherSuite::Unspecified {
                    return Err(invalid(format!("unknown cipher suite '{name}'")));
                }
                suites.push(suite);
            }
            suites
        }
        _ => Vec::new(),
    };

    let ports: Vec<&str> = pairs
        .iter()
        .filter(|(k, _)| k == "port")
        .map(|(_, v)| v.as_ref())
        .collect();
    let protocols: Vec<&str> = pairs
        .iter()
        .filter(|(k, _)| k == "protocol")
        .map(|(_, v)| v.as_ref())
        .collect();
    if ports.len() != protocols.len() {
        return Err(invalid(format!(
            "port count ({}) and protocol count ({}) must match",
            ports.len(),
            protocols.len()
        )));
    }
    if ports.is_empty() {
        return Err(invalid("at least one port/protocol pair is required"));
    }
    let mut port_bindings = Vec::with_capacity(ports.len());
    for (port_text, protocol_text) in ports.into_iter().zip(protocols) {
        let protocol = TransportProtocol::from_name(protocol_text);
        if !protocol.is_known() {
            return Err(invalid(format!("unknown protocol '{protocol_text}'")));
        }
        if protocol == TransportProtocol::Tcp {
            return Err(invalid(
                "TCP external transport has been removed; use protocol UDP",
            ));
        }
        let (port, port_range) = if port_text.contains('-') {
            if parse_port_range(port_text).is_none() {
                return Err(invalid(format!("invalid port range '{port_text}'")));
            }
            (None, Some(port_text.to_owned()))
        } else {
            let parsed = port_text
                .parse::<i32>()
                .map_err(|_| invalid(format!("invalid port '{port_text}'")))?;
            if !is_valid_port(parsed) {
                return Err(invalid(format!("invalid port '{port_text}'")));
            }
            (Some(parsed), None)
        };
        port_bindings.push(PortBinding {
            port,
            port_range,
            protocol,
        });
    }

    let mtu = match find("mtu") {
        Some(raw) => Some(
            raw.parse::<i32>()
                .map_err(|_| invalid(format!("invalid mtu '{raw}'")))?,
        ),
        None => None,
    };
    let multiplexing = match find("multiplexing") {
        Some(raw) => {
            let level = MultiplexingLevel::from_name(raw);
            if !level.is_known() {
                return Err(invalid(format!("unknown multiplexing level '{raw}'")));
            }
            Some(MultiplexingConfig { level })
        }
        None => None,
    };
    let handshake_mode = match find("handshake-mode") {
        Some(raw) => {
            let mode = HandshakeMode::from_name(raw);
            if !mode.is_known() {
                return Err(invalid(format!("unknown handshake mode '{raw}'")));
            }
            Some(mode)
        }
        None => None,
    };
    let host_text = match host {
        Host::Ipv4(addr) => addr.to_string(),
        Host::Ipv6(addr) => addr.to_string(),
        Host::Domain(domain) => domain.trim_matches(['[', ']']).to_owned(),
    };
    // Non-special schemes expose even IP literals as opaque domains. Detect
    // them here so the imported endpoint stores the value in `ipAddress`.
    let (ip_address, domain_name) = if host_text.parse::<std::net::IpAddr>().is_ok() {
        (Some(host_text), None)
    } else {
        (None, Some(host_text))
    };

    let profile = ClientProfile {
        profile_name: Some(profile_name.to_owned()),
        user: Some(User {
            name: Some(user_name.to_owned()),
            password: Some(password.to_owned()),
            ..Default::default()
        }),
        servers: vec![ServerEndpoint {
            ip_address,
            domain_name,
            port_bindings,
        }],
        mtu,
        multiplexing,
        handshake_mode,
        cipher_suites,
        ..Default::default()
    };
    let config = ClientConfig {
        profiles: vec![profile],
        active_profile: Some(profile_name.to_owned()),
        ..Default::default()
    };
    config.validate()?;
    Ok(config)
}

/// Import either URL scheme, dispatching on the scheme prefix.
pub fn import_url(url: &str) -> Result<ClientConfig> {
    if url.starts_with(FULL_PREFIX) {
        import_full_url(url)
    } else if url.starts_with(&format!("{SIMPLE_SCHEME}://")) {
        import_simple_url(url)
    } else {
        Err(invalid("unsupported URL scheme"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ClientConfig {
        serde_json::from_str::<ClientConfig>(
            r#"{
                "profiles":[{
                    "profileName":"default",
                    "user":{"name":"user1","password":"password1"},
                    "servers":[{
                        "domainName":"example.com",
                        "portBindings":[
                            {"portRange":"2012-2022","protocol":"UDP"},
                            {"port":2027,"protocol":"UDP"}
                        ]
                    }],
                    "mtu":1400,
                    "multiplexing":{"level":"MULTIPLEXING_HIGH"},
                    "handshakeMode":"HANDSHAKE_NO_WAIT",
                    "cipherSuites":["CIPHER_SUITE_AES_256_GCM","CIPHER_SUITE_XCHACHA20_POLY1305"]
                }],
                "activeProfile":"default"
            }"#,
        )
        .unwrap()
    }

    #[test]
    fn full_url_round_trip() {
        let cfg = sample();
        let url = export_full_url(&cfg).unwrap();
        assert!(url.starts_with("shadowlemon://"));
        assert_eq!(import_full_url(&url).unwrap(), cfg);
        assert_eq!(import_url(&url).unwrap(), cfg);
    }

    #[test]
    fn simple_url_round_trip() {
        let cfg = sample();
        let urls = export_simple_urls(&cfg).unwrap();
        assert_eq!(urls.len(), 1);
        let imported = import_simple_url(&urls[0]).unwrap();
        assert_eq!(
            imported.profiles[0].profile_name.as_deref(),
            Some("default")
        );
        assert_eq!(
            imported.profiles[0].user.as_ref().unwrap().name.as_deref(),
            Some("user1")
        );
        assert_eq!(
            imported.profiles[0]
                .user
                .as_ref()
                .unwrap()
                .password
                .as_deref(),
            Some("password1")
        );
        assert_eq!(imported.profiles[0].mtu, Some(1400));
        assert_eq!(
            imported.profiles[0].cipher_suites,
            cfg.profiles[0].cipher_suites
        );
        assert_eq!(
            imported.profiles[0].servers[0].domain_name.as_deref(),
            Some("example.com")
        );
        assert_eq!(imported.profiles[0].servers[0].port_bindings.len(), 2);
        assert_eq!(import_url(&urls[0]).unwrap(), imported);
    }

    #[test]
    fn simple_url_uses_bracketed_ipv6() {
        let mut cfg = sample();
        cfg.profiles[0].servers[0].domain_name = None;
        cfg.profiles[0].servers[0].ip_address = Some("2001:db8::1".into());
        let url = &export_simple_urls(&cfg).unwrap()[0];
        assert!(url.contains("@[2001:db8::1]/"), "{url}");
        let imported = import_simple_url(url).unwrap();
        assert_eq!(
            imported.profiles[0].servers[0].ip_address.as_deref(),
            Some("2001:db8::1")
        );
    }

    #[test]
    fn simple_url_rejects_unknown_suite() {
        let mut url = export_simple_urls(&sample()).unwrap().remove(0);
        url = url.replace("CIPHER_SUITE_AES_256_GCM", "CIPHER_SUITE_MADE_UP");
        let err = import_simple_url(&url).unwrap_err().to_string();
        assert!(err.contains("unknown cipher suite"), "{err}");
    }

    #[test]
    fn simple_url_rejects_tcp_protocol() {
        let url = export_simple_urls(&sample()).unwrap().remove(0);
        let tcp_url = url.replace("protocol=UDP", "protocol=TCP");
        let err = import_url(&tcp_url).unwrap_err().to_string();
        assert!(
            err.contains("TCP external transport has been removed; use protocol UDP"),
            "{err}"
        );
    }

    #[test]
    fn simple_url_rejects_port_protocol_count_mismatch() {
        let url = export_simple_urls(&sample()).unwrap().remove(0);
        let mut broken = url.clone();
        // Remove one protocol parameter, leaving two ports and one protocol.
        broken = broken.replacen("&protocol=UDP", "", 1);
        let err = import_simple_url(&broken).unwrap_err().to_string();
        assert!(err.contains("must match"), "{err}");
    }
}
