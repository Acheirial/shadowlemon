//! Validation of loaded or newly constructed configurations.
//!
//! Every rule from `rust/docs/config-v0.2.md` §8 is enforced here. Errors carry
//! a dotted, indexed path (for example `profiles[0].cipherSuites[1]`) so callers
//! can point at the exact offending value.

use std::{collections::HashSet, net::IpAddr, str::FromStr};

use crate::{
    enums::{CipherSuite, EgressAction, KnownEnum, LowEntropyMode},
    error::{ConfigError, Result},
    schema::{
        is_valid_port, parse_port_range, Auth, ClientConfig, ClientDialer, ClientProfile, Egress,
        EgressRule, NoncePattern, PortBinding, ServerConfig, ServerEndpoint, TrafficPattern, User,
        DNS,
    },
};

/// A config value that can be checked against the V0.2 validation rules.
pub trait Validate {
    /// Validate the value, returning the first rule violation with a path.
    fn validate(&self) -> Result<()>;
}

fn invalid(path: impl Into<String>, message: impl Into<String>) -> ConfigError {
    ConfigError::invalid(path, message)
}

fn check_enum<E: KnownEnum>(value: &E, path: &str) -> Result<()> {
    if value.is_known() {
        Ok(())
    } else {
        Err(invalid(
            path,
            format!(
                "unknown enum value '{}'",
                value.unknown().unwrap_or("<unknown>")
            ),
        ))
    }
}

/// Check that a string is even-length, lowercase/uppercase hex and at most
/// `max_bytes` bytes long.
fn check_hex(text: &str, max_bytes: usize, path: &str) -> Result<()> {
    if text.len() % 2 != 0 {
        return Err(invalid(
            path,
            "hex string must have an even number of digits",
        ));
    }
    if !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(invalid(path, "string is not valid hex"));
    }
    if text.len() / 2 > max_bytes {
        return Err(invalid(
            path,
            format!("hex string exceeds the {max_bytes}-byte limit"),
        ));
    }
    Ok(())
}

fn validate_auth(auth: &Auth, path: &str) -> Result<()> {
    let user = auth.user.as_deref().unwrap_or("");
    let password = auth.password.as_deref().unwrap_or("");
    if user.is_empty() || password.is_empty() {
        return Err(invalid(
            path,
            "socks5 authentication requires both user and password",
        ));
    }
    Ok(())
}

fn validate_user(user: &User, path: &str) -> Result<()> {
    match user.name.as_deref() {
        Some(name) if !name.trim().is_empty() => {}
        _ => {
            return Err(invalid(
                format!("{path}.name"),
                "user name must not be empty",
            ))
        }
    }
    if let Some(hashed) = &user.hashed_password {
        check_hex(hashed, usize::MAX, &format!("{path}.hashedPassword"))?;
    }
    Ok(())
}

fn validate_binding(binding: &PortBinding, path: &str) -> Result<()> {
    check_enum(&binding.protocol, &format!("{path}.protocol"))?;
    match (&binding.port, &binding.port_range) {
        (Some(_), Some(_)) => Err(invalid(path, "port and portRange are mutually exclusive")),
        (Some(port), None) => {
            if is_valid_port(*port) {
                Ok(())
            } else {
                Err(invalid(
                    format!("{path}.port"),
                    "port must be in the range 1..=65535",
                ))
            }
        }
        (None, Some(range)) => {
            if parse_port_range(range).is_some() {
                Ok(())
            } else {
                Err(invalid(
                    format!("{path}.portRange"),
                    "portRange must be a 'begin-end' range of ports in 1..=65535 with begin <= end",
                ))
            }
        }
        (None, None) => Err(invalid(path, "either port or portRange must be set")),
    }
}

fn validate_server_endpoint(endpoint: &ServerEndpoint, path: &str) -> Result<()> {
    let has_domain = endpoint
        .domain_name
        .as_deref()
        .is_some_and(|v| !v.is_empty());
    let has_ip = endpoint
        .ip_address
        .as_deref()
        .is_some_and(|v| !v.is_empty());
    if !has_domain && !has_ip {
        return Err(invalid(
            path,
            "a server needs either domainName or ipAddress",
        ));
    }
    for (i, binding) in endpoint.port_bindings.iter().enumerate() {
        validate_binding(binding, &format!("{path}.portBindings[{i}]"))?;
    }
    Ok(())
}

fn validate_dialer(dialer: &ClientDialer, path: &str) -> Result<()> {
    check_enum(&dialer.protocol, &format!("{path}.protocol"))?;
    if let Some(port) = dialer.port {
        if !is_valid_port(port) {
            return Err(invalid(
                format!("{path}.port"),
                "port must be in the range 1..=65535",
            ));
        }
    }
    if let Some(auth) = &dialer.socks5_authentication {
        validate_auth(auth, &format!("{path}.socks5Authentication"))?;
    }
    Ok(())
}

fn validate_cipher_suites(suites: &[CipherSuite], path: &str) -> Result<()> {
    for (i, suite) in suites.iter().enumerate() {
        let at = format!("{path}[{i}]");
        match suite {
            CipherSuite::Unspecified => {
                return Err(invalid(
                    at,
                    "CIPHER_SUITE_UNSPECIFIED is not a usable cipher suite",
                ));
            }
            CipherSuite::Unknown(raw) => {
                return Err(invalid(at, format!("unknown cipher suite '{raw}'")));
            }
            _ => {}
        }
    }
    Ok(())
}

fn validate_nonce(nonce: &NoncePattern, path: &str) -> Result<()> {
    check_enum(&nonce.nonce_type, &format!("{path}.type"))?;
    if let Some(max_len) = nonce.max_len {
        if !(0..=12).contains(&max_len) {
            return Err(invalid(
                format!("{path}.maxLen"),
                "nonce maxLen must be in the range 0..=12",
            ));
        }
    }
    for (i, hex) in nonce.custom_hex_strings.iter().enumerate() {
        check_hex(hex, 12, &format!("{path}.customHexStrings[{i}]"))?;
    }
    Ok(())
}

impl Validate for TrafficPattern {
    fn validate(&self) -> Result<()> {
        self.validate_at("trafficPattern")
    }
}

impl TrafficPattern {
    /// Validate with a custom field path prefix (used by client/server configs).
    pub fn validate_at(&self, path: &str) -> Result<()> {
        if let Some(tcp) = &self.tcp_fragment {
            if let Some(ms) = tcp.max_sleep_ms {
                if !(0..=100).contains(&ms) {
                    return Err(invalid(
                        format!("{path}.tcpFragment.maxSleepMs"),
                        "tcpFragment.maxSleepMs must be in the range 0..=100",
                    ));
                }
            }
        }
        if let Some(nonce) = &self.nonce {
            validate_nonce(nonce, &format!("{path}.nonce"))?;
        }
        if let Some(padding) = &self.padding {
            if let Some(len) = padding.max_middle_padding_len {
                if !(0..=255).contains(&len) {
                    return Err(invalid(
                        format!("{path}.padding.maxMiddlePaddingLen"),
                        "padding length must be in the range 0..=255",
                    ));
                }
            }
            if let Some(len) = padding.max_end_padding_len {
                if !(0..=255).contains(&len) {
                    return Err(invalid(
                        format!("{path}.padding.maxEndPaddingLen"),
                        "padding length must be in the range 0..=255",
                    ));
                }
            }
        }
        if let Some(low) = &self.low_entropy {
            check_enum(&low.mode, &format!("{path}.lowEntropy.mode"))?;
            check_enum(
                &low.mask_rotation,
                &format!("{path}.lowEntropy.maskRotation"),
            )?;
            if low.mode != LowEntropyMode::Off && !cfg!(feature = "low-entropy") {
                return Err(ConfigError::FeatureDisabled {
                    path: format!("{path}.lowEntropy.mode"),
                    feature: "low-entropy",
                });
            }
        }
        Ok(())
    }
}

impl Validate for ClientProfile {
    fn validate(&self) -> Result<()> {
        self.validate_at("profiles[0]")
    }
}

impl ClientProfile {
    /// Validate with a custom field path prefix.
    pub fn validate_at(&self, path: &str) -> Result<()> {
        match self.profile_name.as_deref() {
            Some(name) if !name.is_empty() => {}
            _ => {
                return Err(invalid(
                    format!("{path}.profileName"),
                    "profileName must not be empty",
                ))
            }
        }
        match &self.user {
            Some(user) => validate_user(user, &format!("{path}.user"))?,
            None => return Err(invalid(format!("{path}.user"), "profile user is required")),
        }
        for (i, server) in self.servers.iter().enumerate() {
            validate_server_endpoint(server, &format!("{path}.servers[{i}]"))?;
        }
        if let Some(mtu) = self.mtu {
            if !(1280..=1500).contains(&mtu) {
                return Err(invalid(
                    format!("{path}.mtu"),
                    "mtu must be in the range 1280..=1500",
                ));
            }
        }
        if let Some(mux) = &self.multiplexing {
            check_enum(&mux.level, &format!("{path}.multiplexing.level"))?;
        }
        if let Some(handshake) = &self.handshake_mode {
            check_enum(handshake, &format!("{path}.handshakeMode"))?;
        }
        if let Some(pattern) = &self.traffic_pattern {
            pattern.validate_at(&format!("{path}.trafficPattern"))?;
        }
        if let Some(dialer) = &self.dialer {
            validate_dialer(dialer, &format!("{path}.dialer"))?;
        }
        validate_cipher_suites(&self.cipher_suites, &format!("{path}.cipherSuites"))?;
        Ok(())
    }
}

impl Validate for ClientConfig {
    fn validate(&self) -> Result<()> {
        check_enum(&self.logging_level, "loggingLevel")?;

        let mut names = HashSet::new();
        for (i, profile) in self.profiles.iter().enumerate() {
            profile.validate_at(&format!("profiles[{i}]"))?;
            if let Some(name) = &profile.profile_name {
                if !names.insert(name.as_str()) {
                    return Err(invalid(
                        format!("profiles[{i}].profileName"),
                        format!("duplicate profile name '{name}'"),
                    ));
                }
            }
        }

        if let Some(active) = &self.active_profile {
            if !active.is_empty() && !names.contains(active.as_str()) {
                return Err(invalid(
                    "activeProfile",
                    format!("no profile named '{active}' exists"),
                ));
            }
        }
        if let Some(port) = self.socks5_port {
            if !is_valid_port(port) {
                return Err(invalid("socks5Port", "port must be in the range 1..=65535"));
            }
        }
        for (i, auth) in self.socks5_authentication.iter().enumerate() {
            validate_auth(auth, &format!("socks5Authentication[{i}]"))?;
        }
        Ok(())
    }
}

fn validate_egress(egress: &Egress, path: &str) -> Result<()> {
    let mut proxy_names = HashSet::new();
    for (i, proxy) in egress.proxies.iter().enumerate() {
        let at = format!("{path}.proxies[{i}]");
        match proxy.name.as_deref() {
            Some(name) if !name.is_empty() => {
                if !proxy_names.insert(name) {
                    return Err(invalid(
                        format!("{at}.name"),
                        format!("duplicate egress proxy name '{name}'"),
                    ));
                }
            }
            _ => {
                return Err(invalid(
                    format!("{at}.name"),
                    "proxy name must not be empty",
                ))
            }
        }
        check_enum(&proxy.protocol, &format!("{at}.protocol"))?;
        match proxy.host.as_deref() {
            Some(host) if !host.is_empty() => {}
            _ => {
                return Err(invalid(
                    format!("{at}.host"),
                    "proxy host must not be empty",
                ))
            }
        }
        match proxy.port {
            Some(port) if is_valid_port(port) => {}
            _ => {
                return Err(invalid(
                    format!("{at}.port"),
                    "port must be in the range 1..=65535",
                ))
            }
        }
        if let Some(auth) = &proxy.socks5_authentication {
            validate_auth(auth, &format!("{at}.socks5Authentication"))?;
        }
    }

    for (i, rule) in egress.rules.iter().enumerate() {
        validate_egress_rule(rule, &format!("{path}.rules[{i}]"), &proxy_names)?;
    }
    Ok(())
}

fn validate_egress_rule(rule: &EgressRule, path: &str, proxy_names: &HashSet<&str>) -> Result<()> {
    check_enum(&rule.action, &format!("{path}.action"))?;
    for (i, cidr) in rule.ip_ranges.iter().enumerate() {
        let at = format!("{path}.ipRanges[{i}]");
        if cidr == "*" {
            continue;
        }
        if ipnet::IpNet::from_str(cidr).is_err() {
            return Err(invalid(at, format!("'{cidr}' is not a valid CIDR or '*'")));
        }
    }
    for (i, domain) in rule.domain_names.iter().enumerate() {
        let at = format!("{path}.domainNames[{i}]");
        if domain == "*" {
            continue;
        }
        if domain.is_empty() || domain.starts_with('.') || domain.ends_with('.') {
            return Err(invalid(
                at,
                "a domain must be non-empty and must not start or end with '.'",
            ));
        }
    }
    if rule.action == EgressAction::Proxy {
        if rule.proxy_names.is_empty() {
            return Err(invalid(
                format!("{path}.proxyNames"),
                "PROXY rules require at least one proxy name",
            ));
        }
        for (i, name) in rule.proxy_names.iter().enumerate() {
            if !proxy_names.contains(name.as_str()) {
                return Err(invalid(
                    format!("{path}.proxyNames[{i}]"),
                    format!("unknown egress proxy '{name}'"),
                ));
            }
        }
    }
    Ok(())
}

fn validate_dns(dns: &DNS, path: &str) -> Result<()> {
    check_enum(&dns.dual_stack, &format!("{path}.dualStack"))?;
    for (domain, ip) in &dns.hosts {
        if ip.parse::<IpAddr>().is_err() {
            return Err(invalid(
                format!("{path}.hosts.{domain}"),
                format!("'{ip}' is not a valid IP address"),
            ));
        }
    }
    Ok(())
}

impl Validate for ServerConfig {
    fn validate(&self) -> Result<()> {
        check_enum(&self.logging_level, "loggingLevel")?;
        for (i, binding) in self.port_bindings.iter().enumerate() {
            validate_binding(binding, &format!("portBindings[{i}]"))?;
        }

        let mut user_names = HashSet::new();
        for (i, user) in self.users.iter().enumerate() {
            validate_user(user, &format!("users[{i}]"))?;
            if let Some(name) = &user.name {
                if !user_names.insert(name.as_str()) {
                    return Err(invalid(
                        format!("users[{i}].name"),
                        format!("duplicate user name '{name}'"),
                    ));
                }
            }
        }

        if let Some(ip) = &self.listen_ip_address {
            if !ip.is_empty() && ip.parse::<IpAddr>().is_err() {
                return Err(invalid(
                    "listenIPAddress",
                    format!("'{ip}' is not a valid IP address"),
                ));
            }
        }
        if let Some(mtu) = self.mtu {
            if !(1280..=1500).contains(&mtu) {
                return Err(invalid("mtu", "mtu must be in the range 1280..=1500"));
            }
        }
        if let Some(egress) = &self.egress {
            validate_egress(egress, "egress")?;
        }
        if let Some(dns) = &self.dns {
            validate_dns(dns, "dns")?;
        }
        if let Some(pattern) = &self.traffic_pattern {
            pattern.validate_at("trafficPattern")?;
        }
        validate_cipher_suites(&self.cipher_suites, "cipherSuites")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        enums::{EgressAction, LowEntropyMaskRotation, LowEntropyMode, ProxyProtocol},
        schema::{
            Egress, EgressProxy, EgressRule, LowEntropyPattern, NoncePattern, PaddingPattern,
            TCPFragment,
        },
    };

    fn client() -> ClientConfig {
        serde_json::from_str::<ClientConfig>(
            r#"{
                "profiles":[{
                    "profileName":"default",
                    "user":{"name":"u","password":"p"},
                    "servers":[{"ipAddress":"1.2.3.4","portBindings":[{"port":443,"protocol":"TCP"}]}],
                    "mtu":1400,
                    "cipherSuites":["CIPHER_SUITE_XCHACHA20_POLY1305"]
                }],
                "activeProfile":"default"
            }"#,
        )
        .unwrap()
    }

    #[test]
    fn valid_client_passes() {
        client().validate().unwrap();
    }

    #[test]
    fn rejects_unspecified_suite_with_path() {
        let mut cfg = client();
        cfg.profiles[0].cipher_suites.push(CipherSuite::Unspecified);
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("profiles[0].cipherSuites[1]"), "{err}");
    }

    #[test]
    fn rejects_bad_mtu_and_ports() {
        let mut cfg = client();
        cfg.profiles[0].mtu = Some(1279);
        assert!(cfg
            .validate()
            .unwrap_err()
            .to_string()
            .contains("profiles[0].mtu"));

        let mut cfg = client();
        cfg.profiles[0].servers[0].port_bindings[0].port_range = Some("100-200".into());
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("port and portRange"), "{err}");

        let mut cfg = client();
        cfg.profiles[0].servers[0].port_bindings[0].port = None;
        cfg.profiles[0].servers[0].port_bindings[0].port_range = Some("200-100".into());
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_active_profile_mismatch() {
        let mut cfg = client();
        cfg.active_profile = Some("missing".into());
        assert!(cfg
            .validate()
            .unwrap_err()
            .to_string()
            .contains("activeProfile"));
    }

    #[test]
    fn rejects_traffic_pattern_violations() {
        let mut cfg = client();
        let pattern = TrafficPattern {
            tcp_fragment: Some(TCPFragment {
                enable: Some(true),
                max_sleep_ms: Some(101),
            }),
            ..Default::default()
        };
        cfg.profiles[0].traffic_pattern = Some(pattern);
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("tcpFragment.maxSleepMs"), "{err}");

        let mut cfg = client();
        cfg.profiles[0].traffic_pattern = Some(TrafficPattern {
            nonce: Some(NoncePattern {
                max_len: Some(13),
                custom_hex_strings: vec!["000102030405060708090a0b0c".into()],
                ..Default::default()
            }),
            ..Default::default()
        });
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("nonce.maxLen"), "{err}");

        let mut cfg = client();
        cfg.profiles[0].traffic_pattern = Some(TrafficPattern {
            nonce: Some(NoncePattern {
                custom_hex_strings: vec!["00ff1".into()],
                ..Default::default()
            }),
            ..Default::default()
        });
        assert!(cfg.validate().is_err());

        let mut cfg = client();
        cfg.profiles[0].traffic_pattern = Some(TrafficPattern {
            padding: Some(PaddingPattern {
                max_middle_padding_len: Some(256),
                max_end_padding_len: None,
            }),
            ..Default::default()
        });
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_bad_egress_rule_and_dns() {
        let mut cfg = ServerConfig {
            egress: Some(Egress {
                proxies: vec![EgressProxy {
                    name: Some("p".into()),
                    protocol: ProxyProtocol::Socks5ProxyProtocol,
                    host: Some("localhost".into()),
                    port: Some(1080),
                    ..Default::default()
                }],
                rules: vec![EgressRule {
                    action: EgressAction::Proxy,
                    proxy_names: vec!["missing".into()],
                    ..Default::default()
                }],
            }),
            ..Default::default()
        };
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("proxyNames[0]"), "{err}");

        cfg.egress = None;
        cfg.dns = Some(DNS {
            hosts: [("example.com".into(), "not-an-ip".into())].into(),
            ..Default::default()
        });
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("dns.hosts.example.com"), "{err}");
    }

    #[test]
    fn low_entropy_requires_feature() {
        let mut cfg = client();
        cfg.profiles[0].traffic_pattern = Some(TrafficPattern {
            low_entropy: Some(LowEntropyPattern {
                mode: LowEntropyMode::Mode32,
                mask_rotation: LowEntropyMaskRotation::RotateLeft3,
            }),
            ..Default::default()
        });
        if cfg!(feature = "low-entropy") {
            cfg.validate().unwrap();
        } else {
            let err = cfg.validate().unwrap_err().to_string();
            assert!(err.contains("low-entropy"), "{err}");
        }
    }

    #[test]
    fn rejects_non_hex_hashed_password() {
        let mut cfg = ServerConfig::default();
        cfg.users.push(User {
            name: Some("u".into()),
            hashed_password: Some("nothex!".into()),
            ..Default::default()
        });
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("hashedPassword"), "{err}");
    }
}
