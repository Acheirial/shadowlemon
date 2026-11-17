//! Egress rule evaluation (PROXY / DIRECT / REJECT).

use std::{net::IpAddr, str::FromStr};

use ipnet::IpNet;

use crate::Credential;

/// The action selected by an egress rule.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum EgressAction {
    /// Dial the destination directly through the injected proxy dialer.
    #[default]
    Direct,
    /// Forward the request to another SOCKS5 proxy (egress proxy).
    Proxy,
    /// Refuse the request with a SOCKS5 `NOT_ALLOWED` reply.
    Reject,
}

/// A single egress rule.
///
/// Rules are evaluated in order; the first match wins. An IP range is either
/// a CIDR string such as `10.0.0.0/8` or the wildcard `*`. A domain name is an
/// exact name, a `.suffix` match, or the wildcard `*`. Domain comparisons are
/// case-insensitive and ignore a trailing dot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EgressRule {
    /// CIDR ranges (or `*`) matched against a literal/resolved IP.
    pub ip_ranges: Vec<String>,
    /// Domain names (or `*`) matched against a destination hostname.
    pub domain_names: Vec<String>,
    /// Action to take on a match.
    pub action: EgressAction,
    /// Candidate egress proxy names. One is selected at random when a PROXY
    /// rule matches and more than one name is configured.
    pub proxy_names: Vec<String>,
}

impl EgressRule {
    /// Creates a rule.
    pub fn new(
        ip_ranges: impl IntoIterator<Item = impl Into<String>>,
        domain_names: impl IntoIterator<Item = impl Into<String>>,
        action: EgressAction,
        proxy_names: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            ip_ranges: ip_ranges.into_iter().map(Into::into).collect(),
            domain_names: domain_names.into_iter().map(Into::into).collect(),
            action,
            proxy_names: proxy_names.into_iter().map(Into::into).collect(),
        }
    }
}

/// Description of a downstream SOCKS5 proxy used by PROXY egress rules.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EgressProxy {
    /// Name referenced by [`EgressRule::proxy_names`].
    pub name: String,
    /// Proxy hostname or IP literal.
    pub host: String,
    /// Proxy TCP port.
    pub port: u16,
    /// Optional credentials for the downstream SOCKS5 proxy.
    pub credential: Option<Credential>,
}

impl EgressProxy {
    /// Creates an egress proxy with no credentials.
    pub fn new(name: impl Into<String>, host: impl Into<String>, port: u16) -> Self {
        Self {
            name: name.into(),
            host: host.into(),
            port,
            credential: None,
        }
    }

    /// Attaches SOCKS5 credentials for the downstream proxy.
    pub fn with_credential(mut self, credential: Credential) -> Self {
        self.credential = Some(credential);
        self
    }
}

/// The result of egress policy evaluation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EgressDecision {
    /// The selected action.
    pub action: EgressAction,
    /// The proxy selected for a PROXY action, when one is configured.
    ///
    /// When a PROXY rule matches but none of its proxy names resolve to a
    /// configured proxy, this is `None` and the server falls back to DIRECT.
    pub proxy: Option<EgressProxy>,
}

impl EgressDecision {
    fn direct() -> Self {
        Self {
            action: EgressAction::Direct,
            proxy: None,
        }
    }
}

/// A collection of egress rules and the proxies they reference.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EgressConfig {
    /// Ordered rules; the first matching rule decides the action.
    pub rules: Vec<EgressRule>,
    /// Proxies referenced by PROXY rules.
    pub proxies: Vec<EgressProxy>,
}

impl EgressConfig {
    /// Creates an empty policy (everything is DIRECT).
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a rule, returning `self` for chaining.
    pub fn with_rule(mut self, rule: EgressRule) -> Self {
        self.rules.push(rule);
        self
    }

    /// Adds a proxy, returning `self` for chaining.
    pub fn with_proxy(mut self, proxy: EgressProxy) -> Self {
        self.proxies.push(proxy);
        self
    }

    /// Evaluates the policy for a destination.
    ///
    /// `ip` is the literal or resolved destination address; `domain` is the
    /// original hostname, when the destination was specified by name. Either
    /// may be `None`, but at least one should be present for a meaningful
    /// decision.
    pub fn find_action(&self, ip: Option<IpAddr>, domain: Option<&str>) -> EgressDecision {
        for rule in &self.rules {
            let ip_matched =
                ip.is_some_and(|ip| rule.ip_ranges.iter().any(|range| match_ip_range(range, ip)));
            let domain_matched = domain.is_some_and(|name| {
                rule.domain_names
                    .iter()
                    .any(|pattern| match_domain(pattern, name))
            });
            if !ip_matched && !domain_matched {
                continue;
            }

            if rule.action == EgressAction::Proxy {
                let selected_name = random_choice(&rule.proxy_names);
                if let Some(name) = selected_name {
                    if let Some(proxy) = self.proxies.iter().find(|proxy| proxy.name == *name) {
                        return EgressDecision {
                            action: EgressAction::Proxy,
                            proxy: Some(proxy.clone()),
                        };
                    }
                }
                // No usable proxy: fall back to DIRECT rather than dropping
                // the connection.
                return EgressDecision::direct();
            }

            return EgressDecision {
                action: rule.action,
                proxy: None,
            };
        }
        EgressDecision::direct()
    }
}

fn match_ip_range(range: &str, ip: IpAddr) -> bool {
    if range == "*" {
        return true;
    }
    match IpNet::from_str(range) {
        Ok(network) => network.contains(&ip),
        Err(_) => false,
    }
}

fn normalize_domain(name: &str) -> String {
    name.strip_suffix('.').unwrap_or(name).to_ascii_lowercase()
}

fn match_domain(pattern: &str, name: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    let pattern = normalize_domain(pattern);
    let name = normalize_domain(name);
    if pattern.is_empty() || name.is_empty() {
        return false;
    }
    name == pattern
        || (name.len() > pattern.len()
            && name.ends_with(&pattern)
            && name.as_bytes()[name.len() - pattern.len() - 1] == b'.')
}

fn random_choice(items: &[String]) -> Option<&String> {
    if items.is_empty() {
        return None;
    }
    let index = rand::random_range(0..items.len());
    items.get(index)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(value: [u8; 4]) -> IpAddr {
        IpAddr::V4(Ipv4Addr::from(value))
    }

    #[test]
    fn ip_ranges_and_wildcards() {
        let config = EgressConfig::new().with_rule(EgressRule::new(
            ["10.0.0.0/8", "2001:db8::/32"],
            Vec::<&str>::new(),
            EgressAction::Reject,
            Vec::<&str>::new(),
        ));
        assert_eq!(
            config.find_action(Some(ip([10, 1, 2, 3])), None).action,
            EgressAction::Reject
        );
        assert_eq!(
            config
                .find_action(Some("2001:db8::5".parse().unwrap()), None)
                .action,
            EgressAction::Reject
        );
        assert_eq!(
            config.find_action(Some(ip([11, 1, 2, 3])), None).action,
            EgressAction::Direct
        );

        let wildcard = EgressConfig::new().with_rule(EgressRule::new(
            ["*"],
            Vec::<&str>::new(),
            EgressAction::Reject,
            Vec::<&str>::new(),
        ));
        assert_eq!(
            wildcard.find_action(Some(ip([8, 8, 8, 8])), None).action,
            EgressAction::Reject
        );
    }

    #[test]
    fn domain_matching_normalizes_and_matches_subdomains() {
        let config = EgressConfig::new().with_rule(EgressRule::new(
            Vec::<&str>::new(),
            ["blocked.com"],
            EgressAction::Reject,
            Vec::<&str>::new(),
        ));
        for name in [
            "blocked.com",
            "BLOCKED.COM.",
            "www.blocked.com",
            "a.b.blocked.com",
        ] {
            assert_eq!(
                config.find_action(None, Some(name)).action,
                EgressAction::Reject,
                "{name} should match"
            );
        }
        for name in ["notblocked.com", "blocked.com.evil.test"] {
            assert_eq!(
                config.find_action(None, Some(name)).action,
                EgressAction::Direct,
                "{name} should not match"
            );
        }

        let wildcard = EgressConfig::new().with_rule(EgressRule::new(
            Vec::<&str>::new(),
            ["*"],
            EgressAction::Reject,
            Vec::<&str>::new(),
        ));
        assert_eq!(
            wildcard.find_action(None, Some("anything.test")).action,
            EgressAction::Reject
        );
    }

    #[test]
    fn proxy_selection_and_default() {
        let config = EgressConfig::new()
            .with_rule(EgressRule::new(
                ["192.0.2.0/24"],
                Vec::<&str>::new(),
                EgressAction::Proxy,
                ["one", "two"],
            ))
            .with_proxy(EgressProxy::new("one", "10.0.0.1", 1080))
            .with_proxy(EgressProxy::new("two", "10.0.0.2", 1080));

        let decision = config.find_action(Some(ip([192, 0, 2, 5])), None);
        assert_eq!(decision.action, EgressAction::Proxy);
        assert!(matches!(
            decision.proxy.as_ref().map(|proxy| proxy.name.as_str()),
            Some("one") | Some("two")
        ));

        assert_eq!(
            EgressConfig::new().find_action(Some(ip([8, 8, 8, 8])), None),
            EgressDecision::direct()
        );
    }

    #[test]
    fn first_matching_rule_wins() {
        let config = EgressConfig::new()
            .with_rule(EgressRule::new(
                ["*"],
                Vec::<&str>::new(),
                EgressAction::Reject,
                Vec::<&str>::new(),
            ))
            .with_rule(EgressRule::new(
                Vec::<&str>::new(),
                ["*"],
                EgressAction::Proxy,
                Vec::<&str>::new(),
            ));
        assert_eq!(
            config
                .find_action(Some(ip([8, 8, 8, 8])), Some("example.com"))
                .action,
            EgressAction::Reject
        );
    }
}
