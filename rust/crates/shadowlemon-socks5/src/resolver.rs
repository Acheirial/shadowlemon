//! Name resolution abstraction.

use std::{io, net::IpAddr};

use futures::future::BoxFuture;

use crate::{Address, Error, Result};

/// Resolves host names to IP addresses.
///
/// Implement this for tests or custom DNS; [`SystemResolver`] uses Tokio's
/// system resolver.
pub trait Resolver: Send + Sync + std::fmt::Debug {
    /// Looks up `host` and returns all discovered addresses.
    fn lookup_ip<'a>(&'a self, host: &'a str) -> BoxFuture<'a, io::Result<Vec<IpAddr>>>;
}

/// A [`Resolver`] backed by `tokio::net::lookup_host` (the system resolver).
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemResolver;

impl Resolver for SystemResolver {
    fn lookup_ip<'a>(&'a self, host: &'a str) -> BoxFuture<'a, io::Result<Vec<IpAddr>>> {
        Box::pin(async move {
            let resolved: Vec<IpAddr> = tokio::net::lookup_host((host, 0))
                .await?
                .map(|socket_addr| socket_addr.ip())
                .collect();
            if resolved.is_empty() {
                Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("no IP addresses for {host}"),
                ))
            } else {
                Ok(resolved)
            }
        })
    }
}

/// Resolves a SOCKS5 [`Address`] to a concrete IP address.
///
/// IP literals short-circuit without consulting the resolver. For domain
/// names, the original host string is returned alongside the selected IP so
/// callers can pass it to the dialer for name-based routing.
pub async fn resolve_target(
    address: &Address,
    resolver: &dyn Resolver,
) -> Result<(IpAddr, Option<String>)> {
    match address {
        Address::Ip(ip) => Ok((*ip, None)),
        Address::Domain(host) => {
            if let Ok(ip) = host.parse::<IpAddr>() {
                return Ok((ip, Some(host.clone())));
            }
            let addresses = resolver
                .lookup_ip(host)
                .await
                .map_err(|err| Error::Resolution(err.to_string()))?;
            let ip = *addresses
                .first()
                .ok_or_else(|| Error::Resolution(format!("no IP addresses for {host}")))?;
            Ok((ip, Some(host.clone())))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::HashMap, net::Ipv4Addr, sync::Mutex};

    #[derive(Debug, Default)]
    struct TestResolver {
        entries: Mutex<HashMap<String, Vec<IpAddr>>>,
    }

    impl TestResolver {
        fn insert(&self, host: &str, ips: &[IpAddr]) {
            self.entries
                .lock()
                .unwrap()
                .insert(host.to_owned(), ips.to_vec());
        }
    }

    impl Resolver for TestResolver {
        fn lookup_ip<'a>(&'a self, host: &'a str) -> BoxFuture<'a, io::Result<Vec<IpAddr>>> {
            Box::pin(async move {
                self.entries
                    .lock()
                    .unwrap()
                    .get(host)
                    .cloned()
                    .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "unknown host"))
            })
        }
    }

    #[tokio::test]
    async fn literals_short_circuit_and_domains_use_resolver() {
        let resolver = TestResolver::default();
        let ip = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
        resolver.insert("example.com", &[ip]);

        let literal = Address::Domain("127.0.0.1".into());
        assert_eq!(
            resolve_target(&literal, &resolver).await.unwrap(),
            (IpAddr::V4(Ipv4Addr::LOCALHOST), Some("127.0.0.1".into()))
        );

        let domain = Address::Domain("example.com".into());
        assert_eq!(
            resolve_target(&domain, &resolver).await.unwrap(),
            (ip, Some("example.com".into()))
        );

        let unknown = Address::Domain("missing.example".into());
        assert!(resolve_target(&unknown, &resolver).await.is_err());
    }
}
