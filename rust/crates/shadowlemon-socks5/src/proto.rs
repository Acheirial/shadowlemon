//! SOCKS5 wire format: constants, requests, replies and UDP framing.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use tokio::io::{AsyncRead, AsyncReadExt};

use crate::{Error, Result};

pub const VERSION: u8 = 5;

pub const CMD_CONNECT: u8 = 0x01;
pub const CMD_BIND: u8 = 0x02;
pub const CMD_UDP_ASSOCIATE: u8 = 0x03;

pub const ATYP_IPV4: u8 = 0x01;
pub const ATYP_DOMAIN: u8 = 0x03;
pub const ATYP_IPV6: u8 = 0x04;

pub const METHOD_NO_AUTH: u8 = 0x00;
pub const METHOD_USERPASS: u8 = 0x02;
pub const METHOD_NO_ACCEPTABLE: u8 = 0xff;
pub const USERPASS_VERSION: u8 = 0x01;
pub const AUTH_SUCCESS: u8 = 0x00;
pub const AUTH_FAILURE: u8 = 0x01;

pub const REP_SUCCESS: u8 = 0x00;
pub const REP_NOT_ALLOWED: u8 = 0x02;
pub const REP_NETWORK_UNREACHABLE: u8 = 0x03;
pub const REP_HOST_UNREACHABLE: u8 = 0x04;
pub const REP_CONNECTION_REFUSED: u8 = 0x05;
pub const REP_COMMAND_NOT_SUPPORTED: u8 = 0x07;
pub const REP_ADDR_TYPE_NOT_SUPPORTED: u8 = 0x08;

/// Maximum size of a UDP datagram relayed by an association (RFC 1928 uses a
/// 16-bit length field, so 64 KiB is the largest possible payload).
pub const MAX_UDP_DATAGRAM: usize = 65_536;

/// A SOCKS5 address: either a literal IP or a domain name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Address {
    /// An IPv4 or IPv6 literal address.
    Ip(IpAddr),
    /// A fully qualified domain name (not NUL terminated on the wire).
    Domain(String),
}

impl Address {
    /// Returns the domain name, if this is a domain address.
    pub fn host(&self) -> Option<&str> {
        match self {
            Address::Domain(host) => Some(host),
            Address::Ip(_) => None,
        }
    }

    /// Returns the literal IP address, if this is an IP address.
    pub fn ip(&self) -> Option<IpAddr> {
        match self {
            Address::Ip(ip) => Some(*ip),
            Address::Domain(_) => None,
        }
    }
}

impl From<IpAddr> for Address {
    fn from(ip: IpAddr) -> Self {
        Address::Ip(ip)
    }
}

impl From<SocketAddr> for Address {
    fn from(addr: SocketAddr) -> Self {
        Address::Ip(addr.ip())
    }
}

/// A decoded SOCKS5 connection request (`CONNECT`, `BIND`, `UDP ASSOCIATE`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    /// Command byte, see `CMD_*` constants.
    pub command: u8,
    /// Destination address.
    pub address: Address,
    /// Destination port.
    pub port: u16,
}

impl Request {
    /// Creates a request.
    pub fn new(command: u8, address: Address, port: u16) -> Self {
        Self {
            command,
            address,
            port,
        }
    }

    /// Returns the destination as a socket address when it is a literal IP.
    pub fn socket_addr(&self) -> Option<SocketAddr> {
        self.address.ip().map(|ip| SocketAddr::new(ip, self.port))
    }
}

/// A decoded SOCKS5 UDP request/response datagram header plus payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UdpDatagram {
    /// The complete on-wire header (RSV, FRAG, ATYP, address, port). It is kept
    /// verbatim so a response can reuse exactly the address type the client
    /// sent, which is what a SOCKS5 client expects to see.
    pub header: Vec<u8>,
    /// Destination (request) or source (response) address.
    pub address: Address,
    /// Destination (request) or source (response) port.
    pub port: u16,
    /// Datagram payload after the header.
    pub payload: Vec<u8>,
}

/// Encodes an address in the SOCKS5 `DST.ADDR` / `BND.ADDR` format.
pub fn encode_address(address: &Address, out: &mut Vec<u8>) {
    match address {
        Address::Ip(IpAddr::V4(ip)) => {
            out.push(ATYP_IPV4);
            out.extend_from_slice(&ip.octets());
        }
        Address::Ip(IpAddr::V6(ip)) => {
            out.push(ATYP_IPV6);
            out.extend_from_slice(&ip.octets());
        }
        Address::Domain(host) => {
            out.push(ATYP_DOMAIN);
            let len = host.len().min(255);
            out.push(len as u8);
            out.extend_from_slice(&host.as_bytes()[..len]);
        }
    }
}

/// Encodes a complete SOCKS5 connection request.
pub fn encode_request(command: u8, address: &Address, port: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(16);
    out.extend_from_slice(&[VERSION, command, 0x00]);
    encode_address(address, &mut out);
    out.extend_from_slice(&port.to_be_bytes());
    out
}

/// Encodes a SOCKS5 reply with a bound address.
pub fn encode_reply(reply: u8, bind_address: &Address, bind_port: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(16);
    out.extend_from_slice(&[VERSION, reply, 0x00]);
    encode_address(bind_address, &mut out);
    out.extend_from_slice(&bind_port.to_be_bytes());
    out
}

/// Encodes a reply carrying the unspecified bind address `0.0.0.0:0`.
pub fn encode_error_reply(reply: u8) -> Vec<u8> {
    encode_reply(reply, &Address::Ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED)), 0)
}

/// Reads a connection request directly from an async reader.
///
/// The reader is expected to be buffered (for example a `tokio::io::BufStream`):
/// any application bytes that follow the request stay in the buffer and are
/// preserved for the relaying phase, which is what makes the "no-wait" style
/// handshake safe. The function also returns the exact wire bytes of the
/// request, which are needed when forwarding to an egress SOCKS5 proxy.
pub async fn read_request<R: AsyncRead + Unpin>(reader: &mut R) -> Result<(Request, Vec<u8>)> {
    let mut raw = Vec::with_capacity(16);
    let mut head = [0u8; 4];
    reader.read_exact(&mut head).await?;
    raw.extend_from_slice(&head);

    if head[0] != VERSION {
        return Err(Error::UnsupportedVersion(head[0]));
    }
    let command = head[1];
    // head[2] is RESV and is ignored, matching the reference implementation.

    let address = match head[3] {
        ATYP_IPV4 => {
            let mut octets = [0u8; 4];
            reader.read_exact(&mut octets).await?;
            raw.extend_from_slice(&octets);
            Address::Ip(IpAddr::V4(Ipv4Addr::from(octets)))
        }
        ATYP_IPV6 => {
            let mut octets = [0u8; 16];
            reader.read_exact(&mut octets).await?;
            raw.extend_from_slice(&octets);
            Address::Ip(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            reader.read_exact(&mut len).await?;
            raw.extend_from_slice(&len);
            let mut bytes = vec![0u8; len[0] as usize];
            reader.read_exact(&mut bytes).await?;
            raw.extend_from_slice(&bytes);
            let host = String::from_utf8(bytes)
                .map_err(|_| Error::Resolution("destination name is not UTF-8".to_owned()))?;
            Address::Domain(host)
        }
        atyp => return Err(Error::UnsupportedAddressType(atyp)),
    };

    let mut port = [0u8; 2];
    reader.read_exact(&mut port).await?;
    raw.extend_from_slice(&port);

    Ok((
        Request {
            command,
            address,
            port: u16::from_be_bytes(port),
        },
        raw,
    ))
}

/// Reads a SOCKS5 reply, returning its raw bytes. Used by the egress-proxy
/// forwarding path where the downstream proxy's reply must be consumed.
pub async fn read_reply<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Vec<u8>> {
    let mut head = [0u8; 4];
    reader.read_exact(&mut head).await?;
    let mut raw = head.to_vec();
    if head[0] != VERSION {
        return Err(Error::UnsupportedVersion(head[0]));
    }
    match head[3] {
        ATYP_IPV4 => {
            let mut octets = [0u8; 4];
            reader.read_exact(&mut octets).await?;
            raw.extend_from_slice(&octets);
        }
        ATYP_IPV6 => {
            let mut octets = [0u8; 16];
            reader.read_exact(&mut octets).await?;
            raw.extend_from_slice(&octets);
        }
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            reader.read_exact(&mut len).await?;
            raw.extend_from_slice(&len);
            let mut bytes = vec![0u8; len[0] as usize];
            reader.read_exact(&mut bytes).await?;
            raw.extend_from_slice(&bytes);
        }
        atyp => return Err(Error::UnsupportedAddressType(atyp)),
    }
    let mut port = [0u8; 2];
    reader.read_exact(&mut port).await?;
    raw.extend_from_slice(&port);
    Ok(raw)
}

/// Parses a SOCKS5 UDP request/response datagram from a single datagram buffer.
///
/// RSV must be zero and FRAG must be zero; fragmented datagrams are rejected.
pub fn parse_udp_datagram(packet: &[u8]) -> Result<UdpDatagram> {
    if packet.len() < 4 {
        return Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "SOCKS5 UDP datagram is shorter than its header",
        )));
    }
    if packet[0] != 0 || packet[1] != 0 {
        return Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "SOCKS5 UDP RSV field is non-zero",
        )));
    }
    if packet[2] != 0 {
        return Err(Error::FragmentedDatagram);
    }

    let mut pos = 3usize;
    let address = match packet[pos] {
        ATYP_IPV4 => {
            pos += 1;
            let octets: [u8; 4] = packet
                .get(pos..pos + 4)
                .ok_or_else(|| io_eof("truncated IPv4 UDP address"))?
                .try_into()
                .expect("slice length checked");
            pos += 4;
            Address::Ip(IpAddr::V4(Ipv4Addr::from(octets)))
        }
        ATYP_IPV6 => {
            pos += 1;
            let octets: [u8; 16] = packet
                .get(pos..pos + 16)
                .ok_or_else(|| io_eof("truncated IPv6 UDP address"))?
                .try_into()
                .expect("slice length checked");
            pos += 16;
            Address::Ip(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        ATYP_DOMAIN => {
            pos += 1;
            let len = *packet
                .get(pos)
                .ok_or_else(|| io_eof("missing domain length"))? as usize;
            pos += 1;
            let bytes = packet
                .get(pos..pos + len)
                .ok_or_else(|| io_eof("truncated domain name"))?;
            pos += len;
            let host = std::str::from_utf8(bytes)
                .map_err(|_| Error::Resolution("UDP destination name is not UTF-8".to_owned()))?;
            Address::Domain(host.to_owned())
        }
        atyp => return Err(Error::UnsupportedAddressType(atyp)),
    };

    let port_bytes: [u8; 2] = packet
        .get(pos..pos + 2)
        .ok_or_else(|| io_eof("missing UDP port"))?
        .try_into()
        .expect("slice length checked");
    pos += 2;

    Ok(UdpDatagram {
        header: packet[..pos].to_vec(),
        address,
        port: u16::from_be_bytes(port_bytes),
        payload: packet[pos..].to_vec(),
    })
}

/// Builds a SOCKS5 UDP datagram from a verbatim header and a payload.
pub fn encode_udp_datagram(header: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(header.len() + payload.len());
    out.extend_from_slice(header);
    out.extend_from_slice(payload);
    out
}

/// Builds a fresh SOCKS5 UDP header for the given address and port.
pub fn encode_udp_header(address: &Address, port: u16) -> Vec<u8> {
    let mut out = vec![0u8, 0, 0];
    encode_address(address, &mut out);
    out.extend_from_slice(&port.to_be_bytes());
    out
}

fn io_eof(message: &'static str) -> Error {
    Error::Io(std::io::Error::new(
        std::io::ErrorKind::UnexpectedEof,
        message,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn parses_and_encodes_requests() {
        for (address, atyp) in [
            (
                Address::Ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
                ATYP_IPV4,
            ),
            (
                Address::Ip(IpAddr::V6("2001:db8::1".parse().unwrap())),
                ATYP_IPV6,
            ),
            (Address::Domain("example.com".into()), ATYP_DOMAIN),
        ] {
            let raw = encode_request(CMD_CONNECT, &address, 443);
            assert_eq!(raw[3], atyp);
            let mut cursor = &raw[..];
            // Decode synchronously by reading the same fields as read_request.
            assert_eq!(cursor[0], VERSION);
            assert_eq!(cursor[1], CMD_CONNECT);
            cursor = &cursor[4..];
            let decoded_address = match atyp {
                ATYP_IPV4 => Address::Ip(IpAddr::V4(Ipv4Addr::new(
                    cursor[0], cursor[1], cursor[2], cursor[3],
                ))),
                ATYP_IPV6 => {
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(&cursor[0..16]);
                    Address::Ip(IpAddr::V6(Ipv6Addr::from(octets)))
                }
                _ => {
                    let len = cursor[0] as usize;
                    Address::Domain(String::from_utf8(cursor[1..1 + len].to_vec()).unwrap())
                }
            };
            assert_eq!(decoded_address, address);
        }
    }

    #[test]
    fn udp_datagram_framing_and_frag_rejection() {
        let header = encode_udp_header(&Address::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)), 53);
        let packet = encode_udp_datagram(&header, b"hello");
        let parsed = parse_udp_datagram(&packet).unwrap();
        assert_eq!(parsed.address, Address::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert_eq!(parsed.port, 53);
        assert_eq!(parsed.payload, b"hello");
        assert_eq!(parsed.header, header);
        assert_eq!(encode_udp_datagram(&parsed.header, &parsed.payload), packet);

        let mut bad = packet.clone();
        bad[2] = 1;
        assert!(matches!(
            parse_udp_datagram(&bad),
            Err(Error::FragmentedDatagram)
        ));

        let mut bad_rsv = packet;
        bad_rsv[0] = 1;
        assert!(parse_udp_datagram(&bad_rsv).is_err());
    }
}
