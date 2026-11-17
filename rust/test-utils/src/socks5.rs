//! Minimal SOCKS5 client framing (RFC 1928), used by the helper clients.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const VERSION: u8 = 0x05;
pub const CMD_CONNECT: u8 = 0x01;
pub const CMD_UDP_ASSOCIATE: u8 = 0x03;
pub const ATYP_IPV4: u8 = 0x01;
pub const ATYP_DOMAIN: u8 = 0x03;
pub const ATYP_IPV6: u8 = 0x04;
pub const REP_SUCCESS: u8 = 0x00;

#[derive(Debug, Clone)]
pub enum Addr {
    Ip(IpAddr),
    Domain(String),
}

impl Addr {
    /// The reply's bind address is often unspecified; callers then substitute
    /// the IP address of the proxy's TCP endpoint.
    pub fn ip_or(&self, fallback: IpAddr) -> IpAddr {
        match self {
            Addr::Ip(ip) if !ip.is_unspecified() => *ip,
            _ => fallback,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Reply {
    pub addr: Addr,
    pub port: u16,
}

/// Serialize `host:port` as a SOCKS5 address field (ATYP + address + port).
pub fn encode_address(host: &str, port: u16) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    if let Ok(ipv4) = host.parse::<Ipv4Addr>() {
        out.push(ATYP_IPV4);
        out.extend_from_slice(&ipv4.octets());
    } else if let Ok(ipv6) = host.parse::<Ipv6Addr>() {
        out.push(ATYP_IPV6);
        out.extend_from_slice(&ipv6.octets());
    } else {
        let domain = host.as_bytes();
        if domain.is_empty() || domain.len() > 255 {
            return Err(format!("invalid SOCKS5 destination host: {host:?}"));
        }
        out.push(ATYP_DOMAIN);
        out.push(domain.len() as u8);
        out.extend_from_slice(domain);
    }
    out.extend_from_slice(&port.to_be_bytes());
    Ok(out)
}

/// Build a SOCKS5 UDP request header (RSV=0, FRAG=0, ATYP, address, port).
pub fn udp_header(host: &str, port: u16) -> Result<Vec<u8>, String> {
    let mut header = vec![0u8, 0, 0];
    header.extend_from_slice(&encode_address(host, port)?);
    Ok(header)
}

/// Extract the payload of a SOCKS5 UDP datagram.
pub fn udp_payload(packet: &[u8]) -> Result<&[u8], String> {
    if packet.len() < 4 {
        return Err("SOCKS5 UDP datagram is too short".to_owned());
    }
    if packet[0] != 0 || packet[1] != 0 {
        return Err("invalid SOCKS5 UDP RSV field".to_owned());
    }
    if packet[2] != 0 {
        return Err("fragmented SOCKS5 UDP datagrams are not supported".to_owned());
    }
    let (_, _, offset) = decode_address(packet, 3)?;
    if offset > packet.len() {
        return Err("SOCKS5 UDP datagram is too short for its address".to_owned());
    }
    Ok(&packet[offset..])
}

/// Perform the no-auth greeting and a CONNECT / UDP ASSOCIATE request.
pub async fn request<S>(stream: &mut S, command: u8, host: &str, port: u16) -> Result<Reply, String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    stream
        .write_all(&[VERSION, 1, 0x00])
        .await
        .map_err(|error| format!("failed to write SOCKS5 greeting: {error}"))?;
    stream
        .flush()
        .await
        .map_err(|error| format!("failed to flush SOCKS5 greeting: {error}"))?;

    let mut method = [0u8; 2];
    stream
        .read_exact(&mut method)
        .await
        .map_err(|error| format!("failed to read SOCKS5 greeting response: {error}"))?;
    if method[0] != VERSION {
        return Err(format!(
            "unexpected SOCKS5 version in greeting: {}",
            method[0]
        ));
    }
    if method[1] != 0x00 {
        return Err(format!(
            "unsupported SOCKS5 authentication method: {}",
            method[1]
        ));
    }

    let mut req = vec![VERSION, command, 0x00];
    req.extend_from_slice(&encode_address(host, port)?);
    stream
        .write_all(&req)
        .await
        .map_err(|error| format!("failed to write SOCKS5 request: {error}"))?;
    stream
        .flush()
        .await
        .map_err(|error| format!("failed to flush SOCKS5 request: {error}"))?;

    let mut header = [0u8; 4];
    stream
        .read_exact(&mut header)
        .await
        .map_err(|error| format!("failed to read SOCKS5 response: {error}"))?;
    if header[0] != VERSION {
        return Err(format!(
            "unexpected SOCKS5 version in response: {}",
            header[0]
        ));
    }
    if header[1] != REP_SUCCESS {
        return Err(format!(
            "SOCKS5 request failed with reply code {}",
            header[1]
        ));
    }
    read_reply_address(stream, header[3]).await
}

async fn read_reply_address<S>(stream: &mut S, atyp: u8) -> Result<Reply, String>
where
    S: AsyncRead + Unpin,
{
    let addr = match atyp {
        ATYP_IPV4 => {
            let mut bytes = [0u8; 4];
            stream
                .read_exact(&mut bytes)
                .await
                .map_err(|error| format!("failed to read SOCKS5 bind address: {error}"))?;
            Addr::Ip(IpAddr::V4(Ipv4Addr::from(bytes)))
        }
        ATYP_IPV6 => {
            let mut bytes = [0u8; 16];
            stream
                .read_exact(&mut bytes)
                .await
                .map_err(|error| format!("failed to read SOCKS5 bind address: {error}"))?;
            Addr::Ip(IpAddr::V6(Ipv6Addr::from(bytes)))
        }
        ATYP_DOMAIN => {
            let mut length = [0u8; 1];
            stream
                .read_exact(&mut length)
                .await
                .map_err(|error| format!("failed to read SOCKS5 bind address length: {error}"))?;
            let mut bytes = vec![0u8; length[0] as usize];
            stream
                .read_exact(&mut bytes)
                .await
                .map_err(|error| format!("failed to read SOCKS5 bind address: {error}"))?;
            Addr::Domain(String::from_utf8_lossy(&bytes).into_owned())
        }
        other => return Err(format!("unsupported SOCKS5 address type: {other}")),
    };
    let mut port = [0u8; 2];
    stream
        .read_exact(&mut port)
        .await
        .map_err(|error| format!("failed to read SOCKS5 bind port: {error}"))?;
    Ok(Reply {
        addr,
        port: u16::from_be_bytes(port),
    })
}

/// Decode an address field from a byte slice. Returns the address, port and
/// the offset just past the port field.
fn decode_address(data: &[u8], start: usize) -> Result<(Addr, u16, usize), String> {
    let atyp = *data
        .get(start)
        .ok_or_else(|| "SOCKS5 datagram has no address type".to_owned())?;
    match atyp {
        ATYP_IPV4 => {
            let bytes: [u8; 4] = data
                .get(start + 1..start + 5)
                .ok_or_else(|| "SOCKS5 datagram has a short IPv4 address".to_owned())?
                .try_into()
                .map_err(|_| "SOCKS5 datagram has a short IPv4 address".to_owned())?;
            let port = read_port(data, start + 5)?;
            Ok((Addr::Ip(IpAddr::V4(Ipv4Addr::from(bytes))), port, start + 7))
        }
        ATYP_IPV6 => {
            let bytes: [u8; 16] = data
                .get(start + 1..start + 17)
                .ok_or_else(|| "SOCKS5 datagram has a short IPv6 address".to_owned())?
                .try_into()
                .map_err(|_| "SOCKS5 datagram has a short IPv6 address".to_owned())?;
            let port = read_port(data, start + 17)?;
            Ok((
                Addr::Ip(IpAddr::V6(Ipv6Addr::from(bytes))),
                port,
                start + 19,
            ))
        }
        ATYP_DOMAIN => {
            let length = *data
                .get(start + 1)
                .ok_or_else(|| "SOCKS5 datagram has a short domain name".to_owned())?
                as usize;
            let name = data
                .get(start + 2..start + 2 + length)
                .ok_or_else(|| "SOCKS5 datagram has a short domain name".to_owned())?;
            let port = read_port(data, start + 2 + length)?;
            Ok((
                Addr::Domain(String::from_utf8_lossy(name).into_owned()),
                port,
                start + 4 + length,
            ))
        }
        other => Err(format!("unsupported SOCKS5 address type: {other}")),
    }
}

fn read_port(data: &[u8], offset: usize) -> Result<u16, String> {
    let bytes = data
        .get(offset..offset + 2)
        .ok_or_else(|| "SOCKS5 datagram has no port".to_owned())?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}
