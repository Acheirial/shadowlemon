use std::{net::SocketAddr, time::Duration};

use rand::Rng;
use shadowlemon_test_utils::{
    args::{fatal, Args},
    socks5,
};
use tokio::{
    net::{TcpStream, UdpSocket},
    time::timeout,
};

#[tokio::main]
async fn main() {
    let args = Args::parse(&[]);
    let dst_host = args.string("dst_host", "");
    let dst_port = args.int("dst_port", 0);
    let proxy_host = args.string("local_proxy_host", "");
    let proxy_port = args.int("local_proxy_port", 0);
    let interval_ms = args.int("interval_ms", 0);
    let num_request = args.int("num_request", 1);
    let num_conn = args.int("num_conn", 1);
    let max_payload = args.int("max_payload", 1400);

    if dst_host.is_empty() || dst_port == 0 {
        fatal("destination host or port is not set");
    }
    if proxy_host.is_empty() || proxy_port == 0 {
        fatal("local socks proxy host or port is not set");
    }
    if interval_ms < 0 {
        fatal("interval can't be a negative number");
    }
    if num_request <= 0 {
        fatal("number of requests must be bigger than 0");
    }
    if num_conn <= 0 {
        fatal("number of connections must be bigger than 0");
    }
    if max_payload <= 0 {
        fatal("max UDP payload size must be bigger than 0");
    }
    if !(1..=65535).contains(&dst_port) || !(1..=65535).contains(&proxy_port) {
        fatal("port is out of range");
    }

    let interval = Duration::from_millis(interval_ms as u64);
    let mut total_requests = 0usize;
    for index in 0..num_conn {
        if let Err(error) = association(
            &proxy_host,
            proxy_port as u16,
            &dst_host,
            dst_port as u16,
            num_request as usize,
            max_payload as usize,
            interval,
        )
        .await
        {
            eprintln!("socksudpclient association {index} failed: {error}");
            std::process::exit(1);
        }
        total_requests += num_request as usize;
        println!("Sent {total_requests} UDP requests to proxy address {dst_host}:{dst_port}");
    }
}

async fn association(
    proxy_host: &str,
    proxy_port: u16,
    dst_host: &str,
    dst_port: u16,
    num_request: usize,
    max_payload: usize,
    interval: Duration,
) -> Result<(), String> {
    let mut control = timeout(
        Duration::from_secs(10),
        TcpStream::connect((proxy_host, proxy_port)),
    )
    .await
    .map_err(|_| "connect to socks5 proxy timed out".to_owned())?
    .map_err(|error| format!("connect to socks5 proxy failed: {error}"))?;

    let reply = timeout(
        Duration::from_secs(10),
        socks5::request(&mut control, socks5::CMD_UDP_ASSOCIATE, dst_host, dst_port),
    )
    .await
    .map_err(|_| "socks5 UDP ASSOCIATE timed out".to_owned())??;

    let proxy_ip = control
        .peer_addr()
        .map_err(|error| format!("failed to determine proxy address: {error}"))?
        .ip();
    let relay = SocketAddr::new(reply.addr.ip_or(proxy_ip), reply.port);
    let udp = UdpSocket::bind("127.0.0.1:0")
        .await
        .map_err(|error| format!("failed to bind local UDP socket: {error}"))?;

    for sequence in 0..num_request {
        let size = rand::random_range(1..=max_payload);
        let mut payload = vec![0u8; size];
        rand::rng().fill_bytes(&mut payload);

        let mut packet = socks5::udp_header(dst_host, dst_port)?;
        packet.extend_from_slice(&payload);
        udp.send_to(&packet, relay)
            .await
            .map_err(|error| format!("failed to send UDP datagram: {error}"))?;

        let mut buffer = vec![0u8; 65536];
        let echoed = loop {
            let (length, from) = timeout(Duration::from_secs(1), udp.recv_from(&mut buffer))
                .await
                .map_err(|_| format!("timed out waiting for UDP echo {sequence}"))?
                .map_err(|error| format!("failed to read UDP datagram: {error}"))?;
            // The SOCKS5 relay often answers from a wildcard bind address, so
            // the reply endpoint is compared by port (as the Go helper did).
            if from.port() != relay.port() {
                continue;
            }
            break socks5::udp_payload(&buffer[..length])?.to_vec();
        };
        if echoed != payload {
            return Err(format!(
                "unexpected echo for request {sequence}: sent {} bytes, received {} bytes",
                payload.len(),
                echoed.len()
            ));
        }
        tokio::time::sleep(interval).await;
    }
    Ok(())
}
