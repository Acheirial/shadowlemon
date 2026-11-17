//! End-to-end tests using in-memory dialers and sockets. No external network.

use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use futures::future::BoxFuture;
use shadowlemon_socks5::{
    encode_udp_datagram, encode_udp_header, read_reply, Address, AsyncIo, Config, Credential,
    DatagramSocket, EgressAction, EgressConfig, EgressProxy, EgressRule, Error, ProxyDialer,
    Resolver, Server, CMD_CONNECT, CMD_UDP_ASSOCIATE, REP_NOT_ALLOWED, REP_SUCCESS, VERSION,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream},
    net::UdpSocket,
    sync::{mpsc, Mutex},
    time::timeout,
};

type TcpDial = (SocketAddr, Option<String>, DuplexStream);
type UdpDial = (
    SocketAddr,
    Option<String>,
    Arc<MockDatagram>,
    MockDatagramHandle,
);

struct MockDialer {
    tcp: mpsc::UnboundedSender<TcpDial>,
    udp: mpsc::UnboundedSender<UdpDial>,
}

impl ProxyDialer for MockDialer {
    fn dial_tcp<'a>(
        &'a self,
        addr: SocketAddr,
        host: Option<&'a str>,
    ) -> BoxFuture<'a, io::Result<Box<dyn AsyncIo>>> {
        let sender = self.tcp.clone();
        Box::pin(async move {
            let (client, server) = tokio::io::duplex(64 * 1024);
            sender
                .send((addr, host.map(str::to_owned), server))
                .map_err(|_| io::Error::other("mock dialer closed"))?;
            Ok(Box::new(client) as Box<dyn AsyncIo>)
        })
    }

    fn dial_udp<'a>(
        &'a self,
        addr: SocketAddr,
        host: Option<&'a str>,
    ) -> BoxFuture<'a, io::Result<Box<dyn DatagramSocket>>> {
        let sender = self.udp.clone();
        Box::pin(async move {
            let (socket, handle) = mock_datagram();
            sender
                .send((addr, host.map(str::to_owned), socket.clone(), handle))
                .map_err(|_| io::Error::other("mock dialer closed"))?;
            Ok(Box::new(SharedMockDatagram(socket)) as Box<dyn DatagramSocket>)
        })
    }
}

struct MockDatagram {
    sent: mpsc::UnboundedSender<(Vec<u8>, SocketAddr)>,
    inbound: Mutex<mpsc::UnboundedReceiver<(Vec<u8>, SocketAddr)>>,
}

struct SharedMockDatagram(Arc<MockDatagram>);

impl DatagramSocket for SharedMockDatagram {
    fn send_to<'a>(
        &'a self,
        data: &'a [u8],
        target: SocketAddr,
    ) -> BoxFuture<'a, io::Result<usize>> {
        self.0.send_to(data, target)
    }

    fn recv_from<'a>(
        &'a self,
        buf: &'a mut [u8],
    ) -> BoxFuture<'a, io::Result<(usize, SocketAddr)>> {
        self.0.recv_from(buf)
    }
}

struct MockDatagramHandle {
    sent: mpsc::UnboundedReceiver<(Vec<u8>, SocketAddr)>,
    inbound: mpsc::UnboundedSender<(Vec<u8>, SocketAddr)>,
}

fn mock_datagram() -> (Arc<MockDatagram>, MockDatagramHandle) {
    let (sent_tx, sent_rx) = mpsc::unbounded_channel();
    let (inbound_tx, inbound_rx) = mpsc::unbounded_channel();
    (
        Arc::new(MockDatagram {
            sent: sent_tx,
            inbound: Mutex::new(inbound_rx),
        }),
        MockDatagramHandle {
            sent: sent_rx,
            inbound: inbound_tx,
        },
    )
}

impl DatagramSocket for MockDatagram {
    fn send_to<'a>(
        &'a self,
        data: &'a [u8],
        target: SocketAddr,
    ) -> BoxFuture<'a, io::Result<usize>> {
        let length = data.len();
        let result = self.sent.send((data.to_vec(), target));
        Box::pin(async move {
            result.map_err(|_| io::Error::other("mock datagram closed"))?;
            Ok(length)
        })
    }

    fn recv_from<'a>(
        &'a self,
        buf: &'a mut [u8],
    ) -> BoxFuture<'a, io::Result<(usize, SocketAddr)>> {
        Box::pin(async move {
            let (data, source) = self
                .inbound
                .lock()
                .await
                .recv()
                .await
                .ok_or_else(|| io::Error::other("mock datagram closed"))?;
            let length = data.len().min(buf.len());
            buf[..length].copy_from_slice(&data[..length]);
            Ok((length, source))
        })
    }
}

fn harness() -> (
    Server,
    mpsc::UnboundedReceiver<TcpDial>,
    mpsc::UnboundedReceiver<UdpDial>,
) {
    let (tcp_tx, tcp_rx) = mpsc::unbounded_channel();
    let (udp_tx, udp_rx) = mpsc::unbounded_channel();
    let dialer = Arc::new(MockDialer {
        tcp: tcp_tx,
        udp: udp_tx,
    });
    (Server::new(Config::new(dialer)), tcp_rx, udp_rx)
}

async fn send_greeting<S: AsyncWrite + Unpin>(stream: &mut S, methods: &[u8]) {
    let mut greeting = vec![VERSION, methods.len() as u8];
    greeting.extend_from_slice(methods);
    stream.write_all(&greeting).await.unwrap();
}

async fn expect_method<S: AsyncRead + Unpin>(stream: &mut S) -> u8 {
    let mut response = [0u8; 2];
    stream.read_exact(&mut response).await.unwrap();
    assert_eq!(response[0], VERSION);
    response[1]
}

fn connect_request(address: &Address, port: u16) -> Vec<u8> {
    shadowlemon_socks5::encode_request(CMD_CONNECT, address, port)
}

#[derive(Debug)]
struct FixedResolver {
    address: IpAddr,
}

impl Resolver for FixedResolver {
    fn lookup_ip<'a>(&'a self, host: &'a str) -> BoxFuture<'a, io::Result<Vec<IpAddr>>> {
        let address = self.address;
        Box::pin(async move {
            if host == "example.com" {
                Ok(vec![address])
            } else {
                Err(io::Error::new(io::ErrorKind::NotFound, "unknown host"))
            }
        })
    }
}

#[tokio::test]
async fn connect_ipv4_relays_piggybacked_data() {
    let (server, mut dials, _) = harness();
    let (mut client, server_io) = tokio::io::duplex(64 * 1024);
    let task = tokio::spawn(async move { server.serve(server_io).await });

    send_greeting(&mut client, &[0]).await;
    assert_eq!(expect_method(&mut client).await, 0);

    let mut request = connect_request(&Address::Ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))), 443);
    // Application data arrives in the same write as the SOCKS request.
    request.extend_from_slice(b"PING");
    client.write_all(&request).await.unwrap();

    let (dial_addr, host, mut target) = dials.recv().await.unwrap();
    assert_eq!(dial_addr, "8.8.8.8:443".parse().unwrap());
    assert_eq!(host, None);

    let reply = read_reply(&mut client).await.unwrap();
    assert_eq!(reply[1], REP_SUCCESS);
    assert_eq!(&reply[2..10], &[0, 1, 0, 0, 0, 0, 0, 0]);

    let mut piggyback = [0u8; 4];
    target.read_exact(&mut piggyback).await.unwrap();
    assert_eq!(&piggyback, b"PING");
    target.write_all(b"PONG").await.unwrap();

    let mut response = [0u8; 4];
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"PONG");

    drop(target);
    client.shutdown().await.unwrap();
    assert!(task.await.unwrap().is_ok());
}

#[tokio::test]
async fn connect_ipv6() {
    let (server, mut dials, _) = harness();
    let (mut client, server_io) = tokio::io::duplex(64 * 1024);
    let task = tokio::spawn(async move { server.serve(server_io).await });

    send_greeting(&mut client, &[0]).await;
    assert_eq!(expect_method(&mut client).await, 0);
    client
        .write_all(&connect_request(
            &Address::Ip(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            80,
        ))
        .await
        .unwrap();

    let (dial_addr, _, _) = dials.recv().await.unwrap();
    assert_eq!(dial_addr, "[::1]:80".parse().unwrap());
    let reply = read_reply(&mut client).await.unwrap();
    assert_eq!(reply[3], 1); // IPv4 bound address
    client.shutdown().await.unwrap();
    assert!(task.await.unwrap().is_ok());
}

#[tokio::test]
async fn connect_domain_uses_injected_resolver() {
    let (tcp_tx, mut tcp_rx) = mpsc::unbounded_channel();
    let (udp_tx, _) = mpsc::unbounded_channel();
    let dialer = Arc::new(MockDialer {
        tcp: tcp_tx,
        udp: udp_tx,
    });
    let config = Config::new(dialer).with_resolver(Arc::new(FixedResolver {
        address: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
    }));
    let server = Server::new(config);

    let (mut client, server_io) = tokio::io::duplex(64 * 1024);
    let task = tokio::spawn(async move { server.serve(server_io).await });

    send_greeting(&mut client, &[0]).await;
    assert_eq!(expect_method(&mut client).await, 0);
    client
        .write_all(&connect_request(
            &Address::Domain("example.com".into()),
            8080,
        ))
        .await
        .unwrap();

    let (dial_addr, host, _) = tcp_rx.recv().await.unwrap();
    assert_eq!(dial_addr, "93.184.216.34:8080".parse().unwrap());
    assert_eq!(host.as_deref(), Some("example.com"));
    assert_eq!(read_reply(&mut client).await.unwrap()[1], REP_SUCCESS);

    client.shutdown().await.unwrap();
    assert!(task.await.unwrap().is_ok());
}

#[tokio::test]
async fn ingress_userpass_success_and_failure() {
    let credentials = vec![Credential::new("alice", "secret")];

    // Success.
    {
        let (tcp_tx, _) = mpsc::unbounded_channel();
        let (udp_tx, _) = mpsc::unbounded_channel();
        let server = Server::new(
            Config::new(Arc::new(MockDialer {
                tcp: tcp_tx,
                udp: udp_tx,
            }))
            .with_credentials(credentials.clone()),
        );
        let (mut client, server_io) = tokio::io::duplex(64 * 1024);
        let task = tokio::spawn(async move { server.serve(server_io).await });

        send_greeting(&mut client, &[2]).await;
        assert_eq!(expect_method(&mut client).await, 2);
        let mut auth = vec![1, 5];
        auth.extend_from_slice(b"alice");
        auth.push(6);
        auth.extend_from_slice(b"secret");
        client.write_all(&auth).await.unwrap();
        let mut reply = [0u8; 2];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [1, 0]);

        client.shutdown().await.unwrap();
        let _ = task.await.unwrap();
    }

    // Failure: wrong password.
    {
        let (tcp_tx, _) = mpsc::unbounded_channel();
        let (udp_tx, _) = mpsc::unbounded_channel();
        let server = Server::new(
            Config::new(Arc::new(MockDialer {
                tcp: tcp_tx,
                udp: udp_tx,
            }))
            .with_credentials(credentials),
        );
        let (mut client, server_io) = tokio::io::duplex(64 * 1024);
        let task = tokio::spawn(async move { server.serve(server_io).await });

        send_greeting(&mut client, &[0, 2]).await;
        assert_eq!(expect_method(&mut client).await, 2);
        let mut auth = vec![1, 5];
        auth.extend_from_slice(b"alice");
        auth.push(4);
        auth.extend_from_slice(b"wrong");
        client.write_all(&auth).await.unwrap();
        let mut reply = [0u8; 2];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [1, 1]);
        assert!(matches!(
            task.await.unwrap(),
            Err(Error::AuthenticationFailed)
        ));
    }
}

#[tokio::test]
async fn handshake_timeout() {
    let (tcp_tx, _) = mpsc::unbounded_channel();
    let (udp_tx, _) = mpsc::unbounded_channel();
    let server = Server::new(
        Config::new(Arc::new(MockDialer {
            tcp: tcp_tx,
            udp: udp_tx,
        }))
        .with_handshake_timeout(Duration::from_millis(40)),
    );
    let (mut client, server_io) = tokio::io::duplex(1024);
    let task = tokio::spawn(async move { server.serve(server_io).await });

    // Greeting claims one method but never sends it.
    client.write_all(&[VERSION, 1]).await.unwrap();
    let result = timeout(Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(result, Err(Error::HandshakeTimeout)));
}

#[tokio::test]
async fn egress_reject_sends_not_allowed_without_dialing() {
    let (tcp_tx, mut tcp_rx) = mpsc::unbounded_channel();
    let (udp_tx, _) = mpsc::unbounded_channel();
    let egress = EgressConfig::new().with_rule(EgressRule::new(
        ["10.0.0.0/8"],
        Vec::<&str>::new(),
        EgressAction::Reject,
        Vec::<&str>::new(),
    ));
    let server = Server::new(
        Config::new(Arc::new(MockDialer {
            tcp: tcp_tx,
            udp: udp_tx,
        }))
        .with_egress(egress),
    );
    let (mut client, server_io) = tokio::io::duplex(1024);
    let task = tokio::spawn(async move { server.serve(server_io).await });

    send_greeting(&mut client, &[0]).await;
    assert_eq!(expect_method(&mut client).await, 0);
    client
        .write_all(&connect_request(
            &Address::Ip(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))),
            80,
        ))
        .await
        .unwrap();

    let reply = read_reply(&mut client).await.unwrap();
    assert_eq!(reply[1], REP_NOT_ALLOWED);
    assert!(matches!(task.await.unwrap(), Err(Error::Rejected)));
    assert!(tcp_rx.try_recv().is_err(), "no dial should have happened");
}

#[tokio::test]
async fn proxy_egress_no_wait_suppresses_downstream_reply() {
    let (tcp_tx, mut tcp_rx) = mpsc::unbounded_channel();
    let (udp_tx, _) = mpsc::unbounded_channel();
    let egress = EgressConfig::new()
        .with_rule(EgressRule::new(
            ["*"],
            Vec::<&str>::new(),
            EgressAction::Proxy,
            ["egress"],
        ))
        .with_proxy(EgressProxy::new("egress", "127.0.0.1", 1080));
    let server = Server::new(
        Config::new(Arc::new(MockDialer {
            tcp: tcp_tx,
            udp: udp_tx,
        }))
        .with_egress(egress)
        .with_no_wait(true),
    );
    let (mut client, server_io) = tokio::io::duplex(64 * 1024);
    let task = tokio::spawn(async move { server.serve(server_io).await });

    send_greeting(&mut client, &[0]).await;
    assert_eq!(expect_method(&mut client).await, 0);
    client
        .write_all(&connect_request(
            &Address::Ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
            80,
        ))
        .await
        .unwrap();

    let (address, _, mut downstream) = tcp_rx.recv().await.unwrap();
    assert_eq!(address, "127.0.0.1:1080".parse().unwrap());

    // Act as the downstream SOCKS5 egress proxy.
    let mut greeting = [0u8; 3];
    downstream.read_exact(&mut greeting).await.unwrap();
    assert_eq!(greeting, [5, 1, 0]);
    downstream.write_all(&[5, 0]).await.unwrap();

    let mut forwarded = [0u8; 10];
    downstream.read_exact(&mut forwarded).await.unwrap();
    assert_eq!(&forwarded[..4], &[5, 1, 0, 1]);

    downstream
        .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();

    let reply = read_reply(&mut client).await.unwrap();
    assert_eq!(reply[1], REP_SUCCESS);

    client.write_all(b"DATA").await.unwrap();
    let mut data = [0u8; 4];
    downstream.read_exact(&mut data).await.unwrap();
    assert_eq!(&data, b"DATA");
    downstream.write_all(b"ACK!").await.unwrap();
    let mut ack = [0u8; 4];
    client.read_exact(&mut ack).await.unwrap();
    assert_eq!(&ack, b"ACK!");

    drop(downstream);
    client.shutdown().await.unwrap();
    assert!(task.await.unwrap().is_ok());
}

#[tokio::test]
async fn udp_associate_framing_response_and_frag_rejection() {
    let (server, _, mut udp_dials) = harness();
    let (mut control, server_io) = tokio::io::duplex(64 * 1024);
    let task = tokio::spawn(async move { server.serve(server_io).await });

    send_greeting(&mut control, &[0]).await;
    assert_eq!(expect_method(&mut control).await, 0);
    control
        .write_all(&shadowlemon_socks5::encode_request(
            CMD_UDP_ASSOCIATE,
            &Address::Ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            0,
        ))
        .await
        .unwrap();

    let reply = read_reply(&mut control).await.unwrap();
    assert_eq!(reply[1], REP_SUCCESS);
    assert_eq!(reply[3], 1);
    let bind_port = u16::from_be_bytes([reply[8], reply[9]]);
    assert_ne!(bind_port, 0);

    let (_dial_addr, _, _socket, handle) = udp_dials.recv().await.unwrap();
    let MockDatagramHandle {
        mut sent,
        inbound: injected,
    } = handle;

    let client_udp = UdpSocket::bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .await
        .unwrap();
    let relay_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, bind_port));

    // A fragmented datagram must be dropped, not forwarded.
    let header = encode_udp_header(&Address::Ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))), 53);
    let mut fragmented = header.clone();
    fragmented[2] = 1;
    fragmented.extend_from_slice(b"FRAG");
    client_udp.send_to(&fragmented, relay_addr).await.unwrap();
    let none = timeout(Duration::from_millis(120), sent.recv()).await;
    assert!(none.is_err(), "fragmented datagram must not be forwarded");

    // A valid datagram is forwarded with its payload intact.
    let valid = encode_udp_datagram(&header, b"QUERY");
    client_udp.send_to(&valid, relay_addr).await.unwrap();
    let (payload, target) = timeout(Duration::from_secs(2), sent.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(payload, b"QUERY");
    assert_eq!(target, "8.8.8.8:53".parse().unwrap());

    // Inject a response using exactly the address the client expects.
    injected.send((b"ANSWER".to_vec(), target)).unwrap();

    let mut response = [0u8; 128];
    let (length, _) = timeout(Duration::from_secs(2), client_udp.recv_from(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&response[..length], encode_udp_datagram(&header, b"ANSWER"));

    // Closing the TCP control channel ends the association.
    drop(control);
    let result = timeout(Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap();
    assert!(result.is_ok());
}
