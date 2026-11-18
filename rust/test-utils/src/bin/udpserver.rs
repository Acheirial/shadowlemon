use shadowlemon_test_utils::args::Args;
use tokio::net::UdpSocket;

#[tokio::main]
async fn main() {
    let args = Args::parse(&[]);
    let port = args.int("port", 0);
    if !(1..=65535).contains(&port) {
        shadowlemon_test_utils::args::fatal(&format!("invalid UDP listening port {port}"));
    }
    let address = format!("0.0.0.0:{port}");
    let socket = match UdpSocket::bind(&address).await {
        Ok(socket) => socket,
        Err(error) => {
            shadowlemon_test_utils::args::fatal(&format!("failed to bind {address}: {error}"));
        }
    };
    println!("UDP server listening on {address}");
    let mut buffer = vec![0u8; 65536];
    loop {
        let (length, peer) = match socket.recv_from(&mut buffer).await {
            Ok(result) => result,
            Err(error) => {
                eprintln!("UDP server read failed: {error}");
                std::process::exit(1);
            }
        };
        if length == 0 {
            continue;
        }
        if let Err(error) = socket.send_to(&buffer[..length], peer).await {
            eprintln!("UDP server write failed: {error}");
            std::process::exit(1);
        }
    }
}
