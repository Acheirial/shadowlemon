use std::{net::SocketAddr, sync::Arc};

use rand::Rng;
use shadowlemon_test_utils::{args::Args, http};
use tokio::{
    io::{AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
};

const SMALL_DATA_SIZE: usize = 64 * 1024;
const LARGE_DATA_SIZE: usize = 1024 * 1024;
const HUGE_DATA_SIZE: usize = 64 * 1024 * 1024;
const SMALL_UPPER_RANGE: usize = 90;

struct State {
    blocks: Vec<Vec<u8>>,
    checksums: Vec<String>,
}

fn fill_data(huge: bool) -> State {
    let sizes: Vec<usize> = if huge {
        vec![HUGE_DATA_SIZE]
    } else {
        (0..100)
            .map(|i| {
                if i < SMALL_UPPER_RANGE {
                    SMALL_DATA_SIZE
                } else {
                    LARGE_DATA_SIZE
                }
            })
            .collect()
    };
    let mut blocks = Vec::with_capacity(sizes.len());
    for size in sizes {
        let mut block = vec![0u8; size];
        rand::rng().fill_bytes(&mut block);
        blocks.push(block);
    }
    let checksums = blocks.iter().map(|block| http::sha1_hex(block)).collect();
    State { blocks, checksums }
}

#[tokio::main]
async fn main() {
    let args = Args::parse(&["huge"]);
    let port = args.int("port", 8080);
    if !(1..=65535).contains(&port) {
        shadowlemon_test_utils::args::fatal(&format!("invalid HTTP listening port {port}"));
    }
    let state = Arc::new(fill_data(args.boolean("huge")));
    let address = SocketAddr::from(([0, 0, 0, 0], port as u16));
    let listener = match TcpListener::bind(address).await {
        Ok(listener) => listener,
        Err(error) => {
            shadowlemon_test_utils::args::fatal(&format!("failed to listen on {address}: {error}"))
        }
    };
    println!("HTTP server listening on {address}");
    loop {
        match listener.accept().await {
            Ok((socket, _)) => {
                let state = Arc::clone(&state);
                tokio::spawn(async move { serve(socket, state).await });
            }
            Err(error) => eprintln!("HTTP server accept failed: {error}"),
        }
    }
}

async fn serve(socket: TcpStream, state: Arc<State>) {
    let mut reader = BufReader::new(socket);
    loop {
        match http::read_request_head(&mut reader).await {
            Ok(true) => {}
            Ok(false) => return,
            Err(error) => {
                eprintln!("{error}");
                return;
            }
        }
        let partition = rand::random_range(0..state.blocks.len());
        let block = &state.blocks[partition];
        let header = format!(
            "HTTP/1.1 200 OK\r\nX-SHA1: {}\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
            state.checksums[partition],
            block.len()
        );
        let writer = reader.get_mut();
        if let Err(error) = writer.write_all(header.as_bytes()).await {
            eprintln!("HTTP server write header failed: {error}");
            return;
        }
        if let Err(error) = writer.write_all(block).await {
            eprintln!("HTTP server write body failed: {error}");
            return;
        }
        if let Err(error) = writer.flush().await {
            eprintln!("HTTP server flush failed: {error}");
            return;
        }
    }
}
