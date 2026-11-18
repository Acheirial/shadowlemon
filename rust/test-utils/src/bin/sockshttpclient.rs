use std::time::{Duration, Instant};

use shadowlemon_test_utils::{
    args::{fatal, Args},
    http, socks5,
};
use tokio::{
    io::{AsyncWriteExt, BufReader},
    net::TcpStream,
    time::timeout,
};

const SOCKS5_PROXY_MODE: &str = "socks5";
const NO_PROXY_MODE: &str = "no";
const NEW_CONN_TEST: &str = "new_conn";
const REUSE_CONN_TEST: &str = "reuse_conn";

struct Config {
    proxy_mode: String,
    dst_host: String,
    dst_port: u16,
    proxy_host: String,
    proxy_port: u16,
    test_case: String,
    interval: Duration,
    num_request: usize,
    print_speed: usize,
    test_time: Duration,
}

impl Config {
    fn from_args() -> Self {
        let args = Args::parse(&[]);
        let proxy_mode = args.string("proxy_mode", SOCKS5_PROXY_MODE);
        let dst_host = args.string("dst_host", "");
        let dst_port = args.int("dst_port", 0);
        let proxy_host = args.string("local_proxy_host", "");
        let proxy_port = args.int("local_proxy_port", 0);
        let test_case = args.string("test_case", NEW_CONN_TEST);
        let interval_ms = args.int("interval_ms", 0);
        let num_request = args.int("num_request", 0);
        let print_speed = args.int("print_speed", 100);
        let test_time_sec = args.int("test_time_sec", 0);

        if dst_host.is_empty() || dst_port == 0 {
            fatal("HTTP server host or port is not set");
        }
        if proxy_mode != SOCKS5_PROXY_MODE && proxy_mode != NO_PROXY_MODE {
            fatal(&format!("proxy mode {proxy_mode:?} is invalid"));
        }
        if proxy_mode == SOCKS5_PROXY_MODE && (proxy_host.is_empty() || proxy_port == 0) {
            fatal("local socks proxy host or port is not set");
        }
        if test_case != NEW_CONN_TEST && test_case != REUSE_CONN_TEST {
            fatal(&format!("test case {test_case:?} is unknown"));
        }
        if interval_ms < 0 {
            fatal("interval can't be a negative number");
        }
        if num_request <= 0 && test_time_sec <= 0 {
            fatal("must specify either -num_request or -test_time_sec");
        }
        if num_request > 0 && test_time_sec > 0 {
            fatal("can't specify both -num_request and -test_time_sec");
        }
        if !(1..=65535).contains(&dst_port)
            || (proxy_mode == SOCKS5_PROXY_MODE && !(1..=65535).contains(&proxy_port))
        {
            fatal("port is out of range");
        }

        Self {
            proxy_mode,
            dst_host,
            dst_port: dst_port as u16,
            proxy_host,
            proxy_port: proxy_port as u16,
            test_case,
            interval: Duration::from_millis(interval_ms as u64),
            num_request: num_request as usize,
            print_speed: print_speed as usize,
            test_time: Duration::from_secs(test_time_sec.max(0) as u64),
        }
    }

    fn should_stop(&self, start: Instant, seq: usize) -> bool {
        if self.num_request > 0 {
            seq > self.num_request
        } else {
            Instant::now() >= start + self.test_time
        }
    }
}

#[tokio::main]
async fn main() {
    let config = Config::from_args();
    if let Err(error) = run(&config).await {
        eprintln!("sockshttpclient failed: {error}");
        std::process::exit(1);
    }
}

async fn run(config: &Config) -> Result<(), String> {
    let start = Instant::now();
    let mut seq = 1usize;
    let mut total_bytes = 0usize;

    if config.test_case == REUSE_CONN_TEST {
        let stream = dial_with_retry(config).await?;
        let mut reader = BufReader::new(stream);
        while !config.should_stop(start, seq) {
            total_bytes += request(&mut reader, config).await?;
            print_speed(config, seq, total_bytes, start);
            tokio::time::sleep(config.interval).await;
            seq += 1;
        }
    } else {
        while !config.should_stop(start, seq) {
            let stream = dial_with_retry(config).await?;
            let mut reader = BufReader::new(stream);
            total_bytes += request(&mut reader, config).await?;
            print_speed(config, seq, total_bytes, start);
            tokio::time::sleep(config.interval).await;
            seq += 1;
        }
    }
    Ok(())
}

async fn dial_with_retry(config: &Config) -> Result<TcpStream, String> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match dial(config).await {
            Ok(stream) => return Ok(stream),
            Err(error) => {
                if Instant::now() >= deadline {
                    return Err(format!("dial failed: {error}"));
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        }
    }
}

async fn dial(config: &Config) -> Result<TcpStream, String> {
    let connect = async {
        if config.proxy_mode == SOCKS5_PROXY_MODE {
            let proxy_host = if config.proxy_host == "localhost" {
                "127.0.0.1".to_owned()
            } else {
                config.proxy_host.clone()
            };
            let mut stream = TcpStream::connect((proxy_host.as_str(), config.proxy_port))
                .await
                .map_err(|error| format!("failed to connect to socks5 proxy: {error}"))?;
            socks5::request(
                &mut stream,
                socks5::CMD_CONNECT,
                &config.dst_host,
                config.dst_port,
            )
            .await?;
            Ok(stream)
        } else {
            TcpStream::connect((config.dst_host.as_str(), config.dst_port))
                .await
                .map_err(|error| format!("failed to connect to HTTP server: {error}"))
        }
    };
    timeout(Duration::from_secs(10), connect)
        .await
        .map_err(|_| "dial timed out".to_owned())?
}

async fn request(reader: &mut BufReader<TcpStream>, config: &Config) -> Result<usize, String> {
    let req = http::build_get(&config.dst_host, config.dst_port);
    reader
        .get_mut()
        .write_all(&req)
        .await
        .map_err(|error| format!("failed to write HTTP request: {error}"))?;
    reader
        .get_mut()
        .flush()
        .await
        .map_err(|error| format!("failed to flush HTTP request: {error}"))?;

    let response = http::read_response(reader).await?;
    if response.status != 200 {
        return Err(format!("server responded status {}", response.status));
    }
    let computed = http::sha1_hex(&response.body);
    if let Some(provided) = response.header("x-sha1") {
        if provided != computed {
            return Err(format!(
                "SHA-1 checksum not match: provided {provided}, computed {computed}"
            ));
        }
    }
    Ok(response.body.len())
}

fn print_speed(config: &Config, seq: usize, total_bytes: usize, start: Instant) {
    if config.print_speed == 0 || seq % config.print_speed != 0 {
        return;
    }
    let seconds = start.elapsed().as_secs().max(1);
    println!(
        "Round {seq}: network speed is {} KB/s",
        total_bytes / (1024 * seconds as usize)
    );
}
