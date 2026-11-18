//! Client and server application wiring for ShadowLemon V0.2.
//!
//! This crate owns the clap command tree, configuration discovery (including
//! the environment variables used by existing deployments), logging, daemon
//! lifecycle and the foreground runtimes that connect the SOCKS5 ingress to
//! the real cryptographic mux drivers in `shadowlemon_protocol::driver`.
//!
//! `platform` is the only module containing `unsafe`; it needs POSIX signal
//! registration and Android's `SCM_RIGHTS` call.

pub mod config;
pub mod platform;
pub mod runtime;

use std::{fs, path::PathBuf, sync::OnceLock};

use clap::{Args, Parser, Subcommand};
use shadowlemon_config::{
    apply_file_auto, describe_file_auto, export_full_url, export_simple_urls, import_url,
    replace_file_auto, write_auto, ClientConfig, ServerConfig,
};
use thiserror::Error;
use tracing::{Event, Subscriber};
use tracing_subscriber::{
    fmt::{format::FormatEvent, format::FormatFields, format::Writer, FmtContext},
    registry::LookupSpan,
};

use crate::{
    config::Mode, runtime::run_client as run_client_runtime,
    runtime::run_server as run_server_runtime,
};

/// Errors reported by the application layer.
#[derive(Debug, Error)]
pub enum AppError {
    /// Invalid or incomplete configuration.
    #[error("configuration error: {0}")]
    Config(String),
    /// The config crate rejected a file or operation.
    #[error("configuration error: {0}")]
    ConfigLib(#[from] shadowlemon_config::ConfigError),
    /// Operating-system error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// Daemon/pidfile failure.
    #[error("daemon error: {0}")]
    Daemon(String),
    /// URL import/export failure.
    #[error("share URL error: {0}")]
    Url(String),
}

static LOG_PREFIX: OnceLock<&'static str> = OnceLock::new();

/// Set the one-letter log prefix (`C` or `S`) chosen from `argv[1]`.
pub fn set_log_prefix(prefix: &'static str) {
    let _ = LOG_PREFIX.set(prefix);
}

fn log_prefix() -> &'static str {
    LOG_PREFIX.get().copied().unwrap_or("S")
}

struct PrefixedFormat<F> {
    inner: F,
    prefix: &'static str,
}

impl<S, N, F> FormatEvent<S, N> for PrefixedFormat<F>
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
    F: FormatEvent<S, N>,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> std::fmt::Result {
        write!(writer, "[{}] ", self.prefix)?;
        self.inner.format_event(ctx, writer, event)
    }
}

/// Initialise tracing. `SHADOWLEMON_LOG_NO_TIMESTAMP` disables timestamps.
pub fn init_logging(level: tracing::Level) {
    let event_format = PrefixedFormat {
        inner: tracing_subscriber::fmt::format()
            .with_ansi(false)
            .with_target(false),
        prefix: log_prefix(),
    };
    let result = if std::env::var_os("SHADOWLEMON_LOG_NO_TIMESTAMP").is_some() {
        tracing_subscriber::fmt()
            .with_max_level(level)
            .without_time()
            .event_format(event_format)
            .try_init()
    } else {
        tracing_subscriber::fmt()
            .with_max_level(level)
            .event_format(event_format)
            .try_init()
    };
    let _ = result;
}

/// Top-level command tree. The `client` / `server` subcommands mirror the Go
/// command set documented in `rust/docs/reference-go-v3.md` §9.
#[derive(Debug, Parser)]
#[command(name = "shadowlemon", version, about = "ShadowLemon V0.2")]
pub struct Cli {
    /// Print the negotiated protocol description and exit.
    #[arg(long)]
    pub protocol_info: bool,
    #[command(subcommand)]
    pub command: Option<RootCommand>,
}

/// Mode selector.
#[derive(Debug, Subcommand)]
pub enum RootCommand {
    /// Local SOCKS5 client commands.
    Client(ClientCli),
    /// Remote tunnel server commands.
    Server(ServerCli),
}

/// Commands available for the client.
#[derive(Debug, Args)]
pub struct ClientCli {
    #[command(subcommand)]
    pub command: ClientCommand,
}

/// Commands available for the server.
#[derive(Debug, Args)]
pub struct ServerCli {
    #[command(subcommand)]
    pub command: ServerCommand,
}

/// Client subcommands.
#[derive(Debug, Subcommand)]
pub enum ClientCommand {
    /// Start the client as a background daemon.
    Start,
    /// Stop the background client.
    Stop,
    /// Report whether the background client is running.
    Status,
    /// Run the client in the foreground.
    Run,
    /// Merge a YAML or JSON patch into the client configuration.
    Apply(ConfigFileArgs),
    /// Replace the client configuration wholesale.
    Replace(ConfigFileArgs),
    /// Print the client configuration.
    Describe(DescribeArgs),
    /// Import a client configuration from a share URL.
    Import(ImportArgs),
    /// Export a client configuration as a share URL.
    Export(ExportArgs),
    /// Print version information.
    Version,
}

/// Server subcommands.
#[derive(Debug, Subcommand)]
pub enum ServerCommand {
    /// Start the server as a background daemon.
    Start,
    /// Stop the background server.
    Stop,
    /// Report whether the background server is running.
    Status,
    /// Run the server in the foreground.
    Run,
    /// Merge a YAML or JSON patch into the server configuration.
    Apply(ConfigFileArgs),
    /// Replace the server configuration wholesale.
    Replace(ConfigFileArgs),
    /// Print the server configuration.
    Describe(DescribeArgs),
    /// Print version information.
    Version,
}

/// `<config <FILE>>` argument group shared by `apply` and `replace`.
#[derive(Debug, Args)]
pub struct ConfigFileArgs {
    #[command(subcommand)]
    pub target: ConfigFileTarget,
}

/// The only valid target of `apply`/`replace` is `config`.
#[derive(Debug, Subcommand)]
pub enum ConfigFileTarget {
    /// Apply to the configuration file.
    Config { file: PathBuf },
}

/// `<config <URL>>` argument group shared by `import`.
#[derive(Debug, Args)]
pub struct ImportArgs {
    #[command(subcommand)]
    pub target: ImportTarget,
}

/// The only valid target of `import` is `config`.
#[derive(Debug, Subcommand)]
pub enum ImportTarget {
    /// Import into the configuration file.
    Config { url: String },
}

/// `describe config` argument group.
#[derive(Debug, Args)]
pub struct DescribeArgs {
    #[command(subcommand)]
    pub target: DescribeTarget,
}

/// The only valid target of `describe` is `config`.
#[derive(Debug, Subcommand)]
pub enum DescribeTarget {
    /// Describe the configuration file.
    Config,
}

/// `export config [simple]` argument group.
#[derive(Debug, Args)]
pub struct ExportArgs {
    #[command(subcommand)]
    pub target: ExportTarget,
}

/// The only valid target of `export` is `config`.
#[derive(Debug, Subcommand)]
pub enum ExportTarget {
    /// Export from the configuration file.
    Config {
        #[command(subcommand)]
        style: Option<ExportStyle>,
    },
}

/// Optional export style.
#[derive(Debug, Subcommand)]
pub enum ExportStyle {
    /// One human-readable URL per configured server.
    Simple,
}

/// Parse and dispatch a command tree.
pub fn run(cli: Cli) -> Result<(), AppError> {
    match cli.command {
        Some(RootCommand::Client(client)) => run_client_cli(client.command),
        Some(RootCommand::Server(server)) => run_server_cli(server.command),
        None => Err(AppError::Config(
            "expected a `client` or `server` subcommand".to_owned(),
        )),
    }
}

fn print_version() {
    println!(
        "shadowlemon {} ({})",
        env!("CARGO_PKG_VERSION"),
        shadowlemon_crypto::PROTOCOL_IDENTIFIER
    );
}

fn blocking<T>(
    future: impl std::future::Future<Output = Result<T, AppError>>,
) -> Result<T, AppError> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(future)
}

fn run_client_cli(command: ClientCommand) -> Result<(), AppError> {
    match command {
        ClientCommand::Run => {
            let path = config::config_path(Mode::Client)?;
            let config = config::load_client(&path)?;
            init_logging(config::tracing_level(&config.logging_level));
            let stop = platform::install_signal_handlers();
            blocking(run_client_runtime(path, stop))
        }
        ClientCommand::Start => {
            init_logging(tracing::Level::INFO);
            let path = config::config_path(Mode::Client)?;
            config::load_client(&path)?;
            platform::start_daemon(Mode::Client)
        }
        ClientCommand::Stop => {
            init_logging(tracing::Level::INFO);
            platform::stop_daemon(Mode::Client).map(|_| ())
        }
        ClientCommand::Status => platform::daemon_status(Mode::Client).map(|_| ()),
        ClientCommand::Apply(args) => {
            init_logging(tracing::Level::INFO);
            edit_config(Mode::Client, args, true)
        }
        ClientCommand::Replace(args) => {
            init_logging(tracing::Level::INFO);
            edit_config(Mode::Client, args, false)
        }
        ClientCommand::Describe(args) => {
            init_logging(tracing::Level::INFO);
            let _ = args.target;
            let path = config::config_path(Mode::Client)?;
            println!("{}", describe_file_auto::<ClientConfig>(&path)?);
            Ok(())
        }
        ClientCommand::Import(args) => {
            init_logging(tracing::Level::INFO);
            let ImportTarget::Config { url } = args.target;
            let path = config::config_path(Mode::Client)?;
            let imported = import_url(&url).map_err(|error| AppError::Url(error.to_string()))?;
            write_auto(&path, &imported)?;
            println!("imported client configuration from {}", path.display());
            Ok(())
        }
        ClientCommand::Export(args) => {
            init_logging(tracing::Level::INFO);
            let ExportTarget::Config { style } = args.target;
            let path = config::config_path(Mode::Client)?;
            let config = config::load_client(&path)?;
            match style {
                Some(ExportStyle::Simple) => {
                    for url in export_simple_urls(&config)
                        .map_err(|error| AppError::Url(error.to_string()))?
                    {
                        println!("{url}");
                    }
                }
                None => println!(
                    "{}",
                    export_full_url(&config).map_err(|error| AppError::Url(error.to_string()))?
                ),
            }
            Ok(())
        }
        ClientCommand::Version => {
            print_version();
            Ok(())
        }
    }
}

fn run_server_cli(command: ServerCommand) -> Result<(), AppError> {
    match command {
        ServerCommand::Run => {
            let path = config::config_path(Mode::Server)?;
            let config = config::load_server(&path)?;
            init_logging(config::tracing_level(&config.logging_level));
            let stop = platform::install_signal_handlers();
            blocking(run_server_runtime(path, stop))
        }
        ServerCommand::Start => {
            init_logging(tracing::Level::INFO);
            let path = config::config_path(Mode::Server)?;
            config::load_server(&path)?;
            platform::start_daemon(Mode::Server)
        }
        ServerCommand::Stop => {
            init_logging(tracing::Level::INFO);
            platform::stop_daemon(Mode::Server).map(|_| ())
        }
        ServerCommand::Status => platform::daemon_status(Mode::Server).map(|_| ()),
        ServerCommand::Apply(args) => {
            init_logging(tracing::Level::INFO);
            edit_config(Mode::Server, args, true)
        }
        ServerCommand::Replace(args) => {
            init_logging(tracing::Level::INFO);
            edit_config(Mode::Server, args, false)
        }
        ServerCommand::Describe(args) => {
            init_logging(tracing::Level::INFO);
            let _ = args.target;
            let path = config::config_path(Mode::Server)?;
            println!("{}", describe_file_auto::<ServerConfig>(&path)?);
            Ok(())
        }
        ServerCommand::Version => {
            print_version();
            Ok(())
        }
    }
}

fn edit_config(mode: Mode, args: ConfigFileArgs, apply: bool) -> Result<(), AppError> {
    let ConfigFileTarget::Config { file } = args.target;
    let patch = fs::read_to_string(&file)?;
    let path = config::config_path(mode)?;
    let described = match (mode, apply) {
        (Mode::Client, true) => apply_file_auto::<ClientConfig>(&path, &patch)?,
        (Mode::Server, true) => apply_file_auto::<ServerConfig>(&path, &patch)?,
        (Mode::Client, false) => replace_file_auto::<ClientConfig>(&path, &patch)?,
        (Mode::Server, false) => replace_file_auto::<ServerConfig>(&path, &patch)?,
    };
    println!("{described}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        net::SocketAddr,
        sync::{atomic::AtomicI32, Arc, Mutex},
        time::Duration,
    };

    use shadowlemon_config::ClientConfig;
    use shadowlemon_crypto::suite::Suite;
    use shadowlemon_protocol::{
        mux::{ClientMux, Endpoint, MuxConfig, PortBindingSpec, ServerMux, TransportKind},
        serveruser::User,
        underlay_packet::PacketConfig,
        ClientCredential, RealClientConfig, RealClientHandshake, RealServerConfig,
        RealServerHandshake,
    };
    use shadowlemon_socks5::{
        encode_request, read_reply, Address, Config as SocksConfig, EgressConfig,
        Server as SocksServer, CMD_CONNECT,
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, UdpSocket},
    };

    use super::*;

    fn mux_config() -> MuxConfig {
        MuxConfig {
            handshake_timeout: Duration::from_secs(3),
            cleanup_interval: Duration::from_millis(50),
            underlay_ttl: Duration::from_secs(1),
            ..MuxConfig::default()
        }
    }

    fn client_config(suite: Suite) -> RealClientConfig {
        RealClientConfig {
            username: "alice".to_owned(),
            credential: ClientCredential::Password("secret".to_owned()),
            suites: vec![suite],
            packet: PacketConfig::default(),
            handshake_timeout: Duration::from_secs(3),
        }
    }

    fn server_config(suite: Suite) -> RealServerConfig {
        RealServerConfig {
            users: vec![User::from_password("alice", "secret", vec![suite]).unwrap()],
            hint_mandatory: true,
            allowed_suites: vec![suite],
            egress: EgressConfig::new(),
            ..RealServerConfig::default()
        }
    }

    /// A SOCKS5 CONNECT through the encrypted mux to a local echo server.
    async fn round_trip(suite: Suite) {
        let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = echo.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    loop {
                        match stream.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if stream.write_all(&buf[..n]).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                });
            }
        });

        let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);
        let server_mux = ServerMux::new(
            mux_config(),
            "127.0.0.1".parse().unwrap(),
            vec![PortBindingSpec::new(port, TransportKind::Udp)],
            Arc::new(RealServerHandshake::new(server_config(suite)).unwrap()),
        )
        .unwrap();
        server_mux.start().await.unwrap();

        let client_mux = ClientMux::new(
            mux_config(),
            vec![Endpoint::new(
                "127.0.0.1",
                vec![PortBindingSpec::new(port, TransportKind::Udp)],
            )],
            Box::new(RealClientHandshake::new(client_config(suite)).unwrap()),
        )
        .unwrap();
        let socks = SocksServer::new(SocksConfig::new(Arc::new(client_mux)));
        let (mut local, remote) = tokio::io::duplex(16 * 1024);
        let serve = tokio::spawn(async move { socks.serve(remote).await });

        local.write_all(&[5, 1, 0]).await.unwrap();
        let mut method = [0u8; 2];
        local.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [5, 0]);
        local
            .write_all(&encode_request(
                CMD_CONNECT,
                &Address::Ip(echo_addr.ip()),
                echo_addr.port(),
            ))
            .await
            .unwrap();
        let reply = read_reply(&mut local).await.unwrap();
        assert_eq!(reply[1], 0);
        local.write_all(b"ping-pong-over-tunnel").await.unwrap();
        local.flush().await.unwrap();
        let mut received = [0u8; 21];
        tokio::time::timeout(Duration::from_secs(5), local.read_exact(&mut received))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&received, b"ping-pong-over-tunnel");
        drop(local);
        let _ = tokio::time::timeout(Duration::from_secs(2), serve).await;
        server_mux.stop().await;
    }

    #[tokio::test]
    async fn end_to_end_connect_round_trips_for_every_suite() {
        for suite in Suite::all_suites() {
            round_trip(suite).await;
        }
    }

    /// A CONNECT response larger than the stream layer's 60 KiB read chunk must
    /// be delivered in full; the tunnel socket used to drop the tail.
    #[tokio::test]
    async fn end_to_end_connect_large_response_is_not_truncated() {
        const BODY_LEN: usize = 64 * 1024 + 512;
        let body: Vec<u8> = (0..BODY_LEN).map(|i| (i % 251) as u8).collect();

        let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        let payload = body.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = echo.accept().await else {
                    break;
                };
                let payload = payload.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    if stream.read(&mut buf).await.is_err() {
                        return;
                    }
                    let _ = stream.write_all(&payload).await;
                });
            }
        });

        let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);
        let suite = Suite::XChaCha20Poly1305;
        let server_mux = ServerMux::new(
            mux_config(),
            "127.0.0.1".parse().unwrap(),
            vec![PortBindingSpec::new(port, TransportKind::Udp)],
            Arc::new(RealServerHandshake::new(server_config(suite)).unwrap()),
        )
        .unwrap();
        server_mux.start().await.unwrap();
        let client_mux = ClientMux::new(
            mux_config(),
            vec![Endpoint::new(
                "127.0.0.1",
                vec![PortBindingSpec::new(port, TransportKind::Udp)],
            )],
            Box::new(RealClientHandshake::new(client_config(suite)).unwrap()),
        )
        .unwrap();
        let socks = SocksServer::new(SocksConfig::new(Arc::new(client_mux)));
        let (mut local, remote) = tokio::io::duplex(16 * 1024);
        let serve = tokio::spawn(async move { socks.serve(remote).await });

        local.write_all(&[5, 1, 0]).await.unwrap();
        let mut method = [0u8; 2];
        local.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [5, 0]);
        local
            .write_all(&encode_request(
                CMD_CONNECT,
                &Address::Ip(echo_addr.ip()),
                echo_addr.port(),
            ))
            .await
            .unwrap();
        let reply = read_reply(&mut local).await.unwrap();
        assert_eq!(reply[1], 0);
        local.write_all(b"go").await.unwrap();
        local.flush().await.unwrap();

        let mut received = vec![0u8; BODY_LEN];
        tokio::time::timeout(Duration::from_secs(20), local.read_exact(&mut received))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received, body);
        drop(local);
        let _ = tokio::time::timeout(Duration::from_secs(2), serve).await;
        server_mux.stop().await;
    }

    #[tokio::test]
    async fn end_to_end_udp_round_trips_for_every_suite() {
        for suite in Suite::all_suites() {
            let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let echo_addr = echo.local_addr().unwrap();
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                loop {
                    let Ok((len, peer)) = echo.recv_from(&mut buf).await else {
                        break;
                    };
                    if echo.send_to(&buf[..len], peer).await.is_err() {
                        break;
                    }
                }
            });

            let probe = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let port = probe.local_addr().unwrap().port();
            drop(probe);
            let server_mux = ServerMux::new(
                mux_config(),
                "127.0.0.1".parse().unwrap(),
                vec![PortBindingSpec::new(port, TransportKind::Udp)],
                Arc::new(RealServerHandshake::new(server_config(suite)).unwrap()),
            )
            .unwrap();
            server_mux.start().await.unwrap();
            let client_mux = ClientMux::new(
                mux_config(),
                vec![Endpoint::new(
                    "127.0.0.1",
                    vec![PortBindingSpec::new(port, TransportKind::Udp)],
                )],
                Box::new(RealClientHandshake::new(client_config(suite)).unwrap()),
            )
            .unwrap();
            let socket = client_mux.open_udp(echo_addr, None).await.unwrap();
            socket.send_to(b"udp encrypted", echo_addr).await.unwrap();
            let mut buf = [0u8; 2048];
            let (len, from) =
                tokio::time::timeout(Duration::from_secs(5), socket.recv_from(&mut buf))
                    .await
                    .unwrap()
                    .unwrap();
            assert_eq!(&buf[..len], b"udp encrypted");
            assert_eq!(from, echo_addr);
            server_mux.stop().await;
        }
    }

    #[test]
    fn cli_parses_all_registered_commands() {
        for args in [
            vec!["shadowlemon", "client", "start"],
            vec!["shadowlemon", "client", "stop"],
            vec!["shadowlemon", "client", "status"],
            vec!["shadowlemon", "client", "run"],
            vec!["shadowlemon", "client", "apply", "config", "a.json"],
            vec!["shadowlemon", "client", "replace", "config", "a.json"],
            vec!["shadowlemon", "client", "describe", "config"],
            vec![
                "shadowlemon",
                "client",
                "import",
                "config",
                "shadowlemon://abc",
            ],
            vec!["shadowlemon", "client", "export", "config"],
            vec!["shadowlemon", "client", "export", "config", "simple"],
            vec!["shadowlemon", "client", "version"],
            vec!["shadowlemon", "server", "start"],
            vec!["shadowlemon", "server", "status"],
            vec!["shadowlemon", "server", "describe", "config"],
            vec!["shadowlemon", "server", "version"],
        ] {
            Cli::try_parse_from(args).unwrap_or_else(|error| panic!("{error}"));
        }
    }

    #[test]
    fn config_env_vars_are_honoured() {
        static LOCK: Mutex<()> = Mutex::new(());
        let _guard = LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let json = dir.path().join("client.json");
        fs::write(&json, "{}").unwrap();
        std::env::set_var("SHADOWLEMON_CLIENT_CONFIG_JSON_FILE", &json);
        assert_eq!(config::config_path(Mode::Client).unwrap(), json);

        let proto = dir.path().join("client.conf.pb");
        fs::write(&proto, [0x0a, 0x05, 0x01]).unwrap();
        std::env::remove_var("SHADOWLEMON_CLIENT_CONFIG_JSON_FILE");
        std::env::set_var("SHADOWLEMON_CLIENT_CONFIG_FILE", &proto);
        let error = config::config_path(Mode::Client).unwrap_err().to_string();
        assert!(
            error.contains("protobuf configuration is no longer supported"),
            "{error}"
        );

        fs::write(&proto, "{}").unwrap();
        assert_eq!(config::config_path(Mode::Client).unwrap(), proto);
        std::env::remove_var("SHADOWLEMON_CLIENT_CONFIG_FILE");
    }

    #[test]
    fn client_and_server_credentials_match_from_config() {
        let profile = shadowlemon_config::ClientProfile {
            user: Some(shadowlemon_config::User {
                name: Some("alice".to_owned()),
                password: Some("secret".to_owned()),
                ..Default::default()
            }),
            cipher_suites: vec![shadowlemon_config::CipherSuite::Aes256Gcm],
            ..Default::default()
        };
        let client = config::client_driver_config(&profile).unwrap();
        assert_eq!(client.suites, vec![Suite::Aes256Gcm]);
        let server_config = shadowlemon_config::ServerConfig {
            users: vec![shadowlemon_config::User {
                name: Some("alice".to_owned()),
                password: Some("secret".to_owned()),
                ..Default::default()
            }],
            cipher_suites: vec![shadowlemon_config::CipherSuite::Aes256Gcm],
            ..Default::default()
        };
        let server = config::server_driver_config(&server_config).unwrap();
        let expected = shadowlemon_crypto::kdf::hash_password(b"secret", "alice");
        assert_eq!(server.users[0].credential(), &expected);
        assert!(matches!(client.credential, ClientCredential::Password(_)));
    }

    #[allow(dead_code)]
    fn assert_types(_cfg: ClientConfig, _addr: SocketAddr, _flag: &'static AtomicI32) {}
}
