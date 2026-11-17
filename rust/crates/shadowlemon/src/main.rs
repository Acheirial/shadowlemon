//! ShadowLemon V0.2 command line entry point.

use clap::Parser;
use shadowlemon_app::Cli;

fn main() {
    // The first argument selects the log prefix (C/S), matching the Go CLI.
    let prefix: &'static str = match std::env::args().nth(1).as_deref() {
        Some("client") => "C",
        Some("server") => "S",
        _ => "S",
    };
    shadowlemon_app::set_log_prefix(prefix);

    let cli = Cli::parse();
    if cli.protocol_info {
        println!(
            "{} (version byte {})",
            shadowlemon_crypto::PROTOCOL_IDENTIFIER,
            shadowlemon_crypto::DEFAULT_PROTOCOL_VERSION
        );
        return;
    }
    #[cfg(feature = "embedded")]
    tracing::debug!("running embedded build");

    if let Err(error) = shadowlemon_app::run(cli) {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shadowlemon_app::RootCommand;

    #[test]
    fn binary_accepts_both_command_sets() {
        for args in [
            vec!["shadowlemon", "client", "status"],
            vec!["shadowlemon", "server", "status"],
        ] {
            let cli = Cli::try_parse_from(args).expect("parses command set");
            assert!(matches!(
                cli.command,
                Some(RootCommand::Client(_)) | Some(RootCommand::Server(_))
            ));
        }
    }
}
