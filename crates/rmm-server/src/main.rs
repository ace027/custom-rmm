//! Server binary: api, ingest, authd and migrate run as separate processes.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use utoipa::OpenApi;

/// RMM server.
#[derive(Debug, Parser)]
#[command(name = "rmm-server", version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand, PartialEq, Eq)]
enum Command {
    /// Run the HTTP API.
    Api,
    /// Run the telemetry ingest process.
    Ingest,
    /// Run the NATS auth callout service.
    Authd,
    /// Apply database migrations.
    Migrate,
    /// Print the OpenAPI document as pretty JSON.
    Openapi,
    /// Probe an http:// URL and exit non-zero unless it answers 200.
    Healthcheck {
        /// URL to probe, e.g. http://127.0.0.1:8080/healthz
        url: String,
    },
}

fn healthcheck(url: &str) -> Result<()> {
    let rest = url
        .strip_prefix("http://")
        .context("only http:// URLs are supported")?;
    let (authority, path) = match rest.split_once('/') {
        Some((a, p)) => (a, format!("/{p}")),
        None => (rest, "/".to_string()),
    };
    let addr = if authority.contains(':') {
        authority.to_string()
    } else {
        format!("{authority}:80")
    };
    let mut stream = TcpStream::connect(&addr).with_context(|| format!("connect {addr}"))?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n"
    )?;
    let mut head = String::new();
    stream.take(64).read_to_string(&mut head).ok();
    if head.starts_with("HTTP/1.1 200") || head.starts_with("HTTP/1.0 200") {
        Ok(())
    } else {
        bail!(
            "unhealthy: {}",
            head.lines().next().unwrap_or("no response")
        )
    }
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    match Cli::parse().command {
        Command::Openapi => {
            let json = rmm_api::ApiDoc::openapi().to_pretty_json()?;
            println!("{json}");
        }
        Command::Healthcheck { url } => healthcheck(&url)?,
        Command::Api | Command::Ingest | Command::Authd | Command::Migrate => {
            tracing::warn!("not implemented in phase 1 skeleton");
            eprintln!("not implemented in phase 1 skeleton");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_subcommands() {
        for (arg, want) in [
            ("api", Command::Api),
            ("ingest", Command::Ingest),
            ("authd", Command::Authd),
            ("migrate", Command::Migrate),
            ("openapi", Command::Openapi),
        ] {
            assert_eq!(
                Cli::try_parse_from(["rmm-server", arg]).expect(arg).command,
                want
            );
        }
        let cli = Cli::try_parse_from(["rmm-server", "healthcheck", "http://x/y"]).expect("hc");
        assert_eq!(
            cli.command,
            Command::Healthcheck {
                url: "http://x/y".to_string()
            }
        );
    }
}
