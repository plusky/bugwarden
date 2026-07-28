//! bugwarden — Rust MCP server for Bugzilla with operator-controlled
//! security guards.
//!
//! The binary is a thin transport wrapper; the CLI and the MCP tool surface
//! live in the `bugwarden` library crate (`config`, `server`) so integration
//! tests can drive the tools without a process boundary.

use std::sync::Arc;

use anyhow::{bail, Context};
use bugwarden::{config, server};
use bugwarden_core::{client::BugzillaClient, guard::Guard, policy::Policy};
use clap::Parser;
use rmcp::{
    transport::{
        stdio,
        streamable_http_server::{
            session::local::LocalSessionManager, StreamableHttpServerConfig, StreamableHttpService,
        },
    },
    ServiceExt,
};
use tracing_subscriber::EnvFilter;

use config::{Cli, Transport};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Tracing always goes to stderr: stdout belongs to the stdio transport.
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .init();

    // Guard policy comes ONLY from the TOML file given at startup (I1);
    // without one the built-in default policy applies.
    let mut policy = match &cli.policy {
        Some(path) => Policy::load(path)
            .with_context(|| format!("failed to load guard policy from {}", path.display()))?,
        None => Policy::default(),
    };
    // CLI/env can only tighten policy (I9).
    policy.global.read_only |= cli.read_only;

    match cli.transport {
        Transport::Stdio => {
            if cli.api_key.as_deref().is_none_or(str::is_empty) {
                bail!(
                    "--transport stdio requires --api-key or the BUGZILLA_API_KEY environment variable"
                );
            }
        }
        Transport::Http => {
            if cli.api_key.is_some() {
                tracing::warn!(
                    "--api-key / BUGZILLA_API_KEY is set but ignored with --transport http \
                     (clients send the key per-request via the API key header). \
                     Unset it to clean the config."
                );
            }
        }
    }

    let bz = Arc::new(
        BugzillaClient::new(&cli.bugzilla_server, cli.use_auth_header)
            .context("failed to build Bugzilla client")?,
    );
    let guard = Arc::new(Guard { policy });
    let cfg = Arc::new(cli);
    let server = server::BugWarden::new(cfg.clone(), guard, bz)
        .context("failed to build the MCP server from the guard policy")?;

    match cfg.transport {
        Transport::Stdio => {
            tracing::info!("Starting Bugzilla MCP server on stdio");
            let service = server.serve(stdio()).await.inspect_err(|e| {
                tracing::error!("serving error: {:?}", e);
            })?;
            service.waiting().await?;
        }
        Transport::Http => {
            let ct = tokio_util::sync::CancellationToken::new();

            let service = StreamableHttpService::new(
                move || Ok(server.clone()),
                LocalSessionManager::default().into(),
                StreamableHttpServerConfig::default().with_cancellation_token(ct.child_token()),
            );

            let router = axum::Router::new().nest_service("/mcp", service);
            let addr = format!("{}:{}", cfg.host, cfg.port);
            tracing::info!("Starting Bugzilla MCP server on {addr}");
            let tcp_listener = tokio::net::TcpListener::bind(&addr)
                .await
                .with_context(|| format!("failed to bind {addr}"))?;
            axum::serve(tcp_listener, router)
                .with_graceful_shutdown(async move {
                    let _ = tokio::signal::ctrl_c().await;
                    ct.cancel();
                })
                .await?;
        }
    }

    Ok(())
}
