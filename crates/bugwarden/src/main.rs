//! bugwarden — Rust MCP server for Bugzilla with operator-controlled
//! security guards.
//!
//! The binary is a thin transport wrapper; the CLI and the MCP tool surface
//! live in the `bugwarden` library crate (`config`, `server`) so integration
//! tests can drive the tools without a process boundary.

use std::sync::Arc;

use anyhow::Context;
use bugwarden::audit::{
    policy_hash_of, AuditConfig, AuditSink, AuditState, FailMode, TransportKind,
};
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

    // API key custody (stdio-without-key bail, http --api-key warn, key
    // file handling) is resolved inside BugWarden::new — before the audit
    // sink below, so a key misconfiguration aborts startup without first
    // creating or rotating an audit file.
    let bz = Arc::new(
        BugzillaClient::new(&cli.bugzilla_server, cli.use_auth_header)
            .context("failed to build Bugzilla client")?,
    );
    let guard = Arc::new(Guard { policy });
    let cfg = Arc::new(cli);
    let server =
        server::BugWarden::new(cfg.clone(), guard, bz).context("failed to build the MCP server")?;

    // Audit stream, when configured. The fail mode falls back to the
    // transport-derived default; the policy digest ties every record to
    // the policy document in force.
    let audit = match &cfg.audit_config {
        Some(path) => {
            let audit_cfg = AuditConfig::load(path)?;
            let transport = match cfg.transport {
                Transport::Stdio => TransportKind::Stdio,
                Transport::Http => TransportKind::Http,
            };
            let fail_mode = FailMode::resolve(audit_cfg.fail_mode, transport);
            // The digest re-reads the file Policy::load parsed above
            // (load also owns the unix permission warning, so it stays
            // the one parse path). A rewrite between the two reads could
            // hash different bytes than were parsed; the window is
            // operator-local and harmless — the operator who swaps the
            // policy mid-startup gets the digest of what is on disk.
            let policy_hash = match &cfg.policy {
                Some(policy_path) => {
                    let bytes = std::fs::read(policy_path).with_context(|| {
                        format!(
                            "failed to read guard policy from {} for the audit digest",
                            policy_path.display()
                        )
                    })?;
                    Some(policy_hash_of(&bytes))
                }
                None => None,
            };
            let sink = AuditSink::open(audit_cfg).context("failed to open the audit sink")?;
            Some(Arc::new(AuditState::new(sink, fail_mode, policy_hash)))
        }
        None => None,
    };
    if audit.is_none() && cfg.transport == Transport::Http {
        tracing::warn!(
            "auditing is OFF: remote tool calls over http will leave no audit \
             record — pass --audit-config / BUGWARDEN_AUDIT_CONFIG to enable it"
        );
    }

    let server = match audit {
        Some(audit) => server.with_audit(audit),
        None => server,
    };

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
            // Connect-info makes the remote peer address available in the
            // request extensions, where the audit session info reads it.
            axum::serve(
                tcp_listener,
                router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .with_graceful_shutdown(async move {
                let _ = tokio::signal::ctrl_c().await;
                ct.cancel();
            })
            .await?;
        }
    }

    Ok(())
}
