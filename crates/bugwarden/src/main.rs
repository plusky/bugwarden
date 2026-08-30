//! bugwarden — Rust MCP server for Bugzilla with operator-controlled
//! security guards.
//!
//! The binary is a thin transport wrapper; the CLI and the MCP tool surface
//! live in the `bugwarden` library crate (`config`, `server`) so integration
//! tests can drive the tools without a process boundary.

use std::sync::{Arc, OnceLock};

use anyhow::Context;
use bugwarden::audit::{
    policy_hash_of, select_sinks, AuditConfig, AuditSink, AuditState, FailMode, SinkSelection,
    TransportKind,
};
use bugwarden::http_auth::{self, HttpEnv};
use bugwarden::otel::{self, OtelEnv, Pipeline};
use bugwarden::{config, server};
use bugwarden_core::{guard::Guard, policy::Policy};
use clap::Parser;
use rmcp::{
    transport::{
        stdio,
        streamable_http_server::{session::local::LocalSessionManager, StreamableHttpService},
    },
    ServiceExt,
};
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;
use tracing_subscriber::EnvFilter;

use config::{Cli, Transport};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // OTLP export configuration, resolved before anything is installed:
    // parsing the environment starts no task and opens no socket, but a
    // protocol this build cannot speak has to be a startup error rather
    // than a surprise once records exist. Unset or empty
    // OTEL_EXPORTER_OTLP_ENDPOINT means the whole feature stays off.
    let otel_config = otel::resolve(&OtelEnv::from_env())?;
    // Filled in below, once the audit sink has opened; the diagnostics
    // layer reads it and does nothing while it is empty.
    let otel_slot: Arc<OnceLock<Arc<Pipeline>>> = Arc::new(OnceLock::new());

    // Tracing always goes to stderr: stdout belongs to the stdio transport.
    // The OTLP layer, when export is on, sits beside the stderr one under
    // the same filter, so both carry the same events.
    let registry = tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(std::io::stderr)
                .with_ansi(false),
        );
    if otel_config.is_some() {
        registry
            .with(Pipeline::diagnostics_layer(otel_slot.clone()))
            .init();
    } else {
        registry.init();
    }

    // The http bearer gate, resolved before anything else runs: over http
    // the port is the access boundary, and a half-configured credential must
    // never degrade into open access. Ahead of the policy load, the Bugzilla
    // client, the identity preflight and the audit sink alike, so a token
    // misconfiguration aborts startup without binding a port, opening a
    // socket to Bugzilla, or creating or rotating an audit file. `None` for
    // stdio, where the client owns the process and the tokens are ignored.
    let http_auth =
        http_auth::resolve_for(cli.transport, &HttpEnv::from_env(), cli.insecure_no_auth)
            .map(|auth| auth.map(Arc::new))?;
    if let Some(auth) = &http_auth {
        auth.log_startup_mode();
    }

    // Which audit sinks this deployment runs (issue #31, revised
    // 2026-08-18): file, OTLP, both, or none. Resolved here — pure
    // configuration, no file touched — so the two ambiguous spellings
    // (an endpoint with no file decision, `none` with no endpoint) refuse
    // startup before any network or filesystem work. The sinks themselves
    // open after the preflight, below, exactly as before.
    let sinks = select_sinks(cli.audit_config.as_deref(), otel_config.is_some())?;

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
    // Built in the library target, not here: the client's identity to
    // Bugzilla (I12-adjacent, issue #55) is only testable where a test can
    // reach the constructor.
    let bz = Arc::new(server::bugzilla_client(&cli)?);
    let guard = Arc::new(Guard { policy });
    let cfg = Arc::new(cli);
    let server =
        server::BugWarden::new(cfg.clone(), guard, bz).context("failed to build the MCP server")?;
    // Turns a silent whoami-blackout (I4 denying every created_by_me
    // classification) into an actionable startup failure. Before the audit
    // sink below: a failed preflight must not create or rotate an audit
    // file (the same ordering rationale as key custody resolution above).
    server.preflight().await?;

    // OTLP export, started AFTER the identity preflight and BEFORE the
    // audit file is created: a collector that will not take records must
    // refuse to start without leaving a file behind, the same ordering
    // the preflight already keeps. Off entirely when no endpoint is
    // configured: no task, no thread, no layer.
    let otel = match otel_config {
        Some(otel_cfg) => Some(Arc::new(Pipeline::start(otel_cfg)?)),
        None => None,
    };
    if let Some(pipeline) = &otel {
        // Fills the slot the diagnostics layer installed above reads.
        let _ = otel_slot.set(pipeline.clone());
        // The delivery probe, mirroring the identity preflight: a
        // deployment that cannot deliver its audit records refuses to
        // start (bounded retry inside — a co-starting collector may lose
        // the race by a few seconds).
        pipeline.probe().await?;
        tracing::info!(
            "OTLP export enabled: audit records are exported to the configured \
             collector and gate serving when delivery fails; diagnostics are \
             copied best-effort"
        );
    }

    // Audit sinks, per the selection above. The fail mode falls back to
    // the transport-derived default — an OTLP-only sink has no document
    // to say otherwise, so it always derives — and the policy digest ties
    // every record to the policy document in force.
    let audit_sink = match sinks {
        SinkSelection::NoAudit => None,
        SinkSelection::FileOnly | SinkSelection::Both | SinkSelection::OtlpOnly => {
            let audit_cfg = match sinks {
                SinkSelection::FileOnly | SinkSelection::Both => {
                    match cfg.audit_config.as_deref() {
                        Some(path) => AuditConfig::load(path)?,
                        // Unreachable: `select_sinks` returns a file-bearing
                        // selection only for a real path. Refuse rather than
                        // panic, like the http bearer gate below.
                        None => anyhow::bail!(
                            "internal error: a file-bearing sink selection has no path"
                        ),
                    }
                }
                _ => AuditConfig::fileless(),
            };
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
            Some((sink, fail_mode, policy_hash))
        }
    };

    let audit = audit_sink.map(|(sink, fail_mode, policy_hash)| {
        let sink = match &otel {
            Some(pipeline) => sink.with_export(pipeline.audit_exporter()),
            None => sink,
        };
        Arc::new(AuditState::new(sink, fail_mode, policy_hash))
    });
    if audit.is_none() && cfg.transport == Transport::Http {
        tracing::warn!(
            "auditing is OFF: remote tool calls over http will leave no audit \
             record — pass --audit-config / BUGWARDEN_AUDIT_CONFIG for a file, \
             or set OTEL_EXPORTER_OTLP_ENDPOINT with BUGWARDEN_AUDIT_CONFIG=none \
             for a collector-only trail"
        );
    }

    let server = match audit {
        Some(audit) => server.with_audit(audit),
        None => server,
    };
    // Per-request scopes exist only where a per-request credential does:
    // authenticated http. stdio issues none, and --insecure-no-auth issues
    // none by definition.
    let server =
        server.with_scope_enforcement(http_auth.as_ref().is_some_and(|auth| !auth.is_insecure()));

    // Cloned into the serve future so a stdio SIGTERM can flush before
    // `process::exit`. The original stays here for the HTTP / peer-close
    // path, which returns from the future instead of exiting.
    let otel_on_signal = otel.clone();
    // The result is held rather than propagated so the OTLP flush below
    // runs on every exit path, a transport error included.
    let served: anyhow::Result<()> = async move {
        match cfg.transport {
            Transport::Stdio => {
                // Two stages: an unused stdio container sits in `serve`
                // (handshake). After initialize it sits in `waiting`.
                // Handlers register on the first poll of `shutdown`, which
                // is this `select!` immediately after the startup line.
                let shutdown = shutdown_signal();
                tokio::pin!(shutdown);
                tracing::info!("Starting Bugzilla MCP server on stdio");
                let service = tokio::select! {
                    result = server.serve(stdio()) => {
                        result.inspect_err(|e| {
                            tracing::error!("serving error: {:?}", e);
                        })?
                    }
                    () = &mut shutdown => {
                        tracing::info!("received shutdown signal");
                        // serve() is already blocked in tokio::io::stdin()'s
                        // uncancellable read. Returning from main drops the
                        // runtime onto that blocking thread. Flush first:
                        // process::exit would otherwise skip the tail of a
                        // load-bearing OTLP-only sink.
                        flush_otel_and_exit(otel_on_signal.as_deref()).await;
                    }
                };
                let cancel = service.cancellation_token();
                tokio::select! {
                    result = service.waiting() => {
                        result?;
                    }
                    () = shutdown => {
                        tracing::info!("received shutdown signal");
                        cancel.cancel();
                        flush_otel_and_exit(otel_on_signal.as_deref()).await;
                    }
                }
            }
            Transport::Http => {
                let ct = tokio_util::sync::CancellationToken::new();

                // Derived from the server's own guard policy (the POST body cap
                // follows `global.max_attachment_bytes`, issue #52), so it is
                // built while `server` can still be borrowed.
                let config = server
                    .http_server_config()?
                    .with_cancellation_token(ct.child_token());
                let service = StreamableHttpService::new(
                    move || Ok(server.clone()),
                    LocalSessionManager::default().into(),
                    config,
                );
                // `resolve_for` returns the gate for every http start, so the
                // bail below is unreachable — it exists so a future refactor
                // that lost the gate fails to serve rather than serving open.
                let Some(auth) = http_auth else {
                    anyhow::bail!("internal error: the http transport has no resolved bearer gate");
                };
                let router = http_auth::guard_router(
                    axum::Router::new().nest_service("/mcp", service),
                    auth,
                );
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
                    shutdown_signal().await;
                    tracing::info!("received shutdown signal");
                    // Tear the live streamable-HTTP transport down with the
                    // listener: axum's graceful shutdown alone waits for
                    // in-flight connections, and an open MCP session is one.
                    ct.cancel();
                })
                .await?;
            }
        }
        Ok(())
    }
    .await;

    // Best-effort, bounded flush of whatever is still queued. On http this
    // runs after graceful shutdown, i.e. after the SIGINT that cancelled
    // it; on stdio after the peer closed the session.
    if let Some(pipeline) = &otel {
        pipeline.shutdown().await;
    }

    served
}

/// Bounded OTLP flush, then `_exit`. Used on the stdio signal arms: those
/// cannot return from `main` (rmcp's stdin read is uncancellable) and
/// must not skip a load-bearing collector either.
async fn flush_otel_and_exit(otel: Option<&Pipeline>) -> ! {
    if let Some(pipeline) = otel {
        pipeline.shutdown().await;
    }
    std::process::exit(0);
}

/// Wait until the process should stop serving.
///
/// `SIGINT` (`ctrl_c`) and, on Unix, `SIGTERM`. As container PID 1 the
/// kernel does not apply SIGTERM's default terminate action, so without
/// this waiter `docker stop` / `podman stop` wait out the runtime grace
/// period and SIGKILL (issue #114). Both signals take the same path: the
/// caller then cancels whatever is serving (the HTTP transport token, or
/// the stdio `select!`). A failed SIGTERM install is logged and the
/// waiter falls back to SIGINT only — refusing to start would be worse
/// than a container that still needs `--init`.
async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();
    #[cfg(unix)]
    {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {
                    _ = ctrl_c => {}
                    _ = term.recv() => {}
                }
            }
            Err(err) => {
                tracing::error!(
                    error = %err,
                    "failed to install SIGTERM handler; only SIGINT will stop the process"
                );
                let _ = ctrl_c.await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = ctrl_c.await;
    }
}
