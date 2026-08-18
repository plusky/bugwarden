//! The shipped binary stops on SIGTERM / SIGINT (issue #114).
//!
//! As container PID 1 the kernel does not apply SIGTERM's default terminate
//! action, so a process that only listened for SIGINT (`ctrl_c`) made
//! `docker stop` wait out its grace period and SIGKILL. These tests spawn
//! the real executable — the handlers live in `main` — and assert a
//! **graceful** exit (`status.code() == Some(0)`). An unhandled SIGTERM
//! still kills a non-PID-1 child, but with `code() == None` and
//! `signal() == SIGTERM`; requiring `Some(0)` is what makes a missing
//! handler fail this file.
//!
//! Coverage contract (each of these mutations must fail at least one test):
//! - HTTP graceful-shutdown waiting only on `ctrl_c` (no SIGTERM);
//! - stdio wrapping only `waiting()` and not `serve` (the handshake wait
//!   is where an unused stdio container sits);
//! - stdio wrapping only `serve` and not `waiting()`;
//! - HTTP SIGTERM returning without `ct.cancel()`, leaving an open MCP
//!   session to outlive the shutdown.

#![cfg(unix)]

use std::net::SocketAddr;
use std::process::Stdio;
use std::time::Duration;

use rmcp::service::RoleClient;
use rmcp::service::RunningService;
use rmcp::transport::streamable_http_client::StreamableHttpClientTransportConfig;
use rmcp::transport::StreamableHttpClientTransport;
use rmcp::ServiceExt as _;
use tokio::io::AsyncBufReadExt;
use tokio::io::AsyncWriteExt;
use tokio::io::BufReader;
use tokio::process::Child;
use tokio::process::Command;

/// Bounded so a binary that ignores the signal fails this test rather than
/// hanging the suite until CI's own timeout kills it. Well under docker's
/// default 10s grace, so a "it will die eventually" path cannot pass.
const EXIT_TIMEOUT: Duration = Duration::from_secs(5);

/// Every environment variable the binary reads, cleared before each spawn.
const AMBIENT_VARS: &[&str] = &[
    "BUGZILLA_SERVER",
    "BUGZILLA_API_KEY",
    "BUGZILLA_API_KEY_FILE",
    "BUGWARDEN_POLICY",
    "BUGWARDEN_AUDIT_CONFIG",
    "BUGWARDEN_HTTP_TOKEN",
    "BUGWARDEN_HTTP_READ_TOKEN",
    "BUGZILLA_USE_AUTH_HEADER",
    "MCP_TRANSPORT",
    "MCP_HOST",
    "MCP_PORT",
    "MCP_ALLOWED_HOSTS",
    "MCP_READ_ONLY",
    "MCP_API_KEY_HEADER",
    "RUST_LOG",
];

/// The scrub list is only as good as its coverage of `Cli`.
#[test]
fn the_scrub_list_covers_every_environment_fallback() {
    let mut cmd = bugwarden::config::command();
    cmd.build();
    let unscrubbed: Vec<String> = cmd
        .get_arguments()
        .filter_map(clap::Arg::get_env)
        .map(|env| env.to_string_lossy().into_owned())
        .filter(|env| !AMBIENT_VARS.contains(&env.as_str()))
        .collect();
    assert!(
        unscrubbed.is_empty(),
        "these environment fallbacks reach the spawned binary: {unscrubbed:?}"
    );
    for var in [
        bugwarden::http_auth::WRITE_TOKEN_VAR,
        bugwarden::http_auth::READ_TOKEN_VAR,
    ] {
        assert!(AMBIENT_VARS.contains(&var), "{var} must be scrubbed");
    }
}

/// A port to hand the child, chosen by binding and releasing an ephemeral
/// one. Racy in principle; the child's readiness poll below turns a lost
/// race into a test failure rather than a hang.
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind")
        .local_addr()
        .expect("addr")
        .port()
}

fn send_signal(pid: u32, signal: &str) {
    let status = std::process::Command::new("kill")
        .args(["-s", signal, &pid.to_string()])
        .status()
        .expect("kill must be executable");
    assert!(status.success(), "kill -s {signal} {pid} failed: {status}");
}

/// Spawn the shipped binary. Stdin is piped so a stdio child does not see
/// EOF the moment we start; stderr is piped so tests can wait on the
/// startup line. `kill_on_drop` reaps a child if the assertion panics.
fn spawn_binary(args: &[&str]) -> Child {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_bugwarden"));
    cmd.args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for var in AMBIENT_VARS {
        cmd.env_remove(var);
    }
    cmd.env("RUST_LOG", "info");
    cmd.kill_on_drop(true);
    cmd.spawn().expect("the built binary must start")
}

async fn wait_for_tcp(addr: SocketAddr) {
    let ready = tokio::time::timeout(EXIT_TIMEOUT, async {
        loop {
            if tokio::net::TcpStream::connect(addr).await.is_ok() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await;
    assert!(ready.is_ok(), "the binary must start serving on {addr}");
}

/// Block until `needle` appears on the child's stderr, so a signal is not
/// delivered before `shutdown_signal` is armed.
async fn wait_for_stderr(child: &mut Child, needle: &str) {
    let stderr = child.stderr.as_mut().expect("stderr is piped");
    let mut lines = BufReader::new(stderr).lines();
    let found = tokio::time::timeout(EXIT_TIMEOUT, async {
        loop {
            let line = lines
                .next_line()
                .await
                .expect("stderr must be readable")
                .expect("the server must log the startup line before EOF");
            if line.contains(needle) {
                return;
            }
        }
    })
    .await;
    assert!(
        found.is_ok(),
        "timed out waiting for {needle:?} on the child's stderr"
    );
}

async fn assert_graceful_exit(child: Child, what: &str) {
    let output = tokio::time::timeout(EXIT_TIMEOUT, child.wait_with_output())
        .await
        .unwrap_or_else(|_| panic!("{what}: the process must exit within {EXIT_TIMEOUT:?}"))
        .expect("the child must be waitable");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(0),
        "{what}: SIGTERM/SIGINT must be a clean exit 0, not a signal-kill \
         (code=None) or an error: status={status:?} stderr={stderr}",
        status = output.status
    );
    assert!(
        stderr.contains("received shutdown signal"),
        "{what}: the shutdown path must log that it ran: {stderr}"
    );
}

async fn connect_insecure(addr: SocketAddr) -> RunningService<RoleClient, ()> {
    let transport = StreamableHttpClientTransport::with_client(
        reqwest::Client::new(),
        StreamableHttpClientTransportConfig::with_uri(format!("http://{addr}/mcp")),
    );
    ().serve(transport)
        .await
        .expect("MCP handshake must succeed under --insecure-no-auth")
}

#[tokio::test]
async fn http_sigterm_exits_zero_on_an_idle_listener() {
    let port = free_port();
    let child = spawn_binary(&[
        "--bugzilla-server",
        "https://bugzilla.example.invalid",
        "--host",
        "127.0.0.1",
        "--port",
        &port.to_string(),
        "--insecure-no-auth",
    ]);
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().expect("addr");
    wait_for_tcp(addr).await;
    let pid = child.id().expect("the child has a pid");
    send_signal(pid, "TERM");
    assert_graceful_exit(child, "http idle SIGTERM").await;
}

#[tokio::test]
async fn http_sigint_still_exits_zero() {
    let port = free_port();
    let child = spawn_binary(&[
        "--bugzilla-server",
        "https://bugzilla.example.invalid",
        "--host",
        "127.0.0.1",
        "--port",
        &port.to_string(),
        "--insecure-no-auth",
    ]);
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().expect("addr");
    wait_for_tcp(addr).await;
    let pid = child.id().expect("the child has a pid");
    send_signal(pid, "INT");
    assert_graceful_exit(child, "http idle SIGINT").await;
}

#[tokio::test]
async fn http_sigterm_cancels_a_live_session() {
    // axum's graceful shutdown waits for in-flight connections. A live
    // streamable-HTTP session is one: without `ct.cancel()` the process
    // stays up until this test's timeout, which is the mutation.
    let port = free_port();
    let child = spawn_binary(&[
        "--bugzilla-server",
        "https://bugzilla.example.invalid",
        "--host",
        "127.0.0.1",
        "--port",
        &port.to_string(),
        "--insecure-no-auth",
    ]);
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().expect("addr");
    wait_for_tcp(addr).await;
    let _session = connect_insecure(addr).await;
    let pid = child.id().expect("the child has a pid");
    send_signal(pid, "TERM");
    assert_graceful_exit(child, "http live-session SIGTERM").await;
}

#[tokio::test]
async fn stdio_sigterm_during_the_handshake_wait_exits_zero() {
    // `serve(stdio())` blocks on initialize. A stdio container that no
    // client has spoken to yet is in this wait, not in `waiting()`.
    let mut child = spawn_binary(&[
        "--transport",
        "stdio",
        "--bugzilla-server",
        "https://bugzilla.example.invalid",
        "--api-key",
        "test-key",
    ]);
    wait_for_stderr(&mut child, "Starting Bugzilla MCP server on stdio").await;
    // Keep stdin open: wait_with_output drops it and EOF-unblocks the
    // child's blocking read, so a handshake arm that only `return Ok(())`
    // would go green. Matching the post-initialize test, take stdin and
    // wait() instead.
    let _stdin = child.stdin.take();
    let pid = child.id().expect("the child has a pid");
    send_signal(pid, "TERM");
    let status = tokio::time::timeout(EXIT_TIMEOUT, child.wait())
        .await
        .expect("stdio pre-handshake SIGTERM: the process must exit")
        .expect("the child must be waitable");
    assert_eq!(
        status.code(),
        Some(0),
        "stdio pre-handshake SIGTERM: clean exit 0, not a signal-kill: {status:?}"
    );
}

#[tokio::test]
async fn stdio_sigterm_after_initialize_exits_zero() {
    let mut child = spawn_binary(&[
        "--transport",
        "stdio",
        "--bugzilla-server",
        "https://bugzilla.example.invalid",
        "--api-key",
        "test-key",
    ]);
    wait_for_stderr(&mut child, "Starting Bugzilla MCP server on stdio").await;

    let mut stdin = child.stdin.take().expect("stdin is piped");
    let stdout = child.stdout.take().expect("stdout is piped");
    let mut stdout = BufReader::new(stdout).lines();
    stdin
        .write_all(
            br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"binary-shutdown-test","version":"0"}}}
"#,
        )
        .await
        .expect("the child must accept the handshake");
    let reply = tokio::time::timeout(EXIT_TIMEOUT, stdout.next_line())
        .await
        .expect("the handshake must not hang")
        .expect("stdout must be readable")
        .expect("the server must answer initialize");
    assert!(
        reply.contains("bugwarden"),
        "initialize must complete before the signal: {reply}"
    );

    // Keep draining stdout so a cancel-path write cannot fill the pipe
    // and block the child's serve loop.
    let _drain =
        tokio::spawn(async move { while stdout.next_line().await.ok().flatten().is_some() {} });

    let pid = child.id().expect("the child has a pid");
    send_signal(pid, "TERM");
    // stdin/stdout already taken; wait() not wait_with_output.
    let status = tokio::time::timeout(EXIT_TIMEOUT, child.wait())
        .await
        .expect("stdio post-handshake SIGTERM: the process must exit")
        .expect("the child must be waitable");
    assert_eq!(
        status.code(),
        Some(0),
        "stdio post-handshake SIGTERM: clean exit 0, not a signal-kill: {status:?}"
    );
}
