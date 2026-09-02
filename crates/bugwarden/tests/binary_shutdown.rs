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
//! The same spawned binary also pins how a stdio frame over the request
//! cap ends (#234). Both halves need a real process: the refusal is a
//! transport-level read error, and rmcp reports it to the service as an
//! ordinary close, so after the handshake only the exit code tells a
//! refused frame from a peer hangup.
//!
//! Coverage contract (each of these mutations must fail at least one test):
//! - HTTP graceful-shutdown waiting only on `ctrl_c` (no SIGTERM);
//! - stdio wrapping only `waiting()` and not `serve` (the handshake wait
//!   is where an unused stdio container sits);
//! - stdio wrapping only `serve` and not `waiting()`;
//! - HTTP SIGTERM returning without `ct.cancel()`, leaving an open MCP
//!   session to outlive the shutdown;
//! - stdio served on a bare `stdio()` instead of the bounded reader, which
//!   buffers the whole frame and never exits;
//! - stdio dropping the over-cap flag `main` checks after `waiting()`,
//!   which exits 0 on a refusal it was the point of refusing.
//!
//! Both races this file used to lose (#173) were readiness barriers that
//! did not prove what they had to, and both are answered in `main`:
//! the port is the kernel's choice, read back from the child's own startup
//! line, so no stranger holding a guessed port can answer for the child;
//! and `shutdown_signal` arms the handlers *before* that line is logged, so
//! a signal sent the instant it appears cannot land on the kernel's default
//! disposition and kill the process. Waiting on the line is the whole
//! barrier — a sleep would only trade a fast flake for a slow one.

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
use tokio::process::ChildStdin;
use tokio::process::Command;

#[path = "common/scrub_env.rs"]
mod scrub_env;

#[path = "common/startup_line.rs"]
mod startup_line;

use startup_line::HTTP_READY;

/// Bounded so a binary that ignores the signal fails this test rather than
/// hanging the suite until CI's own timeout kills it. Well under docker's
/// default 10s grace, so a "it will die eventually" path cannot pass.
const EXIT_TIMEOUT: Duration = Duration::from_secs(5);

/// Each binary runs the walker itself, so a single-binary
/// `cargo test --test binary_shutdown` still proves what its scrub claims.
#[test]
fn the_scrub_list_covers_every_environment_fallback() {
    scrub_env::assert_the_scrub_list_covers_every_environment_fallback(
        scrub_env::AMBIENT_VARS,
        scrub_env::HTTP_TOKEN_VARS,
    );
}

/// [`HTTP_READY`]'s counterpart for stdio, which has no address to parse.
const STDIO_READY: &str = "Starting Bugzilla MCP server on stdio";

/// Past the 4 MiB cap the default policy derives, and with no delimiter
/// anywhere in it: an unbounded read is the defect, so the frame must be
/// one the server can never complete.
const OVER_CAP_FRAME: usize = 5 * 1024 * 1024;

/// bugwarden's own refusal line, in full.
///
/// rmcp logs `Error reading from stream: {e}` and `{e}` is this reader's
/// error, so the first half of this string appears whether or not bugwarden
/// logs anything at all — the tail after the `;` is what makes the needle
/// bugwarden's line and not the SDK's. The cap is spelled out because the
/// default policy derives the 4 MiB floor, so a derivation that stopped
/// following the policy would show up here too.
const OVER_CAP_LINE: &str =
    "stdio frame exceeds the 4194304-byte request cap; closing the transport";

/// A spawned binary, its pipes, and every stderr line it has written.
struct Server {
    child: Child,
    /// Held until the process exits, never dropped early: `Child::wait`
    /// closes the child's stdin, and EOF there unblocks a stdio child's
    /// read — which would let a handshake arm that merely returned pass
    /// the pre-handshake test.
    stdin: Option<ChildStdin>,
    /// One reader for the process's whole life. A `BufReader` built per
    /// wait throws away whatever it buffered past the line it matched,
    /// which can swallow the line a later assertion needs.
    stderr: startup_line::StderrLines,
    /// Every stderr line read so far, for the assertions and diagnostics.
    log: String,
}

impl Server {
    /// Spawn the shipped binary with every environment fallback scrubbed.
    /// `kill_on_drop` reaps the child if an assertion panics.
    fn spawn(args: &[&str]) -> Self {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_bugwarden"));
        cmd.args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for var in scrub_env::AMBIENT_VARS {
            cmd.env_remove(var);
        }
        cmd.env("RUST_LOG", "info");
        cmd.kill_on_drop(true);
        let mut child = cmd.spawn().expect("the built binary must start");
        let stdin = child.stdin.take();
        let stderr = startup_line::stderr_lines(&mut child);
        Self {
            child,
            stdin,
            stderr,
            log: String::new(),
        }
    }

    /// Read stderr until a line contains `needle`, and return that line.
    /// The startup lines are the readiness barriers: see the module docs.
    async fn wait_for_stderr(&mut self, needle: &str) -> String {
        startup_line::wait_for_line(&mut self.stderr, &mut self.log, needle, EXIT_TIMEOUT).await
    }

    /// Next stderr line, recorded in `log`; `None` at EOF.
    async fn next_stderr_line(&mut self) -> Option<String> {
        startup_line::next_logged_line(&mut self.stderr, &mut self.log).await
    }

    fn pid(&self) -> u32 {
        self.child.id().expect("the child has a pid")
    }

    fn signal(&self, signal: &str) {
        let pid = self.pid();
        let status = std::process::Command::new("kill")
            .args(["-s", signal, &pid.to_string()])
            .status()
            .expect("kill must be executable");
        assert!(status.success(), "kill -s {signal} {pid} failed: {status}");
    }

    /// The process exits 0 — not a signal-kill, not an error — and its
    /// stderr shows the shutdown path ran.
    async fn assert_graceful_exit(mut self, what: &str) {
        let status = tokio::time::timeout(EXIT_TIMEOUT, self.child.wait())
            .await
            .unwrap_or_else(|_| panic!("{what}: the process must exit within {EXIT_TIMEOUT:?}"))
            .expect("the child must be waitable");
        // The tail of stderr: the exit raced the writes, so read to EOF
        // rather than assert on whatever had arrived by then.
        let _ = tokio::time::timeout(EXIT_TIMEOUT, async {
            while self.next_stderr_line().await.is_some() {}
        })
        .await;
        assert_eq!(
            status.code(),
            Some(0),
            "{what}: SIGTERM/SIGINT must be a clean exit 0, not a signal-kill \
             (code=None) or an error: status={status:?} stderr={log}",
            log = self.log
        );
        assert!(
            self.log.contains("received shutdown signal"),
            "{what}: the shutdown path must log that it ran: {log}",
            log = self.log
        );
    }

    /// The process exits `1` and says on stderr which bound it enforced.
    ///
    /// Same bound as [`Self::assert_graceful_exit`]: without the cap the
    /// child buffers the whole frame and waits for a delimiter that never
    /// arrives, so `wait` times out here rather than the suite hanging.
    async fn assert_over_cap_exit(mut self, what: &str) {
        let status = tokio::time::timeout(EXIT_TIMEOUT, self.child.wait())
            .await
            .unwrap_or_else(|_| {
                panic!("{what}: an over-cap frame must end the process within {EXIT_TIMEOUT:?}")
            })
            .expect("the child must be waitable");
        // The tail of stderr: the exit raced the writes, as above.
        let _ = tokio::time::timeout(EXIT_TIMEOUT, async {
            while self.next_stderr_line().await.is_some() {}
        })
        .await;
        assert_eq!(
            status.code(),
            Some(1),
            "{what}: a refused frame must be a failure exit, not the `0` rmcp's \
             silent close would produce: status={status:?} stderr={log}",
            log = self.log
        );
        assert!(
            self.log.contains(OVER_CAP_LINE),
            "{what}: bugwarden must log the cap it enforced: {log}",
            log = self.log
        );
    }
}

/// Spawn the stdio transport with a Bugzilla server nothing will reach:
/// the default policy needs no identity, so the preflight is a no-op and
/// the process serves without a single upstream call.
fn spawn_stdio() -> Server {
    Server::spawn(&[
        "--transport",
        "stdio",
        "--bugzilla-server",
        "https://bugzilla.example.invalid",
        "--api-key",
        "test-key",
    ])
}

/// Complete the MCP handshake over the child's pipes, then keep draining
/// its stdout so a cancel-path write cannot fill the pipe and block the
/// child's serve loop.
async fn initialize_and_drain(server: &mut Server) -> tokio::task::JoinHandle<()> {
    let stdin = server.stdin.as_mut().expect("stdin is piped");
    let stdout = server.child.stdout.take().expect("stdout is piped");
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
        "initialize must complete before the test acts: {reply}"
    );
    tokio::spawn(async move { while stdout.next_line().await.ok().flatten().is_some() {} })
}

/// Write one over-cap frame, delimiter-free, and ignore the write result:
/// the child refuses partway through and closes the pipe, so the tail of
/// this write is expected to fail with `BrokenPipe`. Bounded so a build
/// that buffers the whole thing fails here rather than hanging.
async fn write_an_over_cap_frame(server: &mut Server) {
    let stdin = server.stdin.as_mut().expect("stdin is piped");
    let frame = vec![b'a'; OVER_CAP_FRAME];
    let _ = tokio::time::timeout(EXIT_TIMEOUT, stdin.write_all(&frame)).await;
}

/// Spawn the http transport and return the address it actually bound.
///
/// `--port 0` leaves the choice to the kernel, which assigns the port to
/// the process that then keeps it: unlike bind-then-drop there is no window
/// for anything else on the host to take it (#173), the pattern
/// `tests/common/mod.rs` documents as known-bad. The address comes back
/// from the child's own startup line, which is also a stronger readiness
/// barrier than a connect probe — a stranger holding a guessed port would
/// have answered that probe on the child's behalf.
async fn spawn_http() -> (Server, SocketAddr) {
    let mut server = Server::spawn(&[
        "--bugzilla-server",
        "https://bugzilla.example.invalid",
        "--host",
        "127.0.0.1",
        "--port",
        "0",
        "--insecure-no-auth",
    ]);
    let line = server.wait_for_stderr(HTTP_READY).await;
    let addr = startup_line::parse_bound_addr(&line);
    wait_for_tcp(addr).await;
    (server, addr)
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
    let (server, _addr) = spawn_http().await;
    server.signal("TERM");
    server.assert_graceful_exit("http idle SIGTERM").await;
}

#[tokio::test]
async fn http_sigint_still_exits_zero() {
    let (server, _addr) = spawn_http().await;
    server.signal("INT");
    server.assert_graceful_exit("http idle SIGINT").await;
}

#[tokio::test]
async fn http_sigterm_cancels_a_live_session() {
    // axum's graceful shutdown waits for in-flight connections. A live
    // streamable-HTTP session is one: without `ct.cancel()` the process
    // stays up until this test's timeout, which is the mutation.
    let (server, addr) = spawn_http().await;
    let _session = connect_insecure(addr).await;
    server.signal("TERM");
    server
        .assert_graceful_exit("http live-session SIGTERM")
        .await;
}

#[tokio::test]
async fn stdio_sigterm_during_the_handshake_wait_exits_zero() {
    // `serve` blocks on initialize. A stdio container that no client has
    // spoken to yet is in this wait, not in `waiting()`.
    let mut server = spawn_stdio();
    // `Server` holds stdin open for the whole test: EOF there unblocks the
    // child's read, so a handshake arm that only `return Ok(())` would go
    // green.
    server.wait_for_stderr(STDIO_READY).await;
    server.signal("TERM");
    server
        .assert_graceful_exit("stdio pre-handshake SIGTERM")
        .await;
}

#[tokio::test]
async fn stdio_an_over_cap_frame_before_the_handshake_exits_one() {
    // Served on a bare `stdio()` this never returns: rmcp's `read_until`
    // takes all 5 MiB into an unbounded `Vec` and waits for the delimiter,
    // so `wait` times out instead of the process exiting (#234).
    let mut server = spawn_stdio();
    server.wait_for_stderr(STDIO_READY).await;
    write_an_over_cap_frame(&mut server).await;
    server
        .assert_over_cap_exit("stdio pre-handshake over-cap")
        .await;
}

#[tokio::test]
async fn stdio_sigterm_after_initialize_exits_zero() {
    let mut server = spawn_stdio();
    server.wait_for_stderr(STDIO_READY).await;
    let _drain = initialize_and_drain(&mut server).await;
    server.signal("TERM");
    server
        .assert_graceful_exit("stdio post-handshake SIGTERM")
        .await;
}

#[tokio::test]
async fn stdio_an_over_cap_frame_after_initialize_exits_one() {
    // The half no in-process test can reach: here the refusal reaches
    // `waiting()` as `QuitReason::Closed`, the same `Ok` a peer hangup
    // produces. Dropping the over-cap flag `main` checks turns this into
    // exit 0 and nothing else notices.
    let mut server = spawn_stdio();
    server.wait_for_stderr(STDIO_READY).await;
    let _drain = initialize_and_drain(&mut server).await;
    write_an_over_cap_frame(&mut server).await;
    server
        .assert_over_cap_exit("stdio post-handshake over-cap")
        .await;
}
