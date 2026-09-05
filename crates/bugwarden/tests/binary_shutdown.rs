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
//! It also pins what the two lines a failed stdio handshake writes may say
//! (#261). rmcp's `ServerInitializeError` carries the client's whole first
//! frame in its Debug *and* its Display, so logging the error, or letting
//! it reach `main`'s `anyhow::Result` where Rust prints `Error: {:?}` of
//! it, put a client-sized string on stderr twice. `main` classifies it to
//! one of its own literals instead, and only a process shows both lines:
//! the exit line is written by the runtime after `main` returns.
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
//!   which exits 0 on a refusal it was the point of refusing;
//! - the over-cap frame refused BEFORE the handshake described as a peer
//!   hangup, or in any wording but the one the post-handshake refusal uses;
//! - either handshake-failure line formatting rmcp's error instead of the
//!   classification, or the classification naming the wrong frame kind;
//! - any `serve_failure` arm deleted so its failure falls to the wildcard,
//!   or any two of its literals exchanged. Three arms have no row, and
//!   cannot: `ExpectedInitializeRequest(None)` is constructed nowhere in
//!   rmcp 3.1.4, `UnexpectedInitializeResponse` cannot happen while rmcp
//!   maps this handler's own `InitializeResult` into the result it then
//!   checks, and `Cancelled` needs a cancellation token `ServiceExt::serve`
//!   creates and never cancels. cargo-mutants reaches only the OUTER
//!   match's arms, so the four frame kinds share one generated mutant and
//!   the rows that separate them are the exchanged-literal ones — which
//!   is why the four texts differ in more than one word each.
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

/// The refusal `main` itself reports for that frame, and the whole of the
/// line the process then exits with.
///
/// Two constants because they are two different statements: the one above
/// is the reader saying which bound it applied, this one is `main` saying
/// what became of the session. This one must read the same whichever side
/// of `initialize` the frame arrived on.
const OVER_CAP_CLOSE: &str = "stdio transport closed: an inbound frame exceeded the request cap";
const OVER_CAP_EXIT_LINE: &str =
    "Error: stdio transport closed: an inbound frame exceeded the request cap";

/// The `serving error` line's prefix, and the whole of the exit line's.
///
/// `main` writes the first; the runtime writes the second from the
/// `anyhow::Error` `main` returned. Both must be followed by a
/// classification `main` authored and nothing else (#261).
const SERVING_ERROR_PREFIX: &str = "serving error: ";
const EXIT_LINE_PREFIX: &str = "Error: stdio serving failed: ";

/// Ceiling on either of those lines, in characters.
///
/// The longest classification any of these rows can reach is 51 chars (53
/// counting `UnexpectedInitializeResponse`, which nothing can reach), and
/// the `serving error` line carries tracing's timestamp, level and target
/// ahead of it — 111 chars measured. The defect these tests exist for
/// produced 100 403 and 100 365, so anything between the two is a bound;
/// 200 is chosen close enough to the real lines that a *new* client string
/// leaking in would trip it too.
const HANDSHAKE_LINE_MAX: usize = 200;

/// A client string long enough that a line embedding it is bounded by the
/// 4 MiB frame cap and by nothing else.
const FILLER_CHARS: usize = 100_000;

/// A run of filler this long appears in no line the binary authors, so
/// finding one on stderr means client bytes reached it. Well under
/// `PARAM_VALUE_MAX_CHARS`, so even a line merely *capped* at the server's
/// usual 1024-char bound would still fail — these two lines carry no
/// client text at all, not a shortened copy of it.
const FILLER_RUN: usize = 64;

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
        Self::spawn_with_stdout(args, Stdio::piped())
    }

    /// [`Self::spawn`] with the child's stdout chosen by the caller, for
    /// the one row that needs a stdout nothing will ever read.
    fn spawn_with_stdout(args: &[&str], stdout: Stdio) -> Self {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_bugwarden"));
        cmd.args(args)
            .stdin(Stdio::piped())
            .stdout(stdout)
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
    ///
    /// The exit line is asserted for every caller, because it is the one
    /// sentence the refusal must not vary: the cap fires the same way on
    /// both sides of `initialize`, and rmcp hands the two sides different
    /// error shapes for it — `ConnectionClosed` out of `serve`, an
    /// ordinary `Ok` close out of `waiting()` — so nothing but this
    /// assertion keeps them from drifting into two descriptions of one
    /// refusal (#261). `pre_handshake` says the refusal came out of
    /// `serve`, which additionally writes the classified `serving error`
    /// line; the post-handshake arm writes only the exit line.
    async fn assert_over_cap_exit(mut self, what: &str, pre_handshake: bool) {
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
        assert!(
            self.log.lines().any(|line| line == OVER_CAP_EXIT_LINE),
            "{what}: the process must exit naming the cap, in the one wording \
             both sides of the handshake share: {log}",
            log = self.log
        );
        let serving_error = self
            .log
            .lines()
            .find(|line| line.contains(SERVING_ERROR_PREFIX));
        if pre_handshake {
            let line = serving_error.unwrap_or_else(|| {
                panic!(
                    "{what}: a refusal out of `serve` must log it: {log}",
                    log = self.log
                )
            });
            assert!(
                line.ends_with(OVER_CAP_CLOSE),
                "{what}: the `serving error` line must name the cap, not a \
                 hangup the peer never chose: {line}"
            );
            assert!(
                line.chars().count() <= HANDSHAKE_LINE_MAX,
                "{what}: the `serving error` line must stay under \
                 {HANDSHAKE_LINE_MAX} chars: {len} chars",
                len = line.chars().count()
            );
        } else {
            assert!(
                serving_error.is_none(),
                "{what}: a refusal out of `waiting()` never entered `serve`'s \
                 error path: {log}",
                log = self.log
            );
        }
    }

    /// The process exits `1`, and both lines a failed handshake writes
    /// carry `classification` and nothing the client chose (#261).
    ///
    /// `forbidden` is checked against the WHOLE log, not just those two
    /// lines: the frame reached rmcp's own tracing too, so a leak that
    /// moved rather than stopped must fail here.
    ///
    /// Bounded like the other two waits: without the fix the process still
    /// exits 1, so what fails here is the size and content of the lines,
    /// not the wait. Stderr is drained BEFORE the wait, unlike the two
    /// above: the unfixed lines are larger than a pipe, so a `wait()` first
    /// deadlocks against the child's own blocked write and the assertions
    /// below never run.
    async fn assert_bounded_handshake_failure(
        mut self,
        what: &str,
        classification: &str,
        forbidden: Option<&str>,
    ) {
        // To EOF, which the exit closes — and the exit line is the LAST
        // thing written, so nothing shorter sees it at all.
        let drained = tokio::time::timeout(EXIT_TIMEOUT, async {
            while self.next_stderr_line().await.is_some() {}
        })
        .await;
        assert!(
            drained.is_ok(),
            "{what}: a failed handshake must end the process within {EXIT_TIMEOUT:?}: {log}",
            log = self.log
        );
        let status = tokio::time::timeout(EXIT_TIMEOUT, self.child.wait())
            .await
            .unwrap_or_else(|_| panic!("{what}: the process must be reaped after its stderr ends"))
            .expect("the child must be waitable");
        assert_eq!(
            status.code(),
            Some(1),
            "{what}: a failed handshake must stay a failure exit: status={status:?} \
             stderr={log}",
            log = self.log
        );
        for prefix in [SERVING_ERROR_PREFIX, EXIT_LINE_PREFIX] {
            let mut matched = self.log.lines().filter(|line| line.contains(prefix));
            let line = matched.next().unwrap_or_else(|| {
                panic!(
                    "{what}: stderr must carry a {prefix:?} line: {log}",
                    log = self.log
                )
            });
            assert!(
                matched.next().is_none(),
                "{what}: {prefix:?} must be written once, not per attempt: {log}",
                log = self.log
            );
            assert!(
                line.ends_with(classification),
                "{what}: {prefix:?} must be followed by the classification and \
                 nothing else: {line}"
            );
            assert!(
                line.chars().count() <= HANDSHAKE_LINE_MAX,
                "{what}: {prefix:?} must stay under {HANDSHAKE_LINE_MAX} chars, \
                 not grow with the frame: {len} chars",
                len = line.chars().count()
            );
        }
        if let Some(needle) = forbidden {
            assert!(
                !self.log.contains(needle),
                "{what}: no {run}-char run of the client's own string may reach \
                 stderr: {log}",
                run = needle.chars().count(),
                log = self.log
            );
        }
    }

    /// Write one newline-delimited frame, ignoring the write result and
    /// bounding the wait: the child answers some of these and dies on all
    /// of them, so the tail of a large frame may meet a closed pipe.
    async fn write_frame(&mut self, frame: &str) {
        let stdin = self.stdin.as_mut().expect("stdin is piped");
        let _ = tokio::time::timeout(EXIT_TIMEOUT, stdin.write_all(frame.as_bytes())).await;
        let _ = tokio::time::timeout(EXIT_TIMEOUT, stdin.write_all(b"\n")).await;
    }

    /// Close the child's stdin, which is the peer hanging up.
    ///
    /// Exposed to the same fd inheritance `stdout_with_no_reader` exists
    /// to defeat — a sibling row's in-flight spawn holds a copy of this
    /// write end — but benignly: an extra writer only DELAYS the child's
    /// EOF until that sibling execs, and the frame it then reads is the
    /// same one. Measured under eight threads spawning in a loop, the
    /// worst close-to-exit was 20 ms against this file's 5s budget, and
    /// no run read a different classification. Closing after the spawn is
    /// also what the row is about: a peer that connected and left.
    fn close_stdin(&mut self) {
        self.stdin = None;
    }
}

/// A stdout with no reader anywhere, proven so before the child exists.
///
/// Closing the read end AFTER the spawn does not do this. `EPIPE` needs
/// the reader count to be zero, and every concurrent `Command::spawn` in
/// this process duplicates the whole fd table until its exec — so a
/// sibling row's in-flight spawn holds a copy of this pipe's read end, the
/// child's reply lands in the buffer instead of failing, and rmcp goes on
/// to `ExpectedInitializeRequest`. That is what CI hit, and hammering
/// `/bin/true` spawns from eight threads loses the same race here about a
/// third of the time.
///
/// So the reader is dropped before anything can fork, and the probing
/// write is the proof rather than an argument: `BrokenPipe` means the
/// kernel counted zero readers at that instant, and a fork that had copied
/// the fd earlier would still be holding it. Past that point this process
/// owns no read end, so no later fork can make one and the child's write
/// cannot succeed on any schedule. The retry is for the one case the probe
/// itself can lose — a sibling that forked just before the drop and has
/// not reached its exec — and normally does not run at all.
fn stdout_with_no_reader() -> Stdio {
    let (reader, mut writer) = std::io::pipe().expect("the test host must provide a pipe");
    drop(reader);
    for _ in 0..PROBE_ATTEMPTS {
        match std::io::Write::write(&mut writer, b"\0") {
            Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => return Stdio::from(writer),
            // A byte in the buffer is harmless: EPIPE counts readers, not
            // bytes, so the child still fails once the last one is gone.
            _ => std::thread::sleep(PROBE_WAIT),
        }
    }
    panic!("a pipe whose only reader was dropped never became BrokenPipe");
}

/// `run` copies of `filler`, as one string: the needle a leaked client
/// string would put on stderr.
fn run_of(filler: char, run: usize) -> String {
    std::iter::repeat_n(filler, run).collect()
}

/// Bound on [`stdout_with_no_reader`]'s probe: an inherited copy of the
/// read end lives only until the forking sibling execs, which is orders of
/// magnitude inside this, and a probe that never breaks means something
/// other than a spawn race is holding the fd — worth failing over.
const PROBE_ATTEMPTS: usize = 1000;
const PROBE_WAIT: Duration = Duration::from_millis(1);

/// Spawn the stdio transport with a Bugzilla server nothing will reach:
/// the default policy needs no identity, so the preflight is a no-op and
/// the process serves without a single upstream call.
fn spawn_stdio() -> Server {
    Server::spawn(&STDIO_ARGS)
}

/// The arguments [`spawn_stdio`] uses, named so the one row that spawns
/// with its own stdout starts the same server every other row does.
const STDIO_ARGS: [&str; 6] = [
    "--transport",
    "stdio",
    "--bugzilla-server",
    "https://bugzilla.example.invalid",
    "--api-key",
    "test-key",
];

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

/// Answer a `server/discover` probe over the child's pipes, then keep
/// draining its stdout, as [`initialize_and_drain`] does. The probe is
/// answered by the transport wrapper and commits no lifecycle (#267), so
/// rmcp is still waiting for a first committing frame afterwards.
async fn probe_and_drain(server: &mut Server) -> tokio::task::JoinHandle<()> {
    let stdin = server.stdin.as_mut().expect("stdin is piped");
    let stdout = server.child.stdout.take().expect("stdout is piped");
    let mut stdout = BufReader::new(stdout).lines();
    stdin
        .write_all(
            br#"{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}
"#,
        )
        .await
        .expect("the child must accept the probe");
    let reply = tokio::time::timeout(EXIT_TIMEOUT, stdout.next_line())
        .await
        .expect("the probe must not hang")
        .expect("stdout must be readable")
        .expect("the server must answer the probe");
    assert!(
        reply.contains("supportedVersions"),
        "the probe must be answered before the test acts: {reply}"
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
        .assert_over_cap_exit("stdio pre-handshake over-cap", true)
        .await;
}

#[tokio::test]
async fn stdio_a_probe_then_an_over_cap_frame_still_exits_one() {
    // The one exit `main` forgives since #267 is a hangup after a probe,
    // and only that: an over-cap frame closes the transport exactly the
    // same way (`receive() -> None`, then rmcp's `ConnectionClosed`), so
    // a probed session must not turn the refused frame into exit 0.
    let mut server = spawn_stdio();
    server.wait_for_stderr(STDIO_READY).await;
    let _drain = probe_and_drain(&mut server).await;
    write_an_over_cap_frame(&mut server).await;
    server
        .assert_over_cap_exit("stdio probed pre-handshake over-cap", true)
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
        .assert_over_cap_exit("stdio post-handshake over-cap", false)
        .await;
}

#[tokio::test]
async fn stdio_a_pre_initialize_tool_call_never_logs_the_frame() {
    // The #261 reproduction. rmcp answers this frame -32602 (its `_meta`
    // declares no handshake-free lifecycle) and then hands `main`
    // `ExpectedInitializeRequest(Some(..))` holding the whole request, so
    // both the `serving error` line and the runtime's `Error:` line grew
    // with the query: 100 403 and 100 365 chars measured.
    let mut server = spawn_stdio();
    server.wait_for_stderr(STDIO_READY).await;
    let query = run_of('a', FILLER_CHARS);
    server
        .write_frame(&format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"bug_info","arguments":{{"query":"{query}"}}}}}}"#
        ))
        .await;
    server
        .assert_bounded_handshake_failure(
            "stdio pre-handshake tools/call",
            "the first frame was a request other than initialize",
            Some(&run_of('a', FILLER_RUN)),
        )
        .await;
}

#[tokio::test]
async fn stdio_a_pre_initialize_notification_is_named_by_kind() {
    // The other construction site: a non-request frame never reaches
    // rmcp's `_meta` check, so this one is refused with no reply at all.
    // The kind is the whole diagnostic — the method is not named, because
    // `ClientRequest::CustomRequest` makes method names client free text.
    let mut server = spawn_stdio();
    server.wait_for_stderr(STDIO_READY).await;
    server
        .write_frame(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#)
        .await;
    server
        .assert_bounded_handshake_failure(
            "stdio pre-handshake notification",
            "the first frame was a notification, not initialize",
            None,
        )
        .await;
}

#[tokio::test]
async fn stdio_a_pre_initialize_response_never_logs_its_id() {
    // A JSON-RPC string id is client-chosen text of any length, and this
    // frame carries nothing else worth logging — so the kind is named and
    // the id is absent, not shortened.
    let mut server = spawn_stdio();
    server.wait_for_stderr(STDIO_READY).await;
    let id = run_of('x', 4096);
    server
        .write_frame(&format!(r#"{{"jsonrpc":"2.0","id":"{id}","result":{{}}}}"#))
        .await;
    server
        .assert_bounded_handshake_failure(
            "stdio pre-handshake response",
            "the first frame was a response, not initialize",
            Some(&run_of('x', FILLER_RUN)),
        )
        .await;
}

#[tokio::test]
async fn stdio_a_pre_initialize_error_reply_never_logs_its_message() {
    // The fourth frame kind, and the one whose payload is free text by
    // protocol: `ErrorData::message` is whatever the client wrote.
    let mut server = spawn_stdio();
    server.wait_for_stderr(STDIO_READY).await;
    let message = run_of('e', FILLER_CHARS);
    server
        .write_frame(&format!(
            r#"{{"jsonrpc":"2.0","id":1,"error":{{"code":-32000,"message":"{message}"}}}}"#
        ))
        .await;
    server
        .assert_bounded_handshake_failure(
            "stdio pre-handshake error reply",
            "the first frame was an error reply, not initialize",
            Some(&run_of('e', FILLER_RUN)),
        )
        .await;
}

#[tokio::test]
async fn stdio_a_hangup_before_initialize_is_classified_not_echoed() {
    // `ConnectionClosed`, which an EOF, a read error and this build's own
    // frame-cap refusal all reach — so the classification is deliberately
    // neutral about who ended the stream, and the over-cap rows above pin
    // the one case `main` can name. Its payload is server-authored today,
    // which is exactly why it must not be echoed either: a `String` on a
    // `#[non_exhaustive]` enum is an upstream bump away from client text.
    let mut server = spawn_stdio();
    server.wait_for_stderr(STDIO_READY).await;
    server.close_stdin();
    server
        .assert_bounded_handshake_failure(
            "stdio pre-handshake hangup",
            "the stream ended before initialize",
            None,
        )
        .await;
}

#[tokio::test]
async fn stdio_a_broken_stdout_during_the_handshake_is_classified() {
    // The one arm reached by an I/O condition rather than by a frame:
    // rmcp answers this request -32602 and the write meets a closed pipe,
    // so `serve` returns `TransportError`. Its payload holds the
    // transport's own type name and an `io::Error` — no client bytes, but
    // it is a `DynamicTransportError` on a `#[non_exhaustive]` enum, so it
    // is classified like every other arm rather than trusted.
    // The stdout is dead before the child is spawned, not closed after it
    // — see `stdout_with_no_reader` for why the difference is the whole
    // determinism of this row.
    let mut server = Server::spawn_with_stdout(&STDIO_ARGS, stdout_with_no_reader());
    server.wait_for_stderr(STDIO_READY).await;
    server
        .write_frame(r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#)
        .await;
    server
        .assert_bounded_handshake_failure(
            "stdio pre-handshake broken stdout",
            "the stdio transport failed during the handshake",
            None,
        )
        .await;
}

/// The audit sink's own `initialize` refusal, reachable only on Linux.
///
/// `initialize` has exactly one production `Err`: a record the sink would
/// not take under `fail_mode = "closed_all"`. Making a sink that already
/// opened refuse a record afterwards needs the write to fail, and
/// `/dev/full` — which opens like a regular file and answers every write
/// `ENOSPC` — is the way to arrange that without privileges or a mount of
/// this test's own. It is Linux-only, so this row is too: macOS runs the
/// same suite and has no such device.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn stdio_a_refused_initialize_is_classified_not_echoed() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let config = dir.path().join("audit.toml");
    std::fs::write(
        &config,
        "path = \"/dev/full\"\nfail_mode = \"closed_all\"\n",
    )
    .expect("the audit config must be writable");
    let mut server = Server::spawn(&[
        "--transport",
        "stdio",
        "--bugzilla-server",
        "https://bugzilla.example.invalid",
        "--api-key",
        "test-key",
        "--audit-config",
        config.to_str().expect("a utf-8 temp path"),
    ]);
    server.wait_for_stderr(STDIO_READY).await;
    server
        .write_frame(
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"binary-shutdown-test","version":"0"}}}"#,
        )
        .await;
    server
        .assert_bounded_handshake_failure(
            "stdio initialize refused by the audit sink",
            "this server refused initialize",
            None,
        )
        .await;
}
