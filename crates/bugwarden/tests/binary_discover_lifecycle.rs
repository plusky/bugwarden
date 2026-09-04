//! What a `server/discover` probe does to the SHIPPED BINARY's stdio
//! session (issue #267).
//!
//! Only a process proves this. rmcp reads the stdio lifecycle off the first
//! frame in `serve_server_with_ct_inner` — code the in-process rows drive
//! too, but the failure the reporter hit was a *process* one: the probe
//! stuck a flag on the session's peer, or ended the process outright, and
//! everything after it was refused -32602 by a binary that looked healthy.
//! So both chains are driven end to end over real pipes, including the exit
//! code, which no in-process test observes.
//!
//! Coverage contract (each of these must fail a test here):
//! - the wrapper dropped from `main`, leaving rmcp to answer the probe;
//! - a probe answered but still committing the lifecycle;
//! - a probe rmcp refuses ending the process instead of the request.

use std::collections::HashSet;
use std::process::{ExitStatus, Stdio};
use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::process::{Child, ChildStdin};

#[path = "common/scrub_env.rs"]
mod scrub_env;

/// Bounded so a binary that never answers fails this test rather than
/// hanging the suite until CI's own timeout kills it.
const REPLY_BUDGET: Duration = Duration::from_secs(20);

/// A revision no build serves. Stands in for the next one a client adopts
/// before bugwarden does — the reporter's chain, and the one the Go SDK's
/// retry loop reads the served list back from.
const UNSERVED: &str = "2027-01-01";

/// Each binary runs the walker itself, so a single-binary
/// `cargo test --test binary_discover_lifecycle` still proves what its
/// scrub claims.
#[test]
fn the_scrub_list_covers_every_environment_fallback() {
    scrub_env::assert_the_scrub_list_covers_every_environment_fallback(
        scrub_env::AMBIENT_VARS,
        scrub_env::HTTP_TOKEN_VARS,
    );
}

/// A spawned `bugwarden --transport stdio`, driven over its real pipes.
///
/// Bugzilla is deliberately unreachable: every frame here is answered
/// before any upstream call, so the whole exchange happens without a mock.
struct Server {
    child: Child,
    stdin: ChildStdin,
    stdout: tokio::io::Lines<BufReader<tokio::process::ChildStdout>>,
}

impl Server {
    fn spawn() -> Self {
        Self::spawn_with(Stdio::null())
    }

    /// The same child with its log kept, for a test that pins what `main`
    /// said on the way out as well as what it exited with.
    fn spawn_logged() -> Self {
        Self::spawn_with(Stdio::piped())
    }

    fn spawn_with(stderr: Stdio) -> Self {
        let mut cmd = tokio::process::Command::new(env!("CARGO_BIN_EXE_bugwarden"));
        cmd.args(["--transport", "stdio"])
            .args(["--bugzilla-server", "https://bugzilla.example.invalid"])
            .args(["--api-key", "test-key"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(stderr)
            .kill_on_drop(true);
        // Scrubbed and NOT set back: an ambient value would change exactly
        // what is under test.
        for var in scrub_env::AMBIENT_VARS {
            cmd.env_remove(var);
        }
        let mut child = cmd.spawn().expect("the built binary must start");
        let stdin = child.stdin.take().expect("stdin is piped");
        let stdout = BufReader::new(child.stdout.take().expect("stdout is piped")).lines();
        Server {
            child,
            stdin,
            stdout,
        }
    }

    async fn send(&mut self, message: Value) {
        self.stdin
            .write_all(format!("{message}\n").as_bytes())
            .await
            .expect("the child must accept input");
    }

    /// The next frame the child wrote to stdout, parsed.
    async fn recv(&mut self) -> Value {
        let line = tokio::time::timeout(REPLY_BUDGET, self.stdout.next_line())
            .await
            .expect("the child must answer within the budget")
            .expect("the child's stdout must be readable")
            .expect("the child must not close stdout before answering");
        serde_json::from_str(&line).unwrap_or_else(|e| panic!("{line:?}: {e}"))
    }

    async fn call(&mut self, message: Value) -> Value {
        self.send(message).await;
        self.recv().await
    }

    /// Write every frame in one go, so the child is still writing replies
    /// when the next frames land — the contention that makes rmcp's
    /// `select!` cancel a `receive` mid-send.
    async fn burst(&mut self, frames: &[Value]) {
        let mut buffer = String::new();
        for frame in frames {
            buffer.push_str(&format!("{frame}\n"));
        }
        self.stdin
            .write_all(buffer.as_bytes())
            .await
            .expect("the child must accept input");
    }

    /// Close stdin and wait, yielding the exit status and the child's log
    /// (empty unless it was spawned with [`Server::spawn_logged`]).
    async fn finish(self) -> (ExitStatus, String) {
        drop(self.stdin);
        let output = tokio::time::timeout(REPLY_BUDGET, self.child.wait_with_output())
            .await
            .expect("the child must exit when stdin closes")
            .expect("the child must be waitable");
        (
            output.status,
            String::from_utf8_lossy(&output.stderr).into_owned(),
        )
    }

    /// Close stdin and wait: a clean peer hangup must end the process 0.
    /// A probe that ended the serve loop early exits 1 here.
    async fn close(self) {
        let (status, _) = self.finish().await;
        assert!(
            status.success(),
            "a probe must refuse the request, never the process: {status}"
        );
    }
}

/// The Go SDK v1.7.0 discover frame (`mcp/client.go`): the two required
/// `_meta` keys plus the client's own identity, which is what makes this
/// the shape a real client sends rather than a minimal one.
fn go_sdk_discover(id: u32, version: &str) -> Value {
    json!({
        "jsonrpc": "2.0", "id": id, "method": "server/discover",
        "params": { "_meta": {
            "io.modelcontextprotocol/protocolVersion": version,
            "io.modelcontextprotocol/clientCapabilities": {},
            "io.modelcontextprotocol/clientInfo": { "name": "agy", "version": "1.7.0" },
        }}
    })
}

/// The legacy handshake the Go SDK falls back to when its probe loop gives
/// up, at the revision it names.
fn legacy_initialize(id: u32) -> Value {
    json!({
        "jsonrpc": "2.0", "id": id, "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": { "name": "agy", "version": "1.7.0" },
        }
    })
}

/// A `tools/list` with no `_meta`, which is every legacy client's listing.
fn bare_list(id: u32) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "method": "tools/list", "params": {} })
}

#[tokio::test]
async fn a_refused_probe_leaves_the_legacy_handshake_intact() {
    // The reported chain, byte for byte. The probe is refused -32022 with
    // the served list — that part always worked — and the session the
    // client then opens must serve its `_meta`-free listing.
    let mut server = Server::spawn();
    let probe = server.call(go_sdk_discover(1, UNSERVED)).await;
    assert_eq!(probe["error"]["code"], json!(-32022), "{probe}");
    assert_eq!(probe["error"]["data"]["requested"], UNSERVED, "{probe}");
    assert!(
        probe["error"]["data"]["supported"]
            .as_array()
            .is_some_and(|served| served.contains(&json!("2026-07-28"))),
        "the refusal must hand back the served list the client retries from: {probe}"
    );

    let init = server.call(legacy_initialize(2)).await;
    assert_eq!(init["result"]["protocolVersion"], "2025-11-25", "{init}");
    server
        .send(json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }))
        .await;

    let listed = server.call(bare_list(3)).await;
    assert!(
        listed["result"]["tools"]
            .as_array()
            .is_some_and(|tools| !tools.is_empty()),
        "a probed-then-handshook session must be served its tools: {listed}"
    );
    server.close().await;
}

#[tokio::test]
async fn a_served_probe_leaves_the_legacy_handshake_intact() {
    // The same chain with a probe this build DOES serve — the commoner
    // shape, and the one that fails without a client ever seeing an error
    // before the listing.
    let mut server = Server::spawn();
    let probe = server.call(go_sdk_discover(1, "2026-07-28")).await;
    assert_eq!(
        probe["result"]["_meta"]["io.modelcontextprotocol/serverInfo"],
        json!({ "name": "bugwarden", "version": env!("CARGO_PKG_VERSION") }),
        "the probe must name this build: {probe}"
    );

    server.call(legacy_initialize(2)).await;
    server
        .send(json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }))
        .await;
    let listed = server.call(bare_list(3)).await;
    assert!(
        listed["result"]["tools"]
            .as_array()
            .is_some_and(|tools| !tools.is_empty()),
        "a served probe must not commit the session either: {listed}"
    );
    server.close().await;
}

#[tokio::test]
async fn a_probe_with_no_meta_refuses_the_request_not_the_process() {
    // On main this frame was answered and then ended the process with
    // `ExpectedInitializeRequest` (exit 1), so the client's `initialize`
    // read EOF. The refusal text is rmcp's own and unchanged; what the fix
    // changes is that the session survives it — and that the process still
    // exits 0 when the peer hangs up for real.
    let mut server = Server::spawn();
    let probe = server
        .call(
            json!({ "jsonrpc": "2.0", "id": 1, "method": "server/discover",
                      "params": {} }),
        )
        .await;
    assert_eq!(probe["error"]["code"], json!(-32602), "{probe}");
    assert_eq!(
        probe["error"]["message"],
        json!(
            "request _meta is missing or has malformed required fields: \
             io.modelcontextprotocol/protocolVersion, \
             io.modelcontextprotocol/clientCapabilities"
        ),
        "{probe}"
    );

    let init = server.call(legacy_initialize(2)).await;
    assert_eq!(init["result"]["protocolVersion"], "2025-11-25", "{init}");
    server
        .send(json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }))
        .await;
    let listed = server.call(bare_list(3)).await;
    assert!(
        listed["result"]["tools"]
            .as_array()
            .is_some_and(|tools| !tools.is_empty()),
        "a malformed probe must not end the session: {listed}"
    );
    server.close().await;
}

#[tokio::test]
async fn a_probe_still_commits_nothing_that_a_declaring_request_does_not() {
    // The guard the fix must not weaken, at binary level: rmcp's
    // per-request lifecycle is still chosen by the first `_meta`-carrying
    // request, and rmcp's gate still refuses one that drops the `_meta`
    // afterwards. A wrapper that had relaxed anything past discover serves
    // the second listing instead.
    let mut server = Server::spawn();
    server.call(go_sdk_discover(1, "2026-07-28")).await;
    let declared = server
        .call(json!({
            "jsonrpc": "2.0", "id": 2, "method": "tools/list",
            "params": { "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {},
            }}
        }))
        .await;
    assert!(
        declared["result"]["tools"]
            .as_array()
            .is_some_and(|tools| !tools.is_empty()),
        "{declared}"
    );
    let bare = server.call(bare_list(3)).await;
    assert_eq!(
        bare["error"]["code"],
        json!(-32602),
        "the handshake-free lifecycle must still demand per-request _meta: {bare}"
    );
    server.close().await;
}

#[tokio::test]
async fn a_probe_only_client_hangs_up_cleanly() {
    // The simplest client there is — probe, read, close — and the one the
    // wrapper puts on rmcp's least travelled path: the probe never
    // reaches rmcp, so rmcp is still inside `expect_next_message`'s wait
    // for a first COMMITTING frame when stdin ends, and calls that
    // `ConnectionClosed` rather than a clean close
    // (`service/server.rs:432, 511`). `main` reads it as the hangup it is
    // — exit 0, as before #267 and as for every other peer that just
    // leaves — whether the probe was served or refused.
    for probe in [
        go_sdk_discover(1, "2026-07-28"),
        go_sdk_discover(1, UNSERVED),
        json!({ "jsonrpc": "2.0", "id": 1, "method": "server/discover", "params": {} }),
    ] {
        let mut server = Server::spawn_logged();
        server.call(probe.clone()).await;
        let (status, log) = server.finish().await;
        assert!(
            status.success(),
            "a probe-only client hung up: {probe}: {status}"
        );
        assert!(
            log.contains("peer hung up after a server/discover probe"),
            "the hangup must be logged as one: {probe}: {log}"
        );
        assert!(
            !log.contains("serving error"),
            "a hangup is not a serving failure: {probe}: {log}"
        );
    }
}

#[tokio::test]
async fn a_pipelined_probe_is_answered_over_real_pipes() {
    // A probe behind other traffic, which no lock-step row here reaches:
    // rmcp polls `receive` as one arm of a `select!` (rmcp 3.1.4
    // `service.rs:1395`) and drops that future whenever another arm wins,
    // so a reply the wrapper awaited on `receive`'s own stack would be
    // dropped with it — the frame consumed, the id never answered, the
    // client hung on it while every other reply arrives. The listings are
    // the filler because their replies are far larger than a pipe.
    const FRAMES: u32 = 40;
    let mut server = Server::spawn();
    server.call(legacy_initialize(1)).await;
    server
        .send(json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }))
        .await;
    let frames: Vec<Value> = (2..=FRAMES + 1)
        .map(|id| {
            if id % 2 == 0 {
                go_sdk_discover(id, "2026-07-28")
            } else {
                bare_list(id)
            }
        })
        .collect();
    server.burst(&frames).await;
    let mut answered = HashSet::new();
    for _ in 0..FRAMES {
        let reply = server.recv().await;
        answered.insert(
            reply["id"]
                .as_u64()
                .unwrap_or_else(|| panic!("every reply names its request: {reply}")),
        );
    }
    let unanswered: Vec<u64> = (2..=u64::from(FRAMES) + 1)
        .filter(|id| !answered.contains(id))
        .collect();
    assert!(unanswered.is_empty(), "unanswered ids: {unanswered:?}");
    server.close().await;
}
