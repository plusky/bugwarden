//! What `main`'s startup wiring does, driven through the SHIPPED BINARY
//! (issue #269).
//!
//! Three sites in `main.rs` run in a spawned process and nowhere else: the
//! I9 tightening `policy.global.read_only |= cli.read_only`, the arm that
//! loads the operator's `--audit-config` document for a file-bearing sink
//! selection, and the "auditing is OFF" warning. Every in-process suite
//! hands `BugWarden::new` a `Policy` it built itself and attaches its
//! audit state afterwards through `with_audit`, so none of them executes
//! a line of this — which is why a mutation run left all three bare.
//!
//! Coverage contract (each of these mutations must fail a test here):
//! - `|=` at the tightening site becoming `^=`, which makes `--read-only`
//!   CLEAR a policy that already said `read_only = true`;
//! - the same `|=` becoming `&=`, which makes `--read-only` never tighten
//!   a policy that said `false` — and makes a policy that said `true`
//!   depend on the flag to mean anything at all;
//! - the `FileOnly | Both` arm deleted, which silently substitutes
//!   `AuditConfig::fileless()` for the operator's document and writes no
//!   audit file at all;
//! - the warning condition's `==` becoming `!=` or its `&&` becoming
//!   `||`, either of which fires the warning in the wrong deployments.
//!
//! Bugzilla is deliberately unreachable everywhere here: the default
//! policy consults no identity, so the preflight makes no request, and
//! every frame these tests send is answered before any upstream call.

use std::collections::BTreeSet;
use std::path::Path;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use bugwarden::server::WRITE_TOOLS;
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::process::{Child, ChildStdin, Command};

#[path = "common/scrub_env.rs"]
mod scrub_env;

#[path = "common/startup_line.rs"]
mod startup_line;

/// Bounded so a binary that never answers fails this test rather than
/// hanging the suite until CI's own timeout kills it. The same budget
/// `binary_user_agent` and `binary_discover_lifecycle` give a child.
const REPLY_BUDGET: Duration = Duration::from_secs(20);

/// The needle both transports' readiness lines start with — the http one
/// continues with the bound address, the stdio one with `stdio`. Every
/// line this file reads stderr for is logged BEFORE it, so matching it is
/// proof that the startup sequence ran past the site under test.
const STARTUP_READY: &str = "Starting Bugzilla MCP server on ";

/// Enough of the warning at `main.rs:192` to identify it and no more: the
/// rest of the text names the two ways to configure a sink and would tie
/// this file to that wording.
const NO_AUDIT_WARNING: &str = "auditing is OFF";

/// Each binary runs the walker itself, so a single-binary
/// `cargo test --test binary_startup_policy` still proves what its scrub
/// claims.
#[test]
fn the_scrub_list_covers_every_environment_fallback() {
    scrub_env::assert_the_scrub_list_covers_every_environment_fallback(
        scrub_env::AMBIENT_VARS,
        scrub_env::HTTP_TOKEN_VARS,
    );
}

/// The shipped binary, spawned with every environment fallback scrubbed
/// and NOT set back: an ambient value would change exactly what is under
/// test. `RUST_LOG` goes with them, so the stderr assertions read the
/// lines at the level `main` falls back to.
fn command(args: &[&str]) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_bugwarden"));
    cmd.args(args).kill_on_drop(true);
    for var in scrub_env::AMBIENT_VARS {
        cmd.env_remove(var);
    }
    cmd
}

/// A spawned `bugwarden --transport stdio`, driven over its real pipes.
struct Server {
    child: Child,
    stdin: ChildStdin,
    stdout: tokio::io::Lines<BufReader<tokio::process::ChildStdout>>,
}

impl Server {
    /// `args` are appended to the stdio transport, the unreachable
    /// Bugzilla server and the startup key every case here shares.
    fn spawn(args: &[&str]) -> Self {
        let mut cmd = command(&[
            "--transport",
            "stdio",
            "--bugzilla-server",
            "https://bugzilla.example.invalid",
            "--api-key",
            "test-key",
        ]);
        cmd.args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
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
    async fn call(&mut self, message: Value) -> Value {
        self.send(message).await;
        let line = tokio::time::timeout(REPLY_BUDGET, self.stdout.next_line())
            .await
            .expect("the child must answer within the budget")
            .expect("the child's stdout must be readable")
            .expect("the child must not close stdout before answering");
        serde_json::from_str(&line).unwrap_or_else(|e| panic!("{line:?}: {e}"))
    }

    /// Complete the MCP handshake, so the session may be served.
    async fn handshake(&mut self) {
        let init = self
            .call(json!({
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {},
                    "clientInfo": { "name": "binary-startup-policy-test", "version": "0" }
                }
            }))
            .await;
        assert_eq!(init["result"]["protocolVersion"], "2025-11-25", "{init}");
        self.send(json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }))
            .await;
    }

    /// Close stdin and wait for a clean exit, so a child is never left
    /// behind holding the tempdir a test is about to drop.
    async fn close(mut self) {
        drop(self.stdin);
        let status = tokio::time::timeout(REPLY_BUDGET, self.child.wait())
            .await
            .expect("the child must exit when stdin closes")
            .expect("the child must be waitable");
        assert_eq!(
            status.code(),
            Some(0),
            "a peer hangup must end the process cleanly: {status}"
        );
    }
}

/// A guard policy that says `read_only = <read_only>` and nothing else,
/// written where a spawned child can read it.
///
/// `dir` is the caller's own `tempfile::tempdir()`, never a shared path:
/// libtest runs these cases on parallel threads, and a fixed name would
/// have two of them truncating and rewriting one file while a third child
/// reads it.
fn policy_file(dir: &Path, read_only: bool) -> PathBuf {
    let path = dir.join(format!("policy-read-only-{read_only}.toml"));
    std::fs::write(&path, format!("[global]\nread_only = {read_only}\n"))
        .expect("the policy file must be writable");
    path
}

/// The tool names a spawned binary lists under `policy`, with
/// `--read-only` passed or not.
async fn listed_tools(policy: &Path, read_only_flag: bool) -> BTreeSet<String> {
    let policy = policy.to_str().expect("utf-8 path");
    let mut args = vec!["--policy", policy];
    if read_only_flag {
        args.push("--read-only");
    }
    let mut server = Server::spawn(&args);
    server.handshake().await;
    let listed = server
        .call(json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {} }))
        .await;
    let tools: BTreeSet<String> = listed["result"]["tools"]
        .as_array()
        .unwrap_or_else(|| panic!("a served listing carries an array of tools: {listed}"))
        .iter()
        .map(|tool| {
            tool["name"]
                .as_str()
                .unwrap_or_else(|| panic!("every listed tool is named: {listed}"))
                .to_owned()
        })
        .collect();
    server.close().await;
    tools
}

/// A restricted listing is exactly the `loosened` one minus
/// [`WRITE_TOOLS`] — asserted in both directions, so neither an empty
/// listing nor one that lost a read tool can pass for a delisting.
///
/// `loosened` is a deployment that restricts nothing, and its only job is
/// to prove the write-tool names exist to be removed; it is not a
/// one-variable control for every caller (see the `^=` test).
fn assert_delisted(restricted: &BTreeSet<String>, loosened: &BTreeSet<String>, what: &str) {
    for name in WRITE_TOOLS {
        assert!(
            loosened.contains(*name),
            "{what}: {name} must be listed by a deployment that restricts \
             nothing, or its absence under one proves nothing: {loosened:?}"
        );
        assert!(
            !restricted.contains(*name),
            "{what}: {name} must be removed from the listing (I13): {restricted:?}"
        );
    }
    let expected: BTreeSet<String> = loosened
        .iter()
        .filter(|name| !WRITE_TOOLS.contains(&name.as_str()))
        .cloned()
        .collect();
    assert!(
        !expected.is_empty(),
        "{what}: the read tools must survive the restriction, \
         or the assertion below passes on an empty listing"
    );
    assert_eq!(
        *restricted, expected,
        "{what}: read-only removes the write tools and nothing else"
    );
}

#[tokio::test]
async fn the_flag_over_a_read_only_policy_keeps_the_write_tools_delisted() {
    // `^=` at the tightening site: `true ^ true` is false, so the flag an
    // operator passes for belt and braces would RE-ENABLE every write tool
    // the policy file had already forbidden — the one direction I9 rules
    // out.
    //
    // The policy is checked restrictive on its own first, because the kill
    // rests on it: were `Policy::load` to ignore `read_only = true`, the
    // mutated `false ^ true` would still restrict and the mutant would
    // live. Nothing else pins that at binary level.
    //
    // This pair has no one-variable control. (true, no flag) is itself
    // restricted, so the listing that still carries the write tools has to
    // come from a deployment that restricts nothing — it proves the names
    // exist to be removed and no more. The flag is varied alone in the
    // `&=` test below.
    let dir = tempfile::tempdir().expect("tempdir");
    let restrictive = policy_file(dir.path(), true);
    let policy_alone = listed_tools(&restrictive, false).await;
    let with_the_flag = listed_tools(&restrictive, true).await;
    let loosened = listed_tools(&policy_file(dir.path(), false), false).await;
    assert_delisted(&policy_alone, &loosened, "policy true, no flag");
    assert_delisted(&with_the_flag, &loosened, "policy true + --read-only");
}

#[tokio::test]
async fn the_flag_tightens_a_policy_that_says_read_only_false() {
    // `&=` at the same site: `false & true` is false, so the flag would
    // never tighten anything a policy had not already tightened. One
    // policy file, spawned twice — the flag is the only thing that varies,
    // which is what makes this pair differential.
    let dir = tempfile::tempdir().expect("tempdir");
    let policy = policy_file(dir.path(), false);
    let restricted = listed_tools(&policy, true).await;
    let loosened = listed_tools(&policy, false).await;
    assert_delisted(&restricted, &loosened, "policy false + --read-only");
}

#[tokio::test]
async fn a_file_bearing_selection_writes_the_operator_s_audit_file() {
    // `--audit-config` with no OTLP endpoint is `SinkSelection::FileOnly`,
    // the selection whose arm the mutation deletes; without it the match
    // falls to `AuditConfig::fileless()`, whose `path` is `None`, and the
    // sink writes nowhere. `path` is the setting this test observes — the
    // file appearing where the operator's document put it, and holding the
    // records of the session that ran, is what the arm buys.
    let dir = tempfile::tempdir().expect("tempdir");
    let audit_path = dir.path().join("startup-policy-audit.jsonl");
    let config_path = dir.path().join("audit.toml");
    std::fs::write(
        &config_path,
        format!("path = {:?}\n", audit_path.to_str().expect("utf-8 path")),
    )
    .expect("write the audit config");

    let mut server = Server::spawn(&["--audit-config", config_path.to_str().expect("utf-8 path")]);
    server.handshake().await;
    // Served from the server's own state, so the whole exchange happens
    // without a Bugzilla request; the record is written before the reply.
    let info = server
        .call(json!({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": { "name": "mcp_server_info", "arguments": {} }
        }))
        .await;
    assert_eq!(info["result"]["isError"], json!(false), "{info}");
    server.close().await;

    let written = std::fs::read_to_string(&audit_path).unwrap_or_else(|e| {
        panic!(
            "the operator's audit file must exist at {}: {e}",
            audit_path.display()
        )
    });
    let records: Vec<Value> = written
        .lines()
        .map(|line| serde_json::from_str(line).unwrap_or_else(|e| panic!("{line:?}: {e}")))
        .collect();
    assert!(
        records.iter().any(|r| r["event"] == "initialize"),
        "the session's handshake must be recorded: {written}"
    );
    let served = records
        .iter()
        .filter(|r| r["event"] == "tool_call" && r["request"]["tool"] == "mcp_server_info")
        .count();
    assert_eq!(
        served, 1,
        "the served call must reach the operator's file exactly once (I15): {written}"
    );
}

/// Everything the shipped binary logged on its way to [`STARTUP_READY`].
///
/// The warning under test is emitted while the audit sinks are wired,
/// which both transports do before they announce readiness, so a log that
/// reaches the readiness line and does not carry the warning is proof the
/// warning did not fire.
async fn startup_log(args: &[&str]) -> String {
    let mut cmd = command(args);
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("the built binary must start");
    // Not the barrier: `main` logs the readiness line before `serve` reads
    // a byte, so this reader gets its line either way. Held so the child is
    // still running when `kill()` reaps it — on EOF a stdio child leaves
    // through `ConnectionClosed("initialize request")` and exit 1, which
    // is a noisier teardown than this test has any reason to produce.
    let _stdin = child.stdin.take().expect("stdin is piped");
    let mut lines = startup_line::stderr_lines(&mut child);
    let mut log = String::new();
    startup_line::wait_for_line(&mut lines, &mut log, STARTUP_READY, REPLY_BUDGET).await;
    let _ = child.kill().await;
    log
}

/// An audit configuration document naming a file under `dir`.
fn audit_config_in(dir: &Path) -> PathBuf {
    let path = dir.join("audit.toml");
    std::fs::write(
        &path,
        format!(
            "path = {:?}\n",
            dir.join("audit.jsonl").to_str().expect("utf-8 path")
        ),
    )
    .expect("write the audit config");
    path
}

#[tokio::test]
async fn http_without_a_sink_warns_that_auditing_is_off() {
    // `==` → `!=` at the warning condition silences exactly this case:
    // the only deployment that serves remote clients with no audit trail.
    let log = startup_log(&[
        "--bugzilla-server",
        "https://bugzilla.example.invalid",
        "--host",
        "127.0.0.1",
        "--port",
        "0",
        "--insecure-no-auth",
    ])
    .await;
    assert!(
        log.contains(NO_AUDIT_WARNING),
        "an unaudited http start must say so: {log}"
    );
}

#[tokio::test]
async fn http_with_an_audit_file_does_not_warn() {
    // `&&` → `||` fires the warning here, on a deployment that HAS the
    // file the warning tells the operator to configure.
    let dir = tempfile::tempdir().expect("tempdir");
    let config = audit_config_in(dir.path());
    let log = startup_log(&[
        "--bugzilla-server",
        "https://bugzilla.example.invalid",
        "--host",
        "127.0.0.1",
        "--port",
        "0",
        "--insecure-no-auth",
        "--audit-config",
        config.to_str().expect("utf-8 path"),
    ])
    .await;
    assert!(
        !log.contains(NO_AUDIT_WARNING),
        "an audited http start must not warn: {log}"
    );
}

#[tokio::test]
async fn stdio_without_a_sink_does_not_warn() {
    // The other half of `&&` → `||`, and the reason the condition names
    // the transport at all: an unaudited stdio session is the ordinary
    // desktop deployment, whose operator owns the process.
    let log = startup_log(&[
        "--transport",
        "stdio",
        "--bugzilla-server",
        "https://bugzilla.example.invalid",
        "--api-key",
        "test-key",
    ])
    .await;
    assert!(
        !log.contains(NO_AUDIT_WARNING),
        "a local stdio session is not the deployment this warns about: {log}"
    );
}
