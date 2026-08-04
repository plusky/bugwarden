//! What the SHIPPED BINARY tells Bugzilla it is (issue #55).
//!
//! Every other test of the identity stops one call frame short of `main`,
//! at `server::bugzilla_client`. That leaves the wiring itself untested: a
//! `main` that built its own client — with a plausible-looking constant, or
//! with someone else's — passes all of them while telling every configured
//! Bugzilla whatever it likes. So this drives the real executable over
//! stdio against a real HTTP server and reads the header off the request
//! that arrives.

use std::time::Duration;

use serde_json::json;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Bounded so a binary that never answers fails this test rather than
/// hanging the suite until CI's own timeout kills it.
const REPLY_TIMEOUT: Duration = Duration::from_secs(20);

/// The identity this build must present. Spelled out rather than read from
/// the manifest the code reads: a comparison against `CARGO_PKG_REPOSITORY`
/// agrees with whatever that field says, including a repository belonging
/// to someone else. Only the version is read from the environment, since it
/// moves every release.
fn expected_agent() -> String {
    format!(
        "bugwarden/{} (+https://github.com/plusky/bugwarden)",
        env!("CARGO_PKG_VERSION")
    )
}

/// Write one newline-delimited JSON-RPC message to the child, the framing
/// the stdio transport speaks.
async fn send(stdin: &mut tokio::process::ChildStdin, value: serde_json::Value) {
    stdin
        .write_all(format!("{value}\n").as_bytes())
        .await
        .expect("the child must accept input");
}

/// Run the shipped binary against `mock` until it has made at least one
/// upstream request, and return everything the mock received.
async fn upstream_requests_of_a_real_run(
    mock: &MockServer,
    extra_args: &[&str],
) -> Vec<wiremock::Request> {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_bugwarden"));
    cmd.args(["--transport", "stdio", "--bugzilla-server", &mock.uri()])
        .args(["--api-key", "test-key"])
        .args(extra_args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null());
    // The ambient environment must not reach the child: every one of these
    // is read by `Cli` and would change what is under test.
    for var in [
        "BUGZILLA_SERVER",
        "BUGZILLA_API_KEY",
        "BUGZILLA_API_KEY_FILE",
        "BUGWARDEN_POLICY",
        "BUGWARDEN_AUDIT_CONFIG",
        "MCP_TRANSPORT",
        "MCP_READ_ONLY",
        "RUST_LOG",
    ] {
        cmd.env_remove(var);
    }
    let mut child = cmd.spawn().expect("the built binary must start");

    let mut stdin = child.stdin.take().expect("stdin is piped");
    let mut stdout = BufReader::new(child.stdout.take().expect("stdout is piped")).lines();
    // A real MCP session: handshake, then one tool call that must reach
    // Bugzilla. Nothing here asserts on the responses — the wire is the
    // subject — but each is read so the next write cannot outrun it.
    send(
        &mut stdin,
        json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": { "name": "binary-user-agent-test", "version": "0" }
            }
        }),
    )
    .await;
    tokio::time::timeout(REPLY_TIMEOUT, stdout.next_line())
        .await
        .expect("the handshake must not hang")
        .expect("stdout must be readable")
        .expect("the server must answer initialize");

    send(
        &mut stdin,
        json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
    )
    .await;
    send(
        &mut stdin,
        json!({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": { "name": "bug_info", "arguments": { "bug_ids": [1] } }
        }),
    )
    .await;
    tokio::time::timeout(REPLY_TIMEOUT, stdout.next_line())
        .await
        .expect("the tool call must not hang")
        .expect("stdout must be readable")
        .expect("the server must answer the tool call");

    child.kill().await.expect("the child must be killable");
    mock.received_requests().await.expect("recording enabled")
}

#[tokio::test]
async fn the_shipped_binary_names_this_build_to_bugzilla() {
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/bug"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "bugs": [] })))
        .mount(&mock)
        .await;

    let requests = upstream_requests_of_a_real_run(&mock, &[]).await;
    assert!(
        !requests.is_empty(),
        "the tool call must have reached Bugzilla, or this test proves nothing"
    );
    for req in requests {
        let agent = req
            .headers
            .get("user-agent")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        assert_eq!(
            agent,
            expected_agent(),
            "the binary as shipped must identify itself on {}",
            req.url.path()
        );
    }
}

#[tokio::test]
async fn the_shipped_binary_still_honours_the_auth_mode() {
    // The identity and the credential are chosen by the same constructor,
    // so a wiring that dropped `--use-auth-header` would put the API key
    // back in the query string — into Bugzilla's access log and every proxy
    // in between — while the header under test stayed perfect.
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/bug"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "bugs": [] })))
        .mount(&mock)
        .await;

    let requests = upstream_requests_of_a_real_run(&mock, &["--use-auth-header"]).await;
    assert!(
        !requests.is_empty(),
        "the tool call must have reached Bugzilla"
    );
    for req in requests {
        let agent = req
            .headers
            .get("user-agent")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        assert_eq!(
            agent,
            expected_agent(),
            "the identity is not auth-mode dependent"
        );
        assert_eq!(
            req.headers
                .get("authorization")
                .and_then(|v| v.to_str().ok()),
            Some("Bearer test-key"),
            "--use-auth-header must reach the client that main builds"
        );
        assert!(
            !req.url.query_pairs().any(|(k, _)| k == "api_key"),
            "the key must not also travel in the URL: {}",
            req.url
        );
    }
}
