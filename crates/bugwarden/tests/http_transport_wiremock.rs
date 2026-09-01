//! End-to-end tests of the streamable-HTTP transport: what holds only once
//! a request has crossed a real socket. API key custody is one such
//! property, not the file's subject — it also pins Host validation, the
//! 2026-07-28 handshake-free lifecycle, the audit session anchor, the
//! per-revision cache hints, `_meta` propagation into the audit record, the
//! POST body cap, the identity `server/discover` answers with, and guard
//! parity with stdio.
//!
//! A test builds a [`BugWarden`] with `--transport http` and serves it over
//! an actual TCP listener through `StreamableHttpService`, wiremock playing
//! Bugzilla; the one startup-error leg stops at `http_server_config` and
//! binds nothing. The client is whatever the property needs: an rmcp client
//! through reqwest, raw reqwest where the wire shape is itself the point
//! (the handshake-free lifecycle, the minted session id), or a raw TCP
//! socket for the body cap, whose 413 lands mid-write.
//!
//! Coverage contract (each of these mutations must fail at least one test):
//! - server-held mode falling back to the client's header when one is sent;
//! - `resolve_key_custody` dropping server-held mode on http;
//! - `api_key()` re-reading the key file per request instead of once at
//!   startup;
//! - server-held mode rejecting requests that carry the header;
//! - dropping the trim of the key file's content;
//! - audit trace enrichment reading only the params-struct
//!   `CallToolRequestParams.meta` — always `None` over a serialized
//!   transport, because rmcp strips the wire `_meta` into the request
//!   extensions and hands it to the handler as `RequestContext.meta` —
//!   instead of falling back to `context.meta` (the inverse mutant,
//!   reading only `context.meta`, is behavior-preserving over every
//!   serialized transport and is killed by the direct in-process call
//!   test in server.rs instead);
//! - keeping the empty entry `MCP_ALLOWED_HOSTS=` produces instead of
//!   dropping it, which turns Host validation on with nothing rmcp can
//!   match and refuses every request;
//! - handing an unparsable `--allowed-hosts` entry (`*`, a URL) to rmcp
//!   instead of refusing it at `http_server_config`;
//! - the POST body cap going back to a fixed value, which refuses uploads
//!   the operator's `global.max_attachment_bytes` permits (losing the
//!   4 MiB floor is NOT killed here: the default 2 MiB cap derives
//!   3,844,780 bytes, still under the 5 MiB probe, so that leg's 413
//!   stands with or without the clamp — the floor and its `0` case are
//!   killed by the `max_request_body_bytes` unit tests in server.rs
//!   instead);
//! - `session_info` taking the audit `session.id` from the `mcp-session-id`
//!   REQUEST header again, which leaves every `initialize` record without
//!   the id that would join it to its own session and lets a stateless
//!   caller file a refusal under a live session's id (#180);
//! - serving on a bare `LocalSessionManager` instead of
//!   `AuditedSessionManager`, or a wrapper that stamps in only one of
//!   `initialize_session` / `create_stream`, mints a fresh id per message,
//!   or carries one id across sessions;
//! - the handshake refusal clearing `session.id`, which would unanchor the
//!   refusals that DID open a session — invisible to every other test,
//!   because the stateless refusal's id is absent either way.

use std::io::Write as _;
use std::net::SocketAddr;
use std::sync::Arc;

use bugwarden::audit::{AuditConfig, AuditEvent, AuditEventKind, AuditSink, AuditState, FailMode};
use bugwarden::config::Cli;
use bugwarden::http_session::AuditedSessionManager;
use bugwarden::server::{BugWarden, USER_AGENT};
use bugwarden_core::client::BugzillaClient;
use bugwarden_core::guard::Guard;
use bugwarden_core::policy::Policy;
use clap::Parser as _;
use rmcp::model::{CallToolRequestParams, CallToolResult};
use rmcp::service::{RoleClient, RunningService};
use rmcp::transport::streamable_http_client::StreamableHttpClientTransportConfig;
use rmcp::transport::streamable_http_server::StreamableHttpService;
use rmcp::transport::StreamableHttpClientTransport;
use rmcp::ServiceExt as _;
use serde_json::{json, Value};
use wiremock::matchers::{any, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[path = "common/raw_post.rs"]
mod raw_post;

/// Build the http-transport `Cli` against `mock`, with `key_file` when the
/// test runs in server-held mode. Every field an ambient environment
/// variable could set behind the fixed arguments below is then assigned
/// explicitly — the two key sources (`BUGZILLA_API_KEY`,
/// `BUGZILLA_API_KEY_FILE`) and the Host allowlist (`MCP_ALLOWED_HOSTS`,
/// which would otherwise refuse the loopback authority the harness dials).
/// A new environment-backed flag that changes what a test resolves belongs
/// here too.
fn http_cli(mock: &MockServer, key_file: Option<&std::path::Path>) -> Arc<Cli> {
    let mut cli = Cli::parse_from([
        "bugwarden",
        "--bugzilla-server",
        &mock.uri(),
        "--transport",
        "http",
        "--api-key-header",
        "ApiKey",
    ]);
    cli.api_key = None;
    cli.api_key_file = key_file.map(std::path::Path::to_path_buf);
    cli.allowed_hosts = Vec::new();
    Arc::new(cli)
}

/// Serve a [`BugWarden`] built from `cli` and `policy` over a real TCP
/// listener, with the audit sink wired in when a test needs the record
/// stream; returns the bound address.
async fn serve_http(
    cli: Arc<Cli>,
    policy: &str,
    mock: &MockServer,
    audit: Option<Arc<AuditState>>,
) -> SocketAddr {
    let guard = Arc::new(Guard {
        policy: Policy::from_toml_str(policy).expect("test policy must parse"),
    });
    let bz =
        Arc::new(BugzillaClient::new(&mock.uri(), false, USER_AGENT).expect("client must build"));
    let mut server = BugWarden::new(cli, guard, bz).expect("server must build");
    if let Some(audit) = audit {
        server = server.with_audit(audit);
    }

    // The deployed configuration, not a default one, and derived the way
    // main derives it: the server reads its OWN policy for the POST body
    // cap, so this harness cannot agree with a deployment that reads a
    // different field or a constant.
    let config = server
        .http_server_config()
        .expect("the test Host list must be matchable");
    // Load-bearing pair with main.rs: the session id an audit record
    // carries is stamped by this wrapper, so a harness on the plain
    // LocalSessionManager would test a server no deployment runs.
    let service = StreamableHttpService::new(
        move || Ok(server.clone()),
        AuditedSessionManager::default().into(),
        config,
    );
    let router = axum::Router::new().nest_service("/mcp", service);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind an ephemeral port");
    let addr = listener.local_addr().expect("bound address");
    // `into_make_service_with_connect_info`, as main.rs serves it: without
    // it no record carries `session.remote`, which is the whole of
    // cross-call grouping on the handshake-free path.
    tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await;
    });
    addr
}

/// Connect an MCP client to `addr` over streamable HTTP. With
/// `header_value`, every request carries `ApiKey: <value>` (a reqwest
/// default header); without, no key header exists anywhere in the session.
/// That distinction is what the custody tests turn on, and only http can
/// draw it: stdio resolves one key at startup and carries no per-request
/// header at all.
async fn connect(addr: SocketAddr, header_value: Option<&str>) -> RunningService<RoleClient, ()> {
    let mut builder = reqwest::Client::builder();
    if let Some(value) = header_value {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("ApiKey", value.parse().expect("header value"));
        builder = builder.default_headers(headers);
    }
    let transport = StreamableHttpClientTransport::with_client(
        builder.build().expect("reqwest client"),
        StreamableHttpClientTransportConfig::with_uri(format!("http://{addr}/mcp")),
    );
    ().serve(transport)
        .await
        .expect("MCP handshake must succeed")
}

/// Call `tool` with `args`; the outer `Result` carries protocol errors.
async fn try_call(
    client: &RunningService<RoleClient, ()>,
    tool: &str,
    args: Value,
) -> Result<CallToolResult, rmcp::ServiceError> {
    let Value::Object(args) = args else {
        panic!("tool arguments must be a JSON object");
    };
    client
        .call_tool(CallToolRequestParams::new(tool.to_string()).with_arguments(args))
        .await
}

/// All text blocks of a result, concatenated.
fn text_of(result: &CallToolResult) -> String {
    result
        .content
        .iter()
        .filter_map(|c| c.as_text())
        .map(|t| t.text.as_str())
        .collect()
}

/// A classification response for one world-readable bug.
fn world_readable_bug(id: u64) -> Value {
    json!({
        "id": id,
        "summary": "a plain bug",
        "product": "openSUSE",
        "component": "Kernel",
        "status": "NEW",
        "severity": "normal",
        "priority": "P3",
        "keywords": [],
        "groups": [],
        "whiteboard": "",
        "creation_time": "2020-01-01T00:00:00Z",
    })
}

/// Mount the fetches a served `bug_info` call needs — the bug itself
/// (classification + body, hence unbounded) and the id=0 link-disclosure
/// padding — all REQUIRING `api_key=<key>`: a request authenticating with
/// any other key falls through to the test's catch-all.
async fn mount_bug_for_key(mock: &MockServer, bug: Value, key: &str) {
    let id = bug["id"].as_u64().expect("bug fixture has an id");
    Mock::given(method("GET"))
        .and(path("/rest/bug"))
        .and(query_param("id", id.to_string()))
        .and(query_param("api_key", key))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "bugs": [bug] })))
        .mount(mock)
        .await;
    Mock::given(method("GET"))
        .and(path("/rest/bug"))
        .and(query_param("id", "0"))
        .and(query_param("api_key", key))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "bugs": [] })))
        .mount(mock)
        .await;
}

/// Mount a catch-all expecting ZERO requests carrying `api_key=<key>`.
async fn expect_no_requests_with_key(mock: &MockServer, key: &str) {
    Mock::given(any())
        .and(query_param("api_key", key))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .named(format!("no request may authenticate with '{key}'"))
        .mount(mock)
        .await;
}

/// A named temp file holding `content` — the operator's key file.
fn key_file(content: &str) -> tempfile::NamedTempFile {
    let mut file = tempfile::NamedTempFile::new().expect("temp key file");
    file.write_all(content.as_bytes()).expect("write key file");
    file.flush().expect("flush key file");
    file
}

/// Assert `bug_info` for bug 7 succeeds and serves the bug's content.
async fn assert_bug_7_served(client: &RunningService<RoleClient, ()>) {
    let result = try_call(client, "bug_info", json!({ "bug_ids": [7] }))
        .await
        .expect("bug_info must not be a protocol error");
    assert_ne!(
        result.is_error,
        Some(true),
        "bug_info failed: {}",
        text_of(&result)
    );
    let envelope: Value = serde_json::from_str(&text_of(&result)).expect("bug_info returns JSON");
    assert_eq!(envelope["bugs"][0]["id"], json!(7), "bug 7 must be served");
}

#[tokio::test]
async fn server_held_serves_clients_with_no_credential() {
    // The fleet deployment shape: the key lives in a file only the server
    // reads, the client presents nothing at all — and is served with the
    // server's key. The upstream matcher REQUIRES api_key=srv-key, so this
    // also proves the trailing newline was trimmed end to end.
    let mock = MockServer::start().await;
    mount_bug_for_key(&mock, world_readable_bug(7), "srv-key").await;

    let file = key_file("srv-key\n");
    let cli = http_cli(&mock, Some(file.path()));
    let addr = serve_http(cli, "", &mock, None).await;
    let client = connect(addr, None).await;

    assert_bug_7_served(&client).await;
}

#[tokio::test]
async fn server_held_never_reads_the_client_header() {
    // Acceptance criterion 2: in server-held mode a request that DOES carry
    // the header is served — with the server's key. The header value must
    // never reach Bugzilla: expect(0) on the attacker key, and the bug-7
    // mocks only answer api_key=srv-key, so a fallback to the header would
    // also fail the call itself.
    let mock = MockServer::start().await;
    expect_no_requests_with_key(&mock, "attacker-key").await;
    mount_bug_for_key(&mock, world_readable_bug(7), "srv-key").await;

    let file = key_file("srv-key");
    let cli = http_cli(&mock, Some(file.path()));
    let addr = serve_http(cli, "", &mock, None).await;
    let client = connect(addr, Some("attacker-key")).await;

    assert_bug_7_served(&client).await;
}

#[tokio::test]
async fn per_request_header_still_authenticates_over_http() {
    // Without --api-key-file nothing changes: the client's key header is
    // what authenticates to Bugzilla, exactly as before.
    let mock = MockServer::start().await;
    mount_bug_for_key(&mock, world_readable_bug(7), "client-key").await;

    let cli = http_cli(&mock, None);
    let addr = serve_http(cli, "", &mock, None).await;
    let client = connect(addr, Some("client-key")).await;

    assert_bug_7_served(&client).await;
}

#[tokio::test]
async fn per_request_missing_header_is_a_protocol_error() {
    // Per-request mode with no header: a protocol-level invalid_request —
    // not a tool-text denial — and nothing reaches the upstream at all.
    let mock = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .named("no upstream request without a client key")
        .mount(&mock)
        .await;

    let cli = http_cli(&mock, None);
    let addr = serve_http(cli, "", &mock, None).await;
    let client = connect(addr, None).await;

    let err = try_call(&client, "bug_info", json!({ "bug_ids": [7] }))
        .await
        .expect_err("a missing key header must be a protocol error");
    assert!(
        err.to_string().contains("ApiKey"),
        "the error must name the header: {err}"
    );
}

#[tokio::test]
async fn server_held_key_is_resolved_once_at_startup() {
    // The running server holds the String resolved at startup; the file is
    // never re-read per request. Overwriting it mid-flight changes nothing:
    // the second call still authenticates with srv-key (and an other-key
    // request would both trip the expect(0) and fail the call, since the
    // bug-7 mocks only answer srv-key).
    let mock = MockServer::start().await;
    expect_no_requests_with_key(&mock, "other-key").await;
    mount_bug_for_key(&mock, world_readable_bug(7), "srv-key").await;

    let file = key_file("srv-key\n");
    let cli = http_cli(&mock, Some(file.path()));
    let addr = serve_http(cli, "", &mock, None).await;
    let client = connect(addr, None).await;

    assert_bug_7_served(&client).await;

    // Rotate the file on disk (std::fs::write truncates and rewrites from
    // offset 0, so the file now really holds "other-key\n"); the running
    // server must not notice.
    std::fs::write(file.path(), b"other-key\n").expect("rewrite key file");

    assert_bug_7_served(&client).await;
}

#[tokio::test]
async fn guard_denies_uniformly_over_http() {
    // Transport parity: server-held custody changes who authenticates to
    // Bugzilla, not what the guard says — a policy-hidden bug takes the
    // exact uniform denial text stdio clients get (I2), and its comments
    // are never fetched.
    let mock = MockServer::start().await;
    let mut secret = world_readable_bug(7);
    secret["product"] = json!("SecretSauce");
    mount_bug_for_key(&mock, secret, "srv-key").await;
    Mock::given(method("GET"))
        .and(path("/rest/bug/7/comment"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "bugs": { "7": { "comments": [] } }
        })))
        .expect(0)
        .mount(&mock)
        .await;

    let file = key_file("srv-key\n");
    let cli = http_cli(&mock, Some(file.path()));
    let addr = serve_http(
        cli,
        concat!(
            "[[rule]]\nname = \"hide-secret\"\naction = \"deny\"\n",
            "[rule.match]\nproducts = [\"Secret*\"]\n",
        ),
        &mock,
        None,
    )
    .await;
    let client = connect(addr, None).await;

    let result = try_call(&client, "bug_comments", json!({ "id": 7 }))
        .await
        .expect("a guard refusal is a tool error, not a protocol error");
    assert_eq!(
        result.is_error,
        Some(true),
        "the hidden bug must be refused"
    );
    assert_eq!(
        text_of(&result),
        "Bug 7 is not accessible through this server",
        "the denial must be the uniform text (I2)"
    );
}

#[tokio::test]
async fn a_client_addressing_the_server_by_name_is_served() {
    // rmcp 3.1's `allowed_hosts` default is loopback only, so inheriting it
    // would answer every request whose `Host` is the name the operator
    // actually deployed under — every containerised one — with a rejection.
    // main.rs disables that validation by name; this pins the decision,
    // since the test harness would otherwise always speak to 127.0.0.1 and
    // never notice.
    let mock = MockServer::start().await;
    let file = key_file("srv-key\n");
    let cli = http_cli(&mock, Some(file.path()));
    let addr = serve_http(cli, "", &mock, None).await;

    let response = reqwest::Client::new()
        .post(format!("http://{addr}/mcp"))
        .header("Host", "bugwarden.example:8080")
        .header("Accept", "application/json, text/event-stream")
        .header("Content-Type", "application/json")
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": { "name": "host-probe", "version": "1" }
            }
        }))
        .send()
        .await
        .expect("the request must reach the server");
    let status = response.status();
    let body = response.text().await.expect("a body");
    assert!(
        status.is_success(),
        "a non-loopback Host must be served, got {status}: {body}"
    );
    assert!(
        body.contains("protocolVersion"),
        "the handshake must be answered: {body}"
    );
}

#[tokio::test]
async fn allowed_hosts_serve_the_named_authority_and_refuse_the_others() {
    // `--allowed-hosts` is the operator's opt-in back into rmcp's Host
    // validation: naming an authority can only narrow what the disabled
    // state serves (I9), so the named one is answered and every other name
    // — including the loopback the harness dials — is refused.
    let mock = MockServer::start().await;
    let file = key_file("srv-key\n");
    let mut cli = Arc::into_inner(http_cli(&mock, Some(file.path()))).expect("the sole owner");
    cli.allowed_hosts = vec!["bugwarden.example:8080".into()];
    let addr = serve_http(Arc::new(cli), "", &mock, None).await;

    for (host, served) in [("bugwarden.example:8080", true), ("evil.example", false)] {
        let response = reqwest::Client::new()
            .post(format!("http://{addr}/mcp"))
            .header("Host", host)
            .header("Accept", "application/json, text/event-stream")
            .header("Content-Type", "application/json")
            .json(&json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {},
                    "clientInfo": { "name": "host-probe", "version": "1" }
                }
            }))
            .send()
            .await
            .expect("the request must reach the server");
        assert_eq!(
            response.status().is_success(),
            served,
            "Host {host} must {} be served",
            if served { "" } else { "not" }
        );
    }
}

#[tokio::test]
async fn an_allowed_hosts_entry_naming_no_host_leaves_validation_off() {
    // `MCP_ALLOWED_HOSTS=` (the set-but-empty "unset" idiom of unit files and
    // container specs) reaches the server as one empty entry. rmcp validates
    // against a non-empty list and silently skips the entries it cannot
    // parse, so carrying that entry through would refuse EVERY Host and brick
    // the deployment; dropping it restores the documented default instead.
    let mock = MockServer::start().await;
    let file = key_file("srv-key\n");
    let mut cli = Arc::into_inner(http_cli(&mock, Some(file.path()))).expect("the sole owner");
    cli.allowed_hosts = vec![String::new()];
    let addr = serve_http(Arc::new(cli), "", &mock, None).await;

    let response = reqwest::Client::new()
        .post(format!("http://{addr}/mcp"))
        .header("Host", "bugwarden.example:8080")
        .header("Accept", "application/json, text/event-stream")
        .header("Content-Type", "application/json")
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": { "name": "host-probe", "version": "1" }
            }
        }))
        .send()
        .await
        .expect("the request must reach the server");
    let status = response.status();
    let body = response.text().await.expect("a body");
    assert!(
        status.is_success(),
        "an entry naming no host must leave every Host served, got {status}: {body}"
    );
}

#[tokio::test]
async fn an_unparsable_allowed_hosts_entry_is_a_startup_error() {
    // The same path `serve_http` and `main` take: rmcp 3.1.4 would store
    // `*` as a host that matches only `Host: *`, turning validation on as
    // a silent deny-all. Refusing here is what the operator sees instead
    // of one 403 at a time.
    let mock = MockServer::start().await;
    let file = key_file("srv-key\n");
    let mut cli = Arc::into_inner(http_cli(&mock, Some(file.path()))).expect("the sole owner");
    cli.allowed_hosts = vec!["*".into()];
    let guard = Arc::new(Guard {
        policy: Policy::default(),
    });
    let bz =
        Arc::new(BugzillaClient::new(&mock.uri(), false, USER_AGENT).expect("client must build"));
    let server = BugWarden::new(Arc::new(cli), guard, bz).expect("server must build");
    let err = server
        .http_server_config()
        .expect_err("unparsable Host authorities are a startup error");
    let msg = format!("{err:#}");
    assert!(msg.contains('*'), "the error must name the entry: {msg}");
}

#[tokio::test]
async fn a_handshake_free_call_is_refused_and_never_names_a_client() {
    // rmcp 3.1.4 routes to its handshake-free lifecycle when the request's
    // revision is 2026-07-28 or newer, or `_meta` carries BOTH
    // `protocolVersion` and `clientCapabilities`, synthesising the peer with
    // the SDK's own build identity. The body below sends both keys at
    // 2025-11-25 deliberately: serving 2026-07-28 did not close that second
    // shape — a PRE-2026 revision with both keys still reaches a handler with
    // no `initialize` behind it and a peer named `rmcp`/<sdk version>, a
    // client the server never spoke to, and it declares a lifecycle its own
    // revision does not define. Drop `clientCapabilities` and it takes the
    // session path instead, proving nothing. Narrowing
    // SUPPORTED_PROTOCOL_VERSIONS cannot close it either, the routing never
    // consults it, so the handler refuses the request.
    let mock = MockServer::start().await;
    mount_bug_for_key(&mock, world_readable_bug(7), "srv-key").await;

    let dir = tempfile::tempdir().expect("audit temp dir");
    let audit_path = dir.path().join("audit.jsonl");
    let sink = AuditSink::open(AuditConfig {
        path: Some(audit_path.clone()),
        fsync: false,
        fail_mode: None,
        rotate_max_bytes: 0,
        rotate_keep: 8,
        suppressed_ids: true,
    })
    .expect("audit sink must open");
    let audit = Arc::new(AuditState::new(sink, FailMode::Open, None));

    let file = key_file("srv-key\n");
    let cli = http_cli(&mock, Some(file.path()));
    let addr = serve_http(cli, "", &mock, Some(audit)).await;

    // Raw HTTP: no rmcp client will build this request, which is the point.
    let response = reqwest::Client::new()
        .post(format!("http://{addr}/mcp"))
        .header("Accept", "application/json, text/event-stream")
        .header("Content-Type", "application/json")
        .header("MCP-Protocol-Version", "2025-11-25")
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "bug_info",
                "arguments": { "bug_ids": [7] },
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2025-11-25",
                    "io.modelcontextprotocol/clientCapabilities": {}
                }
            }
        }))
        .send()
        .await
        .expect("the request must reach the server");
    let body = response.text().await.expect("a body");
    assert!(
        !body.contains("world-readable"),
        "a handshake-free call must not be served: {body}"
    );

    // The guard never ran because the call never reached a tool, so
    // Bugzilla was never contacted on its behalf.
    let upstream = mock.received_requests().await.unwrap_or_default();
    assert!(
        upstream.is_empty(),
        "a refused call must contact no upstream: {} request(s)",
        upstream.len()
    );

    // Refused, but not silently: the stream carries the attempt, and the
    // client it could not identify is absent rather than a placeholder.
    let raw = std::fs::read_to_string(&audit_path).expect("audit file must be readable");
    assert!(
        !raw.contains("\"rmcp\""),
        "no record may name the SDK as the calling client: {raw}"
    );
    let events: Vec<AuditEvent> = raw
        .lines()
        .filter(|l| !l.is_empty())
        .map(|l| serde_json::from_str(l).expect("every audit line must parse"))
        .collect();
    let calls: Vec<_> = events
        .iter()
        .filter_map(|e| match &e.kind {
            AuditEventKind::ToolCall(ev) => Some(ev.as_ref()),
            _ => None,
        })
        .collect();
    assert_eq!(calls.len(), 1, "the refused call is recorded exactly once");
    assert_eq!(calls[0].request.tool, "bug_info");
    assert_eq!(calls[0].client.name, None, "no client can be named");
    assert!(
        calls[0].guard.is_none(),
        "the guard never ran, so no verdict may be recorded"
    );
    // Nothing was dispatched, so there is no payload — absent, not zero, or
    // a size aggregation averages in a call that returned nothing (#145).
    assert_eq!(calls[0].outcome.response_bytes, None);
}

#[tokio::test]
async fn discover_names_this_build_and_reaches_nothing_else() {
    // `server/discover` is the SECOND place a peer learns who answered, and
    // it is served with no handshake behind it. It says `bugwarden` today
    // only because rmcp's default implementation delegates to `get_info` —
    // an override (#34 stage 2 plausibly adds one) would take the identity
    // with it, and the handshake tests would not notice.
    let mock = MockServer::start().await;
    mount_bug_for_key(&mock, world_readable_bug(7), "srv-key").await;
    let file = key_file("srv-key\n");
    let cli = http_cli(&mock, Some(file.path()));
    let addr = serve_http(cli, "", &mock, None).await;

    let response = reqwest::Client::new()
        .post(format!("http://{addr}/mcp"))
        .header("Accept", "application/json, text/event-stream")
        .header("Content-Type", "application/json")
        .header("MCP-Protocol-Version", "2025-11-25")
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "server/discover",
            "params": {
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2025-11-25",
                    "io.modelcontextprotocol/clientCapabilities": {}
                }
            }
        }))
        .send()
        .await
        .expect("the request must reach the server");
    let body = response.text().await.expect("a body");

    // Compared whole rather than by field: an extra key here is how the
    // identity gets undermined without contradicting it — `title` is what
    // a client displays in preference to `name`.
    let payload: Value = body
        .lines()
        .find_map(|line| line.strip_prefix("data: "))
        .and_then(|data| serde_json::from_str(data).ok())
        .unwrap_or_else(|| panic!("discover must answer with a JSON-RPC result: {body}"));
    assert_eq!(
        payload["result"]["_meta"]["io.modelcontextprotocol/serverInfo"],
        json!({ "name": "bugwarden", "version": env!("CARGO_PKG_VERSION") }),
        "discover must name this build, and nothing else: {body}"
    );
    // rmcp's `DiscoverResult` hard-codes both SEP-2549 hints as non-Option
    // fields, so this pre-2026 request carries them however `tools/list` is
    // gated. Pinned because the gate's rationale is scoped to *this
    // handler's listings* on the strength of it, and prose that overreached
    // here is exactly what the sequence has been blocked on.
    assert_eq!(
        payload["result"]["ttlMs"],
        json!(0),
        "the SDK's discover serves ttlMs unconditionally: {body}"
    );
    assert_eq!(
        payload["result"]["cacheScope"],
        json!("private"),
        "the SDK's discover serves cacheScope unconditionally: {body}"
    );
    // It answers `get_info` and nothing else: no tool, no guard, no
    // upstream. Says nothing about auth: this harness serves the bare
    // router, while `main` wraps that router in the bearer gate — which
    // `server/discover` needs like any other request (DESIGN.md, "HTTP
    // bearer authentication"), and which http_auth_wiremock.rs pins.
    let upstream = mock.received_requests().await.unwrap_or_default();
    assert!(
        upstream.is_empty(),
        "discover must contact no upstream: {} request(s)",
        upstream.len()
    );
}

#[tokio::test]
async fn a_legacy_session_listing_carries_no_cache_hints() {
    // The regression guard for every client alive today, at the only place
    // it is the real thing: the in-process rows serialize what the handler
    // RETURNS, this reads what a client is actually handed once rmcp has
    // post-processed the result. A gate inversion fails the in-process rows
    // too — what is unique here is the wire, not the inversion. Substring
    // assertions hold because no served schema, description or annotation
    // spells either field; pin that if one ever does.
    let mock = MockServer::start().await;
    let file = key_file("srv-key\n");
    let cli = http_cli(&mock, Some(file.path()));
    let addr = serve_http(cli, "", &mock, None).await;

    let session = raw_initialize(addr, "legacy-client").await;
    let response = mcp_post(addr, Some(&session))
        .header("MCP-Protocol-Version", "2025-11-25")
        .json(&json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {} }))
        .send()
        .await
        .expect("the listing request must reach the server");
    let body = response.text().await.expect("a body");

    assert!(
        body.contains("\"bug_info\""),
        // A named tool, not the `"tools"` key: that key is present even
        // for an empty listing or a scope that reaches nothing.
        "the session must be served a real listing: {body}"
    );
    assert!(
        !body.contains("ttlMs"),
        "a legacy session must see no cache ttl: {body}"
    );
    assert!(
        !body.contains("cacheScope"),
        "a legacy session must see no cache scope: {body}"
    );
}

#[tokio::test]
async fn traceparent_over_http_lands_in_the_audit_record() {
    // End-to-end over REAL streamable http: the client's `params._meta`
    // traceparent survives serialization, transport, and deserialization
    // into the audit record. Over every real transport the SDK strips the
    // wire `_meta` out of the params before the params struct is built —
    // `CallToolRequestParams.meta` arrives `None` here — and delivers it
    // to the handler as the extensions-backed `RequestContext.meta`, so
    // this test pins the `context.meta` fallback that every serialized
    // transport depends on (see the rmcp 3.1 usage notes in DESIGN.md).
    let mock = MockServer::start().await;
    mount_bug_for_key(&mock, world_readable_bug(7), "srv-key").await;

    let dir = tempfile::tempdir().expect("audit temp dir");
    let audit_path = dir.path().join("audit.jsonl");
    let sink = AuditSink::open(AuditConfig {
        path: Some(audit_path.clone()),
        fsync: false,
        fail_mode: None,
        rotate_max_bytes: 0,
        rotate_keep: 8,
        suppressed_ids: true,
    })
    .expect("audit sink must open");
    let audit = Arc::new(AuditState::new(sink, FailMode::Open, None));

    let file = key_file("srv-key\n");
    let cli = http_cli(&mock, Some(file.path()));
    let addr = serve_http(cli, "", &mock, Some(audit)).await;
    let client = connect(addr, None).await;

    let plain = try_call(&client, "bug_info", json!({ "bug_ids": [7] }))
        .await
        .expect("bug_info must not be a protocol error");
    let traceparent = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01";
    let Value::Object(args) = json!({ "bug_ids": [7] }) else {
        panic!("tool arguments must be a JSON object");
    };
    let mut params = CallToolRequestParams::new("bug_info".to_string()).with_arguments(args);
    let mut meta = rmcp::model::RequestMetaObject::new();
    meta.set_traceparent(traceparent);
    params.meta = Some(meta);
    let traced = client
        .call_tool(params)
        .await
        .expect("a traced bug_info must not be a protocol error");

    // Record enrichment only: the served response is unaffected.
    assert_eq!(
        serde_json::to_string(&plain).expect("serialize"),
        serde_json::to_string(&traced).expect("serialize"),
        "a traceparent must not change the response over http"
    );

    let raw = std::fs::read_to_string(&audit_path).expect("audit file must be readable");
    let events: Vec<AuditEvent> = raw
        .lines()
        .filter(|l| !l.is_empty())
        .map(|l| serde_json::from_str(l).expect("every audit line must parse"))
        .collect();
    let calls: Vec<_> = events
        .iter()
        .filter_map(|e| match &e.kind {
            AuditEventKind::ToolCall(ev) => Some(ev.as_ref()),
            _ => None,
        })
        .collect();
    assert_eq!(calls.len(), 2, "both calls must be recorded");
    assert_eq!(calls[0].trace, None, "no meta means no trace field");
    let trace = calls[1]
        .trace
        .as_ref()
        .expect("the traced call's record must carry the sent ids");
    assert_eq!(trace.trace_id, "0af7651916cd43dd8448eb211c80319c");
    assert_eq!(trace.span_id, "b7ad6b7169203331");
}

/// POST a raw JSON-RPC `initialize` whose serialized body is at least
/// `bytes` long, and answer with the status line the transport gave it.
///
/// The size rides on `clientInfo.title`, a plain string field: what is
/// under test is the transport's body cap, which is applied while the body
/// is still being collected — before any tool, session or guard exists —
/// so the cheapest well-formed request that the cap can refuse is the
/// handshake itself. A body the cap admits is answered `200`; one it
/// refuses is answered `413` with no JSON-RPC message at all — and
/// answered mid-write, before the body it is refusing has been read, which
/// is why the status line comes off a raw socket rather than a reqwest
/// round-trip the peer's reset would discard (#167).
async fn initialize_body_of(addr: SocketAddr, bytes: usize) -> String {
    let request = |title: String| {
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": { "name": "cap-test", "version": "1", "title": title }
            }
        })
    };
    let envelope = serde_json::to_vec(&request(String::new()))
        .expect("serialize")
        .len();
    let body = serde_json::to_vec(&request("A".repeat(bytes.saturating_sub(envelope))))
        .expect("serialize");
    assert!(
        body.len() >= bytes,
        "the padding must reach the target size"
    );

    raw_post::post_status_line(addr, None, &body).await
}

#[tokio::test]
async fn the_body_cap_follows_the_policy_attachment_ceiling() {
    // Issue #52: two ceilings governed one thing. The transport's POST cap
    // was pinned at 4 MiB, so base64 expansion (4/3) plus JSON-RPC framing
    // put every `max_attachment_bytes` above ~3 MiB out of reach: the
    // operator raised the limit, and the transport refused the upload
    // anyway — with a bare 413 that reaches no tool and therefore leaves no
    // audit record. The cap is now derived from the policy, so what the
    // guard permits is what the transport admits.
    let mock = MockServer::start().await;
    let file = key_file("srv-key\n");

    // 6 MiB decoded => ceil(6 MiB / 3) * 4 + 1 MiB framing = 9 MiB of body.
    let permissive = serve_http(
        http_cli(&mock, Some(file.path())),
        "[global]\nmax_attachment_bytes = 6291456\n",
        &mock,
        None,
    )
    .await;
    let admitted = initialize_body_of(permissive, 5 * 1024 * 1024).await;
    assert!(
        admitted.starts_with("HTTP/1.1 200"),
        "a body the policy's own attachment cap permits must not be refused \
         by the transport: {admitted:?}"
    );
    let past_derived = initialize_body_of(permissive, 10 * 1024 * 1024).await;
    assert!(
        past_derived.starts_with("HTTP/1.1 413"),
        "past the derived cap the memory bound still holds: {past_derived:?}"
    );

    // Nothing was loosened for everyone else: under the default policy the
    // 4 MiB floor stands, and the very same 5 MiB body is refused.
    let floored = serve_http(http_cli(&mock, Some(file.path())), "", &mock, None).await;
    let at_floor = initialize_body_of(floored, 5 * 1024 * 1024).await;
    assert!(
        at_floor.starts_with("HTTP/1.1 413"),
        "a policy that permits no such attachment keeps the 4 MiB floor: \
         {at_floor:?}"
    );

    // A refused body reaches neither tool nor guard, so it also reaches no
    // upstream: 413 is a transport verdict, invisible to the audit stream.
    let upstream = mock.received_requests().await.unwrap_or_default();
    assert!(
        upstream.is_empty(),
        "no handshake may contact Bugzilla: {} request(s)",
        upstream.len()
    );
}

/// An audit sink writing JSONL to `path`, wired as a deployment wires one.
fn audit_to(path: &std::path::Path) -> Arc<AuditState> {
    let sink = AuditSink::open(AuditConfig {
        path: Some(path.to_path_buf()),
        fsync: false,
        fail_mode: None,
        rotate_max_bytes: 0,
        rotate_keep: 8,
        suppressed_ids: true,
    })
    .expect("audit sink must open");
    Arc::new(AuditState::new(sink, FailMode::Open, None))
}

/// Every record written to `path`, in file order.
fn audit_events(path: &std::path::Path) -> Vec<AuditEvent> {
    std::fs::read_to_string(path)
        .expect("audit file must be readable")
        .lines()
        .filter(|l| !l.is_empty())
        .map(|l| serde_json::from_str(l).expect("every audit line must parse"))
        .collect()
}

/// A POST to `/mcp`, carrying `session` as the `mcp-session-id` request
/// header when one is given. Bounded, so a stream that never ends fails the
/// test instead of hanging the run.
fn mcp_post(addr: SocketAddr, session: Option<&str>) -> reqwest::RequestBuilder {
    let mut builder = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .expect("reqwest client")
        .post(format!("http://{addr}/mcp"))
        .header("Accept", "application/json, text/event-stream")
        .header("Content-Type", "application/json");
    if let Some(id) = session {
        builder = builder.header("mcp-session-id", id);
    }
    builder
}

/// Handshake as `client_name` and return the session id rmcp minted, read
/// off the RESPONSE header.
///
/// Raw reqwest rather than the rmcp client because that header is the whole
/// point: the `initialize` REQUEST cannot carry the id — it does not exist
/// yet — so anything reading the request header records nothing here.
async fn raw_initialize(addr: SocketAddr, client_name: &str) -> String {
    let response = mcp_post(addr, None)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": { "name": client_name, "version": "1" }
            }
        }))
        .send()
        .await
        .expect("the initialize request must reach the server");
    assert!(
        response.status().is_success(),
        "the handshake must succeed, got {}",
        response.status()
    );
    let id = response
        .headers()
        .get("mcp-session-id")
        .expect("rmcp answers initialize with a minted session id")
        .to_str()
        .expect("the minted id is ascii")
        .to_owned();
    // Drain the one-message SSE body: the handshake is complete only once
    // the server has produced its result.
    let _ = response.text().await.expect("an initialize response body");

    let accepted = mcp_post(addr, Some(&id))
        .json(&json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }))
        .send()
        .await
        .expect("the initialized notification must reach the server");
    assert!(
        accepted.status().is_success(),
        "notifications/initialized must be accepted, got {}",
        accepted.status()
    );
    id
}

/// Call `tool` inside session `id` over raw HTTP; returns the SSE body.
async fn raw_call_in_session(addr: SocketAddr, id: &str, tool: &str, args: Value) -> String {
    let response = mcp_post(addr, Some(id))
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": { "name": tool, "arguments": args }
        }))
        .send()
        .await
        .expect("the tool call must reach the server");
    assert!(
        response.status().is_success(),
        "an in-session tool call must be routed, got {}",
        response.status()
    );
    response.text().await.expect("a tool call response body")
}

/// The `initialize` record whose client called itself `name`.
fn initialize_of<'a>(events: &'a [AuditEvent], name: &str) -> &'a AuditEvent {
    events
        .iter()
        .find(|e| match &e.kind {
            AuditEventKind::Initialize(ev) => ev.client.name.as_deref() == Some(name),
            _ => false,
        })
        .unwrap_or_else(|| panic!("no initialize record names {name}"))
}

/// The `tool_call` record whose client called itself `name`.
fn tool_call_of<'a>(events: &'a [AuditEvent], name: &str) -> &'a AuditEvent {
    events
        .iter()
        .find(|e| match &e.kind {
            AuditEventKind::ToolCall(ev) => ev.client.name.as_deref() == Some(name),
            _ => false,
        })
        .unwrap_or_else(|| panic!("no tool_call record names {name}"))
}

#[tokio::test]
async fn initialize_record_joins_its_session() {
    // Issue #180: the record whose whole job is to anchor a session had no
    // join key. `session_info` read the `mcp-session-id` REQUEST header,
    // which cannot exist on `initialize` — rmcp mints the id afterwards and
    // returns it on the response — so the anchor was written with `id:
    // None` and a reader could only join by adjacency.
    let mock = MockServer::start().await;
    mount_bug_for_key(&mock, world_readable_bug(7), "srv-key").await;

    let dir = tempfile::tempdir().expect("audit temp dir");
    let audit_path = dir.path().join("audit.jsonl");
    let file = key_file("srv-key\n");
    let cli = http_cli(&mock, Some(file.path()));
    let addr = serve_http(cli, "", &mock, Some(audit_to(&audit_path))).await;

    let wire_id = raw_initialize(addr, "joining-client").await;
    let body = raw_call_in_session(addr, &wire_id, "bug_info", json!({ "bug_ids": [7] })).await;
    assert!(
        body.contains("\"result\""),
        "the in-session call must be served: {body}"
    );

    let events = audit_events(&audit_path);
    let init = events
        .iter()
        .find(|e| matches!(e.kind, AuditEventKind::Initialize(_)))
        .expect("the handshake is recorded");
    let call = events
        .iter()
        .find(|e| matches!(e.kind, AuditEventKind::ToolCall(_)))
        .expect("the tool call is recorded");

    assert_eq!(
        init.session.id.as_deref(),
        Some(wire_id.as_str()),
        "the anchor must carry the id the transport minted and put on the wire"
    );
    assert_eq!(
        call.session.id, init.session.id,
        "the tool call must join its own initialize"
    );
    assert!(
        init.seq < call.seq,
        "the anchor precedes what it anchors: {} vs {}",
        init.seq,
        call.seq
    );
}

#[tokio::test]
async fn concurrent_sessions_join_to_their_own_initialize() {
    // Two sessions, handshakes interleaved and the calls issued in the
    // reverse order, so adjacency — the nearest preceding initialize from
    // the same remote, which #180 says is not a join — answers wrongly for
    // both. Kills a wrapper carrying id state ACROSS calls (set at
    // initialize, read at create_stream): it stamps the newer session onto
    // the older one's call.
    //
    // Sequential by construction, so it does NOT kill a wrapper that sets
    // and re-reads shared state WITHIN one call. Only overlapping traffic
    // separates that from correct code, and measured here it killed such a
    // mutant in 2 of 20 runs at 8 concurrent sessions — a guard that weak
    // would launder the regression it is meant to catch, so it is left out
    // deliberately. (#167 rhymes without matching: there a race-dependent
    // observation was made deterministic by changing the mechanism; here
    // no deterministic mechanism exists, so the coverage goes rather than
    // the determinism.) What excludes that class is structural, not this
    // test: `stamp` takes the id as a parameter, and the wrapper adds no
    // state of its own to `LocalSessionManager`.
    let mock = MockServer::start().await;
    mount_bug_for_key(&mock, world_readable_bug(7), "srv-key").await;

    let dir = tempfile::tempdir().expect("audit temp dir");
    let audit_path = dir.path().join("audit.jsonl");
    let file = key_file("srv-key\n");
    let cli = http_cli(&mock, Some(file.path()));
    let addr = serve_http(cli, "", &mock, Some(audit_to(&audit_path))).await;

    let a = raw_initialize(addr, "client-a").await;
    let b = raw_initialize(addr, "client-b").await;
    assert_ne!(a, b, "two handshakes are two sessions");
    // b calls first: record order is not handshake order.
    raw_call_in_session(addr, &b, "bug_info", json!({ "bug_ids": [7] })).await;
    raw_call_in_session(addr, &a, "bug_info", json!({ "bug_ids": [7] })).await;

    let events = audit_events(&audit_path);
    assert_eq!(
        initialize_of(&events, "client-a").session.id.as_deref(),
        Some(a.as_str()),
        "a's anchor must carry a's minted id"
    );
    assert_eq!(
        initialize_of(&events, "client-b").session.id.as_deref(),
        Some(b.as_str()),
        "b's anchor must carry b's minted id"
    );
    assert_eq!(
        tool_call_of(&events, "client-a").session.id.as_deref(),
        Some(a.as_str()),
        "a's call must join a's initialize, not the nearest one"
    );
    assert_eq!(
        tool_call_of(&events, "client-b").session.id.as_deref(),
        Some(b.as_str()),
        "b's call must join b's initialize, not the nearest one"
    );
}

#[tokio::test]
async fn a_forged_session_id_is_not_copied_into_a_refusal_record() {
    // The other half of #180. `serve_negotiated_request_directly` injects
    // the request Parts verbatim and `has_session` runs only on the session
    // branch, so on the stateless path `mcp-session-id` is client free
    // text: a caller that never handshook could file its refusal under a
    // live session's id. The record answers with no id rather than a
    // forgeable one (#34: a forgeable id is worse than none).
    let mock = MockServer::start().await;
    mount_bug_for_key(&mock, world_readable_bug(7), "srv-key").await;

    let dir = tempfile::tempdir().expect("audit temp dir");
    let audit_path = dir.path().join("audit.jsonl");
    let file = key_file("srv-key\n");
    let cli = http_cli(&mock, Some(file.path()));
    let addr = serve_http(cli, "", &mock, Some(audit_to(&audit_path))).await;

    let victim = raw_initialize(addr, "real-client").await;

    // The refused half of the forgery pair; the served half is
    // `a_forged_session_id_is_not_copied_into_a_served_record`. This shape
    // — a sub-2026 revision with both keys (see
    // `a_handshake_free_call_is_refused_and_never_names_a_client`) — wears
    // the live session's id.
    let response = mcp_post(addr, Some(&victim))
        .header("MCP-Protocol-Version", "2025-11-25")
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "bug_info",
                "arguments": { "bug_ids": [7] },
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2025-11-25",
                    "io.modelcontextprotocol/clientCapabilities": {}
                }
            }
        }))
        .send()
        .await
        .expect("the forged request must reach the server");
    let body = response.text().await.expect("a body");
    assert!(
        !body.contains("a plain bug"),
        "a handshake-free call must not be served: {body}"
    );

    let events = audit_events(&audit_path);
    let calls: Vec<_> = events
        .iter()
        .filter(|e| matches!(e.kind, AuditEventKind::ToolCall(_)))
        .collect();
    assert_eq!(calls.len(), 1, "the refused call is recorded exactly once");
    assert_eq!(
        calls[0].session.id, None,
        "a client-supplied session id must never become a record's id; \
         the forged value was {victim}"
    );
    // The victim's own anchor is untouched: only the forger loses an id.
    assert_eq!(
        initialize_of(&events, "real-client").session.id.as_deref(),
        Some(victim.as_str()),
        "the handshake that really happened keeps its anchor"
    );
}

#[tokio::test]
async fn a_refused_call_in_a_session_keeps_its_session_anchor() {
    // The refused class spans BOTH arrivals, and only this one has a
    // session to name. `lifecycle_of` refuses any sub-2026 `_meta` protocol
    // declaration, which is deliberately broader than rmcp's stateless
    // routing: such a declaration without `clientCapabilities` stays on
    // the session branch (see that function's rustdoc), so the refusal is
    // recorded with the real minted id and joins its own `initialize` —
    // the join #180 newly makes possible, since that anchor had no id
    // before. Pinned because prose alone got this backwards once.
    //
    // The `MCP-Protocol-Version` header is load-bearing: without it rmcp
    // answers -32020 ("request _meta protocolVersion requires
    // MCP-Protocol-Version header") before any handler runs, and this test
    // would pass having recorded no refusal at all — true for the wrong
    // reason.
    let mock = MockServer::start().await;
    mount_bug_for_key(&mock, world_readable_bug(7), "srv-key").await;

    let dir = tempfile::tempdir().expect("audit temp dir");
    let audit_path = dir.path().join("audit.jsonl");
    let file = key_file("srv-key\n");
    let cli = http_cli(&mock, Some(file.path()));
    let addr = serve_http(cli, "", &mock, Some(audit_to(&audit_path))).await;

    let wire_id = raw_initialize(addr, "declaring-client").await;
    let response = mcp_post(addr, Some(&wire_id))
        .header("MCP-Protocol-Version", "2025-11-25")
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "bug_info",
                "arguments": { "bug_ids": [7] },
                "_meta": { "io.modelcontextprotocol/protocolVersion": "2025-11-25" }
            }
        }))
        .send()
        .await
        .expect("the declaring call must reach the server");
    let body = response.text().await.expect("a body");
    assert!(
        body.contains("served only for a revision this server serves at 2026-07-28 or later"),
        "the declaration must be refused by the handler, not served or \
         turned away by the transport: {body}"
    );
    let upstream = mock.received_requests().await.unwrap_or_default();
    assert!(
        upstream.is_empty(),
        "a refused call must contact no upstream: {} request(s)",
        upstream.len()
    );

    let events = audit_events(&audit_path);
    let calls: Vec<_> = events
        .iter()
        .filter_map(|e| match &e.kind {
            AuditEventKind::ToolCall(ev) => Some((e, ev.as_ref())),
            _ => None,
        })
        .collect();
    assert_eq!(calls.len(), 1, "the refused call is recorded exactly once");
    let (record, event) = calls[0];
    assert_eq!(event.client.name, None, "a refusal names no client");
    assert!(event.guard.is_none(), "the guard never ran");

    let anchor = initialize_of(&events, "declaring-client");
    assert_eq!(
        record.session.id.as_deref(),
        Some(wire_id.as_str()),
        "a refusal that DID open a session keeps its id"
    );
    assert_eq!(
        record.session.id, anchor.session.id,
        "and so joins the initialize that anchors it"
    );
}

// ---------- the 2026-07-28 per-request lifecycle (#34 stage 2) ----------

/// The revision whose requests carry their own context instead of
/// negotiating one.
const PER_REQUEST_REVISION: &str = "2026-07-28";

/// One raw 2026-07-28 per-request POST, answered as the server answers it.
///
/// Every header is load-bearing and rmcp refuses the request before any
/// handler without it: `MCP-Protocol-Version` must be present AND equal the
/// `_meta` revision (-32020 otherwise), and SEP-2243 makes `Mcp-Method` —
/// plus `Mcp-Name` naming the tool, for a `tools/call` — mandatory as soon
/// as that header names 2026-07-28 or newer. `initialize` is exempt from
/// the second pair and declares its revision in the body instead.
///
/// `clientInfo` is deliberately NOT among the keys the protocol requires,
/// which is what makes "a request naming no client at all" a servable
/// shape — and the shape no rmcp client can be made to send.
async fn per_request_post(
    addr: SocketAddr,
    session: Option<&str>,
    method: &str,
    mut params: Value,
    client: Option<Value>,
) -> reqwest::Response {
    if method != "initialize" {
        let mut meta = json!({
            "io.modelcontextprotocol/protocolVersion": PER_REQUEST_REVISION,
            "io.modelcontextprotocol/clientCapabilities": {},
        });
        if let Some(client) = client {
            meta["io.modelcontextprotocol/clientInfo"] = client;
        }
        params["_meta"] = meta;
    }
    let mut builder = mcp_post(addr, session)
        .header("MCP-Protocol-Version", PER_REQUEST_REVISION)
        .header("Mcp-Method", method.to_owned());
    if let Some(name) = params.get("name").and_then(Value::as_str) {
        builder = builder.header("Mcp-Name", name.to_owned());
    }
    builder
        .json(&json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params }))
        .send()
        .await
        .expect("the per-request POST must reach the server")
}

/// A per-request `bug_info` for bug 7, as body text.
async fn per_request_bug_7(addr: SocketAddr, client: Option<Value>) -> String {
    per_request_post(
        addr,
        None,
        "tools/call",
        json!({ "name": "bug_info", "arguments": { "bug_ids": [7] } }),
        client,
    )
    .await
    .text()
    .await
    .expect("a body")
}

/// Serve an audited deployment against `mock` with bug 7 mounted, and
/// return its address plus the audit file.
async fn served_with_audit(
    mock: &MockServer,
    dir: &tempfile::TempDir,
    key: &tempfile::NamedTempFile,
) -> (SocketAddr, std::path::PathBuf) {
    mount_bug_for_key(mock, world_readable_bug(7), "srv-key").await;
    let audit_path = dir.path().join("audit.jsonl");
    let cli = http_cli(mock, Some(key.path()));
    let addr = serve_http(cli, "", mock, Some(audit_to(&audit_path))).await;
    (addr, audit_path)
}

#[tokio::test]
async fn a_per_request_call_naming_no_client_is_served_and_names_no_placeholder() {
    // The acceptance criterion of #34, at the only level that can state it:
    // a tools/call with no `clientInfo` ANYWHERE — no handshake behind it
    // and none in `_meta` — is served, and the record names nobody rather
    // than rmcp. No rmcp client builds this request, so raw HTTP is the
    // only harness in which it exists.
    //
    // The mutation this kills is `client_of` reading `ctx.client_info()` or
    // `peer_info()` on this path: rmcp synthesises the stateless peer with
    // `Implementation::default()`, so either would put
    // `{"name":"rmcp","version":"3.1.4"}` into the record — not a missing
    // field but a plausible wrong one. The whole file is checked for the
    // string, not just this record's field, because a placeholder that
    // leaked into any other record would be the same defect.
    let mock = MockServer::start().await;
    let dir = tempfile::tempdir().expect("audit temp dir");
    let file = key_file("srv-key\n");
    let (addr, audit_path) = served_with_audit(&mock, &dir, &file).await;

    let body = per_request_bug_7(addr, None).await;
    assert!(
        body.contains("a plain bug"),
        "a 2026-07-28 per-request call is served: {body}"
    );

    let raw = std::fs::read_to_string(&audit_path).expect("audit file must be readable");
    assert!(
        !raw.contains("\"rmcp\""),
        "no record may name the SDK as the calling client: {raw}"
    );
    let events = audit_events(&audit_path);
    let calls: Vec<_> = events
        .iter()
        .filter(|e| matches!(e.kind, AuditEventKind::ToolCall(_)))
        .collect();
    assert_eq!(calls.len(), 1, "a served call is recorded exactly once");
    let AuditEventKind::ToolCall(event) = &calls[0].kind else {
        unreachable!("filtered above")
    };
    assert_eq!(event.client.name, None, "the request declared no client");
    assert_eq!(event.client.version, None, "and so declared no version");
    assert!(
        event.guard.is_some(),
        "the call really reached the guard, so absence is not just a refusal"
    );
    // No handshake, so no session: the id would have to come from the
    // forgeable request header, and a forgeable id is worse than none.
    assert_eq!(calls[0].session.id, None, "the path opens no session");
    assert!(
        calls[0].session.remote.is_some(),
        "`remote` plus nothing is the whole of grouping here"
    );
    // Nothing else opened a session either: no anchor exists to join to.
    assert!(
        !events
            .iter()
            .any(|e| matches!(e.kind, AuditEventKind::Initialize(_))),
        "a per-request call performs no handshake"
    );
}

#[tokio::test]
async fn a_per_request_call_records_the_client_it_declares() {
    // The other half, and the one the test above cannot see: an
    // unconditional `(None, None)` in the per-request arm passes there and
    // fails here. Recorded verbatim, capped but not otherwise touched —
    // self-declared at the same trust level as a handshake identity.
    let mock = MockServer::start().await;
    let dir = tempfile::tempdir().expect("audit temp dir");
    let file = key_file("srv-key\n");
    let (addr, audit_path) = served_with_audit(&mock, &dir, &file).await;

    let body = per_request_bug_7(
        addr,
        Some(json!({ "name": "wire-client", "version": "9.9" })),
    )
    .await;
    assert!(
        body.contains("a plain bug"),
        "a declaring per-request call is served too: {body}"
    );

    let events = audit_events(&audit_path);
    let record = tool_call_of(&events, "wire-client");
    let AuditEventKind::ToolCall(event) = &record.kind else {
        unreachable!("selected by kind")
    };
    assert_eq!(
        event.client.version.as_deref(),
        Some("9.9"),
        "the declared version rides with the declared name"
    );
    assert_eq!(
        event.client.principal, None,
        "nothing self-declared is ever promoted into the verified slot"
    );
    assert_eq!(event.client.work_context, None);
    assert_eq!(
        record.session.id, None,
        "declaring a client mints no session"
    );
}

#[tokio::test]
async fn a_forged_session_id_is_not_copied_into_a_served_record() {
    // The C3 hazard, widened by adoption from refusals to SERVED calls: on
    // the stateless branch rmcp validates `mcp-session-id` nowhere
    // (`has_session` runs only on the session branch) and injects the
    // request Parts verbatim, so the header is client free text. A caller
    // that never handshook could otherwise file its own served calls under
    // a live session's id — which is worse than the refusal case, because
    // the forged records now describe work that actually happened.
    let mock = MockServer::start().await;
    let dir = tempfile::tempdir().expect("audit temp dir");
    let file = key_file("srv-key\n");
    let (addr, audit_path) = served_with_audit(&mock, &dir, &file).await;

    let victim = raw_initialize(addr, "real-client").await;
    let served = raw_call_in_session(addr, &victim, "bug_info", json!({ "bug_ids": [7] })).await;
    assert!(
        served.contains("a plain bug"),
        "the victim's own session must really be live: {served}"
    );

    let response = per_request_post(
        addr,
        Some(&victim),
        "tools/call",
        json!({ "name": "bug_info", "arguments": { "bug_ids": [7] } }),
        Some(json!({ "name": "forging-client", "version": "1" })),
    )
    .await;
    let body = response.text().await.expect("a body");
    assert!(
        body.contains("a plain bug"),
        "the forged call is SERVED — this is not the refusal case: {body}"
    );

    let events = audit_events(&audit_path);
    let forged = tool_call_of(&events, "forging-client");
    assert_eq!(
        forged.session.id, None,
        "a client-supplied session id must never become a record's id; \
         the forged value was {victim}"
    );
    // The victim's own records are untouched: only the forger loses an id.
    assert_eq!(
        initialize_of(&events, "real-client").session.id.as_deref(),
        Some(victim.as_str()),
        "the handshake that really happened keeps its anchor"
    );
    assert_eq!(
        tool_call_of(&events, "real-client").session.id.as_deref(),
        Some(victim.as_str()),
        "and so does the call that really ran inside it"
    );
}

#[tokio::test]
async fn an_out_of_contract_listing_is_refused_and_discloses_no_tool() {
    // `list_tools` refuses the same shape `call_tool` does, and for its own
    // reason: the listing is pruned per deployment (I13) and per credential,
    // so answering a caller with no handshake behind it would disclose which
    // tools this policy removed. Unrecorded, as every listing is — the
    // schema has no event kind for one — which is why nothing else in the
    // suite could notice the arm being deleted.
    let mock = MockServer::start().await;
    let file = key_file("srv-key\n");
    let cli = http_cli(&mock, Some(file.path()));
    let addr = serve_http(cli, "", &mock, None).await;

    // The same reachable pre-2026 shape the call-side test uses: both
    // `_meta` keys at a revision this build serves.
    let body = mcp_post(addr, None)
        .header("MCP-Protocol-Version", "2025-11-25")
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": {
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2025-11-25",
                    "io.modelcontextprotocol/clientCapabilities": {}
                }
            }
        }))
        .send()
        .await
        .expect("the listing request must reach the server")
        .text()
        .await
        .expect("a body");

    assert!(
        body.contains("served only for a revision this server serves at 2026-07-28 or later"),
        "the declaration must be refused by the handler: {body}"
    );
    assert!(
        !body.contains("bug_info"),
        "a refused listing must name no tool at all: {body}"
    );
}

#[tokio::test]
async fn a_per_request_listing_carries_the_cache_hints() {
    // The wire companion to the in-process rows in server.rs: end to end,
    // a 2026-07-28 request really does reach the enabled half of the
    // SEP-2549 gate. Substring assertions hold because no served schema,
    // description or annotation spells either field.
    let mock = MockServer::start().await;
    let file = key_file("srv-key\n");
    let cli = http_cli(&mock, Some(file.path()));
    let addr = serve_http(cli, "", &mock, None).await;

    let body = per_request_post(addr, None, "tools/list", json!({}), None)
        .await
        .text()
        .await
        .expect("a body");
    assert!(
        body.contains("\"bug_info\""),
        // A named tool, not the `"tools"` key: that key is present even for
        // an empty listing or a scope that reaches nothing.
        "the per-request caller must be served a real listing: {body}"
    );
    assert!(
        body.contains("\"ttlMs\":0"),
        "a memory-served listing is stale on arrival: {body}"
    );
    assert!(
        body.contains("\"cacheScope\":\"private\""),
        "a per-deployment, per-credential listing is never publicly cacheable: {body}"
    );
}

#[tokio::test]
async fn a_per_request_initialize_is_answered_without_minting_a_session() {
    // The asymmetry adoption creates, pinned where it is observable: rmcp
    // routes a 2026-07-28 `initialize` down the STATELESS path, so over
    // http it is answered and audited but opens nothing — no
    // `mcp-session-id` on the response, no id in the record. (Over stdio
    // the same request is an ordinary handshake and does open a session.)
    // The record is written anyway: recording every handshake
    // unconditionally is the invariant, and joins are on id equality — an
    // anchor with no id anchors nothing, and gathers nothing belonging to
    // another session either.
    let mock = MockServer::start().await;
    let dir = tempfile::tempdir().expect("audit temp dir");
    let file = key_file("srv-key\n");
    let (addr, audit_path) = served_with_audit(&mock, &dir, &file).await;

    let response = per_request_post(
        addr,
        None,
        "initialize",
        json!({
            "protocolVersion": PER_REQUEST_REVISION,
            "capabilities": {},
            "clientInfo": { "name": "modern-client", "version": "2" }
        }),
        None,
    )
    .await;
    assert!(
        response.status().is_success(),
        "the per-request initialize must be answered, got {}",
        response.status()
    );
    assert!(
        response.headers().get("mcp-session-id").is_none(),
        "the stateless path mints no session id"
    );
    let body = response.text().await.expect("a body");
    assert!(
        body.contains(&format!("\"protocolVersion\":\"{PER_REQUEST_REVISION}\"")),
        "the revision this build now serves must be echoed: {body}"
    );

    let events = audit_events(&audit_path);
    let anchor = initialize_of(&events, "modern-client");
    let AuditEventKind::Initialize(event) = &anchor.kind else {
        unreachable!("selected by kind")
    };
    assert_eq!(
        event.protocol_version.as_deref(),
        Some(PER_REQUEST_REVISION),
        "the record names the revision the exchange spoke"
    );
    assert_eq!(
        event.client.version.as_deref(),
        Some("2"),
        "the record names the REQUEST's client, never the synthesised peer"
    );
    assert_eq!(
        anchor.session.id, None,
        "there is no session for the anchor to name"
    );
}

#[tokio::test]
async fn a_header_only_2026_declaration_is_refused_by_the_transport() {
    // The `Handshake` arm leans on this being the sole barrier: a request
    // that names 2026-07-28 in the HTTP header alone carries no `_meta`, so
    // `lifecycle_of` would read it as an ordinary in-session request and
    // `client_of` would fall back to a peer that never handshook. rmcp
    // refuses it first (-32602, `validate_request_protocol_version_meta`),
    // before any handler — pinned here because nothing else does, and
    // because the day it stops being true the identity source silently
    // changes.
    let mock = MockServer::start().await;
    let dir = tempfile::tempdir().expect("audit temp dir");
    let file = key_file("srv-key\n");
    let (addr, audit_path) = served_with_audit(&mock, &dir, &file).await;

    let response = mcp_post(addr, None)
        .header("MCP-Protocol-Version", PER_REQUEST_REVISION)
        .header("Mcp-Method", "tools/call")
        .header("Mcp-Name", "bug_info")
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": { "name": "bug_info", "arguments": { "bug_ids": [7] } }
        }))
        .send()
        .await
        .expect("the header-only request must reach the server");
    assert_eq!(
        response.status(),
        reqwest::StatusCode::BAD_REQUEST,
        "the transport refuses before any handler"
    );
    let body = response.text().await.expect("a body");
    assert!(
        body.contains("-32602"),
        "refused as missing required request metadata: {body}"
    );
    assert!(
        !std::path::Path::new(&audit_path).exists() || audit_events(&audit_path).is_empty(),
        "a request the handler never saw records nothing"
    );
    let upstream = mock.received_requests().await.unwrap_or_default();
    assert!(upstream.is_empty(), "and contacts no upstream");
}

#[tokio::test]
async fn a_per_request_call_cannot_reach_a_tool_the_deployment_pruned_i13() {
    // I13 under the handshake-free lifecycle: the pruned INSTANCE router is
    // what dispatch goes through on this path too, so a write tool
    // `--read-only` removed and a name that never existed must be
    // indistinguishable — byte-identical status and body, since anything
    // that differed would enumerate the deployment's policy.
    let mock = MockServer::start().await;
    mount_bug_for_key(&mock, world_readable_bug(7), "srv-key").await;
    let file = key_file("srv-key\n");
    let cli = http_cli(&mock, Some(file.path()));
    // Read-only through the POLICY, which is where `BugWarden::new` reads
    // it: main folds `--read-only` in there (I9 — the flag may only tighten
    // the policy, never loosen it), so a harness setting the Cli field
    // alone would serve a deployment no operator can configure.
    let addr = serve_http(cli, "[global]\nread_only = true\n", &mock, None).await;

    // Served first, so the deployment is demonstrably alive and reachable
    // on this path — otherwise two identical failures prove nothing.
    let served = per_request_bug_7(addr, None).await;
    assert!(
        served.contains("a plain bug"),
        "the read tool is served: {served}"
    );

    // Count the delta, never match a path: both tools hit `/rest/bug` with no
    // trailing segment, so the old `contains("/rest/bug/")` was vacuous (#193).
    // A leak shows up as create_bug's refused-path padding classify
    // (`GET /rest/bug?id=0`): drop that padding and only byte-identity still
    // catches a prune regression.
    let before = mock.received_requests().await.unwrap_or_default().len();
    let mut answers = Vec::new();
    for name in ["create_bug", "no_such_tool_at_all"] {
        let response = per_request_post(
            addr,
            None,
            "tools/call",
            // Schema-valid for `create_bug`, same literal for both names: with
            // `{}` a leaked dispatch dies at parse and the count cannot move.
            json!({
                "name": name,
                "arguments": {
                    "product": "P",
                    "component": "C",
                    "summary": "S",
                    "version": "V"
                }
            }),
            None,
        )
        .await;
        let status = response.status();
        answers.push((status, response.text().await.expect("a body")));
    }
    assert_eq!(
        answers[0], answers[1],
        "a pruned tool and a nonexistent one must be byte-identical (I13)"
    );
    assert!(
        answers[0].1.contains("\"error\""),
        "and both must be REFUSED, not two identical successes: {:?}",
        answers[0]
    );
    assert_eq!(
        mock.received_requests().await.unwrap_or_default().len(),
        before,
        "no unrouted call may reach Bugzilla"
    );
}

#[tokio::test]
async fn a_per_request_denial_is_uniform_with_a_nonexistent_bug_i2() {
    // I2 under the handshake-free lifecycle: with no session to attribute a
    // refusal to, the refusal text must still not say which of the two
    // reasons applied. Bug 7 is hidden by policy; bug 8 does not exist.
    let mock = MockServer::start().await;
    let mut secret = world_readable_bug(7);
    secret["product"] = json!("SecretSauce");
    mount_bug_for_key(&mock, secret, "srv-key").await;
    Mock::given(method("GET"))
        .and(path("/rest/bug"))
        .and(query_param("id", "8"))
        .and(query_param("api_key", "srv-key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "bugs": [] })))
        .mount(&mock)
        .await;

    let file = key_file("srv-key\n");
    let cli = http_cli(&mock, Some(file.path()));
    let addr = serve_http(
        cli,
        concat!(
            "[[rule]]\nname = \"hide-secret\"\naction = \"deny\"\n",
            "[rule.match]\nproducts = [\"Secret*\"]\n",
        ),
        &mock,
        None,
    )
    .await;

    let mut answers = Vec::new();
    for id in [7, 8] {
        let response = per_request_post(
            addr,
            None,
            "tools/call",
            json!({ "name": "bug_comments", "arguments": { "id": id } }),
            None,
        )
        .await;
        let status = response.status();
        let body = response.text().await.expect("a body");
        assert!(
            body.contains(&format!("Bug {id} is not accessible through this server")),
            "the uniform denial text, for bug {id}: {body}"
        );
        // Only the id the caller already knows may differ; status included so a
        // status-only distinguisher cannot hide behind equal bodies.
        answers.push((status, body.replace(&format!("Bug {id} "), "Bug _ ")));
    }
    assert_eq!(
        answers[0], answers[1],
        "a policy-denied bug and a nonexistent one must be indistinguishable (I2)"
    );
}

/// One per-request `tools/call` POST for `tool`, optionally carrying a stray
/// SEP-2243 `Mcp-Param-*` header, as `(status, body)`.
///
/// Inlined rather than widening [`per_request_post`]: exactly one caller
/// wants the extra header, and no other test should grow a parameter for it.
async fn per_request_call_with_canary(
    addr: SocketAddr,
    tool: &str,
    canary: bool,
) -> (reqwest::StatusCode, String) {
    let mut builder = mcp_post(addr, None)
        .header("MCP-Protocol-Version", PER_REQUEST_REVISION)
        .header("Mcp-Method", "tools/call")
        .header("Mcp-Name", tool.to_owned());
    if canary {
        builder = builder.header("Mcp-Param-X-Bugwarden-Canary", "1");
    }
    let response = builder
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": tool,
                "arguments": { "bug_ids": [7] },
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": PER_REQUEST_REVISION,
                    "io.modelcontextprotocol/clientCapabilities": {}
                }
            }
        }))
        .send()
        .await
        .expect("the per-request POST must reach the server");
    let status = response.status();
    (status, response.text().await.expect("a body"))
}

#[tokio::test]
async fn a_stray_mcp_param_header_is_inert_on_the_per_request_path() {
    // #116's validate-vs-skip oracle, pinned where adoption first makes it
    // meaningful. rmcp's `validate_request_headers` iterates only the
    // properties a served schema ANNOTATES with `x-mcp-header`; we author
    // none — `no_served_tool_authors_an_x_mcp_header_annotation` in
    // server.rs keeps it that way — so the loop has nothing to iterate and a
    // stray `Mcp-Param-*` header changes NEITHER answer: each leg is
    // byte-identical to itself with and without one, whether `get_tool`
    // found the schema or not. (The two legs differ from each other, of
    // course — one is served, one refused.) That per-leg invariance is what
    // makes the missing `RequestContext` on `get_tool` a bounded leak rather
    // than a live one.
    //
    // Honest caveat: the two EQUALITY oracles below pin the SDK, not our
    // code — no bugwarden mutant is uniquely caught by them, and their
    // failure mode is an rmcp bump that starts rejecting or promoting
    // unannotated `Mcp-Param-*` headers, the same genre as
    // `a_header_only_2026_declaration_is_refused_by_the_transport`. The
    // liveness and refusal-shape guards around them do cross our code.
    let mock = MockServer::start().await;
    mount_bug_for_key(&mock, world_readable_bug(7), "srv-key").await;
    let file = key_file("srv-key\n");
    let cli = http_cli(&mock, Some(file.path()));
    let addr = serve_http(cli, "", &mock, None).await;

    // Schema found. Serving it is also the liveness guard: two identical
    // refusals would prove nothing.
    let plain = per_request_call_with_canary(addr, "bug_info", false).await;
    let canaried = per_request_call_with_canary(addr, "bug_info", true).await;
    assert!(
        plain.1.contains("a plain bug"),
        "the schema-found leg must really be served: {plain:?}"
    );
    assert_eq!(
        plain, canaried,
        "a stray Mcp-Param-* header must change nothing for a tool with a schema"
    );

    // Schema absent. Counting upstream requests rather than matching a path
    // prefix: `bug_info` and `create_bug` both hit `/rest/bug` with no
    // trailing segment, so a prefix match would pass vacuously.
    let before = mock.received_requests().await.unwrap_or_default().len();
    let missing = per_request_call_with_canary(addr, "no_such_tool_at_all", false).await;
    let missing_canaried = per_request_call_with_canary(addr, "no_such_tool_at_all", true).await;
    assert!(
        missing.1.contains("\"error\""),
        "the schema-absent leg must be refused, not served: {missing:?}"
    );
    assert_eq!(
        missing, missing_canaried,
        "a stray Mcp-Param-* header must change nothing for a tool without one"
    );
    assert_eq!(
        mock.received_requests().await.unwrap_or_default().len(),
        before,
        "a refused call contacts no upstream, canary header or not"
    );
}
