//! End-to-end tests of API key custody over REAL streamable HTTP.
//!
//! Each test builds a [`BugWarden`] with `--transport http`, serves it over
//! an actual TCP listener through `StreamableHttpService`, and connects an
//! rmcp client through reqwest — the only harness in which the per-request
//! key header physically exists. The wiremock upstream plays Bugzilla; the
//! key reaches it as the `api_key` query parameter, so a `query_param`
//! matcher proves WHICH key served a request.
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
//!   test in server.rs instead).

use std::io::Write as _;
use std::net::SocketAddr;
use std::sync::Arc;

use bugwarden::audit::{AuditConfig, AuditEvent, AuditEventKind, AuditSink, AuditState, FailMode};
use bugwarden::config::Cli;
use bugwarden::server::BugWarden;
use bugwarden_core::client::BugzillaClient;
use bugwarden_core::guard::Guard;
use bugwarden_core::policy::Policy;
use clap::Parser as _;
use rmcp::model::{CallToolRequestParams, CallToolResult};
use rmcp::service::{RoleClient, RunningService};
use rmcp::transport::streamable_http_client::StreamableHttpClientTransportConfig;
use rmcp::transport::streamable_http_server::{
    session::local::LocalSessionManager, StreamableHttpService,
};
use rmcp::transport::StreamableHttpClientTransport;
use rmcp::ServiceExt as _;
use serde_json::{json, Value};
use wiremock::matchers::{any, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Build the http-transport `Cli` against `mock`, with `key_file` when the
/// test runs in server-held mode. Both key fields are then set explicitly,
/// so the ambient environment (`BUGZILLA_API_KEY`, `BUGZILLA_API_KEY_FILE`)
/// cannot leak into what a test resolves.
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
    let bz = Arc::new(BugzillaClient::new(&mock.uri(), false).expect("client must build"));
    let mut server = BugWarden::new(cli, guard, bz).expect("server must build");
    if let Some(audit) = audit {
        server = server.with_audit(audit);
    }

    let service = StreamableHttpService::new(
        move || Ok(server.clone()),
        LocalSessionManager::default().into(),
        // The deployed configuration, not a default one: the transport
        // knobs bugwarden sets by name are only tested if the harness
        // serves what a deployment serves.
        bugwarden::server::http_server_config(),
    );
    let router = axum::Router::new().nest_service("/mcp", service);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind an ephemeral port");
    let addr = listener.local_addr().expect("bound address");
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    addr
}

/// Connect an MCP client to `addr` over streamable HTTP. With
/// `header_value`, every request carries `ApiKey: <value>` (a reqwest
/// default header); without, no key header exists anywhere in the session.
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
async fn a_handshake_free_call_is_refused_and_never_names_a_client() {
    // rmcp routes a request to its handshake-free lifecycle on the mere
    // PRESENCE of `_meta.io.modelcontextprotocol/protocolVersion` — whatever
    // revision that key names — and synthesises the peer with the SDK's own
    // build identity. So a client naming 2025-11-25, a revision this build
    // does serve, reaches a tool with no `initialize` behind it, and the
    // record would name `rmcp`/<sdk version>: a client the server never
    // spoke to. Narrowing SUPPORTED_PROTOCOL_VERSIONS cannot close this —
    // the routing never consults it — so the handler refuses the request.
    let mock = MockServer::start().await;
    mount_bug_for_key(&mock, world_readable_bug(7), "srv-key").await;

    let dir = tempfile::tempdir().expect("audit temp dir");
    let audit_path = dir.path().join("audit.jsonl");
    let sink = AuditSink::open(AuditConfig {
        path: audit_path.clone(),
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
    // It answers `get_info` and nothing else: no tool, no guard, no
    // upstream. That is what makes an unauthenticated pre-request surface
    // acceptable while #32 is open.
    let upstream = mock.received_requests().await.unwrap_or_default();
    assert!(
        upstream.is_empty(),
        "discover must contact no upstream: {} request(s)",
        upstream.len()
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
        path: audit_path.clone(),
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
