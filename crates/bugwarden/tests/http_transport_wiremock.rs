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
//!   test in server.rs instead);
//! - keeping the empty entry `MCP_ALLOWED_HOSTS=` produces instead of
//!   dropping it, which turns Host validation on with nothing rmcp can
//!   match and refuses every request;
//! - handing an unparsable `--allowed-hosts` entry (`*`, a URL) to rmcp
//!   instead of refusing it at `http_server_config`;
//! - the POST body cap going back to a fixed value, which refuses uploads
//!   the operator's `global.max_attachment_bytes` permits, or losing its
//!   4 MiB floor, which would let a policy shrink the transport's memory
//!   bound (or remove it entirely at `0`);
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
    // the SDK's own build
    // identity. The body below sends both keys at 2025-11-25 deliberately:
    // that is the one shape still reachable on a revision this build serves
    // — a tool with no `initialize` behind it, recorded as `rmcp`/<sdk
    // version>, a client the server never spoke to. Drop `clientCapabilities`
    // and it takes the session path instead, proving nothing.
    // Narrowing SUPPORTED_PROTOCOL_VERSIONS cannot close it either, the
    // routing never consults it, so the handler refuses the request.
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

    // The one handshake-free shape still reachable on a revision this build
    // serves (see `a_handshake_free_call_is_refused_and_never_names_a_client`),
    // wearing the live session's id.
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
    // session to name. `skips_the_handshake` fires on any `_meta` protocol
    // declaration, which is deliberately broader than rmcp's stateless
    // routing: a sub-2026 declaration without `clientCapabilities` stays on
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
        body.contains("requires the initialize handshake"),
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
