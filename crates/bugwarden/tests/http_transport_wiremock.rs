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
//! - dropping the trim of the key file's content.

use std::io::Write as _;
use std::net::SocketAddr;
use std::sync::Arc;

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
    session::local::LocalSessionManager, StreamableHttpServerConfig, StreamableHttpService,
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
/// listener; returns the bound address.
async fn serve_http(cli: Arc<Cli>, policy: &str, mock: &MockServer) -> SocketAddr {
    let guard = Arc::new(Guard {
        policy: Policy::from_toml_str(policy).expect("test policy must parse"),
    });
    let bz = Arc::new(BugzillaClient::new(&mock.uri(), false).expect("client must build"));
    let server = BugWarden::new(cli, guard, bz).expect("server must build");

    let service = StreamableHttpService::new(
        move || Ok(server.clone()),
        LocalSessionManager::default().into(),
        StreamableHttpServerConfig::default(),
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
    let addr = serve_http(cli, "", &mock).await;
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
    let addr = serve_http(cli, "", &mock).await;
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
    let addr = serve_http(cli, "", &mock).await;
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
    let addr = serve_http(cli, "", &mock).await;
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
    let addr = serve_http(cli, "", &mock).await;
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
