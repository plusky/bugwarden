//! End-to-end tests of the HTTP bearer gate over REAL streamable HTTP
//! (issue #32).
//!
//! Two layers, both needed. The wire layer serves a [`BugWarden`] through the
//! same `http_auth::guard_router` `main` uses, over an actual TCP listener,
//! and drives it with raw reqwest (for the refusal shape, which is not an MCP
//! message at all) and with an rmcp client (for the per-credential tool
//! surface). The process layer spawns the shipped binary, because "refuses to
//! start before binding the port" is a claim about `main`'s ordering that no
//! in-process test can make.
//!
//! Coverage contract (each of these mutations must fail at least one test):
//! - resolving the bearer gate after the listener is bound, or after the
//!   audit sink is opened;
//! - accepting a request with no `Authorization` header, the wrong token, or
//!   a non-Bearer scheme;
//! - varying the refusal between those cases (status, headers or body), or
//!   answering `404` for an unrouted path instead of the same refusal;
//! - granting the write scope to the read token, or leaving the write tools
//!   in a read-scope `tools/list`;
//! - letting a read-scope write call reach Bugzilla, or answering it with
//!   anything other than the router's own unknown-tool error;
//! - moving the gate behind rmcp's POST body cap, which would let an
//!   unauthenticated caller probe the cap for the policy value it derives;
//! - dropping any of the five startup refusals;
//! - refusing a stdio start over a token in the environment.

use std::net::SocketAddr;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use bugwarden::config::Cli;
use bugwarden::http_auth::{self, HttpAuth, HttpEnv};
use bugwarden::server::{BugWarden, USER_AGENT, WRITE_TOOLS};
use bugwarden_core::client::BugzillaClient;
use bugwarden_core::guard::Guard;
use bugwarden_core::policy::Policy;
use clap::Parser as _;
use rmcp::model::CallToolRequestParams;
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

/// 32 printable non-space characters each, and distinct.
const WRITE_TOKEN: &str = "0123456789abcdef0123456789abcdef";
const READ_TOKEN: &str = "fedcba9876543210fedcba9876543210";

/// Bounded so a binary that never exits fails this test rather than hanging
/// the suite until CI's own timeout kills it.
const EXIT_TIMEOUT: Duration = Duration::from_secs(20);

/// Every environment variable the binary reads, cleared before each spawn:
/// an ambient value would change exactly what is under test.
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

/// The scrub list is only as good as its coverage of `Cli`; a flag added
/// with an `env` fallback would otherwise reach the spawned binary from the
/// runner's environment and change what these tests measure. The two bearer
/// tokens are not clap arguments, so they are checked by name.
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

// ---------- wire-level harness ----------

/// Serve a [`BugWarden`] over a real TCP listener behind the bearer gate
/// `env`/`insecure` resolve to, and return the bound address.
///
/// The router is assembled by `http_auth::guard_router`, the one `main`
/// calls, and scope enforcement is switched the way `main` switches it — so
/// no test can exercise a differently-guarded server than the deployment
/// serves.
async fn serve_guarded(mock: &MockServer, env: &HttpEnv, insecure: bool) -> SocketAddr {
    let mut cli = Cli::parse_from([
        "bugwarden",
        "--bugzilla-server",
        &mock.uri(),
        "--transport",
        "http",
    ]);
    // Both key fields explicitly cleared, so the ambient environment cannot
    // leak into what these tests resolve; the tests send the key per request.
    cli.api_key = None;
    cli.api_key_file = None;
    let guard = Arc::new(Guard {
        policy: Policy::default(),
    });
    let bz =
        Arc::new(BugzillaClient::new(&mock.uri(), false, USER_AGENT).expect("client must build"));
    let auth = Arc::new(HttpAuth::resolve(env, insecure).expect("the test gate must resolve"));
    let server = BugWarden::new(Arc::new(cli), guard, bz)
        .expect("server must build")
        .with_scope_enforcement(!auth.is_insecure());

    let config = server.http_server_config();
    let service = StreamableHttpService::new(
        move || Ok(server.clone()),
        LocalSessionManager::default().into(),
        config,
    );
    let router = http_auth::guard_router(
        axum::Router::new().nest_service("/mcp", service),
        Arc::clone(&auth),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind an ephemeral port");
    let addr = listener.local_addr().expect("bound address");
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    addr
}

/// Both tokens configured.
fn both_tokens() -> HttpEnv {
    HttpEnv {
        write: Some(WRITE_TOKEN.to_owned()),
        read: Some(READ_TOKEN.to_owned()),
    }
}

/// Connect an MCP client that presents `token` as its bearer credential and
/// `test-key` as the per-request Bugzilla key.
async fn connect(addr: SocketAddr, token: Option<&str>) -> RunningService<RoleClient, ()> {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert("ApiKey", "test-key".parse().expect("header value"));
    if let Some(token) = token {
        headers.insert(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {token}").parse().expect("header value"),
        );
    }
    let client = reqwest::Client::builder()
        .default_headers(headers)
        .build()
        .expect("reqwest client");
    let transport = StreamableHttpClientTransport::with_client(
        client,
        StreamableHttpClientTransportConfig::with_uri(format!("http://{addr}/mcp")),
    );
    ().serve(transport)
        .await
        .expect("MCP handshake must succeed")
}

/// The tool names this credential is offered.
async fn listed_tools(client: &RunningService<RoleClient, ()>) -> Vec<String> {
    client
        .list_all_tools()
        .await
        .expect("tools/list must succeed")
        .into_iter()
        .map(|tool| tool.name.to_string())
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

/// Mount the fetches a served `bug_info` call needs.
async fn mount_bug(mock: &MockServer, id: u64) {
    Mock::given(method("GET"))
        .and(path("/rest/bug"))
        .and(query_param("id", id.to_string()))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({ "bugs": [world_readable_bug(id)] })),
        )
        .mount(mock)
        .await;
    Mock::given(method("GET"))
        .and(path("/rest/bug"))
        .and(query_param("id", "0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "bugs": [] })))
        .mount(mock)
        .await;
}

// ---------- the refusal, and its uniformity (I2) ----------

/// One raw HTTP exchange, reduced to what a caller can actually observe.
#[derive(Debug, PartialEq, Eq)]
struct Observed {
    status: u16,
    www_authenticate: Option<String>,
    body: Vec<u8>,
}

async fn probe(client: &reqwest::Client, url: &str, authorization: &[&str]) -> Observed {
    let mut request = client.post(url).json(&json!({
        "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}
    }));
    // Appended, not replaced: passing two values is how a duplicate
    // `Authorization` reaches the server.
    for value in authorization {
        request = request.header(reqwest::header::AUTHORIZATION, *value);
    }
    let response = request.send().await.expect("the server must answer");
    Observed {
        status: response.status().as_u16(),
        www_authenticate: response
            .headers()
            .get(reqwest::header::WWW_AUTHENTICATE)
            .map(|v| v.to_str().expect("ascii header").to_owned()),
        body: response.bytes().await.expect("body").to_vec(),
    }
}

#[tokio::test]
async fn every_unauthenticated_request_gets_one_byte_identical_refusal() {
    let mock = MockServer::start().await;
    // Nothing may reach Bugzilla: a refused request never gets that far.
    Mock::given(any())
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .named("a refused request must make no upstream request")
        .mount(&mock)
        .await;
    let addr = serve_guarded(&mock, &both_tokens(), false).await;
    let http = reqwest::Client::new();
    let mcp = format!("http://{addr}/mcp");

    let baseline = probe(&http, &mcp, &[]).await;
    assert_eq!(baseline.status, 401);
    assert_eq!(baseline.www_authenticate.as_deref(), Some("Bearer"));
    assert!(baseline.body.is_empty(), "{baseline:?}");

    let good = format!("Bearer {WRITE_TOKEN}");
    let good_read = format!("Bearer {READ_TOKEN}");
    for authorization in [
        // Wrong token, a prefix of the right one, the right token as some
        // other scheme, a bare scheme, and a scheme-less value.
        vec!["Bearer 11111111111111111111111111111111"],
        vec!["Bearer 0123456789abcdef0123456789abcde"],
        vec![&*format!("Basic {WRITE_TOKEN}")],
        vec!["Bearer"],
        vec![WRITE_TOKEN],
        vec![""],
        // Two credentials in one request. RFC 9110 makes that malformed, and
        // a proxy on the path forwarding last-wins where the server reads
        // first-wins would authorize the other one — so BOTH orders are
        // refused, including two copies of a token that would be accepted
        // alone.
        vec![&*good, &*good_read],
        vec![&*good_read, &*good],
        vec![&*good, &*good],
        vec![&*good, "Bearer 11111111111111111111111111111111"],
        vec!["Bearer 11111111111111111111111111111111", &*good],
    ] {
        assert_eq!(
            probe(&http, &mcp, &authorization).await,
            baseline,
            "{authorization:?} must be refused exactly like a missing header"
        );
    }
    // The same single credential, alone, is served — so the refusals above
    // are about the duplication and not about the value.
    assert_ne!(probe(&http, &mcp, &[&good]).await.status, 401);

    // Path knowledge is part of the same uniformity: an unrouted path is
    // refused identically, so probing cannot map the surface either.
    for url in [
        format!("http://{addr}/"),
        format!("http://{addr}/mcp/nope"),
        format!("http://{addr}/.well-known/oauth-protected-resource"),
    ] {
        assert_eq!(
            probe(&http, &url, &[]).await,
            baseline,
            "{url} must be refused exactly like /mcp"
        );
        assert_ne!(
            probe(&http, &url, &[&good]).await.status,
            401,
            "an authenticated caller gets the router's own answer, not the gate's"
        );
    }
}

#[tokio::test]
async fn an_oversized_body_from_a_stranger_is_refused_by_the_gate_not_the_cap() {
    // The gate is a layer in FRONT of rmcp, so an unauthenticated caller
    // never reaches the POST body cap and cannot binary-search it. DESIGN.md
    // rests the 413-observability argument on exactly this.
    let mock = MockServer::start().await;
    let addr = serve_guarded(&mock, &both_tokens(), false).await;
    let http = reqwest::Client::new();
    let url = format!("http://{addr}/mcp");
    // Past the 4 MiB floor the default policy derives.
    let oversized = "x".repeat(5 * 1024 * 1024);

    let anonymous = http
        .post(&url)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(oversized.clone())
        .send()
        .await
        .expect("the server must answer");
    assert_eq!(anonymous.status().as_u16(), 401, "the gate answers first");

    let authenticated = http
        .post(&url)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .header(
            reqwest::header::ACCEPT,
            "application/json, text/event-stream",
        )
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {WRITE_TOKEN}"),
        )
        .body(oversized)
        .send()
        .await
        .expect("the server must answer");
    assert_eq!(
        authenticated.status().as_u16(),
        413,
        "a credentialed caller reaches the cap, and only then"
    );

    // The READ scope reaches it too: the cap is a transport limit and the
    // scope gate sits above it in the handler, so a credential that may not
    // upload at all still sees the boundary. DESIGN.md's #52 disclosure note
    // says so; this is what makes that sentence true.
    let read_scope = http
        .post(&url)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .header(
            reqwest::header::ACCEPT,
            "application/json, text/event-stream",
        )
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {READ_TOKEN}"),
        )
        .body("y".repeat(5 * 1024 * 1024))
        .send()
        .await
        .expect("the server must answer");
    assert_eq!(read_scope.status().as_u16(), 413);
}

// ---------- the two scopes ----------

#[tokio::test]
async fn the_write_token_reaches_the_whole_tool_surface() {
    let mock = MockServer::start().await;
    mount_bug(&mock, 7).await;
    Mock::given(method("POST"))
        .and(path("/rest/bug/7/comment"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "id": 99 })))
        .expect(1)
        .mount(&mock)
        .await;
    let addr = serve_guarded(&mock, &both_tokens(), false).await;
    let client = connect(addr, Some(WRITE_TOKEN)).await;

    let listed = listed_tools(&client).await;
    for name in WRITE_TOOLS {
        assert!(
            listed.iter().any(|t| t == name),
            "the write scope must be offered {name}: {listed:?}"
        );
    }
    assert!(listed.iter().any(|t| t == "bug_info"), "{listed:?}");

    let result = client
        .call_tool(
            CallToolRequestParams::new("add_comment".to_owned()).with_arguments(
                json!({ "bug_id": 7, "comment": "hello" })
                    .as_object()
                    .expect("object")
                    .clone(),
            ),
        )
        .await
        .expect("the write scope must reach a write tool");
    assert_ne!(result.is_error, Some(true), "{result:?}");
}

#[tokio::test]
async fn the_read_token_is_offered_only_the_read_tools() {
    let mock = MockServer::start().await;
    let addr = serve_guarded(&mock, &both_tokens(), false).await;

    let read = listed_tools(&connect(addr, Some(READ_TOKEN)).await).await;
    let write = listed_tools(&connect(addr, Some(WRITE_TOKEN)).await).await;

    for name in WRITE_TOOLS {
        assert!(
            !read.iter().any(|t| t == name),
            "the read scope must not be offered {name}: {read:?}"
        );
    }
    // The listing is FILTERED, not emptied: every non-write tool the write
    // scope sees is still there.
    let expected: Vec<&String> = write
        .iter()
        .filter(|t| !WRITE_TOOLS.contains(&t.as_str()))
        .collect();
    assert_eq!(
        read.iter().collect::<Vec<_>>(),
        expected,
        "the read listing must be the write listing minus the write tools"
    );
    assert!(!expected.is_empty(), "the fixture must offer read tools");
}

#[tokio::test]
async fn a_read_scope_write_call_is_refused_as_unrouted_and_reaches_no_bugzilla() {
    let mock = MockServer::start().await;
    // The read tool below is the only thing allowed upstream; anything a
    // refused write call would send falls through to this and fails the test.
    mount_bug(&mock, 7).await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .named("a scope-refused write call must POST nothing")
        .mount(&mock)
        .await;
    let addr = serve_guarded(&mock, &both_tokens(), false).await;
    let client = connect(addr, Some(READ_TOKEN)).await;

    // A read tool still works, so the refusal below is about the scope and
    // not about the session being broken.
    let served = client
        .call_tool(
            CallToolRequestParams::new("bug_info".to_owned()).with_arguments(
                json!({ "bug_ids": [7] })
                    .as_object()
                    .expect("object")
                    .clone(),
            ),
        )
        .await
        .expect("the read scope must reach a read tool");
    assert_ne!(served.is_error, Some(true), "{served:?}");

    let refused = client
        .call_tool(
            CallToolRequestParams::new("add_comment".to_owned()).with_arguments(
                json!({ "bug_id": 7, "comment": "hello" })
                    .as_object()
                    .expect("object")
                    .clone(),
            ),
        )
        .await
        .expect_err("the read scope must not reach a write tool");

    // Compared against the router's OWN answer for a name it does not route,
    // not against a literal: a scope-hidden tool must be indistinguishable
    // from one that does not exist, and this stays true across rmcp bumps.
    let unknown = client
        .call_tool(CallToolRequestParams::new("no_such_tool_at_all".to_owned()))
        .await
        .expect_err("an unknown tool is an error");
    assert_eq!(
        refused.to_string(),
        unknown.to_string(),
        "a write tool must look exactly like a tool that does not exist"
    );
}

#[tokio::test]
async fn insecure_no_auth_serves_every_caller_the_full_surface() {
    let mock = MockServer::start().await;
    let addr = serve_guarded(&mock, &HttpEnv::default(), true).await;
    let listed = listed_tools(&connect(addr, None).await).await;
    for name in WRITE_TOOLS {
        assert!(
            listed.iter().any(|t| t == name),
            "--insecure-no-auth grants the full write scope: {listed:?}"
        );
    }
}

// ---------- startup: the process, not the library ----------

/// Run the shipped binary with `args` and `env`, and return
/// `(exit code, stderr)`.
async fn run_binary(args: &[&str], env: &[(&str, &str)]) -> (Option<i32>, String) {
    let mut cmd = tokio::process::Command::new(env!("CARGO_BIN_EXE_bugwarden"));
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    for var in AMBIENT_VARS {
        cmd.env_remove(var);
    }
    for (key, value) in env {
        cmd.env(key, value);
    }
    let child = cmd.spawn().expect("the built binary must start");
    let output = tokio::time::timeout(EXIT_TIMEOUT, child.wait_with_output())
        .await
        .expect("the binary must exit rather than serve")
        .expect("the binary must be waitable");
    (
        output.status.code(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

#[tokio::test]
async fn every_startup_misconfiguration_refuses_before_the_port_is_bound() {
    // The port is already taken by this test. A start that bound before
    // checking its credentials would fail with a bind error instead of the
    // token error each case asserts — which is what makes this an ordering
    // test and not just a validation test.
    let occupied = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = occupied.local_addr().expect("addr").port().to_string();
    let base: Vec<&str> = vec![
        "--bugzilla-server",
        "https://bugzilla.example.invalid",
        "--port",
        &port,
    ];
    let secret = "SUPERSECRETTOKENSUPERSECRETTOKEN0";

    /// One refusal case: extra flags, environment, and the phrase the
    /// diagnostic must carry.
    struct Case<'a> {
        flags: Vec<&'a str>,
        env: Vec<(&'a str, &'a str)>,
        expected: &'a str,
    }
    let case = |flags: Vec<&'static str>, env, expected| Case {
        flags,
        env,
        expected,
    };
    let cases = vec![
        // 1. http (the DEFAULT transport) with no token and no opt-out.
        case(vec![], vec![], "requires a bearer token"),
        // 2. --insecure-no-auth together with a token.
        case(
            vec!["--insecure-no-auth"],
            vec![("BUGWARDEN_HTTP_TOKEN", secret)],
            "conflicts with a configured bearer token",
        ),
        // 3. too short.
        case(
            vec![],
            vec![("BUGWARDEN_HTTP_TOKEN", "tooshort")],
            "holds fewer than 32 characters",
        ),
        // 4. not printable ASCII.
        case(
            vec![],
            vec![(
                "BUGWARDEN_HTTP_READ_TOKEN",
                "0123456789abcdef 0123456789abcdef",
            )],
            "use printable ASCII, and no spaces",
        ),
        // 5. the read token IS the write token.
        case(
            vec![],
            vec![
                ("BUGWARDEN_HTTP_TOKEN", secret),
                ("BUGWARDEN_HTTP_READ_TOKEN", secret),
            ],
            "identical",
        ),
    ];

    for Case {
        flags,
        env,
        expected,
    } in cases
    {
        let args: Vec<&str> = base.iter().copied().chain(flags.iter().copied()).collect();
        let (code, stderr) = run_binary(&args, &env).await;
        assert_eq!(code, Some(1), "{expected}: {stderr}");
        assert!(
            stderr.contains(expected),
            "expected {expected:?} in: {stderr}"
        );
        assert!(
            !stderr.contains("failed to bind"),
            "the refusal must come before the bind: {stderr}"
        );
        // I12: the diagnostic names the variable, never what it held.
        for (var, value) in &env {
            assert!(
                stderr.contains(var) || expected == "requires a bearer token",
                "{stderr}"
            );
            assert!(
                !stderr.contains(value),
                "the error must not echo the token: {stderr}"
            );
        }
    }

    drop(occupied);
}

/// A port to hand the child, chosen by binding and releasing an ephemeral
/// one. Racy in principle; the child's readiness poll below is what turns a
/// lost race into a test failure rather than a hang.
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind")
        .local_addr()
        .expect("addr")
        .port()
}

#[tokio::test]
async fn the_shipped_binary_wires_the_read_token_to_the_read_surface() {
    // `main` is the only place scope enforcement is switched on, and every
    // other test in this file builds the server itself — so deleting that
    // one call leaves them all green while every deployed read token gets
    // the write surface. This drives the REAL executable end to end.
    let mock = MockServer::start().await;
    let port = free_port();
    let mut cmd = tokio::process::Command::new(env!("CARGO_BIN_EXE_bugwarden"));
    cmd.args(["--bugzilla-server", &mock.uri()])
        .args(["--host", "127.0.0.1", "--port", &port.to_string()])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    for var in AMBIENT_VARS {
        cmd.env_remove(var);
    }
    cmd.env("BUGWARDEN_HTTP_TOKEN", WRITE_TOKEN)
        .env("BUGWARDEN_HTTP_READ_TOKEN", READ_TOKEN);
    cmd.kill_on_drop(true);
    let mut child = cmd.spawn().expect("the built binary must start");

    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().expect("addr");
    let ready = tokio::time::timeout(EXIT_TIMEOUT, async {
        loop {
            if tokio::net::TcpStream::connect(addr).await.is_ok() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await;
    assert!(ready.is_ok(), "the binary must start serving");

    let read = listed_tools(&connect(addr, Some(READ_TOKEN)).await).await;
    let write = listed_tools(&connect(addr, Some(WRITE_TOKEN)).await).await;
    for name in WRITE_TOOLS {
        assert!(
            write.iter().any(|t| t == name),
            "the deployed write token must reach {name}: {write:?}"
        );
        assert!(
            !read.iter().any(|t| t == name),
            "the deployed read token must NOT reach {name}: {read:?}"
        );
    }
    assert!(!read.is_empty(), "the read token must still see read tools");
    let _ = child.kill().await;
}

#[tokio::test]
async fn a_token_refusal_precedes_the_audit_sink() {
    // The gate is resolved ahead of every other startup effect, and the audit
    // sink is the one with a side effect on disk: a refused start must not
    // have created (or rotated) the operator's audit file. Same ordering
    // rationale key custody already has.
    let dir = tempfile::tempdir().expect("tempdir");
    let audit_path = dir.path().join("audit.jsonl");
    let config_path = dir.path().join("audit.toml");
    std::fs::write(
        &config_path,
        format!("path = {:?}\n", audit_path.to_str().expect("utf-8 path")),
    )
    .expect("write the audit config");

    let (code, stderr) = run_binary(
        &[
            "--bugzilla-server",
            "https://bugzilla.example.invalid",
            "--audit-config",
            config_path.to_str().expect("utf-8 path"),
        ],
        &[],
    )
    .await;
    assert_eq!(code, Some(1), "{stderr}");
    assert!(stderr.contains("requires a bearer token"), "{stderr}");
    assert!(
        !audit_path.exists(),
        "a refused start must not have opened the audit sink"
    );
}

#[tokio::test]
async fn a_stdio_start_ignores_the_bearer_tokens() {
    // Every http refusal condition, handed to a stdio run that has no key
    // source: it must fail on the key, which is the error a stdio start
    // without a token already had, and never on the tokens.
    for env in [
        vec![("BUGWARDEN_HTTP_TOKEN", "tooshort")],
        vec![
            ("BUGWARDEN_HTTP_TOKEN", "0123456789abcdef0123456789abcdef"),
            (
                "BUGWARDEN_HTTP_READ_TOKEN",
                "0123456789abcdef0123456789abcdef",
            ),
        ],
    ] {
        let (code, stderr) = run_binary(
            &[
                "--bugzilla-server",
                "https://bugzilla.example.invalid",
                "--transport",
                "stdio",
            ],
            &env,
        )
        .await;
        assert_eq!(code, Some(1), "{stderr}");
        assert!(
            stderr.contains("--transport stdio requires"),
            "a stdio start must fail on its key, not on the tokens: {stderr}"
        );
    }
}
