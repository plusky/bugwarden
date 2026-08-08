//! `BugWarden::preflight` — the startup identity probe (issue: `whoami`
//! blackout, `plans/ISSUE_WHOAMI_IDENTITY.md` PR B).
//!
//! `Guard::resolve_caller` maps every `whoami` failure to `None`, and I4
//! then denies every classification a `created_by_me` rule reaches — a
//! deployment missing `/rest/whoami` (stock Bugzilla Core v1 does not
//! define it) starts up looking healthy and silently blacks out every
//! access classification the shipped `my-own-reports` carve-out covers.
//! `preflight()` turns that into a startup failure the operator can act on.
//!
//! Coverage contract (each of these mutations must fail at least one test):
//! - `preflight` returning `Ok` when `/rest/whoami` fails under server
//!   custody;
//! - `preflight` issuing a `whoami` request when the policy consults no
//!   identity criterion (the laziness contract must hold at startup too);
//! - `preflight` bailing under `KeyCustody::PerRequest` instead of
//!   warning-and-continuing (there is no server-held key to probe with);
//! - an API key leaking into a preflight error's text (I12).

use std::sync::Arc;

use bugwarden::config::Cli;
use bugwarden::server::{BugWarden, USER_AGENT};
use bugwarden_core::client::BugzillaClient;
use bugwarden_core::guard::Guard;
use bugwarden_core::policy::Policy;
use clap::Parser as _;
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// The issue's policy shape: an access-scoped `created_by_me` carve-out
/// above a blanket group-restricted deny. This is what makes
/// `Policy::needs_identity()` true.
const IDENTITY_POLICY: &str = concat!(
    "[[rule]]\nname = \"my-own-reports\"\naction = \"restrict\"\n",
    "capabilities = [\"read\", \"comments\", \"history\", \"attachments\"]\n",
    "operations = [\"access\"]\n",
    "[rule.match]\ncreated_by_me = true\n",
    "[[rule]]\nname = \"group-restricted\"\naction = \"deny\"\n",
    "[rule.match]\ngroup_restricted = true\n",
);

/// A policy that never consults identity at all.
const NO_IDENTITY_POLICY: &str = concat!(
    "[[rule]]\nname = \"group-restricted\"\naction = \"deny\"\n",
    "[rule.match]\ngroup_restricted = true\n",
);

/// The declared-login counterpart of [`IDENTITY_POLICY`]: same rule shape,
/// but resolved without `whoami` at all (PR C,
/// `plans/ISSUE_WHOAMI_IDENTITY.md`).
const DECLARED_IDENTITY_POLICY: &str = concat!(
    "[global]\n",
    "identity_source = \"declared\"\n",
    "identity_login = \"svc@example.com\"\n",
    "[[rule]]\nname = \"my-own-reports\"\naction = \"restrict\"\n",
    "capabilities = [\"read\", \"comments\", \"history\", \"attachments\"]\n",
    "operations = [\"access\"]\n",
    "[rule.match]\ncreated_by_me = true\n",
    "[[rule]]\nname = \"group-restricted\"\naction = \"deny\"\n",
    "[rule.match]\ngroup_restricted = true\n",
);

/// Mount `GET /rest/whoami` answering with `login`, expected `hits` times.
async fn mount_whoami(mock: &MockServer, login: &str, hits: u64) {
    Mock::given(method("GET"))
        .and(path("/rest/whoami"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": 1, "name": login, "real_name": "Reporter",
        })))
        .expect(hits)
        .mount(mock)
        .await;
}

/// Mount `GET /rest/valid_login?login=<login>` answering `result`,
/// expected `hits` times.
async fn mount_valid_login(mock: &MockServer, login: &str, result: bool, hits: u64) {
    Mock::given(method("GET"))
        .and(path("/rest/valid_login"))
        .and(query_param("login", login))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "result": result,
        })))
        .expect(hits)
        .mount(mock)
        .await;
}

/// Build a stdio (server-held key) `BugWarden` against `mock` with `policy`.
fn server_custody_server(policy: &str, mock: &MockServer) -> BugWarden {
    let mut cli = Cli::parse_from([
        "bugwarden",
        "--bugzilla-server",
        &mock.uri(),
        "--transport",
        "stdio",
        "--api-key",
        "test-key",
    ]);
    cli.api_key_file = None; // the ambient environment must not leak in
    let cfg = Arc::new(cli);
    let guard = Arc::new(Guard {
        policy: Policy::from_toml_str(policy).expect("test policy must parse"),
    });
    let bz =
        Arc::new(BugzillaClient::new(&mock.uri(), false, USER_AGENT).expect("client must build"));
    BugWarden::new(cfg, guard, bz).expect("server must build")
}

/// Build an http, per-request-key-custody `BugWarden` against `mock` with
/// `policy` (no `--api-key`/`--api-key-file`, so custody stays
/// `PerRequest`).
fn per_request_custody_server(policy: &str, mock: &MockServer) -> BugWarden {
    let mut cli = Cli::parse_from([
        "bugwarden",
        "--bugzilla-server",
        &mock.uri(),
        "--transport",
        "http",
    ]);
    cli.api_key = None;
    cli.api_key_file = None; // the ambient environment must not leak in
    let cfg = Arc::new(cli);
    let guard = Arc::new(Guard {
        policy: Policy::from_toml_str(policy).expect("test policy must parse"),
    });
    let bz =
        Arc::new(BugzillaClient::new(&mock.uri(), false, USER_AGENT).expect("client must build"));
    BugWarden::new(cfg, guard, bz).expect("server must build")
}

#[tokio::test]
async fn preflight_fails_closed_when_whoami_is_unavailable_under_server_custody() {
    // Stock Bugzilla Core v1: no /rest/whoami. An identity-consulting
    // policy plus a server-held key must refuse to start, naming the
    // endpoint, rather than start and blackout silently.
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/whoami"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&mock)
        .await;
    let server = server_custody_server(IDENTITY_POLICY, &mock);

    let err = server
        .preflight()
        .await
        .expect_err("a missing whoami endpoint must fail preflight");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("GET /rest/whoami"),
        "preflight error must name the failing endpoint: {msg}"
    );
    assert!(
        msg.contains("created_by_me"),
        "preflight error must say WHY it matters: {msg}"
    );
}

#[tokio::test]
async fn preflight_succeeds_when_whoami_answers_under_server_custody() {
    // A deployment that DOES answer whoami starts cleanly, and the probe
    // costs exactly one request (verified when the mock server drops).
    let mock = MockServer::start().await;
    mount_whoami(&mock, "reporter@example.com", 1).await;
    let server = server_custody_server(IDENTITY_POLICY, &mock);

    server
        .preflight()
        .await
        .expect("a working whoami must pass preflight");
}

#[tokio::test]
async fn preflight_costs_zero_requests_without_an_identity_policy() {
    // The laziness contract extends to startup: a policy that never
    // consults created_by_me must not probe whoami at all — pre-identity
    // deployments keep their exact upstream request pattern, startup
    // included. expect(0) is verified when the mock server drops.
    let mock = MockServer::start().await;
    mount_whoami(&mock, "reporter@example.com", 0).await;
    let server = server_custody_server(NO_IDENTITY_POLICY, &mock);

    server
        .preflight()
        .await
        .expect("a policy without identity criteria must never probe whoami");
}

#[tokio::test]
async fn preflight_warns_but_succeeds_under_per_request_custody() {
    // There is no server-held key to verify whoami with at startup under
    // per-request http custody (A5) — the probe would authenticate as
    // nobody in particular. preflight() must not attempt it (expect(0))
    // and must still return Ok: per-request custody stays correct
    // per-call, it is only unverifiable up front.
    let mock = MockServer::start().await;
    mount_whoami(&mock, "reporter@example.com", 0).await;
    let server = per_request_custody_server(IDENTITY_POLICY, &mock);

    server
        .preflight()
        .await
        .expect("per-request custody must not fail preflight");
}

#[tokio::test]
async fn preflight_succeeds_for_a_correct_declared_login_with_zero_whoami_hits() {
    // valid_login verifies the server's key at startup; resolve_caller
    // never looks it up again per call, so whoami must be untouched too.
    let mock = MockServer::start().await;
    mount_valid_login(&mock, "svc@example.com", true, 1).await;
    mount_whoami(&mock, "svc@example.com", 0).await;
    let server = server_custody_server(DECLARED_IDENTITY_POLICY, &mock);

    server
        .preflight()
        .await
        .expect("a key that authenticates as the declared login must pass preflight");
}

#[tokio::test]
async fn preflight_fails_closed_when_the_key_does_not_own_the_declared_login() {
    // A wrong declared login is fail-closed (I4): starting anyway would
    // deny every access classification the identity rules reach.
    let mock = MockServer::start().await;
    mount_valid_login(&mock, "svc@example.com", false, 1).await;
    let server = server_custody_server(DECLARED_IDENTITY_POLICY, &mock);

    let err = server
        .preflight()
        .await
        .expect_err("a login the key does not own must fail preflight");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("svc@example.com"),
        "preflight error must name the declared login: {msg}"
    );
}

#[tokio::test]
async fn preflight_declared_login_transport_error_names_the_endpoint() {
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/valid_login"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&mock)
        .await;
    let server = server_custody_server(DECLARED_IDENTITY_POLICY, &mock);

    let err = server
        .preflight()
        .await
        .expect_err("a failing valid_login endpoint must fail preflight");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("GET /rest/valid_login"),
        "preflight error must name the failing endpoint: {msg}"
    );
}

#[tokio::test]
async fn preflight_transport_error_does_not_leak_the_api_key_i12() {
    // Point the server at a closed port: the whoami lookup fails at the
    // transport level, where the unsanitized error would carry the
    // request URL with api_key=... in it. Nothing in the preflight error
    // text may contain the key.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    drop(listener); // free the port so every connection is refused

    let mut cli = Cli::parse_from([
        "bugwarden",
        "--bugzilla-server",
        &format!("http://{addr}"),
        "--transport",
        "stdio",
        "--api-key",
        "SUPERSECRETKEY123",
    ]);
    cli.api_key_file = None; // the ambient environment must not leak in
    let cfg = Arc::new(cli);
    let guard = Arc::new(Guard {
        policy: Policy::from_toml_str(IDENTITY_POLICY).expect("test policy must parse"),
    });
    let bz = Arc::new(
        BugzillaClient::new(&format!("http://{addr}"), false, USER_AGENT)
            .expect("client must build"),
    );
    let server = BugWarden::new(cfg, guard, bz).expect("server must build");

    let err = server
        .preflight()
        .await
        .expect_err("an unreachable whoami endpoint must fail preflight");
    let msg = format!("{err:#}");
    assert!(
        !msg.contains("SUPERSECRETKEY123"),
        "API key leaked into a preflight error: {msg}"
    );
}
