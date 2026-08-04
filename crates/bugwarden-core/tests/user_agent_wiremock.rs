//! HTTP-level proof that the client identifies its caller on the wire and
//! never itself (issue #55).
//!
//! `BugzillaClient` builds requests three ways — the authenticated GET, the
//! authenticated POST/PUT body, and the unauthenticated `page.cgi` fetch —
//! and both authentication modes reach the builder through the same
//! constructor, so all of them are exercised. A header set on the shared
//! `reqwest::Client` does reach every request, but only a test says so: a
//! construction that made the identity conditional on the auth mode, or a
//! per-request header on one method, is invisible in review and silently
//! replaces the client default rather than duplicating it.

use bugwarden_core::client::BugzillaClient;
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Names neither this crate nor the binary that ships it, so the assertions
/// below can only pass with the caller's value on the wire — an identity
/// this crate invented for itself would read as plausibly correct and fail
/// here.
const CALLER_AGENT: &str = "probe-agent/9.9 (+https://example.invalid/probe)";

/// Deliberately distinctive so a leak into the header is unmistakable (I12).
const KEY: &str = "SUPERSECRETKEY123";

/// Drive one request of every shape the client builds, in one auth mode.
async fn every_request_shape(use_auth_header: bool) {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/version"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "version": "5.0.4" })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/rest/bug"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "id": 42 })))
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path("/rest/bug/42"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "bugs": [{ "id": 42 }] })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/page.cgi"))
        .respond_with(ResponseTemplate::new(200).set_body_string("<html></html>"))
        .mount(&server)
        .await;

    let bz = BugzillaClient::new(&server.uri(), use_auth_header, CALLER_AGENT)
        .expect("client must build");
    bz.version(KEY).await.expect("version must parse");
    bz.create_bug(KEY, json!({ "summary": "boom" }))
        .await
        .expect("create must parse");
    bz.update_bug(KEY, 42, json!({ "summary": "less boom" }))
        .await
        .expect("update must parse");
    bz.quicksearch_syntax_html()
        .await
        .expect("syntax page must fetch");

    let requests = server.received_requests().await.expect("recording enabled");
    assert_eq!(
        requests.len(),
        4,
        "the GET, the POST and PUT bodies and the unauthenticated page must all have been sent"
    );
    for req in requests {
        let agent = req
            .headers
            .get("user-agent")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        let what = format!("{} {}", req.method, req.url.path());
        assert_eq!(
            agent, CALLER_AGENT,
            "{what} (use_auth_header={use_auth_header}) must identify the caller, not this crate"
        );
        assert!(
            !agent.contains("bugwarden-core"),
            "{what}: the library must never name itself to Bugzilla: {agent}"
        );
    }
}

#[tokio::test]
async fn every_request_carries_the_callers_user_agent() {
    // Both auth modes, because the identity and the credential are set on
    // the same builder: a construction that attached the header only in
    // one of them sends no `User-Agent` at all in the other — the exact
    // anonymity #55 exists to end, and every call site in this workspace
    // would still pass with the mode it happens to use.
    every_request_shape(false).await;
    every_request_shape(true).await;
}
