//! HTTP-level integration tests for the guard + client (wiremock).
//!
//! Covers the DESIGN.md "Testing" minimum bar for integration tests:
//! `assess()` denial for embargoed groups, the global min-age gate,
//! batch-failure per-id fallback (fail closed, I4), comment privacy (I5),
//! client error mapping, the API key never appearing in error text (I12),
//! and the summary view carrying no sensitive fields.

use bugwarden_core::client::BugzillaClient;
use bugwarden_core::guard::Guard;
use bugwarden_core::policy::{Access, Capability, Policy};
use serde_json::json;
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

/// Deliberately distinctive so a leak into any error text is unmistakable (I12).
const KEY: &str = "SUPERSECRETKEY123";

fn guard(toml: &str) -> Guard {
    Guard {
        policy: Policy::from_toml_str(toml).expect("test policy must parse"),
    }
}

fn client(server: &MockServer) -> BugzillaClient {
    BugzillaClient::new(&server.uri(), false).expect("client must build")
}

fn bug(id: u64, groups: &[&str], creation_time: &str) -> serde_json::Value {
    json!({
        "id": id,
        "product": "openSUSE Tumbleweed",
        "component": "Kernel",
        "status": "NEW",
        "severity": "major",
        "priority": "P2",
        "keywords": [],
        "groups": groups,
        "whiteboard": "",
        "creation_time": creation_time,
        "summary": "test bug",
    })
}

/// An old creation date so the default fixtures pass any reasonable age gate.
const OLD: &str = "2020-01-01T00:00:00Z";

#[tokio::test]
async fn assess_denies_embargoed_group_and_allows_public() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/bug"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "bugs": [bug(1, &["suse-security-internal"], OLD), bug(2, &[], OLD)],
        })))
        .mount(&server)
        .await;

    let g = guard(
        r#"
[[rule]]
name = "embargo"
action = "deny"
[rule.match]
groups = ["*security*", "*embargo*"]
"#,
    );
    let bz = client(&server);
    let out = g.assess(&bz, KEY, &[1, 2]).await;

    assert!(matches!(out[&1].0, Access::Denied { .. }));
    assert!(out[&2].0.allows(Capability::Read));
}

#[tokio::test]
async fn assess_min_bug_age_denies_young_and_missing_creation_time() {
    let server = MockServer::start().await;
    let now = chrono::Utc::now();
    let young = (now - chrono::Duration::days(1))
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string();
    Mock::given(method("GET"))
        .and(path("/rest/bug"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "bugs": [
                bug(1, &[], &young),
                bug(2, &[], OLD),
                // Bug 3 has no creation_time at all => denied (I4).
                {"id": 3, "product": "openSUSE", "status": "NEW"},
            ],
        })))
        .mount(&server)
        .await;

    let g = guard("[global]\nmin_bug_age_days = 7\n");
    let bz = client(&server);
    let out = g.assess(&bz, KEY, &[1, 2, 3]).await;

    assert!(matches!(out[&1].0, Access::Denied { .. }), "young bug");
    assert!(out[&2].0.allows(Capability::Read), "old bug");
    assert!(matches!(out[&3].0, Access::Denied { .. }), "unknown age");
}

#[tokio::test]
async fn assess_batch_failure_falls_back_per_id_and_fails_closed() {
    let server = MockServer::start().await;
    // The batched request (both ids) fails with a 500 ...
    Mock::given(method("GET"))
        .and(path("/rest/bug"))
        .and(query_param("id", "1,2"))
        .respond_with(ResponseTemplate::new(500).set_body_json(json!({
            "error": true, "message": "internal server error"
        })))
        .mount(&server)
        .await;
    // ... the per-id retry succeeds (200) for 1 ...
    Mock::given(method("GET"))
        .and(path("/rest/bug"))
        .and(query_param("id", "1"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({ "bugs": [bug(1, &[], OLD)] })),
        )
        .mount(&server)
        .await;
    // ... and keeps failing for 2.
    Mock::given(method("GET"))
        .and(path("/rest/bug"))
        .and(query_param("id", "2"))
        .respond_with(ResponseTemplate::new(500).set_body_json(json!({
            "error": true, "message": "internal server error"
        })))
        .mount(&server)
        .await;

    let g = guard(""); // default allow-all policy
    let bz = client(&server);
    let out = g.assess(&bz, KEY, &[1, 2]).await;

    assert_eq!(out.len(), 2, "every requested id has an entry (I4)");
    assert!(out[&1].0.allows(Capability::Read));
    match &out[&2].0 {
        Access::Denied { rule } => assert_eq!(rule, "unavailable"),
        other => panic!("unavailable bug must be denied, got {other:?}"),
    }
    assert!(out[&2].1.is_null());
}

#[tokio::test]
async fn assess_single_id_failure_makes_exactly_one_request() {
    // A failing single-id batch must NOT trigger the per-id fallback: the
    // retry would repeat the identical request, and the extra round trip
    // would give a timing client an existence oracle (nonexistent id => two
    // requests, policy-denied id => one) that I2's uniform text hides.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/bug"))
        .and(query_param("id", "7"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": true, "code": 101, "message": "Bug #7 does not exist."
        })))
        .expect(1) // exactly one upstream request, no retry
        .mount(&server)
        .await;

    let g = guard(""); // default allow-all policy
    let bz = client(&server);
    let out = g.assess(&bz, KEY, &[7]).await;

    assert_eq!(out.len(), 1, "the requested id has an entry (I4)");
    match &out[&7].0 {
        Access::Denied { rule } => assert_eq!(rule, "unavailable"),
        other => panic!("unavailable bug must be denied, got {other:?}"),
    }
    assert!(out[&7].1.is_null());
}

#[tokio::test]
async fn assess_id_absent_from_successful_batch_is_denied() {
    let server = MockServer::start().await;
    // Successful batch that simply lacks bug 2 (server-side hidden).
    Mock::given(method("GET"))
        .and(path("/rest/bug"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({ "bugs": [bug(1, &[], OLD)] })),
        )
        .mount(&server)
        .await;

    let g = guard("");
    let bz = client(&server);
    let out = g.assess(&bz, KEY, &[1, 2]).await;

    assert!(out[&1].0.allows(Capability::Read));
    match &out[&2].0 {
        Access::Denied { rule } => assert_eq!(rule, "unavailable"),
        other => panic!("absent bug must be denied (I4), got {other:?}"),
    }
}

#[tokio::test]
async fn comment_privacy_needs_policy_and_request_opt_in() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/bug/1/comment"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "bugs": {"1": {"comments": [
                {"id": 10, "text": "public", "is_private": false},
                {"id": 11, "text": "private", "is_private": true},
            ]}}
        })))
        .mount(&server)
        .await;

    let bz = client(&server);
    let comments = bz.bug_comments(KEY, 1, None).await.unwrap();
    assert_eq!(comments.len(), 2);

    // Policy off: private comments never surface, even when requested (I5).
    let g = guard("");
    assert_eq!(g.filter_comments(comments.clone(), true).len(), 1);
    assert_eq!(g.filter_comments(comments.clone(), false).len(), 1);

    // Policy on: still needs the per-call opt-in.
    let g = guard("[global]\nallow_private_comments = true\n");
    assert_eq!(g.filter_comments(comments.clone(), false).len(), 1);
    assert_eq!(g.filter_comments(comments, true).len(), 2);
}

#[tokio::test]
async fn client_error_mapping_uses_status_and_bugzilla_message() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/bug"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "error": true, "code": 306, "message": "invalid credentials"
        })))
        .mount(&server)
        .await;

    let bz = client(&server);
    let err = bz.get_bugs(KEY, &[1], None).await.unwrap_err();
    assert_eq!(
        err.to_string(),
        "bugzilla error (HTTP 401): invalid credentials"
    );
}

#[tokio::test]
async fn client_error_mapping_detects_error_body_under_200() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/bug"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "error": true, "message": "Bug 7 does not exist."
        })))
        .mount(&server)
        .await;

    let bz = client(&server);
    let err = bz.get_bugs(KEY, &[7], None).await.unwrap_err();
    assert_eq!(
        err.to_string(),
        "bugzilla error (HTTP 200): Bug 7 does not exist."
    );
}

#[tokio::test]
async fn api_key_reaches_server_but_never_error_text_i12() {
    let server = MockServer::start().await;
    // The server sees the key as a query parameter ...
    Mock::given(method("GET"))
        .and(path("/rest/bug"))
        .and(query_param("api_key", KEY))
        .respond_with(ResponseTemplate::new(500).set_body_string("boom"))
        .expect(1)
        .mount(&server)
        .await;

    let bz = client(&server);
    let err = bz.get_bugs(KEY, &[1], None).await.unwrap_err();
    // ... but the error chain must never contain it (I12).
    let full = format!("{err:#} {err:?}");
    assert!(
        !full.contains(KEY),
        "API key leaked into error text: {full}"
    );
    assert_eq!(err.to_string(), "bugzilla error (HTTP 500): unknown error");
}

#[tokio::test]
async fn api_key_absent_from_transport_error_i12() {
    // Point at a closed port: reqwest yields a connect error whose URL would
    // contain the api_key query parameter — sanitize must strip it.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    drop(listener); // free the port so the connection is refused
    let bz = BugzillaClient::new(&format!("http://{addr}"), false).expect("client");

    let err = bz.get_bugs(KEY, &[1], None).await.unwrap_err();
    let full = format!("{err:#} {err:?}");
    assert!(
        !full.contains(KEY),
        "API key leaked into transport error: {full}"
    );
}

#[tokio::test]
async fn auth_header_mode_sends_bearer_and_no_query_key() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/bug"))
        .respond_with(move |req: &Request| {
            let auth = req
                .headers
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_string();
            let has_query_key = req.url.query_pairs().any(|(k, _)| k == "api_key");
            ResponseTemplate::new(200).set_body_json(json!({
                "bugs": [],
                "seen_auth": auth,
                "query_key": has_query_key,
            }))
        })
        .mount(&server)
        .await;

    let bz = BugzillaClient::new(&server.uri(), true).expect("client");
    let v = bz.get_bugs(KEY, &[1], None).await.unwrap();
    assert_eq!(v["seen_auth"], json!(format!("Bearer {KEY}")));
    assert_eq!(v["query_key"], json!(false));
}

#[tokio::test]
async fn summary_view_strips_sensitive_fields_after_fetch() {
    let server = MockServer::start().await;
    // A bug loaded with everything the redacted view must strip.
    Mock::given(method("GET"))
        .and(path("/rest/bug"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "bugs": [{
                "id": 1,
                "summary": "kernel crash",
                "status": "NEW",
                "resolution": "",
                "product": "openSUSE Tumbleweed",
                "component": "Kernel",
                "severity": "major",
                "priority": "P2",
                "creation_time": OLD,
                "last_change_time": "2020-01-02T00:00:00Z",
                // Must never survive the summary projection:
                "groups": ["suse-internal"],
                "whiteboard": "secret embargo notes",
                "keywords": ["security-sensitive"],
                "assigned_to": "dev@example.com",
                "cc": ["watcher@example.com"],
            }],
        })))
        .mount(&server)
        .await;

    // Summary-only restrict rule => the tool layer would serve summary_view.
    let g = guard(
        r#"
[[rule]]
name = "summaries-only"
action = "restrict"
capabilities = ["summary"]
"#,
    );
    let bz = client(&server);
    let out = g.assess(&bz, KEY, &[1]).await;

    let (access, raw) = &out[&1];
    assert!(access.allows(Capability::Summary));
    assert!(!access.allows(Capability::Read));

    let view = Guard::summary_view(raw);
    let obj = view.as_object().expect("summary view is an object");
    assert_eq!(view["_redacted"], json!(true));
    assert_eq!(view["id"], json!(1));
    assert_eq!(view["summary"], json!("kernel crash"));
    for hidden in ["groups", "whiteboard", "keywords", "assigned_to", "cc"] {
        assert!(
            !obj.contains_key(hidden),
            "summary view must not contain {hidden:?}: {view}"
        );
    }
}
