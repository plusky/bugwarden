//! HTTP-level integration tests for the guard + client (wiremock).
//!
//! Covers the DESIGN.md "Testing" minimum bar for integration tests:
//! `assess()` denial for embargoed groups, the global min-age gate,
//! batch-failure per-id fallback (fail closed, I4), comment privacy (I5),
//! client error mapping, the API key never appearing in error text (I12),
//! and the summary view carrying no sensitive fields.

use std::sync::Arc;

use bugwarden_core::client::{with_upstream_stats, BugzillaClient, UpstreamStats};
use bugwarden_core::guard::{Guard, SearchRequest};
use bugwarden_core::policy::{Access, Capability, Policy};
use serde_json::{json, Value};
use wiremock::http::Method;
use wiremock::matchers::{method, path, query_param, query_param_contains};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

/// Deliberately distinctive so a leak into any error text is unmistakable (I12).
const KEY: &str = "SUPERSECRETKEY123";

/// Any identity will do here — the client requires one (#55) but these
/// suites assert nothing about it; `user_agent_wiremock.rs` owns that
/// proof. Names neither crate, so a check for either finds nothing.
const TEST_USER_AGENT: &str = "probe-agent/0.0.0";

fn guard(toml: &str) -> Guard {
    Guard {
        policy: Policy::from_toml_str(toml).expect("test policy must parse"),
    }
}

fn client(server: &MockServer) -> BugzillaClient {
    BugzillaClient::new(&server.uri(), false, TEST_USER_AGENT).expect("client must build")
}

/// Connect-time failure that wiremock's 127.0.0.1 pool cannot serve (#115).
///
/// The address is `127.0.0.1:1`. Port 1 is privileged: a non-root
/// wiremock listener binds `127.0.0.1:0` and cannot occupy it, so a
/// pooled listener from another test cannot answer this request. The
/// load-bearing assertion is `port() < 1024` — a bind-then-drop of an
/// ephemeral port fails the helper. A 500 ms TCP probe refuses to
/// return an address that accepted or timed out; the URL is built from
/// the probed socket so the two cannot drift.
fn refused_base_url() -> String {
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], 1));
    assert!(
        addr.port() < 1024,
        "I12 transport tests must use a privileged port; wiremock binds 127.0.0.1:0 (#115)"
    );
    match std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(500)) {
        Ok(_) => panic!(
            "{addr} accepted a connection; I12 tests need a refused address \
             that wiremock's 127.0.0.1:0 pool cannot occupy (#115)"
        ),
        Err(e) if e.kind() == std::io::ErrorKind::TimedOut => panic!(
            "{addr} timed out; refusing to point the 30s client at an address \
             that would hang the test (#115)"
        ),
        Err(_) => format!("http://{addr}"),
    }
}

/// Bound on the I12 client calls. Loopback refuse is immediate; a hang
/// here is a proxy or routing defect, not a 30s client timeout.
const REFUSED_CONNECT_BUDGET: std::time::Duration = std::time::Duration::from_secs(2);

/// I12: the error must be a real reqwest transport failure, and neither
/// Display nor Debug may carry the API key. An empty or HTTP-status error
/// would pass a bare `!contains(KEY)` without exercising sanitization.
fn assert_key_absent_from_transport_error(err: &anyhow::Error) {
    let full = format!("{err:#} {err:?}");
    assert!(
        full.contains("error sending request"),
        "expected a reqwest transport error (I12), got: {full}"
    );
    assert!(
        !full.contains(KEY),
        "API key leaked into transport error: {full}"
    );
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
    let out = g.assess(&bz, KEY, &[1, 2], None).await;

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
    let out = g.assess(&bz, KEY, &[1, 2, 3], None).await;

    assert!(matches!(out[&1].0, Access::Denied { .. }), "young bug");
    assert!(out[&2].0.allows(Capability::Read), "old bug");
    assert!(matches!(out[&3].0, Access::Denied { .. }), "unknown age");
}

#[tokio::test]
async fn assess_costs_one_request_per_distinct_id_whatever_the_answer() {
    // The heart of it: a bug that does not exist and a bug the policy hides
    // must cost the SAME upstream work. Bugzilla reports the first by failing
    // the request and the second by quietly omitting it, so the two answers
    // arrive by different routes — the request count must not follow.
    let server = MockServer::start().await;
    // id 1: served normally.
    Mock::given(method("GET"))
        .and(path("/rest/bug"))
        .and(query_param("id", "1"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({ "bugs": [bug(1, &[], OLD)] })),
        )
        .expect(1)
        .mount(&server)
        .await;
    // id 2: nonexistent — Bugzilla errors the request.
    Mock::given(method("GET"))
        .and(path("/rest/bug"))
        .and(query_param("id", "2"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": true, "code": 101, "message": "Bug #2 does not exist."
        })))
        .expect(1)
        .mount(&server)
        .await;
    // id 3: exists but is withheld upstream — a 200 that simply omits it.
    Mock::given(method("GET"))
        .and(path("/rest/bug"))
        .and(query_param("id", "3"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "bugs": [] })))
        .expect(1)
        .mount(&server)
        .await;

    let g = guard(""); // default allow-all policy
    let bz = client(&server);
    let out = g.assess(&bz, KEY, &[1, 2, 3], None).await;

    assert_eq!(out.len(), 3, "every requested id has an entry (I4)");
    assert!(out[&1].0.allows(Capability::Read));
    for id in [2u64, 3] {
        match &out[&id].0 {
            Access::Denied { rule } => {
                assert_eq!(rule, "unavailable");
                // Whatever name the guard denies under here, validation must
                // refuse an operator rule spelled the same — the reservation
                // has to track the name actually emitted, not a copy of it
                // that a rename could leave behind (#84).
                let policy = format!("[[rule]]\nname = \"{rule}\"\naction = \"deny\"\n");
                assert!(
                    Policy::from_toml_str(&policy).is_err(),
                    "an operator rule may not be named {rule:?}"
                );
            }
            other => panic!("bug {id} must be denied, got {other:?}"),
        }
        assert!(out[&id].1.is_null());
    }
    // The .expect(1) assertions above are verified on drop: each id is
    // fetched exactly once. (They bound the mocked paths only — wiremock does
    // not fail on requests that match no mock — but a batched `id=1,2,3`
    // would match none of these three and leave all counts at zero.)
}

#[tokio::test]
async fn assess_never_batches_so_one_bad_id_cannot_poison_the_others() {
    // The batch this replaced could be failed wholesale by a single bad id,
    // taking healthy ids down with it. Per-id fetching makes that impossible
    // without any retry logic to re-open the timing gap.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/bug"))
        .and(query_param("id", "9"))
        .respond_with(ResponseTemplate::new(500).set_body_json(json!({
            "error": true, "message": "internal server error"
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/rest/bug"))
        .and(query_param("id", "1"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({ "bugs": [bug(1, &[], OLD)] })),
        )
        .mount(&server)
        .await;
    // A request naming both ids at once would not match either mock: proof
    // that no batch is attempted.

    let g = guard("");
    let bz = client(&server);
    let out = g.assess(&bz, KEY, &[9, 1], None).await;

    assert!(out[&1].0.allows(Capability::Read), "healthy id survives");
    match &out[&9].0 {
        Access::Denied { rule } => assert_eq!(rule, "unavailable"),
        other => panic!("failed id must be denied, got {other:?}"),
    }
}

#[tokio::test]
async fn assess_fan_out_is_bounded_and_the_excess_is_denied() {
    // assess() is public API: an out-of-tree caller that forgets to bound its
    // input must not be able to turn one call into an unbounded run of
    // upstream requests. Past the bound nothing is fetched and everything
    // falls through to the denial (I4).
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/bug"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "bugs": [] })))
        .expect(Guard::MAX_ASSESS_IDS as u64) // never more, whatever was asked
        .mount(&server)
        .await;

    let ids: Vec<u64> = (1..=Guard::MAX_ASSESS_IDS as u64 * 4).collect();
    let g = guard("");
    let bz = client(&server);
    let out = g.assess(&bz, KEY, &ids, None).await;

    assert_eq!(out.len(), ids.len(), "every id still gets an entry (I4)");
    for id in &ids {
        match &out[id].0 {
            Access::Denied { .. } => {}
            other => panic!("bug {id} must be denied, got {other:?}"),
        }
    }
}

#[tokio::test]
async fn assess_repeated_ids_are_fetched_once() {
    // A caller cannot multiply the upstream cost — or read anything into it —
    // by naming the same bug several times.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/bug"))
        .and(query_param("id", "5"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({ "bugs": [bug(5, &[], OLD)] })),
        )
        .expect(1)
        .mount(&server)
        .await;

    let g = guard("");
    let bz = client(&server);
    let out = g.assess(&bz, KEY, &[5, 5, 5], None).await;

    assert_eq!(out.len(), 1);
    assert!(out[&5].0.allows(Capability::Read));
}

#[tokio::test]
async fn assess_id_absent_from_its_own_response_is_denied() {
    // A 200 that does not contain the bug is Bugzilla's way of saying "not
    // for you". It must land on the same denial as an outright failure, and
    // the response for one id must never be credited to another (the mock
    // answers every id with bug 1's body).
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/bug"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({ "bugs": [bug(1, &[], OLD)] })),
        )
        .mount(&server)
        .await;

    let g = guard("");
    let bz = client(&server);
    let out = g.assess(&bz, KEY, &[1, 2], None).await;

    assert!(out[&1].0.allows(Capability::Read));
    match &out[&2].0 {
        Access::Denied { rule } => assert_eq!(rule, "unavailable"),
        other => panic!("absent bug must be denied (I4), got {other:?}"),
    }
    assert!(
        out[&2].1.is_null(),
        "a mismatched body must never be attached to the requested id"
    );
}

#[tokio::test]
async fn assess_single_id_failure_makes_exactly_one_request() {
    // Unchanged contract, now the general rule rather than a special case.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/bug"))
        .and(query_param("id", "7"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": true, "code": 101, "message": "Bug #7 does not exist."
        })))
        .expect(1)
        .mount(&server)
        .await;

    let g = guard(""); // default allow-all policy
    let bz = client(&server);
    let out = g.assess(&bz, KEY, &[7], None).await;

    assert_eq!(out.len(), 1, "the requested id has an entry (I4)");
    match &out[&7].0 {
        Access::Denied { rule } => assert_eq!(rule, "unavailable"),
        other => panic!("unavailable bug must be denied, got {other:?}"),
    }
    assert!(out[&7].1.is_null());
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
    // Point at an address the wiremock pool can never occupy: reqwest
    // yields a connect error whose URL would contain the api_key query
    // parameter — sanitize must strip it.
    let bz = BugzillaClient::new(&refused_base_url(), false, TEST_USER_AGENT).expect("client");

    let err = tokio::time::timeout(REFUSED_CONNECT_BUDGET, bz.get_bugs(KEY, &[1], None))
        .await
        .expect("connect to the refused privileged port must not hang")
        .unwrap_err();
    assert_key_absent_from_transport_error(&err);
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

    let bz = BugzillaClient::new(&server.uri(), true, TEST_USER_AGENT).expect("client");
    let v = bz.get_bugs(KEY, &[1], None).await.unwrap();
    assert_eq!(v["seen_auth"], json!(format!("Bearer {KEY}")));
    assert_eq!(v["query_key"], json!(false));
}

#[tokio::test]
async fn client_create_bug_posts_the_payload_to_rest_bug() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/rest/bug"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "id": 42 })))
        .expect(1)
        .mount(&server)
        .await;

    let bz = client(&server);
    let payload = json!({
        "product": "openSUSE",
        "component": "Kernel",
        "summary": "boom",
        "version": "1.0",
    });
    let v = bz.create_bug(KEY, payload.clone()).await.unwrap();
    assert_eq!(v["id"], json!(42));

    // The payload travels as the POST body, untouched.
    //
    // Select the request by method and path rather than by position (#93).
    // The recording can contain more than the create POST — `[0]` would
    // then assert against the wrong request.
    let reqs = server.received_requests().await.expect("recording enabled");
    let posts: Vec<&Request> = reqs
        .iter()
        .filter(|r| r.method == Method::POST && r.url.path() == "/rest/bug")
        .collect();
    let [post] = posts[..] else {
        panic!(
            "expected exactly one recorded POST /rest/bug, found {} among {} request(s)",
            posts.len(),
            reqs.len()
        )
    };
    // Name a missing body as a missing body: parsing an empty slice would
    // otherwise surface as "EOF while parsing a value" and point at the
    // payload rather than at the recording.
    assert!(
        !post.body.is_empty(),
        "the recorded POST /rest/bug carries no body"
    );
    let body: Value = serde_json::from_slice(&post.body).expect("POST /rest/bug body must be JSON");
    assert_eq!(body, payload);
}

#[tokio::test]
async fn client_add_attachment_posts_to_the_bug_attachment_path() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/rest/bug/7/attachment"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "ids": [9] })))
        .expect(1)
        .mount(&server)
        .await;

    let bz = client(&server);
    let v = bz
        .add_attachment(KEY, 7, json!({ "ids": [7], "data": "Zm9v" }))
        .await
        .unwrap();
    assert_eq!(v["ids"], json!([9]));
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
    let out = g.assess(&bz, KEY, &[1], None).await;

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

// ---------------------------------------------------------------------------
// quicksearch_window: limit/offset address VISIBLE bugs (I2/I3)
// ---------------------------------------------------------------------------

/// A policy hiding anything in an embargo group.
const EMBARGO_POLICY: &str = concat!(
    "default_action = \"allow\"\n",
    "[[rule]]\nname = \"embargo\"\naction = \"deny\"\n",
    "[rule.match]\ngroups = [\"embargo*\"]\n",
);

/// Serve `total` bugs, every id in `hidden` carrying an embargo group, and
/// answer any offset/limit the way Bugzilla would.
async fn corpus(server: &MockServer, total: u64, hidden: &[u64]) {
    corpus_capped(server, total, hidden, usize::MAX).await;
}

/// Like [`corpus`], but clamps every response to at most `cap` rows the way
/// an administrator's `max_search_results` does, regardless of the `limit`
/// requested.
async fn corpus_capped(server: &MockServer, total: u64, hidden: &[u64], cap: usize) {
    let hidden: std::collections::BTreeSet<u64> = hidden.iter().copied().collect();
    let all: Vec<serde_json::Value> = (1..=total)
        .map(|id| {
            let groups: &[&str] = if hidden.contains(&id) {
                &["embargo-security"]
            } else {
                &[]
            };
            bug(id, groups, OLD)
        })
        .collect();
    Mock::given(method("GET"))
        .and(path("/rest/bug"))
        .respond_with(move |req: &Request| {
            let q: std::collections::HashMap<_, _> = req.url.query_pairs().collect();
            let get = |k: &str| q.get(k).and_then(|v| v.parse::<usize>().ok());
            let offset = get("offset").unwrap_or(0);
            let limit = get("limit").unwrap_or(all.len()).min(cap);
            let page: Vec<_> = all.iter().skip(offset).take(limit).cloned().collect();
            ResponseTemplate::new(200).set_body_json(json!({ "bugs": page }))
        })
        .mount(server)
        .await;
}

/// A search request with the fixture defaults.
fn search(query: &str, limit: u32, offset: u32) -> SearchRequest<'_> {
    SearchRequest {
        query,
        status: "ALL",
        include_fields: "id",
        limit,
        offset,
    }
}

/// Like [`corpus`], but the mock records how many requests it served.
async fn corpus_counted(server: &MockServer, total: u64, hidden: &[u64]) {
    corpus(server, total, hidden).await;
}

/// How many requests the server has received.
async fn requests_to(server: &MockServer) -> usize {
    server
        .received_requests()
        .await
        .map(|r| r.len())
        .unwrap_or(0)
}

fn ids_of(bugs: &[serde_json::Value]) -> Vec<u64> {
    bugs.iter()
        .map(|b| b["id"].as_u64().expect("bug has an id"))
        .collect()
}

#[tokio::test]
async fn quicksearch_window_pages_have_no_holes_when_bugs_are_hidden() {
    // The oracle: hidden bugs used to be cut from an already-paginated page,
    // so a page came back short while the next offset still had results — the
    // gap marking exactly where a hidden bug sat. Every page must now be full
    // whenever visible bugs remain.
    let server = MockServer::start().await;
    corpus(&server, 30, &[2, 3, 4, 11, 12, 20]).await; // 24 visible
    let g = guard(EMBARGO_POLICY);
    let bz = client(&server);

    let mut seen = Vec::new();
    for page in 0..4u32 {
        let got = g
            .quicksearch_window(&bz, KEY, &search("q", 5, page * 5), None)
            .await
            .expect("search succeeds")
            .bugs;
        assert_eq!(
            got.len(),
            5,
            "page {page} is short while visible bugs remain: {:?}",
            ids_of(&got)
        );
        seen.extend(ids_of(&got));
    }
    assert_eq!(
        seen,
        vec![1, 5, 6, 7, 8, 9, 10, 13, 14, 15, 16, 17, 18, 19, 21, 22, 23, 24, 25, 26]
    );
    for id in [2, 3, 4, 11, 12, 20] {
        assert!(!seen.contains(&id), "hidden bug {id} surfaced");
    }
}

#[tokio::test]
async fn quicksearch_window_pages_are_disjoint_and_gapless() {
    // Consecutive pages must tile the visible sequence exactly against a
    // STABLE upstream order, which is what this mock provides. Real relevance
    // ordering is not stable: a row that moves backwards past an already
    // scanned offset is missed by every chunk and appears on no page at all.
    // Dedup catches the forward case, nothing catches the backward one — it
    // hides more rather than less, so it is a correctness wart, not a leak.
    let server = MockServer::start().await;
    corpus(&server, 40, &[5, 6, 7, 8, 9, 10, 30, 31]).await;
    let g = guard(EMBARGO_POLICY);
    let bz = client(&server);

    let mut paged = Vec::new();
    for page in 0..8u32 {
        let got = g
            .quicksearch_window(&bz, KEY, &search("q", 4, page * 4), None)
            .await
            .expect("search succeeds")
            .bugs;
        paged.extend(ids_of(&got));
    }
    let whole = g
        .quicksearch_window(&bz, KEY, &search("q", 32, 0), None)
        .await
        .expect("search succeeds")
        .bugs;
    assert_eq!(
        paged,
        ids_of(&whole),
        "paging must tile the visible sequence"
    );
    let unique: std::collections::BTreeSet<_> = paged.iter().collect();
    assert_eq!(unique.len(), paged.len(), "a bug appeared on two pages");
}

#[tokio::test]
async fn quicksearch_window_page_is_identical_whether_or_not_bugs_are_hidden() {
    // The strongest form: the visible bugs a client gets must not depend on
    // whether hidden bugs are interleaved among them.
    // The hidden bugs must sit BEFORE and INSIDE the requested window, where
    // they can actually shift it — hidden bugs past the window would prove
    // nothing.
    let server_clean = MockServer::start().await;
    corpus(&server_clean, 12, &[]).await;
    let server_mixed = MockServer::start().await;
    corpus(&server_mixed, 12, &[2, 4, 7]).await;

    let g = guard(EMBARGO_POLICY);
    let clean = g
        .quicksearch_window(&client(&server_clean), KEY, &search("q", 4, 2), None)
        .await
        .expect("search succeeds")
        .bugs;
    let mixed = g
        .quicksearch_window(&client(&server_mixed), KEY, &search("q", 4, 2), None)
        .await
        .expect("search succeeds")
        .bugs;
    // Clean: visible are 1..12, so offset 2 limit 4 => 3,4,5,6.
    assert_eq!(ids_of(&clean), vec![3, 4, 5, 6]);
    // Mixed: visible are 1,3,5,6,8,9,10,11,12 => offset 2 limit 4 => 5,6,8,9.
    // Same SHAPE — four bugs, none hidden, no hole — which is what the client
    // can observe. Sameness of ids is impossible once bugs are removed; what
    // must not differ is that the page is full and the sequence contiguous.
    assert_eq!(ids_of(&mixed), vec![5, 6, 8, 9]);
    assert_eq!(
        clean.len(),
        mixed.len(),
        "a hidden bug must not shorten a page"
    );
}

#[tokio::test]
async fn quicksearch_window_runs_out_like_a_normal_end_of_results() {
    // Past the end the page is short and then empty — the ordinary signal,
    // and the only one a truncated scan is allowed to look like.
    let server = MockServer::start().await;
    corpus(&server, 7, &[3]).await; // 6 visible
    let g = guard(EMBARGO_POLICY);
    let bz = client(&server);

    let tail = g
        .quicksearch_window(&bz, KEY, &search("q", 10, 4), None)
        .await
        .expect("search succeeds")
        .bugs;
    assert_eq!(ids_of(&tail), vec![6, 7]);
    let past = g
        .quicksearch_window(&bz, KEY, &search("q", 10, 50), None)
        .await
        .expect("search succeeds")
        .bugs;
    assert!(past.is_empty());
}

#[tokio::test]
async fn quicksearch_window_scan_is_bounded() {
    // A query whose results are almost entirely hidden must terminate rather
    // than scan forever. Counting the requests is the point: asserting only
    // that the page is empty passes just as well with no bound at all.
    let server = MockServer::start().await;
    let hidden: Vec<u64> = (1..=5_000).collect();
    corpus_counted(&server, 5_000, &hidden).await;
    let g = guard(EMBARGO_POLICY);

    let got = g
        .quicksearch_window(&client(&server), KEY, &search("q", 50, 0), None)
        .await
        .expect("search succeeds")
        .bugs;
    assert!(got.is_empty(), "everything was hidden");
    assert_eq!(
        requests_to(&server).await,
        10,
        "2000 rows / 200 per chunk — the scan must stop at the bound"
    );
}

#[tokio::test]
async fn quicksearch_window_survives_a_capped_page() {
    // A server capping pages at 100 rows used to look identical to one
    // running out of results after the first request: `returned < chunk`
    // fired either way. A short page must not end the scan while the
    // request/row bounds still have room.
    let server = MockServer::start().await;
    corpus_capped(&server, 300, &[], 100).await;
    let g = guard(EMBARGO_POLICY);

    let got = g
        .quicksearch_window(&client(&server), KEY, &search("q", 5, 150), None)
        .await
        .expect("search succeeds")
        .bugs;
    assert_eq!(ids_of(&got), (151..=155).collect::<Vec<u64>>());
}

#[tokio::test]
async fn quicksearch_window_capped_page_still_bounds_requests() {
    // The pathological case: a 1-row page cap. The request bound must hold
    // even though the row bound (2000) is nowhere near reached, and the
    // result must look like ordinary truncation, not an error.
    let server = MockServer::start().await;
    corpus_capped(&server, 5_000, &[], 1).await;
    let g = guard(EMBARGO_POLICY);

    let got = g
        .quicksearch_window(&client(&server), KEY, &search("q", 50, 0), None)
        .await
        .expect("search succeeds")
        .bugs;
    assert_eq!(
        requests_to(&server).await,
        10,
        "the request bound must hold when the row bound cannot"
    );
    assert_eq!(ids_of(&got), (1..=10).collect::<Vec<u64>>());
}

#[tokio::test]
async fn quicksearch_window_deep_offset_is_empty_whether_or_not_bugs_are_hidden() {
    // Past the addressable window the answer is an empty page — and it must
    // be the SAME empty page whether or not bugs were hidden earlier. When
    // the slice bounds were computed independently this case panicked, and
    // only when something had been hidden: a cleaner oracle than the one the
    // windowing removed, plus a way to kill the session.
    for hidden in [vec![], vec![7u64]] {
        let server = MockServer::start().await;
        corpus(&server, 1_400, &hidden).await;
        let g = guard(EMBARGO_POLICY);
        for offset in [1_001u32, 1_010, 1_200, u32::MAX] {
            let got = g
                .quicksearch_window(&client(&server), KEY, &search("q", 1, offset), None)
                .await
                .expect("a deep offset is not an error")
                .bugs;
            assert!(
                got.is_empty(),
                "offset {offset} with hidden={hidden:?} must be an empty page"
            );
        }
    }
}

#[tokio::test]
async fn quicksearch_window_scan_target_does_not_track_the_requested_limit() {
    // The timing channel: if the scan stopped the instant the window filled,
    // the request count would flip at limit == visible-in-first-chunk, and a
    // client could binary-search `limit` against the clock to recover the
    // exact number of bugs hidden in each block. Quantising the target means
    // every limit within a block costs the same.
    let mut counts = Vec::new();
    for limit in [1u32, 50, 150, 199, 200] {
        let server = MockServer::start().await;
        // 60 of the first 200 rows hidden, so the first chunk yields 140.
        let hidden: Vec<u64> = (1..=60).collect();
        corpus_counted(&server, 1_000, &hidden).await;
        let g = guard(EMBARGO_POLICY);
        let _ = g
            .quicksearch_window(&client(&server), KEY, &search("q", limit, 0), None)
            .await
            .expect("search succeeds")
            .bugs;
        counts.push(requests_to(&server).await);
    }
    assert!(
        counts.iter().all(|c| *c == counts[0]),
        "request count must not vary with limit inside a chunk: {counts:?}"
    );
}

#[tokio::test]
async fn quicksearch_window_drops_rows_without_a_readable_id() {
    // A row that cannot be classified cannot be served (I4), and it must not
    // occupy a slot in the window either.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/bug"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "bugs": [
                bug(1, &[], OLD),
                json!({ "summary": "no id here", "groups": [] }),
                bug(2, &[], OLD),
            ]
        })))
        .mount(&server)
        .await;

    let g = guard(EMBARGO_POLICY);
    let got = g
        .quicksearch_window(&client(&server), KEY, &search("q", 10, 0), None)
        .await
        .expect("search succeeds")
        .bugs;
    assert_eq!(ids_of(&got), vec![1, 2]);
}

#[tokio::test]
async fn quicksearch_window_dedupes_rows_repeated_across_chunks() {
    // Relevance ordering is not stable between calls, so the same bug can
    // come back in two chunks. It must be served once.
    let server = MockServer::start().await;
    let page: Vec<serde_json::Value> = (1..=200).map(|id| bug(id, &[], OLD)).collect();
    // Every chunk returns the same 200 rows, whatever the offset.
    Mock::given(method("GET"))
        .and(path("/rest/bug"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "bugs": page })))
        .mount(&server)
        .await;

    let g = guard(EMBARGO_POLICY);
    let got = g
        .quicksearch_window(&client(&server), KEY, &search("q", 400, 0), None)
        .await
        .expect("search succeeds")
        .bugs;
    let ids = ids_of(&got);
    let unique: std::collections::BTreeSet<_> = ids.iter().collect();
    assert_eq!(unique.len(), ids.len(), "a bug was served twice: {ids:?}");
    assert_eq!(ids.len(), 200, "only the 200 distinct bugs exist");
}

#[tokio::test]
async fn quicksearch_window_zero_limit_touches_nothing() {
    let server = MockServer::start().await;
    // No mock is mounted: any upstream request would fail the call.
    let g = guard(EMBARGO_POLICY);
    let window = g
        .quicksearch_window(&client(&server), KEY, &search("q", 0, 0), None)
        .await
        .expect("zero limit is not an error");
    assert!(window.bugs.is_empty());
    // Nothing was fetched, so there is nothing to account for either.
    assert_eq!(window.scanned, 0);
    assert!(window.dropped.is_empty());
}

#[tokio::test]
async fn quicksearch_window_returns_the_classified_objects() {
    // What is returned must be what was judged — no second fetch can slip a
    // different body past the verdict.
    let server = MockServer::start().await;
    corpus(&server, 3, &[2]).await;
    let g = guard(EMBARGO_POLICY);
    let got = g
        .quicksearch_window(&client(&server), KEY, &search("q", 10, 0), None)
        .await
        .expect("search succeeds")
        .bugs;
    assert_eq!(ids_of(&got), vec![1, 3]);
    assert_eq!(got[0]["summary"], json!("test bug"), "full object returned");
}

#[tokio::test]
async fn quicksearch_window_accounts_for_scanned_rows_and_dropped_ids() {
    // The accounting exists for the audit record (issue #29): `scanned` is
    // every upstream row the scan examined, `dropped` is exactly the ids
    // the verdict withheld — in scan order, nothing more.
    let server = MockServer::start().await;
    corpus(&server, 30, &[2, 3, 11]).await;
    let g = guard(EMBARGO_POLICY);
    let window = g
        .quicksearch_window(&client(&server), KEY, &search("q", 5, 0), None)
        .await
        .expect("search succeeds");
    assert_eq!(ids_of(&window.bugs), vec![1, 4, 5, 6, 7]);
    assert_eq!(window.scanned, 30, "every upstream row was examined");
    assert_eq!(window.dropped, vec![2, 3, 11]);
}

#[tokio::test]
async fn quicksearch_window_accounts_for_overshoot_denials() {
    // The scan is quantised to whole chunks, so it classifies rows far
    // past the requested window. A denial out there IS part of what this
    // scan withheld while filling this window, and the accounting says so:
    // hidden bug 120 sits well past the 5-bug window but inside the first
    // 200-row chunk.
    let server = MockServer::start().await;
    corpus(&server, 150, &[120]).await;
    let g = guard(EMBARGO_POLICY);
    let window = g
        .quicksearch_window(&client(&server), KEY, &search("q", 5, 0), None)
        .await
        .expect("search succeeds");
    assert_eq!(ids_of(&window.bugs), vec![1, 2, 3, 4, 5]);
    assert_eq!(window.dropped, vec![120], "overshoot denials are counted");
    assert_eq!(window.scanned, 150);
}

#[tokio::test]
async fn quicksearch_window_accounting_skips_idless_rows_and_repeats() {
    // Neither an id-less row nor a deduped repeat reaches the verdict, so
    // neither may appear in the drop accounting (they were never
    // classified, and a non-verdict is not a drop) — but both were fetched
    // and examined, so both count as scanned rows.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/bug"))
        .respond_with(|req: &Request| {
            // A short page is no longer end-of-results, so only the first
            // request may return rows — the second must be empty or the
            // scan keeps going and `scanned` stops meaning "one chunk".
            let q: std::collections::HashMap<_, _> = req.url.query_pairs().collect();
            if q.get("offset").is_some_and(|v| v != "0") {
                return ResponseTemplate::new(200).set_body_json(json!({ "bugs": [] }));
            }
            ResponseTemplate::new(200).set_body_json(json!({
                "bugs": [
                    bug(1, &[], OLD),
                    bug(2, &["embargo-security"], OLD),
                    json!({ "summary": "no id here", "groups": [] }),
                    bug(1, &[], OLD), // repeated inside the chunk
                    bug(3, &[], OLD),
                ]
            }))
        })
        .mount(&server)
        .await;

    let g = guard(EMBARGO_POLICY);
    let window = g
        .quicksearch_window(&client(&server), KEY, &search("q", 10, 0), None)
        .await
        .expect("search succeeds");
    assert_eq!(ids_of(&window.bugs), vec![1, 3]);
    assert_eq!(window.dropped, vec![2], "only the classified denial");
    assert_eq!(window.scanned, 5, "every row upstream served was examined");
}

#[tokio::test]
async fn quicksearch_window_accounting_accumulates_across_chunks() {
    // The accounting is accumulated per chunk (`dropped.extend`,
    // `scanned +=`); a regression that reset either counter each
    // iteration would pass every single-chunk fixture. 250 rows force a
    // second chunk (target 400 for limit 201), with one hidden id in each
    // chunk: 10 in the first (rows 1..=200), 230 in the second
    // (rows 201..=250).
    let server = MockServer::start().await;
    corpus(&server, 250, &[10, 230]).await;
    let g = guard(EMBARGO_POLICY);
    let window = g
        .quicksearch_window(&client(&server), KEY, &search("q", 201, 0), None)
        .await
        .expect("search succeeds");
    assert_eq!(window.scanned, 250, "both chunks' rows are counted");
    assert_eq!(
        window.dropped,
        vec![10, 230],
        "drops from every chunk survive, in scan order"
    );
    let ids = ids_of(&window.bugs);
    assert_eq!(ids.len(), 201, "the window itself is unaffected");
    assert!(!ids.contains(&10) && !ids.contains(&230));
}

#[tokio::test]
async fn quicksearch_window_zero_limit_touches_nothing_at_any_offset() {
    // `needed` is non-zero as soon as the offset is, so at a non-zero offset
    // the `limit == 0` test is the only thing that can stop the scan. An
    // empty page must still cost nothing. No mock is mounted, so any
    // upstream request fails the call outright.
    let server = MockServer::start().await;
    let g = guard(EMBARGO_POLICY);
    let window = g
        .quicksearch_window(&client(&server), KEY, &search("q", 0, 5), None)
        .await
        .expect("a zero limit at a non-zero offset is not an error");
    assert!(window.bugs.is_empty());
    assert_eq!(
        window.scanned, 0,
        "limit 0 scans nothing, whatever the offset"
    );
    assert_eq!(
        requests_to(&server).await,
        0,
        "limit 0 must not contact Bugzilla, whatever the offset"
    );
}

#[tokio::test]
async fn quicksearch_window_stops_the_moment_the_scan_target_is_full() {
    // One SEARCH_SCAN_CHUNK of fully visible bugs already meets the quantised
    // target for every window inside it; a second request would be upstream
    // load no page the client can ask for accounts for.
    let server = MockServer::start().await;
    corpus_counted(&server, 1_000, &[]).await;
    let g = guard(EMBARGO_POLICY);
    let got = g
        .quicksearch_window(&client(&server), KEY, &search("q", 200, 0), None)
        .await
        .expect("search succeeds")
        .bugs;
    assert_eq!(ids_of(&got), (1..=200).collect::<Vec<u64>>());
    assert_eq!(
        requests_to(&server).await,
        1,
        "a full 200-row chunk fills the 200-row target in ONE request"
    );
}

#[tokio::test]
async fn quicksearch_window_row_bound_holds_when_pages_overrun_the_chunk() {
    // SEARCH_SCAN_MAX has to bind on its own. Rows-per-request is the
    // server's choice, so one that answers with more rows than it was asked
    // for reaches 2000 examined rows in four requests — well inside the
    // 10-request bound — and the scan must stop at the ceiling, not one
    // request past it.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/bug"))
        .respond_with(|req: &Request| {
            let q: std::collections::HashMap<_, _> = req.url.query_pairs().collect();
            let offset: u64 = q.get("offset").and_then(|v| v.parse().ok()).unwrap_or(0);
            // 500 hidden rows whatever `limit` asked for: nothing is ever
            // visible, so only a bound can end the scan.
            let rows: Vec<Value> = (offset + 1..=offset + 500)
                .map(|id| bug(id, &["embargo-security"], OLD))
                .collect();
            ResponseTemplate::new(200).set_body_json(json!({ "bugs": rows }))
        })
        .mount(&server)
        .await;
    let g = guard(EMBARGO_POLICY);
    let window = g
        .quicksearch_window(&client(&server), KEY, &search("q", 50, 0), None)
        .await
        .expect("search succeeds");
    assert!(window.bugs.is_empty(), "everything was hidden");
    assert_eq!(
        window.scanned, 2_000,
        "SEARCH_SCAN_MAX rows examined and no more"
    );
    assert_eq!(
        requests_to(&server).await,
        4,
        "4 x 500 rows reaches the row ceiling before the request ceiling"
    );
}

#[tokio::test]
async fn quicksearch_window_never_asks_for_more_rows_than_its_budget() {
    // The chunk is clamped to what is LEFT of SEARCH_SCAN_MAX, so no single
    // request can carry the scan past the ceiling. A conformant upstream
    // never reaches the clamp — nine requests of at most 200 rows leave
    // `scanned` at 1800 at most, and a full 200 still fits — so only a
    // server that overruns the chunk it was given drives `scanned` close
    // enough for the clamp to bite, and the `limit` it then sends pins it.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/bug"))
        .respond_with(|req: &Request| {
            let q: std::collections::HashMap<_, _> = req.url.query_pairs().collect();
            let offset: u64 = q.get("offset").and_then(|v| v.parse().ok()).unwrap_or(0);
            // 1950 hidden rows whatever `limit` asked for, leaving 50 of the
            // 2000-row budget for the next request.
            let rows: Vec<Value> = (offset + 1..=offset + 1_950)
                .map(|id| bug(id, &["embargo-security"], OLD))
                .collect();
            ResponseTemplate::new(200).set_body_json(json!({ "bugs": rows }))
        })
        .mount(&server)
        .await;
    let g = guard(EMBARGO_POLICY);
    let window = g
        .quicksearch_window(&client(&server), KEY, &search("q", 50, 0), None)
        .await
        .expect("search succeeds");
    assert!(window.bugs.is_empty(), "everything was hidden");

    let limits: Vec<String> = server
        .received_requests()
        .await
        .expect("the mock records requests")
        .iter()
        .map(|r| {
            r.url
                .query_pairs()
                .find(|(k, _)| k == "limit")
                .map(|(_, v)| v.into_owned())
                .unwrap_or_default()
        })
        .collect();
    assert_eq!(
        limits,
        vec!["200".to_string(), "50".to_string()],
        "the second request may ask for only the 50 rows left of the budget"
    );
}

// ---------------------------------------------------------------------------
// the scan's server-side accounting line (I3: the count is never the
// client's — this log and the audit record's `guard.scan` are where an
// operator sees it)
// ---------------------------------------------------------------------------

/// What `quicksearch_window` logs when the scan actually withheld something.
const WITHHELD_LINE: &str = "quicksearch: withheld policy-denied bugs";

thread_local! {
    /// Where the calling thread's capture accumulates. `None` means this
    /// thread is not capturing and its events go on the floor.
    static CAPTURED: std::cell::RefCell<Option<Vec<String>>> =
        const { std::cell::RefCell::new(None) };
}

/// The `message` field of one event.
struct Message(String);

impl tracing::field::Visit for Message {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.0 = format!("{value:?}");
        }
    }
}

/// Records the message of every `bugwarden_core` event on the capturing
/// thread. Hand-rolled rather than pulled in from tracing-subscriber: all it
/// has to answer is whether one line was emitted. Everything else keeps the
/// `Interest::never()` short-circuit it had before the subscriber existed.
struct CaptureSubscriber;

impl tracing::Subscriber for CaptureSubscriber {
    fn enabled(&self, meta: &tracing::Metadata<'_>) -> bool {
        meta.target().starts_with("bugwarden_core")
    }

    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        let mut message = Message(String::new());
        event.record(&mut message);
        let Message(message) = message;
        // `try_with`: a thread may still log while its thread-locals are
        // being torn down, and that must not panic.
        let _ = CAPTURED.try_with(move |slot| {
            if let Some(lines) = slot.borrow_mut().as_mut() {
                lines.push(message);
            }
        });
    }

    fn enter(&self, _: &tracing::span::Id) {}

    fn exit(&self, _: &tracing::span::Id) {}
}

/// Install the capture as this test binary's process-wide default, once.
///
/// It cannot be a `with_default` scope: a callsite's `Interest` is cached the
/// first time it is hit, from the registering thread's default subscriber, so
/// a parallel test with no subscriber of its own can cache `Interest::never()`
/// first and the macro then short-circuits forever after (the binary crate hit
/// this as issue #92). The explicit rebuild fixes up whatever was cached
/// before this ran.
fn install_capture() {
    static INSTALLED: std::sync::Once = std::sync::Once::new();
    INSTALLED.call_once(|| {
        tracing::subscriber::set_global_default(CaptureSubscriber)
            .expect("the capture must be this test binary's only global default");
        tracing::callsite::rebuild_interest_cache();
    });
}

/// Run `f`, returning what this crate logged on the calling thread meanwhile.
/// `#[tokio::test]` is single-threaded, so the whole future stays here.
async fn messages_logged_by<T>(f: impl std::future::Future<Output = T>) -> Vec<String> {
    install_capture();
    CAPTURED.with(|slot| *slot.borrow_mut() = Some(Vec::new()));
    let _ = f.await;
    CAPTURED.with(|slot| slot.borrow_mut().take().unwrap_or_default())
}

#[tokio::test]
async fn the_scan_logs_withheld_bugs_only_when_it_withheld_something() {
    // The drop count never reaches the client (I3): this debug line and the
    // audit record's `guard.scan` are where it surfaces. One emitted when
    // nothing was dropped is a false report of a withholding, not a
    // harmless extra log.
    let hiding = MockServer::start().await;
    corpus(&hiding, 10, &[3]).await;
    let g = guard(EMBARGO_POLICY);
    let logged = messages_logged_by(async {
        g.quicksearch_window(&client(&hiding), KEY, &search("q", 5, 0), None)
            .await
            .expect("search succeeds");
    })
    .await;
    assert!(
        logged.iter().any(|m| m.contains(WITHHELD_LINE)),
        "a scan that dropped a bug must say so: {logged:?}"
    );

    let clean = MockServer::start().await;
    corpus(&clean, 10, &[]).await;
    let logged = messages_logged_by(async {
        g.quicksearch_window(&client(&clean), KEY, &search("q", 5, 0), None)
            .await
            .expect("search succeeds");
    })
    .await;
    assert!(
        !logged.iter().any(|m| m.contains(WITHHELD_LINE)),
        "a scan that dropped nothing must not claim it did: {logged:?}"
    );
}

// ---------------------------------------------------------------------------
// disclosable: the I14 link fan-out bound
// ---------------------------------------------------------------------------

#[tokio::test]
async fn disclosable_fetches_at_most_the_link_fan_out_bound() {
    // A tracker bug can name hundreds of others, so the one batched
    // disclosure fetch takes at most MAX_ASSESS_IDS * 8 = 200 ids and the
    // excess is simply not disclosable (I4). Nothing but the request the
    // guard sends shows that bound, so it is pinned there.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/bug"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "bugs": [] })))
        .mount(&server)
        .await;
    let g = guard(EMBARGO_POLICY);
    let ids: std::collections::BTreeSet<u64> = (1..=201).collect();
    let out = g.disclosable(&client(&server), KEY, &ids, None).await;
    assert!(out.is_empty(), "an empty envelope discloses nothing (I4)");

    let requests = server
        .received_requests()
        .await
        .expect("the mock records requests");
    assert_eq!(
        requests.len(),
        1,
        "one batched request, whatever the id count"
    );
    let query: std::collections::HashMap<_, _> = requests[0].url.query_pairs().collect();
    let sent: Vec<&str> = query
        .get("id")
        .expect("the disclosure fetch carries an id list")
        .split(',')
        .collect();
    assert_eq!(
        sent.len(),
        Guard::MAX_ASSESS_IDS * 8,
        "201 linked ids must be cut to the 200-id fan-out bound"
    );
    assert_eq!(
        (sent.first(), sent.last()),
        (Some(&"1"), Some(&"200")),
        "the bound keeps the lowest 200 ids"
    );
}

// ---------------------------------------------------------------------------
// whoami + resolve_caller (identity resolution for created_by_me)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn client_whoami_returns_the_login_name() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/whoami"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": 4242, "name": "reporter@example.com", "real_name": "Reporter",
        })))
        .expect(1)
        .mount(&server)
        .await;

    let bz = client(&server);
    assert_eq!(bz.whoami(KEY).await.unwrap(), "reporter@example.com");
}

#[tokio::test]
async fn client_whoami_missing_non_string_or_blank_name_is_a_failure() {
    // A login that cannot be read is a FAILED resolution, never an empty
    // one — and a blank login IS unreadable: accepting "" would let a
    // degenerate empty caller compare equal to a blank creator field and
    // grant on no evidence. resolve_caller maps the failure to None and
    // identity stays unknown (I4).
    for body in [
        json!({ "id": 1 }),
        json!({ "id": 1, "name": 7 }),
        json!({ "id": 1, "name": "" }),
        json!({ "id": 1, "name": "   " }),
    ] {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/rest/whoami"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body.clone()))
            .mount(&server)
            .await;
        let bz = client(&server);
        let err = bz.whoami(KEY).await.unwrap_err();
        assert!(
            err.to_string().contains("name"),
            "unexpected error for body {body}: {err:#}"
        );
    }
}

#[tokio::test]
async fn whoami_api_key_absent_from_transport_error_i12() {
    // Same pattern as api_key_absent_from_transport_error_i12: a connect
    // error's URL would carry api_key=... — sanitize must strip it.
    let bz = BugzillaClient::new(&refused_base_url(), false, TEST_USER_AGENT).expect("client");

    let err = tokio::time::timeout(REFUSED_CONNECT_BUDGET, bz.whoami(KEY))
        .await
        .expect("connect to the refused privileged port must not hang")
        .unwrap_err();
    assert_key_absent_from_transport_error(&err);
}

// ---------------------------------------------------------------------------
// valid_login (portable identity verifier for declared-login identity)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn client_valid_login_accepts_wrapped_and_bare_boolean_bodies() {
    for body in [json!({ "result": true }), json!(true)] {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/rest/valid_login"))
            .and(query_param("login", "svc@example.com"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body.clone()))
            .expect(1)
            .mount(&server)
            .await;
        let bz = client(&server);
        assert!(
            bz.valid_login(KEY, "svc@example.com").await.unwrap(),
            "body {body} should read as true"
        );
    }

    for body in [json!({ "result": false }), json!(false)] {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/rest/valid_login"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body.clone()))
            .mount(&server)
            .await;
        let bz = client(&server);
        assert!(
            !bz.valid_login(KEY, "someone@example.com").await.unwrap(),
            "body {body} should read as false"
        );
    }
}

#[tokio::test]
async fn client_valid_login_unusable_shape_is_an_error_never_false() {
    // A shape neither a bare bool nor {"result": bool} must fail loudly,
    // not silently read as "not this account" (fail closed, never fail
    // open behind a fail-closed-looking `false`).
    for body in [
        json!({ "id": 1 }),
        json!({ "result": "true" }),
        json!("true"),
        json!(1),
        Value::Null,
    ] {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/rest/valid_login"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body.clone()))
            .mount(&server)
            .await;
        let bz = client(&server);
        let err = bz.valid_login(KEY, "svc@example.com").await.unwrap_err();
        assert!(
            err.to_string().contains("result"),
            "unexpected error for body {body}: {err:#}"
        );
    }
}

#[tokio::test]
async fn valid_login_api_key_absent_from_transport_error_i12() {
    let bz = BugzillaClient::new(&refused_base_url(), false, TEST_USER_AGENT).expect("client");

    let err = tokio::time::timeout(
        REFUSED_CONNECT_BUDGET,
        bz.valid_login(KEY, "svc@example.com"),
    )
    .await
    .expect("connect to the refused privileged port must not hang")
    .unwrap_err();
    assert_key_absent_from_transport_error(&err);
}

#[tokio::test]
async fn resolve_caller_is_lazy_and_maps_failure_to_none() {
    // No identity criterion in the policy: no request at all — the
    // .expect(0) is verified when the mock server drops.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/whoami"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "name": "x@y" })))
        .expect(0)
        .mount(&server)
        .await;
    let g = guard(
        "[[rule]]\nname = \"embargo\"\naction = \"deny\"\n[rule.match]\ngroups = [\"*security*\"]\n",
    );
    assert_eq!(g.resolve_caller(&client(&server), KEY).await, None);
    drop(server);

    let identity = concat!(
        "[[rule]]\nname = \"mine\"\naction = \"restrict\"\ncapabilities = [\"read\"]\n",
        "operations = [\"access\"]\n[rule.match]\ncreated_by_me = true\n",
        "[[rule]]\nname = \"rest\"\naction = \"deny\"\n",
    );

    // Identity policy, working endpoint: exactly one lookup, login returned.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/whoami"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": 1, "name": "reporter@example.com",
        })))
        .expect(1)
        .mount(&server)
        .await;
    let g = guard(identity);
    assert_eq!(
        g.resolve_caller(&client(&server), KEY).await,
        Some("reporter@example.com".to_string())
    );
    drop(server);

    // Identity policy, failing endpoint: None, not an error — the caller
    // stays unknown and classification fails closed downstream (I4).
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/whoami"))
        .respond_with(ResponseTemplate::new(500).set_body_json(json!({
            "error": true, "message": "boom"
        })))
        .expect(1)
        .mount(&server)
        .await;
    let g = guard(identity);
    assert_eq!(g.resolve_caller(&client(&server), KEY).await, None);
}

#[tokio::test]
async fn resolve_caller_under_declared_identity_makes_zero_http_requests() {
    // Verified once at startup (BugWarden::preflight), never looked up
    // again per call — the whole point of a declared login on a stock
    // deployment with no whoami at all. `.expect(0)` on BOTH endpoints
    // proves neither is consulted here.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/whoami"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({ "name": "should-not-be-called" })),
        )
        .expect(0)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/rest/valid_login"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(true)))
        .expect(0)
        .mount(&server)
        .await;

    let g = guard(concat!(
        "[global]\n",
        "identity_source = \"declared\"\n",
        "identity_login = \"svc@example.com\"\n",
        "[[rule]]\nname = \"mine\"\naction = \"restrict\"\ncapabilities = [\"read\"]\n",
        "operations = [\"access\"]\n[rule.match]\ncreated_by_me = true\n",
        "[[rule]]\nname = \"rest\"\naction = \"deny\"\n",
    ));
    assert_eq!(
        g.resolve_caller(&client(&server), KEY).await,
        Some("svc@example.com".to_string())
    );
}

#[tokio::test]
async fn classification_fetch_requests_the_creator_field() {
    // Pins `creator` in CLASSIFY_FIELDS end to end: the bug mock below only
    // answers a classify fetch whose projection asks for the creator column,
    // so dropping the field from CLASSIFY_FIELDS un-matches the mock, the
    // fetch fails, the caller's own bug collapses to the uniform denial
    // (fail closed, I4) — and this test fails. Response-side fixtures alone
    // cannot pin this: they return `creator` whether or not it was asked
    // for.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/whoami"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": 1, "name": "reporter@example.com", "real_name": "Reporter",
        })))
        .mount(&server)
        .await;
    let mut own = bug(7, &["secteam"], OLD);
    own["creator"] = json!("reporter@example.com");
    Mock::given(method("GET"))
        .and(path("/rest/bug"))
        .and(query_param("id", "7"))
        .and(query_param_contains("include_fields", "creator"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "bugs": [own] })))
        .mount(&server)
        .await;

    let g = guard(concat!(
        "[[rule]]\nname = \"my-own-reports\"\naction = \"restrict\"\n",
        "capabilities = [\"read\"]\noperations = [\"access\"]\n",
        "[rule.match]\ncreated_by_me = true\n",
        "[[rule]]\nname = \"group-restricted\"\naction = \"deny\"\n",
        "[rule.match]\ngroup_restricted = true\n",
    ));
    let bz = client(&server);
    let caller = g.resolve_caller(&bz, KEY).await;
    assert_eq!(caller.as_deref(), Some("reporter@example.com"));
    let out = g.assess(&bz, KEY, &[7], caller.as_deref()).await;
    assert!(
        out[&7].0.allows(Capability::Read),
        "the caller's own bug must classify from a creator-carrying projection"
    );
}

#[tokio::test]
async fn upstream_stats_count_every_request_inside_the_scope_and_none_outside() {
    // Issue #118: the audit record's `upstream` block is built from this,
    // so what it counts is what an operator is told the call cost.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/version"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "version": "5.0" })))
        .mount(&server)
        .await;
    let bz = client(&server);

    // Outside a scope the recording is a no-op, not a panic: startup
    // preflight and any embedder call the same client.
    bz.version(KEY).await.expect("version must succeed");

    let stats = Arc::new(UpstreamStats::default());
    with_upstream_stats(Arc::clone(&stats), async {
        bz.version(KEY).await.expect("version must succeed");
        bz.version(KEY).await.expect("version must succeed");
    })
    .await;
    // Two, not three: the pre-scope call is not attributed to this scope.
    assert_eq!(stats.requests(), 2);
    assert_eq!(stats.status(), Some(200));

    // A fresh scope starts from zero and sees only its own request.
    let second = Arc::new(UpstreamStats::default());
    with_upstream_stats(Arc::clone(&second), async {
        bz.version(KEY).await.expect("version must succeed");
    })
    .await;
    assert_eq!(second.requests(), 1);
}

#[tokio::test]
async fn upstream_stats_count_a_failed_request_with_no_status() {
    // A request that never got a response line still cost a round trip, so
    // it is counted — but there is no status to report, and the previous
    // request's must not stand in for it.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/version"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({ "error": true })))
        .mount(&server)
        .await;
    let reachable = client(&server);
    let refused = BugzillaClient::new(&refused_base_url(), false, TEST_USER_AGENT)
        .expect("client must build");

    let stats = Arc::new(UpstreamStats::default());
    tokio::time::timeout(
        REFUSED_CONNECT_BUDGET,
        with_upstream_stats(Arc::clone(&stats), async {
            // An error STATUS is still a response: counted, and reported.
            assert!(reachable.version(KEY).await.is_err());
            assert!(refused.version(KEY).await.is_err());
        }),
    )
    .await
    .expect("a refused loopback connect must not hang");

    assert_eq!(stats.requests(), 2, "both round trips cost something");
    assert_eq!(
        stats.status(),
        None,
        "the last request produced no response, so no status is reported"
    );
}

#[tokio::test]
async fn upstream_stats_latency_tracks_the_wait_and_not_a_constant() {
    // Differential, because a constant passes any lower bound: the SAME
    // request behind a mounted delay must cost most of that delay more
    // than it does without one. No ambient-timing threshold, so nothing
    // here depends on how fast the loopback happens to be.
    const DELAY_MS: u64 = 200;
    let quick = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/version"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "version": "5.0" })))
        .mount(&quick)
        .await;
    let delayed = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/version"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({ "version": "5.0" }))
                .set_delay(std::time::Duration::from_millis(DELAY_MS)),
        )
        .mount(&delayed)
        .await;

    let quick_stats = Arc::new(UpstreamStats::default());
    with_upstream_stats(Arc::clone(&quick_stats), async {
        client(&quick).version(KEY).await.expect("version");
    })
    .await;
    let delayed_stats = Arc::new(UpstreamStats::default());
    with_upstream_stats(Arc::clone(&delayed_stats), async {
        client(&delayed).version(KEY).await.expect("version");
    })
    .await;

    assert!(
        delayed_stats.latency_ms() >= DELAY_MS,
        "the mounted delay is time spent waiting: {} ms",
        delayed_stats.latency_ms()
    );
    assert!(
        delayed_stats.latency_ms() >= quick_stats.latency_ms() + DELAY_MS / 2,
        "latency must track the wait, not report a fixed number: {} ms delayed vs {} ms quick",
        delayed_stats.latency_ms(),
        quick_stats.latency_ms()
    );
}
