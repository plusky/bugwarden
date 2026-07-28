//! HTTP-level integration tests for the guard + client (wiremock).
//!
//! Covers the DESIGN.md "Testing" minimum bar for integration tests:
//! `assess()` denial for embargoed groups, the global min-age gate,
//! batch-failure per-id fallback (fail closed, I4), comment privacy (I5),
//! client error mapping, the API key never appearing in error text (I12),
//! and the summary view carrying no sensitive fields.

use bugwarden_core::client::BugzillaClient;
use bugwarden_core::guard::{Guard, SearchRequest};
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
    let out = g.assess(&bz, KEY, &[1, 2, 3]).await;

    assert_eq!(out.len(), 3, "every requested id has an entry (I4)");
    assert!(out[&1].0.allows(Capability::Read));
    for id in [2u64, 3] {
        match &out[&id].0 {
            Access::Denied { rule } => assert_eq!(rule, "unavailable"),
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
    let out = g.assess(&bz, KEY, &[9, 1]).await;

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
    let out = g.assess(&bz, KEY, &ids).await;

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
    let out = g.assess(&bz, KEY, &[5, 5, 5]).await;

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
    let out = g.assess(&bz, KEY, &[1, 2]).await;

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
    let out = g.assess(&bz, KEY, &[7]).await;

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
    let reqs = server.received_requests().await.expect("recording enabled");
    let body: serde_json::Value = serde_json::from_slice(&reqs[0].body).expect("json body");
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
            let limit = get("limit").unwrap_or(all.len());
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
            .quicksearch_window(&bz, KEY, &search("q", 5, page * 5))
            .await
            .expect("search succeeds");
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
            .quicksearch_window(&bz, KEY, &search("q", 4, page * 4))
            .await
            .expect("search succeeds");
        paged.extend(ids_of(&got));
    }
    let whole = g
        .quicksearch_window(&bz, KEY, &search("q", 32, 0))
        .await
        .expect("search succeeds");
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
        .quicksearch_window(&client(&server_clean), KEY, &search("q", 4, 2))
        .await
        .expect("search succeeds");
    let mixed = g
        .quicksearch_window(&client(&server_mixed), KEY, &search("q", 4, 2))
        .await
        .expect("search succeeds");
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
        .quicksearch_window(&bz, KEY, &search("q", 10, 4))
        .await
        .expect("search succeeds");
    assert_eq!(ids_of(&tail), vec![6, 7]);
    let past = g
        .quicksearch_window(&bz, KEY, &search("q", 10, 50))
        .await
        .expect("search succeeds");
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
        .quicksearch_window(&client(&server), KEY, &search("q", 50, 0))
        .await
        .expect("search succeeds");
    assert!(got.is_empty(), "everything was hidden");
    assert_eq!(
        requests_to(&server).await,
        10,
        "2000 rows / 200 per chunk — the scan must stop at the bound"
    );
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
                .quicksearch_window(&client(&server), KEY, &search("q", 1, offset))
                .await
                .expect("a deep offset is not an error");
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
            .quicksearch_window(&client(&server), KEY, &search("q", limit, 0))
            .await
            .expect("search succeeds");
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
        .quicksearch_window(&client(&server), KEY, &search("q", 10, 0))
        .await
        .expect("search succeeds");
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
        .quicksearch_window(&client(&server), KEY, &search("q", 400, 0))
        .await
        .expect("search succeeds");
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
    let got = g
        .quicksearch_window(&client(&server), KEY, &search("q", 0, 0))
        .await
        .expect("zero limit is not an error");
    assert!(got.is_empty());
}

#[tokio::test]
async fn quicksearch_window_returns_the_classified_objects() {
    // What is returned must be what was judged — no second fetch can slip a
    // different body past the verdict.
    let server = MockServer::start().await;
    corpus(&server, 3, &[2]).await;
    let g = guard(EMBARGO_POLICY);
    let got = g
        .quicksearch_window(&client(&server), KEY, &search("q", 10, 0))
        .await
        .expect("search succeeds");
    assert_eq!(ids_of(&got), vec![1, 3]);
    assert_eq!(got[0]["summary"], json!("test bug"), "full object returned");
}
