//! Local `--release` timings for the CPU we own after a mock returns.
//!
//! Not a CI test: `#[ignore]`. Drive with
//! `cargo test -p bugwarden-core --release --test profile_hot_paths -- --ignored --nocapture`.
//! Wall-clock here is loopback HTTP plus JSON; the iai benches pin classify
//! and I14 without the mock.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::time::Instant;

use bugwarden_core::client::BugzillaClient;
use bugwarden_core::guard::{Guard, SearchRequest};
use bugwarden_core::policy::Policy;
use bugwarden_core::quoted::QuotedError;
use serde_json::{json, Value};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

const KEY: &str = "profile-key";
const UA: &str = "profile-agent/0.0.0";

const POLICY: &str = r#"
default_action = "allow"
[[rule]]
name = "embargo"
action = "deny"
[rule.match]
groups = ["*embargo*"]
"#;

fn guard() -> Guard {
    Guard {
        policy: Policy::from_toml_str(POLICY).expect("policy"),
    }
}

fn client(server: &MockServer) -> BugzillaClient {
    BugzillaClient::new(&server.uri(), false, UA).expect("client")
}

fn bug_json(id: u64) -> Value {
    json!({
        "id": id,
        "summary": format!("bug {id}"),
        "product": "Kernel",
        "component": "general",
        "status": "NEW",
        "groups": [],
        "creation_time": "2020-01-01T00:00:00Z",
        "blocks": [id + 1, 99_999],
        "depends_on": [id + 2],
        "see_also": [format!("https://bugzilla.example/show_bug.cgi?id={id}")],
        "dupe_of": null
    })
}

#[tokio::test]
#[ignore = "local release profile; not a CI gate"]
async fn profile_hot_paths() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/bug"))
        .respond_with(|req: &Request| {
            let q: std::collections::HashMap<_, _> = req.url.query_pairs().collect();
            if let Some(id) = q.get("id").and_then(|s| s.parse::<u64>().ok()) {
                return ResponseTemplate::new(200).set_body_json(json!({ "bugs": [bug_json(id)] }));
            }
            let offset = q
                .get("offset")
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(0);
            let limit = q
                .get("limit")
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(200);
            let page: Vec<_> = (offset + 1..=offset + limit as u64).map(bug_json).collect();
            ResponseTemplate::new(200).set_body_json(json!({ "bugs": page }))
        })
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/rest/bug"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": true,
            "message": "There is no version named '1.0 status=HACKED limit=999' in the 'openSUSE' product."
        })))
        .mount(&server)
        .await;

    let g = guard();
    let bz = client(&server);
    let ids: Vec<u64> = (1..=25).collect();

    let t0 = Instant::now();
    let classified = g.assess(&bz, KEY, &ids, None).await;
    let assess_ms = t0.elapsed();
    assert_eq!(classified.len(), 25);

    let t1 = Instant::now();
    let window = g
        .quicksearch_window(
            &bz,
            KEY,
            &SearchRequest {
                query: "kernel",
                status: "ALL",
                include_fields: "id,summary,product,component,status,groups,creation_time,blocks,depends_on,see_also",
                limit: 50,
                offset: 0,
            },
            None,
        )
        .await
        .expect("search");
    let search_ms = t1.elapsed();
    assert!(!window.bugs.is_empty());

    let mut fat = bug_json(1);
    fat["blocks"] = json!((2..80).collect::<Vec<u64>>());
    fat["depends_on"] = json!((80..160).collect::<Vec<u64>>());
    let allowed: BTreeSet<u64> = (1..100).collect();
    let t2 = Instant::now();
    for _ in 0..10_000 {
        let mut b = fat.clone();
        Guard::scrub_bug_links(&mut b, "https://bugzilla.example", &allowed);
        std::hint::black_box(b);
    }
    let scrub_ms = t2.elapsed();

    let err = bz
        .create_bug(
            KEY,
            json!({
                "product": "openSUSE",
                "component": "Other",
                "summary": "x",
                "version": "1.0 status=HACKED limit=999"
            }),
        )
        .await
        .expect_err("upstream 400");
    let t3 = Instant::now();
    let mut quoted = String::new();
    for _ in 0..50_000 {
        quoted.clear();
        write!(&mut quoted, "{:?}", QuotedError(&err)).expect("fmt");
        std::hint::black_box(&quoted);
    }
    let quote_ms = t3.elapsed();

    let hidden_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/bug"))
        .respond_with(|req: &Request| {
            let q: std::collections::HashMap<_, _> = req.url.query_pairs().collect();
            let offset = q
                .get("offset")
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(0);
            let limit = q
                .get("limit")
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(200);
            let page: Vec<_> = (offset + 1..=offset + limit as u64)
                .map(|id| {
                    let mut b = bug_json(id);
                    b["groups"] = json!(["embargo-2026"]);
                    b
                })
                .collect();
            ResponseTemplate::new(200).set_body_json(json!({ "bugs": page }))
        })
        .mount(&hidden_server)
        .await;
    let hidden_bz = client(&hidden_server);
    let t4 = Instant::now();
    let empty = g
        .quicksearch_window(
            &hidden_bz,
            KEY,
            &SearchRequest {
                query: "kernel",
                status: "ALL",
                include_fields: "id,summary,product,groups,creation_time",
                limit: 50,
                offset: 0,
            },
            None,
        )
        .await
        .expect("hidden scan");
    let hidden_scan_ms = t4.elapsed();
    assert!(empty.bugs.is_empty());

    eprintln!("assess_25ids\t{assess_ms:?}\t(25 sequential mock GETs + classify)");
    eprintln!(
        "quicksearch\t{search_ms:?}\t(one chunk, {} visible)",
        window.bugs.len()
    );
    eprintln!("hidden_scan\t{hidden_scan_ms:?}\t(10 chunks, all embargoed)");
    eprintln!("scrub_10k\t{scrub_ms:?}\t(I14 on ~160 link ids)");
    eprintln!("quoted_50k\t{quote_ms:?}\t(QuotedError of a Bugzilla 400)");
}
