//! HTTP-level integration tests for the custom field type lookup
//! (wiremock): `BugzillaClient::bug_field_types` and `FieldTypeCache`.
//! Covers the request shape (exactly the given names, repeated `names`
//! keys, `include_fields=name,type`), the cache (repeats answered locally, a
//! new name looks up only itself), failure handling (a 500 and a 404/code
//! 51 leave every name of that batch `Unknown` and uncached, so the next
//! call asks again), a name a successful answer omits, chunking at the
//! bound, the fresh variant for writes, and that no error text carries the
//! API key (I12).

use std::collections::{BTreeMap, BTreeSet};

use bugwarden_core::client::BugzillaClient;
use bugwarden_core::custom_fields::{CustomFieldKind, FieldTypeCache};
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

/// Deliberately distinctive so a leak into any error text is unmistakable (I12).
const KEY: &str = "SUPERSECRETKEY123";

/// Any identity will do here — the client requires one (#55) but these
/// suites assert nothing about it; `user_agent_wiremock.rs` owns that
/// proof. Names neither crate, so a check for either finds nothing.
const TEST_USER_AGENT: &str = "probe-agent/0.0.0";

fn client(server: &MockServer) -> BugzillaClient {
    BugzillaClient::new(&server.uri(), false, TEST_USER_AGENT).expect("client must build")
}

fn set(names: &[&str]) -> BTreeSet<String> {
    names.iter().map(|n| (*n).to_string()).collect()
}

/// The `names` query values of one received request, in wire order.
fn names_of(req: &Request) -> Vec<String> {
    req.url
        .query_pairs()
        .filter(|(k, _)| k == "names")
        .map(|(_, v)| v.into_owned())
        .collect()
}

/// Every `names` list wiremock has received at `/rest/field/bug`, one per
/// request, in arrival order.
async fn lookups(server: &MockServer) -> Vec<Vec<String>> {
    server
        .received_requests()
        .await
        .expect("wiremock records requests by default")
        .iter()
        .filter(|r| r.url.path() == "/rest/field/bug")
        .map(names_of)
        .collect()
}

/// Answer like stock Bugzilla's `Bug.fields`: every requested name it knows
/// with its type code, and the whole request fails with 404 / code 51 on
/// the first name it does not.
fn bugzilla_like(table: BTreeMap<&'static str, u64>) -> impl Fn(&Request) -> ResponseTemplate {
    move |req: &Request| {
        let mut fields = Vec::new();
        for name in names_of(req) {
            match table.get(name.as_str()) {
                Some(t) => fields.push(json!({ "name": name, "type": t })),
                None => {
                    return ResponseTemplate::new(404).set_body_json(json!({
                        "error": true,
                        "code": 51,
                        "message": format!("There is no field named '{name}'."),
                    }));
                }
            }
        }
        ResponseTemplate::new(200).set_body_json(json!({ "fields": fields }))
    }
}

async fn mount_types(server: &MockServer, table: BTreeMap<&'static str, u64>) {
    Mock::given(method("GET"))
        .and(path("/rest/field/bug"))
        .respond_with(bugzilla_like(table))
        .mount(server)
        .await;
}

#[tokio::test]
async fn the_lookup_asks_for_exactly_the_given_names_and_name_type_only() {
    let server = MockServer::start().await;
    mount_types(
        &server,
        BTreeMap::from([("cf_regression_of", 6), ("cf_build", 1)]),
    )
    .await;
    let cache = FieldTypeCache::default();

    let kinds = cache
        .kinds(
            &client(&server),
            KEY,
            &set(&["cf_regression_of", "cf_build"]),
        )
        .await;
    assert_eq!(
        kinds,
        BTreeMap::from([
            ("cf_regression_of".to_string(), CustomFieldKind::BugId),
            ("cf_build".to_string(), CustomFieldKind::Other),
        ])
    );

    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1, "one batched request for both names");
    let req = &requests[0];
    assert_eq!(req.url.path(), "/rest/field/bug");
    let mut asked = names_of(req);
    asked.sort();
    assert_eq!(
        asked,
        vec!["cf_build".to_string(), "cf_regression_of".to_string()],
        "exactly the given names, as repeated `names` keys"
    );
    let include: Vec<_> = req
        .url
        .query_pairs()
        .filter(|(k, _)| k == "include_fields")
        .map(|(_, v)| v.into_owned())
        .collect();
    assert_eq!(
        include,
        vec!["name,type".to_string()],
        "only the name and the type code are requested, never the values"
    );
}

#[tokio::test]
async fn cached_names_are_answered_locally_and_a_new_name_looks_up_only_itself() {
    let server = MockServer::start().await;
    mount_types(
        &server,
        BTreeMap::from([("cf_a", 6), ("cf_b", 1), ("cf_c", 2)]),
    )
    .await;
    let bz = client(&server);
    let cache = FieldTypeCache::default();

    let first = cache.kinds(&bz, KEY, &set(&["cf_a", "cf_b"])).await;
    let again = cache.kinds(&bz, KEY, &set(&["cf_a", "cf_b"])).await;
    assert_eq!(first, again);
    assert_eq!(
        lookups(&server).await.len(),
        1,
        "a repeat is answered from the cache"
    );

    let widened = cache.kinds(&bz, KEY, &set(&["cf_a", "cf_c"])).await;
    assert_eq!(widened.get("cf_a"), Some(&CustomFieldKind::BugId));
    assert_eq!(widened.get("cf_c"), Some(&CustomFieldKind::Other));
    let seen = lookups(&server).await;
    assert_eq!(seen.len(), 2);
    assert_eq!(
        seen[1],
        vec!["cf_c".to_string()],
        "only the uncached name goes out"
    );
}

#[tokio::test]
async fn a_failed_lookup_is_not_cached_and_is_retried() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/field/bug"))
        .respond_with(ResponseTemplate::new(500))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    mount_types(&server, BTreeMap::from([("cf_a", 6)])).await;
    let bz = client(&server);
    let cache = FieldTypeCache::default();

    let failed = cache.kinds(&bz, KEY, &set(&["cf_a"])).await;
    assert_eq!(
        failed.get("cf_a"),
        Some(&CustomFieldKind::Unknown),
        "a failure leaves the name unknown (I4)"
    );
    let retried = cache.kinds(&bz, KEY, &set(&["cf_a"])).await;
    assert_eq!(
        retried.get("cf_a"),
        Some(&CustomFieldKind::BugId),
        "the next call asks again and gets the answer"
    );
    assert_eq!(lookups(&server).await.len(), 2);
}

#[tokio::test]
async fn an_unknown_name_fails_the_whole_batch_as_unknown() {
    // Stock Bugzilla answers a batch holding one name it does not know with
    // 404 / code 51 for the whole request: every name of that batch is
    // then Unknown, nothing is cached, and a later call asks again.
    let server = MockServer::start().await;
    mount_types(&server, BTreeMap::from([("cf_a", 6)])).await;
    let bz = client(&server);
    let cache = FieldTypeCache::default();

    let kinds = cache.kinds(&bz, KEY, &set(&["cf_a", "cf_bogus"])).await;
    assert_eq!(kinds.get("cf_a"), Some(&CustomFieldKind::Unknown));
    assert_eq!(kinds.get("cf_bogus"), Some(&CustomFieldKind::Unknown));

    let alone = cache.kinds(&bz, KEY, &set(&["cf_a"])).await;
    assert_eq!(
        alone.get("cf_a"),
        Some(&CustomFieldKind::BugId),
        "the known name was not cached as unknown by the failed batch"
    );
    assert_eq!(lookups(&server).await.len(), 2);
}

#[tokio::test]
async fn a_name_a_successful_answer_omits_is_unknown_and_not_cached() {
    // A non-stock server may answer 200 without naming every field asked
    // for; silence settles nothing.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/field/bug"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({ "fields": [{ "name": "cf_a", "type": 1 }] })),
        )
        .mount(&server)
        .await;
    let bz = client(&server);
    let cache = FieldTypeCache::default();

    let kinds = cache.kinds(&bz, KEY, &set(&["cf_a", "cf_quiet"])).await;
    assert_eq!(kinds.get("cf_a"), Some(&CustomFieldKind::Other));
    assert_eq!(kinds.get("cf_quiet"), Some(&CustomFieldKind::Unknown));

    let _ = cache.kinds(&bz, KEY, &set(&["cf_a", "cf_quiet"])).await;
    let seen = lookups(&server).await;
    assert_eq!(seen.len(), 2);
    assert_eq!(
        seen[1],
        vec!["cf_quiet".to_string()],
        "the answered name is cached, the omitted one is asked again"
    );
}

#[tokio::test]
async fn lookups_are_chunked_at_the_bound() {
    let server = MockServer::start().await;
    let all: Vec<String> = (0..60).map(|i| format!("cf_f{i:02}")).collect();
    let table: BTreeMap<&'static str, u64> = all
        .iter()
        .map(|n| (Box::leak(n.clone().into_boxed_str()) as &'static str, 1))
        .collect();
    mount_types(&server, table).await;
    let cache = FieldTypeCache::default();

    let kinds = cache
        .kinds(&client(&server), KEY, &all.iter().cloned().collect())
        .await;
    assert_eq!(kinds.len(), 60);
    assert!(kinds.values().all(|k| *k == CustomFieldKind::Other));
    let seen = lookups(&server).await;
    assert_eq!(seen.len(), 2, "60 names go out as 50 + 10");
    assert_eq!(seen[0].len(), 50);
    assert_eq!(seen[1].len(), 10);
    let mut asked: Vec<String> = seen.concat();
    asked.sort();
    assert_eq!(asked, all, "every name is asked exactly once");
}

#[tokio::test]
async fn the_fresh_variant_always_requests_and_refreshes_the_cache() {
    // A write judges the field as it is now: the fresh lookup ignores the
    // cache, and what it learns replaces the cached reading.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/field/bug"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({ "fields": [{ "name": "cf_a", "type": 1 }] })),
        )
        .up_to_n_times(1)
        .mount(&server)
        .await;
    mount_types(&server, BTreeMap::from([("cf_a", 6)])).await;
    let bz = client(&server);
    let cache = FieldTypeCache::default();

    let cached = cache.kinds(&bz, KEY, &set(&["cf_a"])).await;
    assert_eq!(cached.get("cf_a"), Some(&CustomFieldKind::Other));
    let fresh = cache.kinds_fresh(&bz, KEY, &set(&["cf_a"])).await;
    assert_eq!(
        fresh.get("cf_a"),
        Some(&CustomFieldKind::BugId),
        "the fresh lookup asked again instead of answering from the cache"
    );
    let after = cache.kinds(&bz, KEY, &set(&["cf_a"])).await;
    assert_eq!(
        after.get("cf_a"),
        Some(&CustomFieldKind::BugId),
        "and refreshed the cache"
    );
    assert_eq!(lookups(&server).await.len(), 2);
}

#[tokio::test]
async fn an_empty_name_list_is_refused_without_a_request() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/field/bug"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "fields": [] })))
        .expect(0)
        .mount(&server)
        .await;
    let err = client(&server)
        .bug_field_types(KEY, &[])
        .await
        .expect_err("an empty list would address the whole catalog");
    assert!(!err.to_string().contains(KEY), "I12: {err}");
}

#[tokio::test]
async fn a_lookup_error_carries_no_api_key() {
    let server = MockServer::start().await;
    mount_types(&server, BTreeMap::new()).await;
    let err = client(&server)
        .bug_field_types(KEY, &["cf_bogus"])
        .await
        .expect_err("an unknown name fails the request");
    let text = err.to_string();
    assert!(text.contains("404"), "the status is reported: {text}");
    assert!(!text.contains(KEY), "I12: {text}");
}
