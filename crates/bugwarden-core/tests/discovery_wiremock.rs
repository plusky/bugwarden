//! HTTP-level integration tests for the discovery client endpoints
//! (wiremock): `enterable_product_ids`, `products`, `bug_fields`. Covers the
//! documented envelope shapes, a malformed envelope, and that no error text
//! contains the API key (I12).

use bugwarden_core::client::BugzillaClient;
use serde_json::json;
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Deliberately distinctive so a leak into any error text is unmistakable (I12).
const KEY: &str = "SUPERSECRETKEY123";

/// Any identity will do here — the client requires one (#55) but these
/// suites assert nothing about it; `user_agent_wiremock.rs` owns that
/// proof. Names neither crate, so a check for either finds nothing.
const TEST_USER_AGENT: &str = "probe-agent/0.0.0";

fn client(server: &MockServer) -> BugzillaClient {
    BugzillaClient::new(&server.uri(), false, TEST_USER_AGENT).expect("client must build")
}

#[tokio::test]
async fn enterable_product_ids_parses_string_ids() {
    // Bugzilla's own documented example encodes ids as strings.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/product_enterable"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "ids": ["2", "3", "19"] })))
        .mount(&server)
        .await;

    let ids = client(&server)
        .enterable_product_ids(KEY)
        .await
        .expect("request must succeed");
    assert_eq!(ids, vec![2, 3, 19]);
}

#[tokio::test]
async fn enterable_product_ids_parses_numeric_ids() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/product_enterable"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "ids": [2, 3, 19] })))
        .mount(&server)
        .await;

    let ids = client(&server)
        .enterable_product_ids(KEY)
        .await
        .expect("request must succeed");
    assert_eq!(ids, vec![2, 3, 19]);
}

#[tokio::test]
async fn enterable_product_ids_errors_on_malformed_envelope() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/product_enterable"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "nope": [] })))
        .mount(&server)
        .await;

    let err = client(&server)
        .enterable_product_ids(KEY)
        .await
        .expect_err("a missing ids array must be an error, never an empty list");
    assert!(err.to_string().contains("ids"));
}

#[tokio::test]
async fn products_sends_ids_names_and_include_fields() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/product"))
        .and(query_param("ids", "1"))
        .and(query_param("names", "TestProduct"))
        .and(query_param("include_fields", "id,name"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "products": [{ "id": 1, "name": "TestProduct" }]
        })))
        .mount(&server)
        .await;

    let v = client(&server)
        .products(KEY, &[1], &["TestProduct"], Some(&["id", "name"]))
        .await
        .expect("request must succeed");
    assert_eq!(v["products"][0]["name"], json!("TestProduct"));
}

#[tokio::test]
async fn products_returns_the_full_envelope() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/product"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "products": [{
                "id": 1,
                "name": "TestProduct",
                "components": [{
                    "name": "core",
                    "default_assigned_to": "admin@bugzilla.org",
                }],
            }]
        })))
        .mount(&server)
        .await;

    let v = client(&server)
        .products(KEY, &[], &[], None)
        .await
        .expect("request must succeed");
    // The client is a raw pass-through; local projection is the server
    // tool's job, not the client's — this pins that the client itself does
    // not already strip anything.
    assert_eq!(
        v["products"][0]["components"][0]["default_assigned_to"],
        json!("admin@bugzilla.org")
    );
}

#[tokio::test]
async fn bug_fields_with_no_name_fetches_the_full_catalog() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/field/bug"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "fields": [{ "name": "priority", "display_name": "Priority" }]
        })))
        .mount(&server)
        .await;

    let v = client(&server)
        .bug_fields(KEY, None)
        .await
        .expect("request must succeed");
    assert_eq!(v["fields"][0]["name"], json!("priority"));
}

#[tokio::test]
async fn bug_fields_with_a_name_addresses_that_field_only() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/field/bug/priority"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "fields": [{ "name": "priority", "values": [{ "name": "P1" }] }]
        })))
        .mount(&server)
        .await;

    let v = client(&server)
        .bug_fields(KEY, Some("priority"))
        .await
        .expect("request must succeed");
    assert_eq!(v["fields"][0]["values"][0]["name"], json!("P1"));
}

#[tokio::test]
async fn bug_fields_percent_encodes_the_name_segment() {
    // A name containing '/' must not be able to address a different
    // endpoint by escaping the path segment.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/field/bug/a%2Fb"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "fields": [] })))
        .mount(&server)
        .await;

    let v = client(&server)
        .bug_fields(KEY, Some("a/b"))
        .await
        .expect("the escaped segment must reach the mock, not /rest/field/bug/a/b");
    assert_eq!(v["fields"], json!([]));
}

#[tokio::test]
async fn discovery_errors_never_leak_the_key() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/product_enterable"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "error": true, "message": "You must log in before using this part of Bugzilla."
        })))
        .mount(&server)
        .await;

    let err = client(&server)
        .enterable_product_ids(KEY)
        .await
        .expect_err("401 must be an error");
    let text = format!("{err:#}");
    assert!(text.contains("401"), "status must be reported: {text}");
    assert!(
        !text.contains(KEY),
        "API key leaked into error text: {text}"
    );
}
