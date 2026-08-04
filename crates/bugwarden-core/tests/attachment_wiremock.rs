//! HTTP-level integration tests for the attachment client endpoints
//! (wiremock), pinning the contracts DESIGN.md asserts for
//! `attachment_meta` / `attachment_data`: the string-keyed envelope parse,
//! `None` when the response carries no entry for the id, exclusion of the
//! blob from the metadata request, and error mapping that never leaks the
//! API key (I12).

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
async fn attachment_meta_parses_string_keyed_envelope_without_data() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/bug/attachment/77"))
        .and(query_param("exclude_fields", "data"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "attachments": {
                "77": { "id": 77, "bug_id": 4242, "size": 12, "is_private": false }
            }
        })))
        .mount(&server)
        .await;

    let meta = client(&server)
        .attachment_meta(KEY, 77)
        .await
        .expect("request must succeed")
        .expect("id 77 must be present");
    assert_eq!(meta["bug_id"], json!(4242));
    assert!(meta.get("data").is_none(), "metadata must carry no blob");
}

#[tokio::test]
async fn attachment_data_returns_the_blob() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/bug/attachment/77"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "attachments": {
                "77": { "id": 77, "bug_id": 4242, "data": "aGVsbG8=" }
            }
        })))
        .mount(&server)
        .await;

    let att = client(&server)
        .attachment_data(KEY, 77)
        .await
        .expect("request must succeed")
        .expect("id 77 must be present");
    assert_eq!(att["data"], json!("aGVsbG8="));
}

#[tokio::test]
async fn absent_id_maps_to_none_not_an_error() {
    let server = MockServer::start().await;
    // A response whose envelope simply does not mention the requested id, and
    // one that maps it to null: both are "no such attachment", not a failure.
    Mock::given(method("GET"))
        .and(path("/rest/bug/attachment/1"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({ "attachments": { "2": { "id": 2 } } })),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/rest/bug/attachment/3"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({ "attachments": { "3": null } })),
        )
        .mount(&server)
        .await;

    let c = client(&server);
    assert!(c.attachment_meta(KEY, 1).await.expect("ok").is_none());
    assert!(c.attachment_data(KEY, 3).await.expect("ok").is_none());
}

#[tokio::test]
async fn error_response_maps_to_error_without_leaking_the_key() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/bug/attachment/9"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "error": true, "message": "You must log in before using this part of Bugzilla."
        })))
        .mount(&server)
        .await;

    let err = client(&server)
        .attachment_meta(KEY, 9)
        .await
        .expect_err("401 must be an error");
    let text = format!("{err:#}");
    assert!(text.contains("401"), "status must be reported: {text}");
    assert!(text.contains("You must log in"), "message kept: {text}");
    assert!(
        !text.contains(KEY),
        "API key leaked into error text: {text}"
    );
}
