//! End-to-end tests of the MCP tool surface against a mock Bugzilla.
//!
//! Each test builds a real [`BugWarden`] server, serves it over an
//! in-memory duplex transport, and CALLS the tools through an rmcp MCP
//! client — the same dispatch path a production client takes, including the
//! tool router. This is what makes the guard calls inside the tool bodies
//! testable at all: a helper-level test would keep passing if a tool simply
//! stopped calling the helper.
//!
//! Coverage contract (each of these mutations must fail at least one test):
//! - swapping `Capability::Attach` for `Capability::Attachments` at the
//!   add_attachment gate;
//! - deleting the `may_create` call from create_bug;
//! - deleting the upload size-cap call from add_attachment.

use std::sync::Arc;

use bugwarden::config::Cli;
use bugwarden::server::BugWarden;
use bugwarden_core::client::BugzillaClient;
use bugwarden_core::guard::Guard;
use bugwarden_core::policy::Policy;
use clap::Parser as _;
use rmcp::model::{CallToolRequestParams, CallToolResult};
use rmcp::service::{RoleClient, RunningService};
use rmcp::ServiceExt as _;
use serde_json::{json, Value};
use wiremock::matchers::{body_partial_json, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// The uniform create refusal (`Guard::create_denial`), pinned by value so a
/// wording change in either path breaks a test instead of passing silently.
const CREATE_DENIAL: &str = "Filing this bug is not permitted through this server";

/// Serve a [`BugWarden`] built from `policy` against `mock`, and connect an
/// MCP client to it over an in-memory duplex transport.
async fn client_for(policy: &str, mock: &MockServer) -> RunningService<RoleClient, ()> {
    let cfg = Arc::new(Cli::parse_from([
        "bugwarden",
        "--bugzilla-server",
        &mock.uri(),
        "--transport",
        "stdio",
        "--api-key",
        "test-key",
    ]));
    let guard = Arc::new(Guard {
        policy: Policy::from_toml_str(policy).expect("test policy must parse"),
    });
    let bz = Arc::new(BugzillaClient::new(&mock.uri(), false).expect("client must build"));
    let server = BugWarden::new(cfg, guard, bz).expect("server must build");

    let (client_io, server_io) = tokio::io::duplex(1 << 16);
    tokio::spawn(async move {
        if let Ok(running) = server.serve(server_io).await {
            let _ = running.waiting().await;
        }
    });
    ().serve(client_io)
        .await
        .expect("MCP handshake must succeed")
}

/// Call `tool` with `args` over the MCP session.
async fn call(client: &RunningService<RoleClient, ()>, tool: &str, args: Value) -> CallToolResult {
    let Value::Object(args) = args else {
        panic!("tool arguments must be a JSON object");
    };
    client
        .call_tool(CallToolRequestParams::new(tool.to_string()).with_arguments(args))
        .await
        .expect("tool call must not be a protocol error")
}

/// All text blocks of a result, concatenated.
fn text_of(result: &CallToolResult) -> String {
    result
        .content
        .iter()
        .filter_map(|c| c.as_text())
        .map(|t| t.text.as_str())
        .collect()
}

fn is_error(result: &CallToolResult) -> bool {
    result.is_error == Some(true)
}

/// A classification response for one world-readable bug carrying every
/// CLASSIFY field a rule could consult.
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

/// Mount the classification fetch for `bug`, expected exactly once.
async fn mount_classify(mock: &MockServer, bug: Value) {
    let id = bug["id"].as_u64().expect("bug fixture has an id");
    Mock::given(method("GET"))
        .and(path("/rest/bug"))
        .and(query_param("id", id.to_string()))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "bugs": [bug] })))
        .expect(1)
        .mount(mock)
        .await;
}

fn create_args(product: &str) -> Value {
    json!({
        "product": product,
        "component": "core",
        "summary": "crash on start",
        "version": "1.0",
    })
}

fn attachment_args(bug_id: u64, data: &str) -> Value {
    json!({
        "bug_id": bug_id,
        "data": data,
        "file_name": "log.txt",
        "summary": "boot log",
        "content_type": "text/plain",
    })
}

// ---------- create_bug (HIGH-1 / HIGH-2) ----------

#[tokio::test]
async fn create_bug_policy_and_upstream_refusals_are_indistinguishable() {
    // Policy refusal: nothing may be POSTed, and the refused path must still
    // cost exactly ONE upstream request (the padding classify against bug id
    // 0), so the request count cannot tell the two refusals apart either.
    let denied = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/bug"))
        .and(query_param("id", "0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "bugs": [] })))
        .expect(1)
        .mount(&denied)
        .await;
    Mock::given(method("POST"))
        .and(path("/rest/bug"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "id": 1 })))
        .expect(0)
        .mount(&denied)
        .await;
    let client = client_for(
        concat!(
            "[[rule]]\nname = \"hide-secret\"\naction = \"deny\"\n",
            "[rule.match]\nproducts = [\"Secret*\"]\n",
        ),
        &denied,
    )
    .await;
    let refused = call(&client, "create_bug", create_args("SecretSauce")).await;
    assert!(is_error(&refused), "policy-denied filing must be refused");
    let policy_text = text_of(&refused);
    assert_eq!(policy_text, CREATE_DENIAL);
    assert_eq!(
        denied.received_requests().await.unwrap().len(),
        1,
        "a policy refusal must cost exactly one upstream request"
    );

    // Upstream refusal (e.g. an invalid version): byte-identical text, same
    // single upstream request. Two texts — or 0 vs 1 requests — would be a
    // free policy-enumeration oracle.
    let upstream = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/rest/bug"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": true,
            "message": "There is no version named '1.0' in the 'openSUSE' product."
        })))
        .expect(1)
        .mount(&upstream)
        .await;
    let client = client_for("", &upstream).await;
    let failed = call(&client, "create_bug", create_args("openSUSE")).await;
    assert!(is_error(&failed), "an upstream refusal is still a refusal");
    assert_eq!(
        text_of(&failed),
        policy_text,
        "policy and upstream refusals must be byte-identical (I2)"
    );
    assert_eq!(
        upstream.received_requests().await.unwrap().len(),
        1,
        "an upstream refusal costs the same one request"
    );
}

#[tokio::test]
async fn create_bug_success_reaches_bugzilla_untouched() {
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/rest/bug"))
        .and(body_partial_json(json!({
            "product": "openSUSE",
            "component": "core",
            "summary": "crash on start",
            "version": "1.0",
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "id": 4242 })))
        .expect(1)
        .mount(&mock)
        .await;
    let client = client_for("", &mock).await;
    let result = call(&client, "create_bug", create_args("openSUSE")).await;
    assert!(!is_error(&result), "an allowed create must go through");
    assert!(text_of(&result).contains("4242"));
}

#[tokio::test]
async fn create_bug_claimed_groups_never_defeat_a_group_rule() {
    // The canonical embargo pattern: the policy denies on group names, and
    // Bugzilla UNIONS the product's mandatory groups into whatever the
    // request claimed. A claimed, non-matching group list must therefore be
    // refused exactly like an omitted one — nothing may reach Bugzilla.
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/bug"))
        .and(query_param("id", "0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "bugs": [] })))
        .expect(2)
        .mount(&mock)
        .await;
    Mock::given(method("POST"))
        .and(path("/rest/bug"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "id": 1 })))
        .expect(0)
        .mount(&mock)
        .await;
    let client = client_for(
        concat!(
            "[[rule]]\nname = \"embargo\"\naction = \"deny\"\n",
            "[rule.match]\ngroups = [\"embargo*\"]\n",
        ),
        &mock,
    )
    .await;

    let mut args = create_args("openSUSE");
    args["groups"] = json!(["totally-harmless"]);
    let claimed = call(&client, "create_bug", args).await;
    assert!(
        is_error(&claimed),
        "a client-claimed group list must not decide a group rule"
    );
    assert_eq!(text_of(&claimed), CREATE_DENIAL);

    let omitted = call(&client, "create_bug", create_args("openSUSE")).await;
    assert!(is_error(&omitted));
    assert_eq!(text_of(&omitted), CREATE_DENIAL);
}

#[tokio::test]
async fn create_bug_group_restricted_policy_refuses_all_creation() {
    // The shipped example policy's first rule: whether the created bug will
    // be group-restricted cannot be known before it exists, so creation is
    // refused entirely under such a policy — documented behaviour.
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/bug"))
        .and(query_param("id", "0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "bugs": [] })))
        .expect(1)
        .mount(&mock)
        .await;
    Mock::given(method("POST"))
        .and(path("/rest/bug"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "id": 1 })))
        .expect(0)
        .mount(&mock)
        .await;
    let client = client_for(
        concat!(
            "[[rule]]\nname = \"group-restricted\"\naction = \"deny\"\n",
            "[rule.match]\ngroup_restricted = true\n",
        ),
        &mock,
    )
    .await;
    let result = call(&client, "create_bug", create_args("openSUSE")).await;
    assert!(is_error(&result));
    assert_eq!(text_of(&result), CREATE_DENIAL);
}

// ---------- add_attachment (HIGH-3 mutations a and c, LOW-2) ----------

#[tokio::test]
async fn add_attachment_requires_attach_not_the_read_side_attachments() {
    // A grant carrying the READ capability `attachments` (and read) but not
    // the WRITE capability `attach` must refuse the upload with the uniform
    // bug denial, before anything is POSTed.
    let mock = MockServer::start().await;
    mount_classify(&mock, world_readable_bug(7)).await;
    Mock::given(method("POST"))
        .and(path("/rest/bug/7/attachment"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "ids": [1] })))
        .expect(0)
        .mount(&mock)
        .await;
    let client = client_for(
        concat!(
            "default_action = \"deny\"\n",
            "[[rule]]\nname = \"read-side\"\naction = \"restrict\"\n",
            "capabilities = [\"read\", \"attachments\"]\n",
        ),
        &mock,
    )
    .await;
    let result = call(&client, "add_attachment", attachment_args(7, "QUFB")).await;
    assert!(
        is_error(&result),
        "attachments (read) must not permit upload"
    );
    assert_eq!(
        text_of(&result),
        "Bug 7 is not accessible through this server"
    );
}

#[tokio::test]
async fn add_attachment_attach_grant_uploads() {
    // The write capability `attach` alone is what opens the gate.
    let mock = MockServer::start().await;
    mount_classify(&mock, world_readable_bug(7)).await;
    Mock::given(method("POST"))
        .and(path("/rest/bug/7/attachment"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "ids": [31] })))
        .expect(1)
        .mount(&mock)
        .await;
    let client = client_for(
        concat!(
            "default_action = \"deny\"\n",
            "[[rule]]\nname = \"uploader\"\naction = \"restrict\"\n",
            "capabilities = [\"attach\"]\n",
        ),
        &mock,
    )
    .await;
    let result = call(&client, "add_attachment", attachment_args(7, "QUFB")).await;
    assert!(!is_error(&result), "attach grant must permit the upload");
    assert!(text_of(&result).contains("31"));
}

#[tokio::test]
async fn add_attachment_size_cap_blocks_before_any_upload() {
    // 12 decoded bytes against an 8-byte cap: refused, and nothing POSTed.
    let mock = MockServer::start().await;
    mount_classify(&mock, world_readable_bug(7)).await;
    Mock::given(method("POST"))
        .and(path("/rest/bug/7/attachment"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "ids": [1] })))
        .expect(0)
        .mount(&mock)
        .await;
    let client = client_for("[global]\nmax_attachment_bytes = 8\n", &mock).await;
    let oversized = "QUFBQUFBQUFBQUFB"; // 12 bytes of 'A'
    let result = call(&client, "add_attachment", attachment_args(7, oversized)).await;
    assert!(is_error(&result), "an oversized upload must be refused");
    assert_eq!(
        text_of(&result),
        "Attachment exceeds the size limit of this server"
    );
}

#[tokio::test]
async fn add_attachment_comment_travels_as_a_plain_string() {
    // Bug.add_attachment documents `comment` as a plain string — NOT the
    // `{"comment": {"body": ...}}` shape Bug.update uses. The body matcher
    // pins the wire format: the object shape would not match and the test
    // would fail on the resulting 404.
    let mock = MockServer::start().await;
    mount_classify(&mock, world_readable_bug(7)).await;
    Mock::given(method("POST"))
        .and(path("/rest/bug/7/attachment"))
        .and(body_partial_json(json!({
            "ids": [7],
            "data": "QUFB",
            "file_name": "log.txt",
            "comment": "see the boot log",
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "ids": [55] })))
        .expect(1)
        .mount(&mock)
        .await;
    let client = client_for("", &mock).await;
    let mut args = attachment_args(7, "QUFB");
    args["comment"] = json!("see the boot log");
    let result = call(&client, "add_attachment", args).await;
    assert!(!is_error(&result), "result: {}", text_of(&result));
    assert!(text_of(&result).contains("55"));
}
