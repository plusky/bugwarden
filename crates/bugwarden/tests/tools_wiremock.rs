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
//! - POSTing a create payload other than the one `may_create` rewrote and
//!   judged — judging a copy compiles, and this suite is what forbids it;
//! - deleting the upload size-cap call from add_attachment;
//! - dropping the local see_also targets from update_bug_fields' assessed
//!   id set (or lowering their Capability::Summary bar to nothing);
//! - attaching the quicksearch id-list advisory only when the served `bugs`
//!   array is non-empty;
//! - suppressing the quicksearch id-list advisory when I14 link scrubbing
//!   removed anything;
//! - dropping the client's guard on field names a path segment cannot
//!   carry, which lets bug_fields answer `..` with the catalog's first
//!   field instead of failing the call;
//! - forwarding Bugzilla's message from any of the seven bug-update tools'
//!   failure arms, or dropping the hint a listed code selects;
//! - keying the hint lookup on the HTTP status, or ignoring the tool or
//!   the request's reach when looking one up;
//! - dropping the `cf_` arm from `linked_bug_ids` (a visible Bug ID custom
//!   field would be blanked) or from `scrub_bug_links` (a hidden one would
//!   be served), or looking field types up for a body;
//! - bug_history skipping the field-type lookup, bypassing its cache,
//!   looking up every field name instead of the `cf_` ones, reading an
//!   unknown field as no link or an Other field as one, or scrubbing
//!   without the kinds;
//! - dropping the Bug ID custom field targets from update_bug_fields' or
//!   create_bug's assessed set, passing an unassessable value through,
//!   assessing an Other field's value, answering a write's lookup from
//!   the cache, counting the cap after a request, skipping the target
//!   assessment when the create gate refused, answering a create's
//!   target denial with anything but the padded create refusal,
//!   resolving the caller for a create without targets, lifting the
//!   custom-field count cap (which lets a client buy lookups by the key),
//!   moving it behind the key lookup, counting values instead of keys, or
//!   answering the unassessable-value refusal before the bug's own check,
//!   which would tell a caller without `fields` a field's kind by name.

use std::sync::Arc;

mod common;

use bugwarden::config::Cli;
use bugwarden::server::{BugWarden, USER_AGENT, WRITE_TOOLS};
use bugwarden_core::client::BugzillaClient;
use bugwarden_core::guard::Guard;
use bugwarden_core::policy::Policy;
use rmcp::model::{CallToolRequestParams, CallToolResult};
use rmcp::service::{RoleClient, RunningService};
use rmcp::ServiceExt as _;
use serde_json::{json, Value};
use wiremock::matchers::{body_partial_json, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[path = "common/deadline.rs"]
mod deadline;
#[path = "common/pinned_cli.rs"]
mod pinned_cli;
#[path = "common/refused.rs"]
mod refused;

use deadline::bounded;
use pinned_cli::pinned;

/// The pin's own self-check, run in each binary that relies on it so a
/// single-binary `cargo test --test ...` still proves what its harness
/// claims. Both halves assert with their own message, so folding them into
/// one test costs no diagnosis.
#[test]
fn the_environment_pin_holds() {
    pinned_cli::assert_the_pin_drops_every_fallback::<Cli>();
    pinned_cli::assert_the_pin_neutralises_a_flag_added_later::<Cli>();
}

/// The uniform create refusal (`Guard::create_denial`), pinned by value so a
/// wording change in either path breaks a test instead of passing silently.
const CREATE_DENIAL: &str = "Filing this bug is not permitted through this server";

/// Serve a [`BugWarden`] built from `policy` against `mock`, and connect an
/// MCP client to it over an in-memory duplex transport.
async fn client_for(policy: &str, mock: &MockServer) -> RunningService<RoleClient, ()> {
    let cfg: Arc<Cli> = Arc::new(pinned(&[
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
    let bz =
        Arc::new(BugzillaClient::new(&mock.uri(), false, USER_AGENT).expect("client must build"));
    let server = BugWarden::new(cfg, guard, bz).expect("server must build");

    let (client_io, server_io) = tokio::io::duplex(1 << 16);
    tokio::spawn(async move {
        if let Ok(running) = server.serve(server_io).await {
            let _ = running.waiting().await;
        }
    });
    bounded("the MCP handshake", ().serve(client_io))
        .await
        .expect("MCP handshake must succeed")
}

/// Call `tool` with `args` over the MCP session.
async fn call(client: &RunningService<RoleClient, ()>, tool: &str, args: Value) -> CallToolResult {
    let Value::Object(args) = args else {
        panic!("tool arguments must be a JSON object");
    };
    bounded(
        &format!("the {tool} call"),
        client.call_tool(CallToolRequestParams::new(tool.to_string()).with_arguments(args)),
    )
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
async fn create_bug_custom_field_reaches_the_post_body() {
    // A custom field Bugzilla reports as free text is forwarded as sent;
    // learning that costs the one type lookup, before the POST.
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/rest/bug"))
        .and(body_partial_json(json!({ "cf_fixed_in": "1.2.3" })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "id": 4243 })))
        .expect(1)
        .mount(&mock)
        .await;
    mount_field_types(&mock, &[("cf_fixed_in", 1)]).await;
    let client = client_for("", &mock).await;
    let mut args = create_args("openSUSE");
    args["custom_fields"] = json!({ "cf_fixed_in": "1.2.3" });
    let result = call(&client, "create_bug", args).await;
    assert!(!is_error(&result), "a cf_* key must reach the POST body");
    let requests: Vec<(String, String)> = mock
        .received_requests()
        .await
        .unwrap()
        .iter()
        .map(|r| (r.method.to_string(), r.url.path().to_string()))
        .collect();
    assert_eq!(
        requests,
        vec![
            ("GET".to_string(), "/rest/field/bug".to_string()),
            ("POST".to_string(), "/rest/bug".to_string()),
        ]
    );
}

#[tokio::test]
async fn create_bug_posts_the_request_as_it_was_judged() {
    // The gate judges the request rewritten the way Bugzilla rewrites it
    // (trimmed names, cleaned summary, skipped keywords), so the POST must
    // carry that rewrite rather than the raw values — and nothing else:
    // description, version, op_sys and platform travel padded, because no
    // criterion reads them and rewriting them decides nothing.
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/rest/bug"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "id": 4244 })))
        .expect(1)
        .mount(&mock)
        .await;
    let client = client_for("", &mock).await;
    let mut args = create_args(" openSUSE\t");
    args["component"] = json!("core\u{3000}");
    args["summary"] = json!("crash\u{1}on\tstart\n");
    args["severity"] = json!(" normal");
    args["priority"] = json!("P3 ");
    args["keywords"] = json!([" regression", "0"]);
    args["version"] = json!(" 1.0 ");
    args["description"] = json!("\tit crashed ");
    args["op_sys"] = json!(" Linux");
    args["platform"] = json!("x86_64 ");
    let result = call(&client, "create_bug", args).await;
    assert!(!is_error(&result), "an allowed create must go through");

    let requests = mock.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    let body: Value = serde_json::from_slice(&requests[0].body).expect("JSON POST body");
    assert_eq!(
        body,
        json!({
            "product": "openSUSE",
            "component": "core",
            "summary": "crash on start",
            "version": " 1.0 ",
            "description": "\tit crashed ",
            "op_sys": " Linux",
            "platform": "x86_64 ",
            "severity": "normal",
            "priority": "P3",
            "keywords": ["regression"],
        })
    );
}

#[tokio::test]
async fn create_bug_padded_product_meets_the_padded_refusal() {
    // A padded product must meet the deny rule for the product Bugzilla
    // resolves it to, and be refused like any other filing: the same text
    // after exactly one upstream request, with nothing POSTed.
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
            "[[rule]]\nname = \"hide-security\"\naction = \"deny\"\n",
            "[rule.match]\nproducts = [\"Security*\"]\n",
        ),
        &mock,
    )
    .await;
    let refused = call(&client, "create_bug", create_args(" Security Response\t")).await;
    assert!(is_error(&refused), "a padded product must not be filed");
    assert_eq!(text_of(&refused), CREATE_DENIAL);
    assert_eq!(
        mock.received_requests().await.unwrap().len(),
        1,
        "the refusal must cost exactly one upstream request"
    );
}

#[tokio::test]
async fn create_bug_rejects_non_cf_custom_keys_with_no_upstream_request() {
    // I7, same gate as update_bug_fields: a non-cf_ key must not smuggle a
    // write through the generic create payload, and the refusal must cost
    // zero upstream requests — it decides nothing about the policy.
    let mock = MockServer::start().await;
    let client = client_for("", &mock).await;
    let mut args = create_args("openSUSE");
    args["custom_fields"] = json!({ "assigned_to": "someone@example.org" });
    let result = call(&client, "create_bug", args).await;
    assert!(is_error(&result));
    assert_eq!(
        text_of(&result),
        "Invalid custom field 'assigned_to': custom field names must start with 'cf_'"
    );
    assert!(
        mock.received_requests().await.unwrap().is_empty(),
        "the cf_ gate must refuse before any upstream request (I7)"
    );
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

#[tokio::test]
async fn create_scoped_rule_files_bugs_without_hiding_reads_issue_26() {
    // Issue #26, fixed: a create-scoped grant placed ahead of the
    // group-consulting deny rule lets filing work while existing bugs in the
    // matched products stay searchable — the pre-fix shape made them vanish
    // from quicksearch entirely.
    let mock = MockServer::start().await;
    let mut bug = world_readable_bug(7);
    bug["product"] = json!("SUSE Linux Enterprise Server 15");
    Mock::given(method("GET"))
        .and(path("/rest/bug"))
        .and(query_param("quicksearch", "ALL product:Enterprise"))
        .and(query_param("offset", "0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "bugs": [bug] })))
        .expect(1)
        .mount(&mock)
        .await;
    Mock::given(method("GET"))
        .and(path("/rest/bug"))
        .and(query_param("quicksearch", "ALL product:Enterprise"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "bugs": [] })))
        .mount(&mock)
        .await;
    Mock::given(method("POST"))
        .and(path("/rest/bug"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "id": 4242 })))
        .expect(1)
        .mount(&mock)
        .await;
    let client = client_for(
        concat!(
            "[[rule]]\nname = \"file-new-bugs\"\naction = \"restrict\"\n",
            "capabilities = [\"create\"]\noperations = [\"create\"]\n",
            "[rule.match]\nproducts = [\"SUSE Linux Enterprise*\"]\n",
            "[[rule]]\nname = \"group-restricted\"\naction = \"deny\"\n",
            "[rule.match]\ngroup_restricted = true\n",
        ),
        &mock,
    )
    .await;

    // The read the pre-fix shape silently revoked: the existing
    // world-readable bug stays in search results, because the create-scoped
    // rule is invisible to access classification.
    let search = call(
        &client,
        "bugs_quicksearch",
        json!({ "query": "product:Enterprise" }),
    )
    .await;
    assert!(
        !is_error(&search),
        "search must succeed: {}",
        text_of(&search)
    );
    // Parse rather than string-match: the wire format is compact JSON, so
    // `"id": 7` with a space is not the shape to assert on.
    let search_json: Value = serde_json::from_str(&text_of(&search)).expect("search returns JSON");
    assert!(
        search_json
            .get("bugs")
            .and_then(Value::as_array)
            .is_some_and(|bugs| bugs.iter().any(|b| b.get("id") == Some(&json!(7)))),
        "the existing bug must not vanish from search: {}",
        text_of(&search)
    );

    // Filing into the matched product reaches Bugzilla: the scoped rule is
    // first match for the create operation and grants `create` before the
    // group rule can fail closed on the unknowable group list.
    let created = call(
        &client,
        "create_bug",
        create_args("SUSE Linux Enterprise Server 15"),
    )
    .await;
    assert!(
        !is_error(&created),
        "create must be permitted: {}",
        text_of(&created)
    );
    assert!(text_of(&created).contains("4242"));
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

// ---------- download_attachment text windowing ----------

/// Attachment 55 of bug 7 with base64 content of `content_type`, mounted for
/// BOTH attachment GETs — the metadata fetch and the blob fetch share the
/// path — plus the classification fetch the owning bug's assessment costs.
async fn mount_download(mock: &MockServer, content_type: &str, data_b64: &str) {
    mount_classify(mock, world_readable_bug(7)).await;
    Mock::given(method("GET"))
        .and(path("/rest/bug/attachment/55"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "attachments": { "55": {
                "id": 55,
                "bug_id": 7,
                "is_private": false,
                "size": 128,
                "file_name": "log.txt",
                "content_type": content_type,
                "data": data_b64,
            } }
        })))
        // Metadata first, blob second (I8): exactly two fetches.
        .expect(2)
        .mount(mock)
        .await;
}

/// The JSON summary of a successful download_attachment call (content[0]).
fn summary_of(result: &CallToolResult) -> Value {
    let block = result.content[0]
        .as_text()
        .expect("the summary block is text");
    serde_json::from_str(&block.text).expect("the summary block is JSON")
}

#[tokio::test]
async fn download_attachment_windows_text_head_and_tail() {
    use base64::{engine::general_purpose, Engine as _};
    let mock = MockServer::start().await;
    let text: String = (1..=10).map(|i| format!("line{i}\n")).collect();
    mount_download(
        &mock,
        "text/plain",
        &general_purpose::STANDARD.encode(&text),
    )
    .await;
    let client = client_for("", &mock).await;
    let result = call(
        &client,
        "download_attachment",
        json!({ "attachment_id": 55, "head_lines": 2, "tail_lines": 2 }),
    )
    .await;
    assert!(
        !is_error(&result),
        "windowed download must succeed: {}",
        text_of(&result)
    );
    assert_eq!(result.content.len(), 2, "summary block + windowed text");
    // The window rides as a plain TEXT block, not a blob resource.
    let window = result.content[1]
        .as_text()
        .expect("the windowed payload is a text block");
    assert_eq!(window.text, "line1\nline2\nline9\nline10");
    let summary = summary_of(&result);
    assert_eq!(
        summary["truncation"],
        json!({ "total_lines": 10, "shown_lines": 4, "truncated_chars": false })
    );
    assert!(summary.get("windowing_ignored").is_none());
}

#[tokio::test]
async fn download_attachment_max_chars_alone_caps_the_full_text() {
    use base64::{engine::general_purpose, Engine as _};
    let mock = MockServer::start().await;
    let text = "hello world\nsecond line\n";
    mount_download(&mock, "text/plain", &general_purpose::STANDARD.encode(text)).await;
    let client = client_for("", &mock).await;
    let result = call(
        &client,
        "download_attachment",
        json!({ "attachment_id": 55, "max_chars": 5 }),
    )
    .await;
    assert!(!is_error(&result), "capped download: {}", text_of(&result));
    let window = result.content[1]
        .as_text()
        .expect("the capped payload is a text block");
    assert_eq!(window.text, "hello");
    assert_eq!(
        summary_of(&result)["truncation"],
        // shown_lines counts the SERVED fragment, not the pre-cap text.
        json!({ "total_lines": 2, "shown_lines": 1, "truncated_chars": true })
    );
}

#[tokio::test]
async fn download_attachment_ignores_windowing_params_on_an_image() {
    use base64::{engine::general_purpose, Engine as _};
    let mock = MockServer::start().await;
    let png = general_purpose::STANDARD.encode(b"\x89PNG\r\n\x1a\n");
    mount_download(&mock, "image/png", &png).await;
    let client = client_for("", &mock).await;
    let result = call(
        &client,
        "download_attachment",
        json!({ "attachment_id": 55, "head_lines": 1, "max_chars": 4 }),
    )
    .await;
    assert!(
        !is_error(&result),
        "the image is served: {}",
        text_of(&result)
    );
    // Params ignored, never an error: the image block is the normal path.
    let image = result.content[1]
        .as_image()
        .expect("an image attachment is served as image content");
    assert_eq!(image.data, png);
    let summary = summary_of(&result);
    assert_eq!(
        summary["windowing_ignored"],
        json!("not a text content type")
    );
    assert!(summary.get("truncation").is_none());
}

#[tokio::test]
async fn download_attachment_ignores_windowing_params_on_a_binary() {
    use base64::{engine::general_purpose, Engine as _};
    let mock = MockServer::start().await;
    let blob = general_purpose::STANDARD.encode(b"\x00\x01\x02\x03");
    mount_download(&mock, "application/octet-stream", &blob).await;
    let client = client_for("", &mock).await;
    let result = call(
        &client,
        "download_attachment",
        json!({ "attachment_id": 55, "tail_lines": 3 }),
    )
    .await;
    assert!(
        !is_error(&result),
        "the blob is served: {}",
        text_of(&result)
    );
    let Some(embedded) = result.content[1].as_resource() else {
        panic!("a binary attachment is served as a blob resource")
    };
    let rmcp::model::ResourceContents::BlobResourceContents { uri, blob: b, .. } =
        &embedded.resource
    else {
        panic!("a binary attachment is served as a BLOB resource")
    };
    assert_eq!(uri, "bugzilla://attachment/55");
    assert_eq!(b, &blob, "the payload is served unwindowed");
    let summary = summary_of(&result);
    assert_eq!(
        summary["windowing_ignored"],
        json!("not a text content type")
    );
    assert!(summary.get("truncation").is_none());
}

#[tokio::test]
async fn download_attachment_denial_is_byte_identical_with_windowing_params() {
    // I2: the params are never consulted on a refusal path. Unknown id 999:
    // a metadata miss runs the constant-cost padding classify against bug id
    // 0 and nothing else — once per call.
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/bug/attachment/999"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "attachments": {} })))
        .expect(2)
        .mount(&mock)
        .await;
    Mock::given(method("GET"))
        .and(path("/rest/bug"))
        .and(query_param("id", "0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "bugs": [] })))
        .expect(2)
        .mount(&mock)
        .await;
    let client = client_for("", &mock).await;
    let plain = call(
        &client,
        "download_attachment",
        json!({ "attachment_id": 999 }),
    )
    .await;
    let windowed = call(
        &client,
        "download_attachment",
        json!({ "attachment_id": 999, "head_lines": 5, "tail_lines": 5, "max_chars": 10 }),
    )
    .await;
    assert!(is_error(&plain) && is_error(&windowed));
    assert_eq!(
        text_of(&plain),
        "Attachment 999 is not accessible through this server"
    );
    assert_eq!(
        serde_json::to_value(&plain).unwrap(),
        serde_json::to_value(&windowed).unwrap(),
        "a denial must not change by one byte when windowing params ride along (I2)"
    );
}

#[tokio::test]
async fn download_attachment_windowing_cannot_serve_an_over_cap_attachment() {
    // Asking for one line of a payload the operator's cap forbids must
    // refuse, not serve one line of it. The metadata `size` lies (8 under a
    // 64-byte cap) so the refusal comes from the DECODED re-check — the last
    // gate before windowing, and the one windowing could have raced.
    use base64::{engine::general_purpose, Engine as _};
    let mock = MockServer::start().await;
    let text: String = (1..=20).map(|i| format!("secret line {i}\n")).collect();
    Mock::given(method("GET"))
        .and(path("/rest/bug"))
        .and(query_param("id", "7"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({ "bugs": [world_readable_bug(7)] })),
        )
        .expect(2)
        .mount(&mock)
        .await;
    Mock::given(method("GET"))
        .and(path("/rest/bug/attachment/55"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "attachments": { "55": {
                "id": 55,
                "bug_id": 7,
                "is_private": false,
                "size": 8,
                "file_name": "log.txt",
                "content_type": "text/plain",
                "data": general_purpose::STANDARD.encode(&text),
            } }
        })))
        // Metadata + blob on each of the two calls: the lying size buys the
        // second fetch, nothing more.
        .expect(4)
        .mount(&mock)
        .await;
    let client = client_for("[global]\nmax_attachment_bytes = 64\n", &mock).await;
    let windowed = call(
        &client,
        "download_attachment",
        json!({ "attachment_id": 55, "head_lines": 1 }),
    )
    .await;
    let plain = call(
        &client,
        "download_attachment",
        json!({ "attachment_id": 55 }),
    )
    .await;
    assert!(is_error(&windowed), "an over-cap attachment stays refused");
    assert_eq!(
        text_of(&windowed),
        "Attachment 55 exceeds the size limit of this server"
    );
    assert_eq!(
        windowed.content.len(),
        1,
        "the refusal carries no content block, windowed or not"
    );
    assert_eq!(
        serde_json::to_value(&windowed).unwrap(),
        serde_json::to_value(&plain).unwrap(),
        "windowing params must not move the over-cap refusal by one byte"
    );
}

#[tokio::test]
async fn download_attachment_without_windowing_params_keeps_the_blob_shape() {
    use base64::{engine::general_purpose, Engine as _};
    let mock = MockServer::start().await;
    let text = "alpha\nbeta\ngamma\n";
    let data = general_purpose::STANDARD.encode(text);
    mount_download(&mock, "text/plain", &data).await;
    let client = client_for("", &mock).await;
    let result = call(
        &client,
        "download_attachment",
        json!({ "attachment_id": 55 }),
    )
    .await;
    assert!(
        !is_error(&result),
        "unwindowed download: {}",
        text_of(&result)
    );
    assert_eq!(result.content.len(), 2, "summary block + blob resource");
    // The summary block is byte-identical to the pre-windowing shape: no
    // truncation object, no ignored note.
    let summary = result.content[0].as_text().expect("summary text block");
    assert_eq!(
        summary.text,
        serde_json::to_string(&json!({
            "id": 55,
            "bug_id": 7,
            "file_name": "log.txt",
            "content_type": "text/plain",
            "size": 128,
        }))
        .unwrap()
    );
    let Some(embedded) = result.content[1].as_resource() else {
        panic!("a text attachment without params keeps the blob resource")
    };
    let rmcp::model::ResourceContents::BlobResourceContents { uri, blob, .. } = &embedded.resource
    else {
        panic!("blob resource")
    };
    assert_eq!(uri, "bugzilla://attachment/55");
    assert_eq!(blob, &data, "the full payload, unwindowed");
}

// ---------- bugs_quicksearch id-list advisory ----------

/// Mount an upstream that answers every quicksearch scan with `rows` and the
/// I14 link-disclosure padding fetch (`id=0`) with an empty envelope.
async fn mount_search(mock: &MockServer, rows: Vec<Value>) {
    // Mounted first so it wins for the id=0 fetch; search requests carry no
    // `id` parameter and fall through to the catch-all below.
    Mock::given(method("GET"))
        .and(path("/rest/bug"))
        .and(query_param("id", "0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "bugs": [] })))
        .mount(mock)
        .await;
    Mock::given(method("GET"))
        .and(path("/rest/bug"))
        .respond_with(move |req: &wiremock::Request| {
            // A short page is no longer end-of-results, so past offset 0 the
            // scan must see an empty page or it replays `rows` up to the
            // request bound.
            let q: std::collections::HashMap<_, _> = req.url.query_pairs().collect();
            if q.get("offset").is_some_and(|v| v != "0") {
                return ResponseTemplate::new(200).set_body_json(json!({ "bugs": [] }));
            }
            ResponseTemplate::new(200).set_body_json(json!({ "bugs": rows.clone() }))
        })
        .mount(mock)
        .await;
}

/// Parsed JSON of a successful quicksearch call for `query`.
async fn quicksearch_json(client: &RunningService<RoleClient, ()>, query: &str) -> Value {
    quicksearch_json_args(client, json!({ "query": query })).await
}

/// Parsed JSON of a successful quicksearch call with full `args`.
async fn quicksearch_json_args(client: &RunningService<RoleClient, ()>, args: Value) -> Value {
    let result = call(client, "bugs_quicksearch", args).await;
    assert!(!is_error(&result), "search failed: {}", text_of(&result));
    serde_json::from_str(&text_of(&result)).expect("quicksearch returns JSON")
}

#[tokio::test]
async fn quicksearch_id_list_advisory_tracks_the_query_alone() {
    // The upstream serves the same rows whatever the query, so any
    // difference between the two results below is the server's own doing.
    let mock = MockServer::start().await;
    mount_search(
        &mock,
        vec![world_readable_bug(101), world_readable_bug(102)],
    )
    .await;
    let client = client_for("", &mock).await;

    // (a) A pure id-list query carries the advisory note.
    let mut with_note = quicksearch_json(&client, "#101, 102").await;
    let note = with_note["note"]
        .as_str()
        .expect("an id-list query must carry the advisory")
        .to_string();
    assert!(note.contains("bug_info"), "the note must steer to bug_info");

    // (b) A content query — even one containing a number — carries none.
    let without = quicksearch_json(&client, "kernel crash 101").await;
    assert!(
        without.get("note").is_none(),
        "a content query must not carry the advisory"
    );

    // (c) Apart from the note the envelopes are identical: same bugs, same
    // order — the advisory never changes what is returned.
    with_note.as_object_mut().unwrap().remove("note");
    assert_eq!(with_note, without);
}

#[tokio::test]
async fn quicksearch_advisory_ignores_hidden_bugs() {
    // Same policy, same id-list query, two upstreams: in one a returned bug
    // is policy-hidden. The hidden bug is silently dropped (I3), but the
    // advisory — presence and text — must not move: a note that tracked
    // verdicts would be a brand-new oracle.
    let policy = concat!(
        "[[rule]]\nname = \"hide-secret\"\naction = \"deny\"\n",
        "[rule.match]\nproducts = [\"Secret*\"]\n",
    );

    let plain = MockServer::start().await;
    mount_search(
        &plain,
        vec![world_readable_bug(101), world_readable_bug(102)],
    )
    .await;
    let client = client_for(policy, &plain).await;
    let served_both = quicksearch_json(&client, "101, 102").await;
    assert_eq!(served_both["bugs"].as_array().unwrap().len(), 2);
    let note_both = served_both["note"]
        .as_str()
        .expect("note present")
        .to_string();

    let hiding = MockServer::start().await;
    let mut hidden = world_readable_bug(101);
    hidden["product"] = json!("SecretSauce");
    mount_search(&hiding, vec![hidden, world_readable_bug(102)]).await;
    let client = client_for(policy, &hiding).await;
    let served_one = quicksearch_json(&client, "101, 102").await;
    let bugs = served_one["bugs"].as_array().unwrap();
    assert_eq!(bugs.len(), 1, "the hidden bug is silently dropped");
    assert_eq!(bugs[0]["id"], json!(102));
    assert_eq!(
        served_one["note"].as_str().expect("note still present"),
        note_both,
        "a hidden bug must not change the advisory"
    );
}

#[tokio::test]
async fn quicksearch_advisory_survives_an_all_hidden_result() {
    // Every matching bug is policy-hidden: the served `bugs` array is empty
    // (I3), and the advisory must still be present, byte-identical to the
    // note the same query carries when everything is visible. A note gated
    // on served results would tell "no match" apart from "all matches
    // hidden" — a fresh oracle.
    let policy = concat!(
        "[[rule]]\nname = \"hide-secret\"\naction = \"deny\"\n",
        "[rule.match]\nproducts = [\"Secret*\"]\n",
    );

    let plain = MockServer::start().await;
    mount_search(
        &plain,
        vec![world_readable_bug(101), world_readable_bug(102)],
    )
    .await;
    let client = client_for(policy, &plain).await;
    let visible = quicksearch_json(&client, "101, 102").await;
    assert_eq!(visible["bugs"].as_array().unwrap().len(), 2);
    let reference_note = visible["note"].as_str().expect("note").to_string();

    let hiding = MockServer::start().await;
    let mut h1 = world_readable_bug(101);
    h1["product"] = json!("SecretSauce");
    let mut h2 = world_readable_bug(102);
    h2["product"] = json!("SecretSauce");
    mount_search(&hiding, vec![h1, h2]).await;
    let client = client_for(policy, &hiding).await;
    let empty = quicksearch_json(&client, "101, 102").await;
    assert_eq!(
        empty["bugs"].as_array().unwrap().len(),
        0,
        "every match is policy-hidden"
    );
    assert_eq!(
        empty["note"]
            .as_str()
            .expect("the note must survive an empty result"),
        reference_note,
        "an all-hidden result must not move the advisory"
    );
}

#[tokio::test]
async fn quicksearch_advisory_unmoved_by_link_scrubbing() {
    // A served bug's depends_on names bug 666. Two upstreams, same policy,
    // same request: in one 666 is world-readable, in the other it is
    // policy-hidden, so I14 scrubbing empties the link field. The note —
    // presence and bytes — must not move with it: scrubbed ids are invisible
    // to the client, so a note that tracked scrubbing would be a covert
    // verdict channel.
    let policy = concat!(
        "[[rule]]\nname = \"hide-secret\"\naction = \"deny\"\n",
        "[rule.match]\nproducts = [\"Secret*\"]\n",
    );
    let args = json!({
        "query": "101, 102",
        "include_fields": "id,summary,depends_on",
    });
    let mut linked = world_readable_bug(101);
    linked["depends_on"] = json!([666]);

    // Control: the linked bug is disclosable, nothing is scrubbed. The
    // id=666 mock is mounted before mount_search's catch-all so it wins the
    // link-disclosure fetch; search requests carry no `id` parameter.
    let plain = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/bug"))
        .and(query_param("id", "666"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({ "bugs": [world_readable_bug(666)] })),
        )
        .mount(&plain)
        .await;
    mount_search(&plain, vec![linked.clone()]).await;
    let client = client_for(policy, &plain).await;
    let unscrubbed = quicksearch_json_args(&client, args.clone()).await;
    assert_eq!(unscrubbed["bugs"][0]["depends_on"], json!([666]));
    let reference_note = unscrubbed["note"].as_str().expect("note").to_string();

    // Same request, but 666 is policy-hidden: the link is scrubbed (I14)
    // and the advisory must not react.
    let hiding = MockServer::start().await;
    let mut secret = world_readable_bug(666);
    secret["product"] = json!("SecretSauce");
    Mock::given(method("GET"))
        .and(path("/rest/bug"))
        .and(query_param("id", "666"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "bugs": [secret] })))
        .mount(&hiding)
        .await;
    mount_search(&hiding, vec![linked]).await;
    let client = client_for(policy, &hiding).await;
    let scrubbed = quicksearch_json_args(&client, args).await;
    assert_eq!(
        scrubbed["bugs"][0]["depends_on"],
        json!([]),
        "the hidden link must actually be scrubbed (I14)"
    );
    assert_eq!(
        scrubbed["note"]
            .as_str()
            .expect("the note must survive link scrubbing"),
        reference_note,
        "link scrubbing must not move the advisory"
    );
}

#[tokio::test]
async fn quicksearch_advisory_wording_tracks_status_and_id_count() {
    // Request-only steering, end to end: with an empty status the query
    // goes upstream bare, where an all-number query is an exact id lookup,
    // so the note must not claim content matching there; and a list longer
    // than bug_info's per-call cap must steer to batching, not straight
    // into the too_many_ids refusal. The upstream serves no rows at all,
    // so every note below also rides on an empty `bugs` array.
    let mock = MockServer::start().await;
    mount_search(&mock, vec![]).await;
    let client = client_for("", &mock).await;

    // Default (non-empty) status: content-matching wording, no batching.
    let dflt = quicksearch_json(&client, "101, 102").await;
    let dflt_note = dflt["note"].as_str().expect("id-list note");
    assert!(dflt_note.contains("matches bug text"), "{dflt_note}");
    assert!(!dflt_note.contains("id lookup"), "{dflt_note}");

    // Explicitly empty status: id-lookup wording, still steering to
    // bug_info.
    let bare = quicksearch_json_args(&client, json!({ "query": "101, 102", "status": "" })).await;
    let bare_note = bare["note"].as_str().expect("note on the bare path");
    assert!(bare_note.contains("exact id lookup"), "{bare_note}");
    assert!(!bare_note.contains("matches bug text"), "{bare_note}");
    assert!(bare_note.contains("bug_info"), "{bare_note}");

    // 26 distinct ids: the steering mentions the cap and batching.
    let long_query = (1..=26)
        .map(|i| i.to_string())
        .collect::<Vec<_>>()
        .join(" ");
    let long = quicksearch_json(&client, &long_query).await;
    let long_note = long["note"].as_str().expect("note on a long id list");
    assert!(long_note.contains("at most 25 ids"), "{long_note}");
    assert!(long_note.contains("batch"), "{long_note}");

    // 25 distinct ids: no batching talk.
    let cap_query = (1..=25)
        .map(|i| i.to_string())
        .collect::<Vec<_>>()
        .join(" ");
    let cap = quicksearch_json(&client, &cap_query).await;
    let cap_note = cap["note"].as_str().expect("note at the cap");
    assert!(!cap_note.contains("batch"), "{cap_note}");
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

// ---------- bugs_quicksearch group_by (issue #143) ----------

/// The deny rule the group_by tests reuse: `Secret*` products are invisible.
const HIDE_SECRET_POLICY: &str = concat!(
    "[[rule]]\nname = \"hide-secret\"\naction = \"deny\"\n",
    "[rule.match]\nproducts = [\"Secret*\"]\n",
);

/// Flatten a grouped envelope back to `{field: value, ...}`-merged bug
/// objects, so a grouped response can be compared against a flat one.
fn ungroup(envelope: &Value) -> Vec<Value> {
    envelope["groups"]
        .as_array()
        .expect("a grouped envelope has `groups`")
        .iter()
        .flat_map(|g| {
            let hoisted: Vec<(String, Value)> = g
                .as_object()
                .expect("group object")
                .iter()
                .filter(|(k, _)| *k != "bugs")
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            g["bugs"]
                .as_array()
                .expect("each group has `bugs`")
                .iter()
                .map(move |b| {
                    let mut bug = b.as_object().expect("bug object").clone();
                    for (k, v) in &hoisted {
                        bug.insert(k.clone(), v.clone());
                    }
                    Value::Object(bug)
                })
                .collect::<Vec<_>>()
        })
        .collect()
}

#[tokio::test]
async fn quicksearch_groups_follow_served_row_order_not_sort_order() {
    // Three bugs, products Z / A / Z: the served window decides group order,
    // so Z comes first because bug 101 did. Sorting the groups — the easy
    // mutation — would put A first and make group order a channel
    // independent of the window the guard built.
    let mock = MockServer::start().await;
    let mut first = world_readable_bug(101);
    first["product"] = json!("Zebra");
    let mut second = world_readable_bug(102);
    second["product"] = json!("Alpha");
    let mut third = world_readable_bug(103);
    third["product"] = json!("Zebra");
    mount_search(&mock, vec![first, second, third]).await;
    let client = client_for("", &mock).await;

    let grouped =
        quicksearch_json_args(&client, json!({ "query": "kernel", "group_by": "product" })).await;
    let groups = grouped["groups"].as_array().expect("groups");
    assert_eq!(groups.len(), 2);
    assert_eq!(
        groups[0]["product"],
        json!("Zebra"),
        "first appearance wins"
    );
    assert_eq!(groups[1]["product"], json!("Alpha"));
    let ids: Vec<&Value> = groups[0]["bugs"]
        .as_array()
        .expect("bugs")
        .iter()
        .map(|b| &b["id"])
        .collect();
    assert_eq!(
        ids,
        vec![&json!(101), &json!(103)],
        "and within a group too"
    );
}

#[tokio::test]
async fn quicksearch_empty_group_by_is_the_flat_response() {
    // A client that fills in every declared param sends `""`; that must mean
    // "no grouping", not "fail the search".
    let mock = MockServer::start().await;
    mount_search(&mock, vec![world_readable_bug(101)]).await;
    let client = client_for("", &mock).await;

    let flat = quicksearch_json_args(&client, json!({ "query": "kernel" })).await;
    let empty = quicksearch_json_args(&client, json!({ "query": "kernel", "group_by": "" })).await;
    assert_eq!(empty, flat, "an empty group_by changes nothing");
}

#[tokio::test]
async fn quicksearch_grouping_only_reshapes_the_same_bugs() {
    // Grouping is a projection, not a filter: ungrouping must give back
    // exactly the flat response, same bugs, same order. Two keys, one of
    // which (`severity`) is not in the default include_fields — it is
    // forced into the projection by group_by alone.
    let mock = MockServer::start().await;
    let mut other = world_readable_bug(102);
    other["component"] = json!("YaST");
    mount_search(&mock, vec![world_readable_bug(101), other]).await;
    let client = client_for("", &mock).await;

    let flat = quicksearch_json_args(&client, json!({ "query": "kernel" })).await;
    let grouped = quicksearch_json_args(
        &client,
        json!({ "query": "kernel", "group_by": "product,severity" }),
    )
    .await;

    assert_eq!(
        grouped["groups"].as_array().expect("groups").len(),
        1,
        "both bugs share product+severity"
    );
    assert_eq!(grouped["groups"][0]["product"], json!("openSUSE"));
    assert_eq!(grouped["groups"][0]["severity"], json!("normal"));
    assert!(
        grouped["groups"][0]["bugs"][0].get("product").is_none(),
        "a grouped field is reported once per group, not per bug"
    );

    // The flat response never asked for `severity`, so drop it before
    // comparing — everything else must match bug for bug, in order.
    let mut round_tripped = ungroup(&grouped);
    for bug in &mut round_tripped {
        bug.as_object_mut().expect("bug object").remove("severity");
    }
    assert_eq!(
        round_tripped,
        *flat["bugs"].as_array().expect("flat bugs"),
        "grouping must not add, drop or reorder a bug"
    );
}

#[tokio::test]
async fn quicksearch_grouping_hides_the_same_bugs_as_a_flat_search() {
    // A policy-hidden row must leave no trace in the grouped envelope: no
    // empty bucket, no group header carrying its product (I3). The grouped
    // result over a hiding upstream must be byte-identical to the grouped
    // result over an upstream that simply never returned that row.
    let hiding = MockServer::start().await;
    let mut hidden = world_readable_bug(101);
    hidden["product"] = json!("SecretSauce");
    mount_search(&hiding, vec![hidden, world_readable_bug(102)]).await;
    let client = client_for(HIDE_SECRET_POLICY, &hiding).await;
    let filtered =
        quicksearch_json_args(&client, json!({ "query": "kernel", "group_by": "product" })).await;

    let clean = MockServer::start().await;
    mount_search(&clean, vec![world_readable_bug(102)]).await;
    let client = client_for(HIDE_SECRET_POLICY, &clean).await;
    let reference =
        quicksearch_json_args(&client, json!({ "query": "kernel", "group_by": "product" })).await;

    assert_eq!(
        filtered, reference,
        "a dropped bug must not show up as a group, a header or a count"
    );
    assert!(
        !serde_json::to_string(&filtered)
            .expect("serializable")
            .contains("SecretSauce"),
        "the hidden bug's product must not be hoisted into a header"
    );
}

#[tokio::test]
async fn quicksearch_grouping_leaves_the_advisory_note_alone() {
    // The note sits beside `groups` exactly as it sits beside `bugs`, with
    // the same text: it is a function of the client's query, and grouping
    // is a reshaping of the results the query found.
    let mock = MockServer::start().await;
    mount_search(
        &mock,
        vec![world_readable_bug(101), world_readable_bug(102)],
    )
    .await;
    let client = client_for("", &mock).await;

    let flat = quicksearch_json(&client, "#101, 102").await;
    let grouped = quicksearch_json_args(
        &client,
        json!({ "query": "#101, 102", "group_by": "product" }),
    )
    .await;
    assert_eq!(
        grouped["note"], flat["note"],
        "the advisory must survive grouping unchanged"
    );
    assert!(
        grouped.get("bugs").is_none() && grouped.get("groups").is_some(),
        "and it must not have replaced the grouped envelope"
    );
}

#[tokio::test]
async fn quicksearch_grouping_keeps_the_redacted_marker() {
    // A summary-only grant still groups: every group_by field is a summary
    // field, so the row buckets normally and keeps `_redacted` — dropping
    // the marker inside a group would misrepresent the grant.
    let policy = concat!(
        "[[rule]]\nname = \"summary-only\"\naction = \"restrict\"\n",
        "capabilities = [\"summary\"]\n",
        "[rule.match]\nproducts = [\"openSUSE\"]\n",
    );
    let mock = MockServer::start().await;
    mount_search(&mock, vec![world_readable_bug(101)]).await;
    let client = client_for(policy, &mock).await;

    let grouped = quicksearch_json_args(
        &client,
        json!({ "query": "kernel", "group_by": "product,status" }),
    )
    .await;
    assert_eq!(grouped["groups"][0]["product"], json!("openSUSE"));
    assert_eq!(grouped["groups"][0]["status"], json!("NEW"));
    assert_eq!(grouped["groups"][0]["bugs"][0]["_redacted"], json!(true));
}

#[tokio::test]
async fn quicksearch_rejects_an_unknown_group_by_without_calling_upstream() {
    // Validated before the round trip, and the refusal quotes only what the
    // client itself sent — no bug id, no rule name (I1/I2).
    let mock = MockServer::start().await;
    mount_search(&mock, vec![world_readable_bug(101)]).await;
    let client = client_for("", &mock).await;

    let result = call(
        &client,
        "bugs_quicksearch",
        json!({ "query": "kernel", "group_by": "assigned_to" }),
    )
    .await;
    assert!(is_error(&result));
    let text = text_of(&result);
    assert!(text.contains("assigned_to"), "text: {text}");
    assert!(text.contains("product"), "the vocabulary is listed: {text}");
    assert!(
        mock.received_requests()
            .await
            .unwrap_or_default()
            .is_empty(),
        "a malformed projection must not cost a Bugzilla round trip"
    );
}

#[tokio::test]
async fn quicksearch_group_by_does_not_soften_a_failing_search() {
    // group_by rides along on an upstream failure without changing the
    // uniform text (I2) — no partial envelope, no mention of the grouping.
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/bug"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&mock)
        .await;
    let client = client_for("", &mock).await;

    let result = call(
        &client,
        "bugs_quicksearch",
        json!({ "query": "kernel", "group_by": "product" }),
    )
    .await;
    assert!(is_error(&result));
    assert_eq!(text_of(&result), "Search failed");
}

// ---------- update_bug_fields: the widened field surface (issue #38) ----------

/// Mount a successful `PUT /rest/bug/7` whose body must carry `body`,
/// expected exactly once.
async fn mount_update_put(mock: &MockServer, body: Value) {
    Mock::given(method("PUT"))
        .and(path("/rest/bug/7"))
        .and(body_partial_json(body))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "bugs": [{ "id": 7 }] })))
        .expect(1)
        .mount(mock)
        .await;
}

#[tokio::test]
async fn update_fields_sends_see_also_add_and_remove() {
    // see_also travels as the {"add": [..], "remove": [..]} object — the
    // shape update_bug_dependencies already pinned for blocks/depends_on —
    // with BOTH sides present when both were given, never a flat array.
    // The entries name bugs on ANOTHER tracker (bugzilla.example.org, not
    // this mock), so they are somebody else's to disclose and must NOT be
    // guard-assessed: the classify mock for bug 7 is the only one mounted,
    // and its expect(1) fails the test if a foreign URL draws a lookup.
    let mock = MockServer::start().await;
    mount_classify(&mock, world_readable_bug(7)).await;
    mount_update_put(
        &mock,
        json!({
            "see_also": {
                "add": ["https://bugzilla.example.org/show_bug.cgi?id=101"],
                "remove": ["https://bugzilla.example.org/show_bug.cgi?id=102"],
            }
        }),
    )
    .await;
    let client = client_for("", &mock).await;
    let result = call(
        &client,
        "update_bug_fields",
        json!({
            "bug_id": 7,
            "see_also_add": ["https://bugzilla.example.org/show_bug.cgi?id=101"],
            "see_also_remove": ["https://bugzilla.example.org/show_bug.cgi?id=102"],
        }),
    )
    .await;
    assert!(!is_error(&result), "result: {}", text_of(&result));
}

#[tokio::test]
async fn update_fields_sends_keywords_as_add_remove_never_set() {
    // The add/remove-vs-set distinction is the point: `set` replaces the
    // WHOLE keyword list, so a stale view would silently wipe concurrent
    // additions. The specific mock accepts only the add shape; the
    // catch-all behind it answers any other PUT body (a `set`-shaped one
    // included) and fails the test through its expect(0) when hit.
    let mock = MockServer::start().await;
    mount_classify(&mock, world_readable_bug(7)).await;
    mount_update_put(&mock, json!({ "keywords": { "add": ["regression"] } })).await;
    Mock::given(method("PUT"))
        .and(path("/rest/bug/7"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "bugs": [{ "id": 7 }] })))
        .expect(0)
        .mount(&mock)
        .await;
    let client = client_for("", &mock).await;
    let result = call(
        &client,
        "update_bug_fields",
        json!({ "bug_id": 7, "keywords_add": ["regression"] }),
    )
    .await;
    assert!(!is_error(&result), "result: {}", text_of(&result));
}

#[tokio::test]
async fn update_fields_sets_scalar_fields() {
    // All five scalar fields land in one PUT body, and the optional
    // comment still rides along in the Bug.update shape.
    let mock = MockServer::start().await;
    mount_classify(&mock, world_readable_bug(7)).await;
    mount_update_put(
        &mock,
        json!({
            "summary": "clearer title",
            "url": "https://example.org/crash-report",
            "whiteboard": "triaged",
            "version": "15.6",
            "target_milestone": "Beta1",
            "comment": { "body": "retitled after triage" },
        }),
    )
    .await;
    let client = client_for("", &mock).await;
    let result = call(
        &client,
        "update_bug_fields",
        json!({
            "bug_id": 7,
            "summary": "clearer title",
            "url": "https://example.org/crash-report",
            "whiteboard": "triaged",
            "version": "15.6",
            "target_milestone": "Beta1",
            "comment": "retitled after triage",
        }),
    )
    .await;
    assert!(!is_error(&result), "result: {}", text_of(&result));
}

#[tokio::test]
async fn update_fields_ignores_empty_strings_and_empty_lists() {
    // Empty values mean "not this field", exactly like the pre-existing
    // params: the body must carry ONLY the real field. The trap mock is
    // mounted first, so a body still carrying "summary" is routed to it
    // and fails its expect(0); the emptied keyword list is checked against
    // the recorded request body directly.
    let mock = MockServer::start().await;
    mount_classify(&mock, world_readable_bug(7)).await;
    Mock::given(method("PUT"))
        .and(path("/rest/bug/7"))
        .and(body_partial_json(json!({ "summary": "" })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "bugs": [{ "id": 7 }] })))
        .expect(0)
        .mount(&mock)
        .await;
    mount_update_put(&mock, json!({ "priority": "P2" })).await;
    let client = client_for("", &mock).await;
    let result = call(
        &client,
        "update_bug_fields",
        json!({ "bug_id": 7, "summary": "", "keywords_add": [], "priority": "P2" }),
    )
    .await;
    assert!(!is_error(&result), "result: {}", text_of(&result));
    let put_body: Value = mock
        .received_requests()
        .await
        .unwrap()
        .iter()
        .find(|r| r.method == wiremock::http::Method::PUT)
        .map(|r| serde_json::from_slice(&r.body).expect("PUT body is JSON"))
        .expect("one PUT reached the mock");
    assert_eq!(
        put_body,
        json!({ "priority": "P2" }),
        "empty strings and empty lists must not reach the wire"
    );
}

#[tokio::test]
async fn update_fields_new_fields_respect_the_guard() {
    // A call touching only the newer fields still goes through deny_unless:
    // a policy-denied bug takes the uniform denial (I2) and nothing is PUT.
    let mock = MockServer::start().await;
    let mut secret = world_readable_bug(7);
    secret["product"] = json!("SecretSauce");
    mount_classify(&mock, secret).await;
    Mock::given(method("PUT"))
        .and(path("/rest/bug/7"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "bugs": [{ "id": 7 }] })))
        .expect(0)
        .mount(&mock)
        .await;
    let client = client_for(
        concat!(
            "[[rule]]\nname = \"hide-secret\"\naction = \"deny\"\n",
            "[rule.match]\nproducts = [\"Secret*\"]\n",
        ),
        &mock,
    )
    .await;
    let result = call(
        &client,
        "update_bug_fields",
        json!({ "bug_id": 7, "summary": "probe", "keywords_add": ["regression"] }),
    )
    .await;
    assert!(is_error(&result));
    assert_eq!(
        text_of(&result),
        "Bug 7 is not accessible through this server",
        "a denied bug takes the uniform denial for new fields too (I2)"
    );
}

#[tokio::test]
async fn update_fields_see_also_targets_respect_the_guard() {
    // A see_also entry naming a bug on THIS instance is a bug-id link, so
    // its target takes the same Capability::Summary bar as dependency
    // targets and duplicate_of (I8/I14): a policy-denied target draws the
    // uniform denial (I2) and nothing is PUT. Otherwise the difference
    // between Bugzilla's success and "does not exist" answers would
    // enumerate every hidden id, and a successful PUT would even write the
    // reciprocal see_also entry onto the denied bug itself.
    let mock = MockServer::start().await;
    mount_classify(&mock, world_readable_bug(7)).await;
    let mut secret = world_readable_bug(999);
    secret["product"] = json!("SecretSauce");
    mount_classify(&mock, secret).await;
    Mock::given(method("PUT"))
        .and(path("/rest/bug/7"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "bugs": [{ "id": 7 }] })))
        .expect(0)
        .mount(&mock)
        .await;
    let client = client_for(
        concat!(
            "[[rule]]\nname = \"hide-secret\"\naction = \"deny\"\n",
            "[rule.match]\nproducts = [\"Secret*\"]\n",
        ),
        &mock,
    )
    .await;
    let result = call(
        &client,
        "update_bug_fields",
        json!({
            "bug_id": 7,
            "see_also_add": [format!("{}/show_bug.cgi?id=999", mock.uri())],
        }),
    )
    .await;
    assert!(is_error(&result));
    assert_eq!(
        text_of(&result),
        "Bug 999 is not accessible through this server",
        "a policy-denied see_also target takes the uniform denial (I2), no PUT"
    );
}

#[tokio::test]
async fn update_fields_still_rejects_non_cf_custom_keys() {
    // I7 unchanged by the widening: `see_also` has a named param now, and
    // as a custom_fields key it still errors before Bugzilla is contacted —
    // the named params did not open a smuggling path through the generic
    // updater.
    let mock = MockServer::start().await;
    let client = client_for("", &mock).await;
    let result = call(
        &client,
        "update_bug_fields",
        json!({
            "bug_id": 7,
            "custom_fields": {
                "see_also": ["https://bugzilla.example.org/show_bug.cgi?id=101"],
            },
        }),
    )
    .await;
    assert!(is_error(&result));
    assert_eq!(
        text_of(&result),
        "Invalid custom field 'see_also': custom field names must start with 'cf_'"
    );
    assert!(
        mock.received_requests().await.unwrap().is_empty(),
        "the cf_ gate must refuse before any upstream request (I7)"
    );
}

#[tokio::test]
async fn update_fields_all_empty_call_errors_without_calling_bugzilla() {
    // Nothing but empty strings and empty lists is an empty call: the
    // at-least-one-field check counts the new params AFTER the emptiness
    // filtering, and refuses before anything upstream happens.
    let mock = MockServer::start().await;
    let client = client_for("", &mock).await;
    let result = call(
        &client,
        "update_bug_fields",
        json!({
            "bug_id": 7,
            "summary": "",
            "url": "",
            "whiteboard": "",
            "keywords_add": [],
            "see_also_remove": [],
        }),
    )
    .await;
    assert!(is_error(&result));
    assert_eq!(text_of(&result), "At least one field must be specified");
    assert!(
        mock.received_requests().await.unwrap().is_empty(),
        "an all-empty call must not contact Bugzilla"
    );
}

/// Read the sole PUT body received by `mock`, asserting exactly one PUT
/// reached it. Used to assert *absence* of keys, not just presence.
async fn sole_put_body(mock: &MockServer) -> Value {
    mock.received_requests()
        .await
        .unwrap()
        .iter()
        .find(|r| r.method == wiremock::http::Method::PUT)
        .map(|r| serde_json::from_slice(&r.body).expect("PUT body is JSON"))
        .expect("one PUT reached the mock")
}

#[tokio::test]
async fn update_bug_status_without_resolution_omits_it_from_the_wire() {
    // Bugzilla rejects a synthesised "resolution":"" on RESOLVED
    // (missing_resolution); the tool must not send it.
    let mock = MockServer::start().await;
    mount_classify(&mock, world_readable_bug(7)).await;
    mount_update_put(&mock, json!({ "status": "RESOLVED" })).await;
    let client = client_for("", &mock).await;
    let result = call(
        &client,
        "update_bug_status",
        json!({ "bug_id": 7, "status": "RESOLVED" }),
    )
    .await;
    assert!(!is_error(&result), "result: {}", text_of(&result));
    assert_eq!(sole_put_body(&mock).await, json!({ "status": "RESOLVED" }));
}

#[tokio::test]
async fn update_bug_status_with_resolution_sends_both() {
    let mock = MockServer::start().await;
    mount_classify(&mock, world_readable_bug(7)).await;
    mount_update_put(
        &mock,
        json!({ "status": "RESOLVED", "resolution": "FIXED" }),
    )
    .await;
    let client = client_for("", &mock).await;
    let result = call(
        &client,
        "update_bug_status",
        json!({ "bug_id": 7, "status": "RESOLVED", "resolution": "FIXED" }),
    )
    .await;
    assert!(!is_error(&result), "result: {}", text_of(&result));
    assert_eq!(
        sole_put_body(&mock).await,
        json!({ "status": "RESOLVED", "resolution": "FIXED" })
    );
}

#[tokio::test]
async fn update_bug_status_closed_without_resolution_reaches_upstream() {
    // There is no local CLOSED pre-check any more: the request reaches
    // Bugzilla, which is free to accept or reject it (missing_resolution).
    let mock = MockServer::start().await;
    mount_classify(&mock, world_readable_bug(7)).await;
    mount_update_put(&mock, json!({ "status": "CLOSED" })).await;
    let client = client_for("", &mock).await;
    let result = call(
        &client,
        "update_bug_status",
        json!({ "bug_id": 7, "status": "CLOSED" }),
    )
    .await;
    assert!(!is_error(&result), "result: {}", text_of(&result));
    assert_eq!(sole_put_body(&mock).await, json!({ "status": "CLOSED" }));
}

#[tokio::test]
async fn mark_as_duplicate_sends_only_dupe_of_and_comment() {
    // No status/resolution insert: the instance's
    // duplicate_or_move_bug_status decides, not this tool.
    let mock = MockServer::start().await;
    mount_classify(&mock, world_readable_bug(7)).await;
    mount_classify(&mock, world_readable_bug(8)).await;
    mount_update_put(
        &mock,
        json!({
            "dupe_of": 8,
            "comment": { "body": "Marking as duplicate of bug 8" },
        }),
    )
    .await;
    let client = client_for("", &mock).await;
    let result = call(
        &client,
        "mark_as_duplicate",
        json!({ "bug_id": 7, "duplicate_of": 8 }),
    )
    .await;
    assert!(!is_error(&result), "result: {}", text_of(&result));
    assert_eq!(
        sole_put_body(&mock).await,
        json!({
            "dupe_of": 8,
            "comment": { "body": "Marking as duplicate of bug 8" },
        })
    );
}

/// Tool names a client sees when it lists the server's tools — a real
/// `tools/list` request over the wire, so the handler's own listing path
/// is what answers.
async fn listed_tools(client: &RunningService<RoleClient, ()>) -> Vec<String> {
    bounded("tools/list", client.list_all_tools())
        .await
        .expect("list_tools must succeed")
        .into_iter()
        .map(|t| t.name.to_string())
        .collect()
}

#[tokio::test]
async fn list_tools_serves_the_pruned_instance_router_i13() {
    // The listing must come from the instance router `BugWarden::new`
    // pruned, not a freshly built default one: a listing that resurrects
    // stripped tools would advertise operations the policy removed (I13).
    let mock = MockServer::start().await;

    let client = client_for("[global]\nread_only = true\n", &mock).await;
    let names = listed_tools(&client).await;
    for tool in WRITE_TOOLS {
        assert!(
            !names.iter().any(|n| n == tool),
            "read-only mode must delist write tool {tool} (I13): {names:?}"
        );
    }
    assert!(
        names.iter().any(|n| n == "bug_info"),
        "a read tool stays listed: {names:?}"
    );

    let client = client_for("[global]\ndisabled_tools = [\"bug_history\"]\n", &mock).await;
    let names = listed_tools(&client).await;
    assert!(
        !names.iter().any(|n| n == "bug_history"),
        "a policy-disabled tool must be delisted (I13): {names:?}"
    );
    assert!(
        names.iter().any(|n| n == "bug_info"),
        "a read tool stays listed: {names:?}"
    );
}

// ---------- created_by_me (identity-relative matcher, issue #33) ----------

/// The issue's policy shape: the caller's own reports carved out of a
/// blanket group_restricted deny. `operations = ["access"]` keeps the
/// carve-out away from the create gate.
const IDENTITY_POLICY: &str = concat!(
    "[[rule]]\nname = \"my-own-reports\"\naction = \"restrict\"\n",
    "capabilities = [\"read\", \"comments\", \"history\", \"attachments\"]\n",
    "operations = [\"access\"]\n",
    "[rule.match]\ncreated_by_me = true\n",
    "[[rule]]\nname = \"group-restricted\"\naction = \"deny\"\n",
    "[rule.match]\ngroup_restricted = true\n",
);

/// A group-restricted bug with an explicit creator.
fn restricted_bug(id: u64, creator: &str) -> Value {
    let mut bug = world_readable_bug(id);
    bug["groups"] = json!(["secteam"]);
    bug["creator"] = json!(creator);
    bug
}

/// Mount `GET /rest/whoami` answering with `login`, expected `hits` times.
async fn mount_whoami(mock: &MockServer, login: &str, hits: u64) {
    Mock::given(method("GET"))
        .and(path("/rest/whoami"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": 1, "name": login, "real_name": "Reporter",
        })))
        .expect(hits)
        .mount(mock)
        .await;
}

/// Mount the classification/full fetch for `bug` (unbounded — bug_info
/// fetches a Read-granted id twice) and the id=0 link-disclosure padding.
async fn mount_bug_and_padding(mock: &MockServer, bug: Value) {
    let id = bug["id"].as_u64().expect("bug fixture has an id");
    Mock::given(method("GET"))
        .and(path("/rest/bug"))
        .and(query_param("id", id.to_string()))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "bugs": [bug] })))
        .mount(mock)
        .await;
    Mock::given(method("GET"))
        .and(path("/rest/bug"))
        .and(query_param("id", "0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "bugs": [] })))
        .mount(mock)
        .await;
}

#[tokio::test]
async fn created_by_me_carves_own_reports_out_of_a_group_restricted_deny() {
    // The issue's scenario end to end: under a policy whose blanket rule
    // denies every group-restricted bug, the caller can still read the
    // group-restricted bug their own account filed — and nobody else's.
    let mock = MockServer::start().await;
    mount_whoami(&mock, "reporter@example.com", 2).await;
    mount_bug_and_padding(&mock, restricted_bug(7, "reporter@example.com")).await;
    mount_bug_and_padding(&mock, restricted_bug(8, "other.person@example.com")).await;
    let client = client_for(IDENTITY_POLICY, &mock).await;

    let own = call(&client, "bug_info", json!({ "bug_ids": [7] })).await;
    assert!(
        !is_error(&own),
        "own report must be served: {}",
        text_of(&own)
    );
    let own: Value = serde_json::from_str(&text_of(&own)).expect("bug_info returns JSON");
    assert_eq!(
        own["bugs"][0]["id"],
        json!(7),
        "the caller's own group-restricted bug is readable"
    );
    assert!(own["restricted"].as_array().unwrap().is_empty());

    let foreign = call(&client, "bug_info", json!({ "bug_ids": [8] })).await;
    let foreign: Value = serde_json::from_str(&text_of(&foreign)).expect("bug_info returns JSON");
    assert!(foreign["bugs"].as_array().unwrap().is_empty());
    assert_eq!(
        foreign["restricted"][0]["note"],
        json!("Bug 8 is not accessible through this server"),
        "someone else's restricted bug takes the uniform denial (I2)"
    );
}

/// The declared-login counterpart of [`IDENTITY_POLICY`] (PR C,
/// `plans/ISSUE_WHOAMI_IDENTITY.md`): the same carve-out, resolved from an
/// operator-declared, startup-verified login instead of `whoami` — the
/// portable path for a stock Bugzilla Core v1 deployment with no identity
/// endpoint at all.
const DECLARED_IDENTITY_POLICY: &str = concat!(
    "[global]\n",
    "identity_source = \"declared\"\n",
    "identity_login = \"reporter@example.com\"\n",
    "[[rule]]\nname = \"my-own-reports\"\naction = \"restrict\"\n",
    "capabilities = [\"read\", \"comments\", \"history\", \"attachments\"]\n",
    "operations = [\"access\"]\n",
    "[rule.match]\ncreated_by_me = true\n",
    "[[rule]]\nname = \"group-restricted\"\naction = \"deny\"\n",
    "[rule.match]\ngroup_restricted = true\n",
);

#[tokio::test]
async fn declared_identity_carves_own_reports_out_with_zero_whoami_hits() {
    // End to end, mirroring created_by_me_carves_own_reports_out_of_a_group
    // _restricted_deny, but under a declared login: the caller's own
    // group-restricted bug is readable, a foreign one takes the uniform
    // denial (I2), and NOT ONE whoami request is made — the declared login
    // was verified once at startup (BugWarden::preflight), never looked up
    // again per call.
    let mock = MockServer::start().await;
    mount_whoami(&mock, "reporter@example.com", 0).await;
    mount_bug_and_padding(&mock, restricted_bug(7, "reporter@example.com")).await;
    mount_bug_and_padding(&mock, restricted_bug(8, "other.person@example.com")).await;
    let client = client_for(DECLARED_IDENTITY_POLICY, &mock).await;

    let own = call(&client, "bug_info", json!({ "bug_ids": [7] })).await;
    let own: Value = serde_json::from_str(&text_of(&own)).expect("bug_info returns JSON");
    assert_eq!(
        own["bugs"][0]["id"],
        json!(7),
        "the caller's own group-restricted bug is readable under a declared login"
    );
    assert!(own["restricted"].as_array().unwrap().is_empty());

    let foreign = call(&client, "bug_info", json!({ "bug_ids": [8] })).await;
    let foreign: Value = serde_json::from_str(&text_of(&foreign)).expect("bug_info returns JSON");
    assert!(foreign["bugs"].as_array().unwrap().is_empty());
    assert_eq!(
        foreign["restricted"][0]["note"],
        json!("Bug 8 is not accessible through this server"),
        "someone else's restricted bug takes the uniform denial (I2)"
    );
}

#[tokio::test]
async fn created_by_me_whoami_failure_yields_the_same_uniform_denial() {
    // whoami down: the caller's own bug must come back with EXACTLY the
    // bytes a foreign bug gets under a working whoami — no different text,
    // no different shape, no oracle for "denied because identity failed".
    let broken = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/whoami"))
        .respond_with(ResponseTemplate::new(500).set_body_json(json!({
            "error": true, "message": "internal server error"
        })))
        .mount(&broken)
        .await;
    mount_bug_and_padding(&broken, restricted_bug(7, "reporter@example.com")).await;
    let client = client_for(IDENTITY_POLICY, &broken).await;
    let under_outage = call(&client, "bug_info", json!({ "bug_ids": [7] })).await;

    let healthy = MockServer::start().await;
    mount_whoami(&healthy, "reporter@example.com", 1).await;
    mount_bug_and_padding(&healthy, restricted_bug(7, "other.person@example.com")).await;
    let client = client_for(IDENTITY_POLICY, &healthy).await;
    let foreign = call(&client, "bug_info", json!({ "bug_ids": [7] })).await;

    assert_eq!(
        serde_json::to_string(&under_outage).unwrap(),
        serde_json::to_string(&foreign).unwrap(),
        "a whoami outage must be indistinguishable from a foreign bug (I2/I4)"
    );
    let envelope: Value = serde_json::from_str(&text_of(&under_outage)).expect("JSON");
    assert_eq!(
        envelope["restricted"][0]["note"],
        json!("Bug 7 is not accessible through this server")
    );
}

#[tokio::test]
async fn whoami_is_called_once_per_tool_call_under_an_identity_policy() {
    // The per-call contract: ONE whoami for one tool call, however many
    // classifications the call runs (assessment, re-check, link
    // disclosure). The .expect(1) is verified when the mock server drops.
    let mock = MockServer::start().await;
    mount_whoami(&mock, "reporter@example.com", 1).await;
    mount_bug_and_padding(&mock, restricted_bug(7, "reporter@example.com")).await;
    let client = client_for(IDENTITY_POLICY, &mock).await;
    let result = call(&client, "bug_info", json!({ "bug_ids": [7] })).await;
    assert!(!is_error(&result));
}

#[tokio::test]
async fn whoami_is_never_called_under_a_policy_without_identity_criteria() {
    // The laziness contract: a policy that never consults created_by_me
    // costs ZERO whoami lookups — pre-identity deployments keep their
    // exact upstream request pattern.
    let mock = MockServer::start().await;
    mount_whoami(&mock, "reporter@example.com", 0).await;
    mount_bug_and_padding(&mock, world_readable_bug(7)).await;
    let client = client_for(
        concat!(
            "[[rule]]\nname = \"group-restricted\"\naction = \"deny\"\n",
            "[rule.match]\ngroup_restricted = true\n",
        ),
        &mock,
    )
    .await;
    let result = call(&client, "bug_info", json!({ "bug_ids": [7] })).await;
    assert!(!is_error(&result));
}

#[tokio::test]
async fn created_by_me_keeps_own_reports_in_quicksearch_results() {
    // The caller must reach the guard's search scan, not only bug_info:
    // under the identity policy the caller's own group-restricted bug stays
    // in the served window while a foreign one is silently dropped (I3) —
    // and the whole tool call still costs exactly one whoami lookup.
    let mock = MockServer::start().await;
    mount_whoami(&mock, "reporter@example.com", 1).await;
    mount_search(
        &mock,
        vec![
            restricted_bug(101, "reporter@example.com"),
            restricted_bug(102, "other.person@example.com"),
        ],
    )
    .await;
    let client = client_for(IDENTITY_POLICY, &mock).await;

    let served = quicksearch_json(&client, "kernel crash").await;
    let ids: Vec<u64> = served["bugs"]
        .as_array()
        .expect("quicksearch returns a bugs array")
        .iter()
        .filter_map(|b| b["id"].as_u64())
        .collect();
    assert_eq!(
        ids,
        vec![101],
        "search must keep the caller's own restricted bug and drop the foreign one: {served}"
    );
}

#[tokio::test]
async fn created_by_me_carves_own_reports_out_for_bug_comments_too() {
    // deny_unless gets the same caller threading as bug_info: the caller's
    // own group-restricted bug serves its comments, a foreign one takes the
    // uniform denial before anything is fetched — one whoami per tool call
    // either way (the .expect counts are verified when the mock drops).
    let mock = MockServer::start().await;
    mount_whoami(&mock, "reporter@example.com", 2).await;
    mount_bug_and_padding(&mock, restricted_bug(7, "reporter@example.com")).await;
    mount_bug_and_padding(&mock, restricted_bug(8, "other.person@example.com")).await;
    Mock::given(method("GET"))
        .and(path("/rest/bug/7/comment"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "bugs": { "7": { "comments": [
                { "id": 1, "bug_id": 7, "text": "first comment", "is_private": false },
            ] } }
        })))
        .expect(1)
        .mount(&mock)
        .await;
    Mock::given(method("GET"))
        .and(path("/rest/bug/8/comment"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "bugs": { "8": { "comments": [] } }
        })))
        .expect(0)
        .mount(&mock)
        .await;
    let client = client_for(IDENTITY_POLICY, &mock).await;

    let own = call(&client, "bug_comments", json!({ "id": 7 })).await;
    assert!(
        !is_error(&own),
        "the caller's own report must serve its comments: {}",
        text_of(&own)
    );
    assert!(text_of(&own).contains("first comment"));

    let foreign = call(&client, "bug_comments", json!({ "id": 8 })).await;
    assert!(is_error(&foreign));
    assert_eq!(
        text_of(&foreign),
        "Bug 8 is not accessible through this server",
        "someone else's restricted bug takes the uniform denial (I2)"
    );
}

#[tokio::test]
async fn created_by_me_carves_own_reports_out_for_bug_history_too() {
    // Every tool threads the caller by hand, so every tool is its own
    // mutation surface: this pins bug_history the way the test above pins
    // bug_comments — the caller's own group-restricted bug serves its
    // history, a foreign one takes the uniform denial before anything is
    // fetched, and each tool call costs exactly one whoami lookup.
    let mock = MockServer::start().await;
    mount_whoami(&mock, "reporter@example.com", 2).await;
    mount_bug_and_padding(&mock, restricted_bug(7, "reporter@example.com")).await;
    mount_bug_and_padding(&mock, restricted_bug(8, "other.person@example.com")).await;
    Mock::given(method("GET"))
        .and(path("/rest/bug/7/history"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "bugs": [{ "id": 7, "history": [{
                "when": "2020-02-01T00:00:00Z",
                "who": "someone@example.com",
                "changes": [
                    { "field_name": "status", "removed": "NEW", "added": "CONFIRMED" },
                ],
            }] }]
        })))
        .expect(1)
        .mount(&mock)
        .await;
    Mock::given(method("GET"))
        .and(path("/rest/bug/8/history"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "bugs": [] })))
        .expect(0)
        .mount(&mock)
        .await;
    let client = client_for(IDENTITY_POLICY, &mock).await;

    let own = call(&client, "bug_history", json!({ "id": 7 })).await;
    assert!(
        !is_error(&own),
        "the caller's own report must serve its history: {}",
        text_of(&own)
    );
    assert!(text_of(&own).contains("CONFIRMED"));

    let foreign = call(&client, "bug_history", json!({ "id": 8 })).await;
    assert!(is_error(&foreign));
    assert_eq!(
        text_of(&foreign),
        "Bug 8 is not accessible through this server",
        "someone else's restricted bug takes the uniform denial (I2)"
    );
}

/// Mount the classify fetch and id=0 padding for bug 7 plus a history
/// endpoint serving `entries` (issue #142 windowing tests).
async fn mount_history_window_fixture(mock: &MockServer, entries: Value) {
    mount_bug_and_padding(mock, world_readable_bug(7)).await;
    Mock::given(method("GET"))
        .and(path("/rest/bug/7/history"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "bugs": [{ "id": 7, "history": entries }]
        })))
        .mount(mock)
        .await;
}

/// Five plain status-change entries; the `when` strings ("2020-01-0N")
/// pin which entries a window kept.
fn five_history_entries() -> Value {
    (1..=5)
        .map(|n| {
            json!({
                "when": format!("2020-01-0{n}T00:00:00Z"),
                "who": "dev@example.org",
                "changes": [
                    { "field_name": "status", "removed": "NEW", "added": "CONFIRMED" },
                ],
            })
        })
        .collect()
}

/// Parse a `bug_history` tool result as JSON.
fn history_json(result: &CallToolResult) -> Value {
    serde_json::from_str(&text_of(result)).expect("bug_history returns JSON")
}

#[tokio::test]
async fn bug_history_without_window_params_serves_the_bare_array() {
    // The default path is byte-stable: with neither head nor tail the
    // response stays the bare array it always was — no envelope, no
    // truncation block.
    let mock = MockServer::start().await;
    mount_history_window_fixture(&mock, five_history_entries()).await;
    let client = client_for("", &mock).await;

    let served = call(&client, "bug_history", json!({ "id": 7 })).await;
    assert!(
        !is_error(&served),
        "the history is served: {}",
        text_of(&served)
    );
    let parsed = history_json(&served);
    let entries = parsed
        .as_array()
        .expect("no window params means the bare array, not an envelope");
    assert_eq!(entries.len(), 5);
}

#[tokio::test]
async fn bug_history_head_keeps_the_first_entries() {
    let mock = MockServer::start().await;
    mount_history_window_fixture(&mock, five_history_entries()).await;
    let client = client_for("", &mock).await;

    let served = call(&client, "bug_history", json!({ "id": 7, "head": 2 })).await;
    let parsed = history_json(&served);
    let shown = parsed["history"].as_array().expect("windowed envelope");
    assert_eq!(shown.len(), 2);
    assert_eq!(shown[0]["when"], json!("2020-01-01T00:00:00Z"));
    assert_eq!(shown[1]["when"], json!("2020-01-02T00:00:00Z"));
    assert_eq!(
        parsed["truncation"],
        json!({ "omitted_entries": 3, "shown_entries": 2 }),
        "the envelope reports what the window omitted: {parsed}"
    );
}

#[tokio::test]
async fn bug_history_tail_keeps_the_last_entries() {
    let mock = MockServer::start().await;
    mount_history_window_fixture(&mock, five_history_entries()).await;
    let client = client_for("", &mock).await;

    let served = call(&client, "bug_history", json!({ "id": 7, "tail": 2 })).await;
    let parsed = history_json(&served);
    let shown = parsed["history"].as_array().expect("windowed envelope");
    assert_eq!(shown.len(), 2);
    assert_eq!(shown[0]["when"], json!("2020-01-04T00:00:00Z"));
    assert_eq!(shown[1]["when"], json!("2020-01-05T00:00:00Z"));
    assert_eq!(
        parsed["truncation"],
        json!({ "omitted_entries": 3, "shown_entries": 2 })
    );
}

#[tokio::test]
async fn bug_history_head_and_tail_keep_both_ends() {
    let mock = MockServer::start().await;
    mount_history_window_fixture(&mock, five_history_entries()).await;
    let client = client_for("", &mock).await;

    let served = call(
        &client,
        "bug_history",
        json!({ "id": 7, "head": 1, "tail": 1 }),
    )
    .await;
    let parsed = history_json(&served);
    let shown = parsed["history"].as_array().expect("windowed envelope");
    assert_eq!(shown.len(), 2);
    assert_eq!(shown[0]["when"], json!("2020-01-01T00:00:00Z"));
    assert_eq!(shown[1]["when"], json!("2020-01-05T00:00:00Z"));
    assert_eq!(
        parsed["truncation"],
        json!({ "omitted_entries": 3, "shown_entries": 2 })
    );
}

#[tokio::test]
async fn bug_history_overlapping_windows_omit_nothing() {
    // head + tail >= len keeps everything: the overlap is not
    // double-counted and the envelope reports zeros — a deterministic
    // shape per call signature, nothing omitted.
    let mock = MockServer::start().await;
    mount_history_window_fixture(&mock, five_history_entries()).await;
    let client = client_for("", &mock).await;

    let served = call(
        &client,
        "bug_history",
        json!({ "id": 7, "head": 3, "tail": 3 }),
    )
    .await;
    let parsed = history_json(&served);
    assert_eq!(parsed["history"].as_array().unwrap().len(), 5);
    assert_eq!(
        parsed["truncation"],
        json!({ "omitted_entries": 0, "shown_entries": 5 })
    );
}

#[tokio::test]
async fn bug_history_windows_after_the_i14_scrub() {
    // Ordering pin: the window closes over the SCRUBBED list. Entry two
    // names only the policy-hidden bug 666, so I14 drops it BEFORE
    // head=2 applies — it must not consume a window slot, and the hidden
    // id must never appear. Ran the other way, head=2 would keep entry
    // two and the scrub would leave a single-entry window.
    let mock = MockServer::start().await;
    mount_bug_and_padding(&mock, world_readable_bug(7)).await;
    Mock::given(method("GET"))
        .and(path("/rest/bug/7/history"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "bugs": [{ "id": 7, "history": [
                {
                    "when": "2020-01-01T00:00:00Z",
                    "who": "dev@example.org",
                    "changes": [
                        { "field_name": "status", "removed": "NEW", "added": "CONFIRMED" },
                    ],
                },
                {
                    "when": "2020-01-02T00:00:00Z",
                    "who": "dev@example.org",
                    "changes": [
                        { "field_name": "depends_on", "removed": "", "added": "666" },
                    ],
                },
                {
                    "when": "2020-01-03T00:00:00Z",
                    "who": "dev@example.org",
                    "changes": [
                        { "field_name": "status", "removed": "CONFIRMED", "added": "RESOLVED" },
                    ],
                },
            ] }]
        })))
        .mount(&mock)
        .await;
    // The linked-id classify fetch answers empty: 666 is not disclosable
    // (I4), so the scrub drops the entry that names it.
    Mock::given(method("GET"))
        .and(path("/rest/bug"))
        .and(query_param("id", "666"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "bugs": [] })))
        .mount(&mock)
        .await;
    let client = client_for(
        concat!(
            "[[rule]]\nname = \"hide-secret\"\naction = \"deny\"\n",
            "[rule.match]\nproducts = [\"Secret*\"]\n",
        ),
        &mock,
    )
    .await;

    let served = call(&client, "bug_history", json!({ "id": 7, "head": 2 })).await;
    assert!(
        !is_error(&served),
        "the history is served: {}",
        text_of(&served)
    );
    let text = text_of(&served);
    assert!(
        !text.contains("666"),
        "the hidden id must never reach the client (I14): {text}"
    );
    let parsed: Value = serde_json::from_str(&text).expect("bug_history returns JSON");
    let shown = parsed["history"].as_array().expect("windowed envelope");
    assert_eq!(
        shown.len(),
        2,
        "the scrubbed-out entry consumed no window slot: {parsed}"
    );
    assert_eq!(shown[0]["when"], json!("2020-01-01T00:00:00Z"));
    assert_eq!(shown[1]["when"], json!("2020-01-03T00:00:00Z"));
    assert_eq!(
        parsed["truncation"],
        json!({ "omitted_entries": 0, "shown_entries": 2 }),
        "the window omitted nothing — the scrub, not the window, dropped \
         the entry: {parsed}"
    );
}

#[tokio::test]
async fn bug_history_window_params_leave_the_denial_untouched_i2() {
    // deny_unless returns before the window code reads head/tail, so a
    // denied bug answers with the uniform text and no envelope however the
    // call is windowed. Pinned because hoisting the envelope around the
    // whole handler would make a denied bug distinguishable from a
    // nonexistent one (I2) — the truncation block alone is the tell.
    let mock = MockServer::start().await;
    mount_bug_and_padding(&mock, world_readable_bug(7)).await;
    Mock::given(method("GET"))
        .and(path("/rest/bug/7/history"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "bugs": [{ "id": 7, "history": five_history_entries() }]
        })))
        .expect(0)
        .mount(&mock)
        .await;
    let client = client_for(
        concat!(
            "[[rule]]\nname = \"hide-kernel\"\naction = \"deny\"\n",
            "[rule.match]\ncomponents = [\"Kernel\"]\n",
        ),
        &mock,
    )
    .await;

    let plain = call(&client, "bug_history", json!({ "id": 7 })).await;
    assert!(is_error(&plain));
    assert_eq!(
        text_of(&plain),
        "Bug 7 is not accessible through this server"
    );

    for args in [
        json!({ "id": 7, "head": 2 }),
        json!({ "id": 7, "tail": 2 }),
        json!({ "id": 7, "head": 1, "tail": 1 }),
    ] {
        let windowed = call(&client, "bug_history", args.clone()).await;
        assert!(is_error(&windowed), "{args}");
        assert_eq!(
            text_of(&windowed),
            text_of(&plain),
            "a windowed denial must be byte-identical to the plain one: {args}"
        );
    }
}

/// A carve-out granting a WRITE capability on the caller's own reports.
/// [`IDENTITY_POLICY`] cannot exercise the write gate: its grant carries
/// no write capabilities, so a write tool refuses even the caller's own
/// bug under it — correctly, but uninformatively for threading coverage.
const IDENTITY_WRITE_POLICY: &str = concat!(
    "[[rule]]\nname = \"my-own-reports\"\naction = \"restrict\"\n",
    "capabilities = [\"read\", \"comment\"]\n",
    "operations = [\"access\"]\n",
    "[rule.match]\ncreated_by_me = true\n",
    "[[rule]]\nname = \"group-restricted\"\naction = \"deny\"\n",
    "[rule.match]\ngroup_restricted = true\n",
);

#[tokio::test]
async fn created_by_me_reaches_the_write_gate_add_comment_too() {
    // The write tools thread the caller through the same deny_unless shape
    // as the read tools; pin one representative so a dropped caller on a
    // write site cannot pass unnoticed. Own bug: the comment is POSTed.
    // Foreign bug: uniform denial, nothing POSTed.
    let mock = MockServer::start().await;
    mount_whoami(&mock, "reporter@example.com", 2).await;
    mount_bug_and_padding(&mock, restricted_bug(7, "reporter@example.com")).await;
    mount_bug_and_padding(&mock, restricted_bug(8, "other.person@example.com")).await;
    Mock::given(method("POST"))
        .and(path("/rest/bug/7/comment"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "id": 99 })))
        .expect(1)
        .mount(&mock)
        .await;
    Mock::given(method("POST"))
        .and(path("/rest/bug/8/comment"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "id": 100 })))
        .expect(0)
        .mount(&mock)
        .await;
    let client = client_for(IDENTITY_WRITE_POLICY, &mock).await;

    let own = call(
        &client,
        "add_comment",
        json!({ "bug_id": 7, "comment": "adding context" }),
    )
    .await;
    assert!(
        !is_error(&own),
        "the caller may comment on their own report: {}",
        text_of(&own)
    );

    let foreign = call(
        &client,
        "add_comment",
        json!({ "bug_id": 8, "comment": "adding context" }),
    )
    .await;
    assert!(is_error(&foreign));
    assert_eq!(
        text_of(&foreign),
        "Bug 8 is not accessible through this server",
        "someone else's restricted bug takes the uniform denial (I2)"
    );
}

#[tokio::test]
async fn whoami_transport_error_does_not_leak_the_api_key_i12() {
    // Point the server at an address the wiremock pool can never occupy:
    // the whoami lookup (and everything after it) fails at the transport
    // level, where the unsanitized error would carry the request URL with
    // api_key=... in it. Nothing the client sees may contain the key.
    let base = refused::refused_base_url();

    let cfg: Arc<Cli> = Arc::new(pinned(&[
        "bugwarden",
        "--bugzilla-server",
        &base,
        "--transport",
        "stdio",
        "--api-key",
        "SUPERSECRETKEY123",
    ]));
    let guard = Arc::new(Guard {
        policy: Policy::from_toml_str(IDENTITY_POLICY).expect("test policy must parse"),
    });
    let bz = Arc::new(BugzillaClient::new(&base, false, USER_AGENT).expect("client must build"));
    let server = BugWarden::new(cfg, guard, bz).expect("server must build");
    let (client_io, server_io) = tokio::io::duplex(1 << 16);
    tokio::spawn(async move {
        if let Ok(running) = server.serve(server_io).await {
            let _ = running.waiting().await;
        }
    });
    let client: RunningService<RoleClient, ()> = bounded("the MCP handshake", ().serve(client_io))
        .await
        .expect("MCP handshake must succeed");

    let result = tokio::time::timeout(
        common::REFUSED_CONNECT_BUDGET,
        call(&client, "bug_info", json!({ "bug_ids": [7] })),
    )
    .await
    .expect("connect to the refused privileged port must not hang");
    let text = serde_json::to_string(&result).unwrap();
    assert!(
        !text.contains("SUPERSECRETKEY123"),
        "API key leaked into a client-visible result: {text}"
    );
    // The bug is simply unavailable — the uniform denial, nothing else.
    let envelope: Value = serde_json::from_str(&text_of(&result)).expect("JSON");
    assert_eq!(
        envelope["restricted"][0]["note"],
        json!("Bug 7 is not accessible through this server")
    );
}

/// Discovery is off unless the operator opts in.
const DISCOVERY_POLICY: &str = "[global]\nallow_discovery = true\n";

#[tokio::test]
async fn bugzilla_products_catalog_is_id_name_pairs_only() {
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/product_enterable"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "ids": [1, 2] })))
        .mount(&mock)
        .await;
    Mock::given(method("GET"))
        .and(path("/rest/product"))
        .and(query_param("ids", "1"))
        .and(query_param("ids", "2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "products": [
                { "id": 1, "name": "TestProduct", "description": "hidden from the catalog" },
                { "id": 2, "name": "OtherProduct" },
            ]
        })))
        .mount(&mock)
        .await;
    let client = client_for(DISCOVERY_POLICY, &mock).await;

    let result = call(&client, "bugzilla_products", json!({})).await;
    assert!(!is_error(&result), "{}", text_of(&result));
    let envelope: Value = serde_json::from_str(&text_of(&result)).expect("JSON");
    assert_eq!(
        envelope["products"],
        json!([
            { "id": 1, "name": "TestProduct" },
            { "id": 2, "name": "OtherProduct" },
        ])
    );
}

#[tokio::test]
async fn bugzilla_products_detail_strips_account_fields() {
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/product"))
        .and(query_param("names", "TestProduct"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "products": [{
                "id": 1,
                "name": "TestProduct",
                "description": "A test product.",
                "is_active": true,
                "default_milestone": "---",
                "has_unconfirmed": true,
                "components": [{
                    "name": "core",
                    "description": "Core component",
                    "is_active": true,
                    "default_assigned_to": "admin@bugzilla.org",
                    "default_qa_contact": "qa@bugzilla.org",
                }],
                "versions": [{ "name": "1.0", "is_active": true }],
                "milestones": [{ "name": "---", "is_active": true }],
            }]
        })))
        .mount(&mock)
        .await;
    let client = client_for(DISCOVERY_POLICY, &mock).await;

    let result = call(
        &client,
        "bugzilla_products",
        json!({ "products": ["TestProduct"] }),
    )
    .await;
    assert!(!is_error(&result), "{}", text_of(&result));
    let text = text_of(&result);
    assert!(
        !text.contains("default_assigned_to") && !text.contains("default_qa_contact"),
        "account emails must never appear in the response: {text}"
    );
    let envelope: Value = serde_json::from_str(&text).expect("JSON");
    assert_eq!(
        envelope["products"][0],
        json!({
            "name": "TestProduct",
            "description": "A test product.",
            "is_active": true,
            "default_milestone": "---",
            "has_unconfirmed": true,
            "components": [{ "name": "core", "description": "Core component", "is_active": true }],
            "versions": [{ "name": "1.0", "is_active": true }],
            "milestones": [{ "name": "---", "is_active": true }],
        })
    );
}

#[tokio::test]
async fn bugzilla_products_over_cap_makes_no_upstream_request() {
    let mock = MockServer::start().await;
    let client = client_for(DISCOVERY_POLICY, &mock).await;
    let result = call(
        &client,
        "bugzilla_products",
        json!({ "products": ["a", "b", "c", "d", "e", "f"] }),
    )
    .await;
    assert!(is_error(&result));
    assert_eq!(text_of(&result), "At most 5 products per call");
    assert!(
        mock.received_requests().await.unwrap().is_empty(),
        "the cap refusal must make zero upstream requests"
    );
}

#[tokio::test]
async fn bug_fields_catalog_carries_no_values() {
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/field/bug"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "fields": [{
                "id": 13,
                "name": "priority",
                "display_name": "Priority",
                "type": 2,
                "is_custom": false,
                "is_mandatory": false,
                "is_on_bug_entry": false,
                "visibility_field": null,
                "visibility_values": [],
                "values": [{ "name": "P1" }, { "name": "P2" }],
            }]
        })))
        .mount(&mock)
        .await;
    let client = client_for(DISCOVERY_POLICY, &mock).await;

    let result = call(&client, "bug_fields", json!({})).await;
    assert!(!is_error(&result), "{}", text_of(&result));
    let text = text_of(&result);
    assert!(
        !text.contains("\"values\""),
        "catalog must carry no values: {text}"
    );
    let envelope: Value = serde_json::from_str(&text).expect("JSON");
    assert_eq!(
        envelope["fields"][0],
        json!({
            "name": "priority",
            "display_name": "Priority",
            "type": 2,
            "is_custom": false,
            "is_mandatory": false,
            "is_on_bug_entry": false,
            "visibility_field": null,
            "visibility_values": [],
            "has_values": true,
        })
    );
}

#[tokio::test]
async fn bug_fields_catalog_can_be_filtered_to_bug_entry_fields() {
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/field/bug"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "fields": [
                { "name": "priority", "is_on_bug_entry": false },
                { "name": "cf_severity_extra", "is_on_bug_entry": true },
            ]
        })))
        .mount(&mock)
        .await;
    let client = client_for(DISCOVERY_POLICY, &mock).await;

    let result = call(&client, "bug_fields", json!({ "on_bug_entry_only": true })).await;
    assert!(!is_error(&result), "{}", text_of(&result));
    let envelope: Value = serde_json::from_str(&text_of(&result)).expect("JSON");
    let names: Vec<&str> = envelope["fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, vec!["cf_severity_extra"]);
}

#[tokio::test]
async fn bug_fields_detail_reports_workflow_data_when_upstream_carries_it() {
    // bug_status carries is_open/can_change_to; a plain field's values stay
    // {name}-only even when fetched through the same detail path.
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/field/bug/bug_status"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "fields": [{
                "name": "bug_status",
                "display_name": "Status",
                "is_custom": false,
                "is_mandatory": false,
                "is_on_bug_entry": false,
                "values": [
                    {
                        "name": "NEW",
                        "is_open": true,
                        "can_change_to": [
                            { "name": "ASSIGNED", "comment_required": false },
                            { "name": "RESOLVED", "comment_required": true },
                        ],
                    },
                    { "name": "RESOLVED", "is_open": false, "can_change_to": [] },
                ],
            }]
        })))
        .mount(&mock)
        .await;
    Mock::given(method("GET"))
        .and(path("/rest/field/bug/priority"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "fields": [{
                "name": "priority",
                "display_name": "Priority",
                "is_custom": false,
                "is_mandatory": false,
                "is_on_bug_entry": false,
                "values": [{ "name": "P1" }, { "name": "P2" }],
            }]
        })))
        .mount(&mock)
        .await;
    let client = client_for(DISCOVERY_POLICY, &mock).await;

    let result = call(
        &client,
        "bug_fields",
        json!({ "field_names": ["bug_status"] }),
    )
    .await;
    assert!(!is_error(&result), "{}", text_of(&result));
    let envelope: Value = serde_json::from_str(&text_of(&result)).expect("JSON");
    assert_eq!(
        envelope["fields"][0]["values"],
        json!([
            {
                "name": "NEW",
                "is_open": true,
                "can_change_to": [
                    { "name": "ASSIGNED", "comment_required": false },
                    { "name": "RESOLVED", "comment_required": true },
                ],
            },
            { "name": "RESOLVED", "is_open": false, "can_change_to": [] },
        ])
    );

    let result = call(
        &client,
        "bug_fields",
        json!({ "field_names": ["priority"] }),
    )
    .await;
    assert!(!is_error(&result), "{}", text_of(&result));
    let envelope: Value = serde_json::from_str(&text_of(&result)).expect("JSON");
    assert_eq!(
        envelope["fields"][0]["values"],
        json!([{ "name": "P1" }, { "name": "P2" }])
    );
}

#[tokio::test]
async fn bug_fields_over_cap_makes_no_upstream_request() {
    let mock = MockServer::start().await;
    let client = client_for(DISCOVERY_POLICY, &mock).await;
    let result = call(
        &client,
        "bug_fields",
        json!({ "field_names": ["a", "b", "c", "d", "e", "f"] }),
    )
    .await;
    assert!(is_error(&result));
    assert_eq!(text_of(&result), "At most 5 field names per call");
    assert!(
        mock.received_requests().await.unwrap().is_empty(),
        "the cap refusal must make zero upstream requests"
    );
}

#[tokio::test]
async fn bug_fields_a_dot_segment_name_fails_the_call_without_a_request() {
    // Sent, `..` vanishes from the URL and the catalog's first field comes
    // back as the detail of a field that does not exist.
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/field/bug"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "fields": [{ "name": "priority", "values": [{ "name": "P1" }] }]
        })))
        .mount(&mock)
        .await;
    let client = client_for(DISCOVERY_POLICY, &mock).await;
    let result = call(&client, "bug_fields", json!({ "field_names": [".."] })).await;
    assert!(is_error(&result), "{}", text_of(&result));
    assert!(
        text_of(&result).starts_with("Failed to fetch bug fields\n"),
        "the generic call-level failure: {}",
        text_of(&result)
    );
    assert!(
        mock.received_requests().await.unwrap().is_empty(),
        "the refused name must make zero upstream requests"
    );
}

#[tokio::test]
async fn discovery_tools_absent_from_the_listing_by_default() {
    let mock = MockServer::start().await;
    let client = client_for("", &mock).await;
    let tools = bounded("tools/list", client.list_all_tools())
        .await
        .expect("list_tools must succeed");
    let names: Vec<&str> = tools.iter().map(|t| t.name.as_ref()).collect();
    assert!(!names.contains(&"bugzilla_products"));
    assert!(!names.contains(&"bug_fields"));

    let client = client_for(DISCOVERY_POLICY, &mock).await;
    let tools = bounded("tools/list", client.list_all_tools())
        .await
        .expect("list_tools must succeed");
    let names: Vec<&str> = tools.iter().map(|t| t.name.as_ref()).collect();
    assert!(names.contains(&"bugzilla_products"));
    assert!(names.contains(&"bug_fields"));
}

/// A world-readable bug carrying the duplicated `*_detail` account fields.
fn detailed_bug(id: u64) -> Value {
    let mut bug = world_readable_bug(id);
    bug["assigned_to"] = json!("dev@example.com");
    bug["assigned_to_detail"] = json!({
        "id": 5, "email": "dev@example.com", "name": "dev@example.com",
        "real_name": "Dev",
    });
    bug["cc"] = json!(["watcher@example.com"]);
    bug["cc_detail"] = json!([{
        "id": 6, "email": "watcher@example.com", "name": "watcher@example.com",
        "real_name": "Watcher",
    }]);
    bug
}

#[tokio::test]
async fn bug_info_detail_false_strips_only_detail_fields() {
    let mock = MockServer::start().await;
    mount_bug_and_padding(&mock, detailed_bug(7)).await;
    let client = client_for("", &mock).await;

    let full = call(&client, "bug_info", json!({ "bug_ids": [7] })).await;
    let full: Value = serde_json::from_str(&text_of(&full)).expect("bug_info returns JSON");
    assert!(
        full["bugs"][0].get("assigned_to_detail").is_some(),
        "the default view keeps the detail fields"
    );

    let lean = call(
        &client,
        "bug_info",
        json!({ "bug_ids": [7], "detail": false }),
    )
    .await;
    assert!(!is_error(&lean), "{}", text_of(&lean));
    let lean: Value = serde_json::from_str(&text_of(&lean)).expect("bug_info returns JSON");
    let bug = lean["bugs"][0].as_object().expect("bug object");
    assert_eq!(bug.get("assigned_to"), Some(&json!("dev@example.com")));
    let leaked: Vec<&String> = bug.keys().filter(|k| k.ends_with("_detail")).collect();
    assert!(
        leaked.is_empty(),
        "detail=false must drop every *_detail field: {leaked:?}"
    );
}

#[tokio::test]
async fn bug_info_include_fields_projects_and_always_keeps_id() {
    let mock = MockServer::start().await;
    mount_bug_and_padding(&mock, detailed_bug(7)).await;
    let client = client_for("", &mock).await;

    let projected = call(
        &client,
        "bug_info",
        json!({ "bug_ids": [7], "include_fields": "summary, product" }),
    )
    .await;
    let projected: Value =
        serde_json::from_str(&text_of(&projected)).expect("bug_info returns JSON");
    let keys: Vec<&String> = projected["bugs"][0]
        .as_object()
        .expect("bug object")
        .keys()
        .collect();
    assert_eq!(
        keys,
        vec!["id", "product", "summary"],
        "exactly the requested fields plus the forced id: {keys:?}"
    );
}

#[tokio::test]
async fn bug_info_include_fields_preserves_the_redacted_marker() {
    // A summary-only grant projected by include_fields must still carry
    // `_redacted` — dropping the marker would misrepresent the grant.
    let policy = concat!(
        "[[rule]]\nname = \"summary-only\"\naction = \"restrict\"\n",
        "capabilities = [\"summary\"]\n",
        "[rule.match]\nproducts = [\"openSUSE\"]\n",
    );
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/bug"))
        .and(query_param("id", "7"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({ "bugs": [detailed_bug(7)] })),
        )
        .mount(&mock)
        .await;
    Mock::given(method("GET"))
        .and(path("/rest/bug"))
        .and(query_param("id", "0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "bugs": [] })))
        .mount(&mock)
        .await;
    let client = client_for(policy, &mock).await;

    let result = call(
        &client,
        "bug_info",
        json!({ "bug_ids": [7], "include_fields": "summary" }),
    )
    .await;
    let result: Value = serde_json::from_str(&text_of(&result)).expect("bug_info returns JSON");
    assert_eq!(result["bugs"][0]["_redacted"], json!(true));
    assert_eq!(result["bugs"][0]["summary"], json!("a plain bug"));
    assert!(
        result["bugs"][0].get("product").is_none(),
        "a field outside the projection stays out even in a summary view"
    );
}

#[tokio::test]
async fn bug_info_include_fields_and_detail_are_mutually_exclusive() {
    let mock = MockServer::start().await;
    // The request is invalid on its own key names, so it must be refused
    // before any upstream traffic.
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "bugs": [] })))
        .expect(0)
        .mount(&mock)
        .await;
    let client = client_for("", &mock).await;

    let result = call(
        &client,
        "bug_info",
        json!({ "bug_ids": [7], "include_fields": "id,summary", "detail": false }),
    )
    .await;
    assert!(is_error(&result), "both projections set must be an error");
    assert!(
        text_of(&result).contains("mutually exclusive"),
        "the refusal must say why: {}",
        text_of(&result)
    );
}

#[tokio::test]
async fn bug_info_projection_drops_link_fields_before_the_disclosure_fetch() {
    // A link field the projection drops is never served, so it must never
    // be assessed either: bug 9 is named only by blocks, and blocks is not
    // in the projection — no request for 9 may leave the server.
    let mut bug = detailed_bug(7);
    bug["blocks"] = json!([9]);
    let mock = MockServer::start().await;
    mount_bug_and_padding(&mock, bug).await;
    Mock::given(method("GET"))
        .and(path("/rest/bug"))
        .and(query_param("id", "9"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({ "bugs": [world_readable_bug(9)] })),
        )
        .expect(0)
        .mount(&mock)
        .await;
    let client = client_for("", &mock).await;

    let projected = call(
        &client,
        "bug_info",
        json!({ "bug_ids": [7], "include_fields": "id,summary" }),
    )
    .await;
    let projected: Value =
        serde_json::from_str(&text_of(&projected)).expect("bug_info returns JSON");
    assert!(
        projected["bugs"][0].get("blocks").is_none(),
        "a link field outside the projection is simply absent"
    );
}

#[tokio::test]
async fn bug_info_projected_link_fields_are_still_scrubbed() {
    // The contrast case: a link field that IS projected in goes through
    // I14 scrubbing exactly as before — bug 9 is policy-hidden upstream
    // (absent from its classify response), so it must not be named.
    let mut bug = detailed_bug(7);
    bug["blocks"] = json!([9]);
    let mock = MockServer::start().await;
    mount_bug_and_padding(&mock, bug).await;
    Mock::given(method("GET"))
        .and(path("/rest/bug"))
        .and(query_param("id", "9"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "bugs": [] })))
        .expect(1)
        .mount(&mock)
        .await;
    let client = client_for("", &mock).await;

    let projected = call(
        &client,
        "bug_info",
        json!({ "bug_ids": [7], "include_fields": "id,blocks" }),
    )
    .await;
    let projected: Value =
        serde_json::from_str(&text_of(&projected)).expect("bug_info returns JSON");
    assert_eq!(
        projected["bugs"][0]["blocks"],
        json!([]),
        "a hidden linked bug is scrubbed out of the projected field (I14)"
    );
}

#[tokio::test]
async fn bug_info_scalar_link_fields_are_scrubbed_like_arrays() {
    // I14 defence in depth: the REST API documents every LINKED_ID_FIELDS
    // slot as an id ARRAY, but an instance answering with a BARE id must not
    // hand that id to the client. Every field at once and looped over the
    // constant, so one added to it later is covered here too.
    for (slot, linked, expected) in [
        (json!(9), vec![], Value::Null),
        (json!(9), vec![world_readable_bug(9)], json!(9)),
        (json!("9"), vec![world_readable_bug(9)], Value::Null),
    ] {
        let mut bug = detailed_bug(7);
        for field in Guard::LINKED_ID_FIELDS {
            bug[*field] = slot.clone();
        }
        let mock = MockServer::start().await;
        mount_bug_and_padding(&mock, bug).await;
        Mock::given(method("GET"))
            .and(path("/rest/bug"))
            .and(query_param("id", "9"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "bugs": linked })))
            .mount(&mock)
            .await;
        let client = client_for("", &mock).await;

        let served = call(&client, "bug_info", json!({ "bug_ids": [7] })).await;
        assert!(!is_error(&served), "bug_info failed: {}", text_of(&served));
        let served: Value = serde_json::from_str(&text_of(&served)).expect("bug_info returns JSON");
        for field in Guard::LINKED_ID_FIELDS {
            assert_eq!(
                served["bugs"][0][*field], expected,
                "a bare {slot} in {field} must be served as {expected} (I14)"
            );
        }
    }
}

#[tokio::test]
async fn bug_info_projection_never_changes_a_restricted_entry() {
    // A denied id produces the uniform restricted entry regardless of
    // projection params (I2) — the projection loop must not touch it.
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/bug"))
        .and(query_param("id", "8"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "bugs": [] })))
        .mount(&mock)
        .await;
    Mock::given(method("GET"))
        .and(path("/rest/bug"))
        .and(query_param("id", "0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "bugs": [] })))
        .mount(&mock)
        .await;
    let client = client_for("", &mock).await;

    let mut restricted: Vec<String> = Vec::new();
    for args in [
        json!({ "bug_ids": [8] }),
        json!({ "bug_ids": [8], "detail": false }),
        json!({ "bug_ids": [8], "include_fields": "id,summary" }),
    ] {
        let result = call(&client, "bug_info", args).await;
        let result: Value = serde_json::from_str(&text_of(&result)).expect("bug_info returns JSON");
        assert!(result["bugs"].as_array().expect("bugs").is_empty());
        restricted.push(result["restricted"].to_string());
    }
    assert!(
        restricted.windows(2).all(|w| w[0] == w[1]),
        "the restricted entry is byte-identical across projections: {restricted:?}"
    );
}

/// Six public comments for bug 7, ids 1..=6, text "comment N".
fn six_comments() -> Vec<Value> {
    (1..=6)
        .map(|i| {
            json!({ "id": i, "bug_id": 7, "is_private": false, "text": format!("comment {i}") })
        })
        .collect()
}

/// Serve `comments` from bug 7's comment endpoint (unbounded).
async fn mount_comments(mock: &MockServer, comments: Vec<Value>) {
    Mock::given(method("GET"))
        .and(path("/rest/bug/7/comment"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "bugs": { "7": { "comments": comments } }
        })))
        .mount(mock)
        .await;
}

/// The `comments` array of a windowed bug_comments envelope.
fn windowed_ids(result: &Value) -> Vec<u64> {
    result["comments"]
        .as_array()
        .expect("envelope carries a comments array")
        .iter()
        .filter_map(|c| c["id"].as_u64())
        .collect()
}

#[tokio::test]
async fn bug_comments_without_windowing_params_stays_a_bare_array() {
    let mock = MockServer::start().await;
    mount_bug_and_padding(&mock, world_readable_bug(7)).await;
    mount_comments(&mock, six_comments()).await;
    let client = client_for("", &mock).await;

    let result = call(&client, "bug_comments", json!({ "id": 7 })).await;
    let parsed: Value = serde_json::from_str(&text_of(&result)).expect("bug_comments returns JSON");
    assert!(
        parsed.is_array(),
        "no windowing params: the response stays the bare array it always was"
    );
    assert_eq!(parsed.as_array().unwrap().len(), 6);
}

#[tokio::test]
async fn bug_comments_head_tail_windows_out_the_middle() {
    let mock = MockServer::start().await;
    mount_bug_and_padding(&mock, world_readable_bug(7)).await;
    mount_comments(&mock, six_comments()).await;
    let client = client_for("", &mock).await;

    let result = call(
        &client,
        "bug_comments",
        json!({ "id": 7, "head": 1, "tail": 2 }),
    )
    .await;
    let parsed: Value = serde_json::from_str(&text_of(&result)).expect("bug_comments returns JSON");
    assert_eq!(
        windowed_ids(&parsed),
        vec![1, 5, 6],
        "first 1 + last 2, middle omitted"
    );
    assert_eq!(
        parsed["truncation"],
        json!({ "omitted_comments": 3, "shown_comments": 3 })
    );
}

#[tokio::test]
async fn bug_comments_tail_only_keeps_the_end() {
    let mock = MockServer::start().await;
    mount_bug_and_padding(&mock, world_readable_bug(7)).await;
    mount_comments(&mock, six_comments()).await;
    let client = client_for("", &mock).await;

    let result = call(&client, "bug_comments", json!({ "id": 7, "tail": 2 })).await;
    let parsed: Value = serde_json::from_str(&text_of(&result)).expect("bug_comments returns JSON");
    assert_eq!(windowed_ids(&parsed), vec![5, 6]);
    assert_eq!(
        parsed["truncation"],
        json!({ "omitted_comments": 4, "shown_comments": 2 })
    );
}

#[tokio::test]
async fn bug_comments_window_overlap_omits_nothing() {
    // head + tail >= len: no window closes, and the envelope still reports
    // a zero-omission truncation block (deterministic shape per signature).
    let mock = MockServer::start().await;
    mount_bug_and_padding(&mock, world_readable_bug(7)).await;
    mount_comments(&mock, six_comments()).await;
    let client = client_for("", &mock).await;

    let result = call(
        &client,
        "bug_comments",
        json!({ "id": 7, "head": 4, "tail": 4 }),
    )
    .await;
    let parsed: Value = serde_json::from_str(&text_of(&result)).expect("bug_comments returns JSON");
    assert_eq!(windowed_ids(&parsed), vec![1, 2, 3, 4, 5, 6]);
    assert_eq!(
        parsed["truncation"],
        json!({ "omitted_comments": 0, "shown_comments": 6 })
    );
}

#[tokio::test]
async fn bug_comments_window_counts_only_post_filter_comments() {
    // I5: the middle comment is private and the policy never serves private
    // content (allow_private_comments defaults to false). The window runs
    // on the post-filter list: shown 1, omitted 1 — the raw total (3) must
    // never appear, or private-comment existence leaks by arithmetic.
    let comments = vec![
        json!({ "id": 1, "bug_id": 7, "is_private": false, "text": "first public" }),
        json!({ "id": 2, "bug_id": 7, "is_private": true, "text": "canary-private-3f9d" }),
        json!({ "id": 3, "bug_id": 7, "is_private": false, "text": "last public" }),
    ];
    let mock = MockServer::start().await;
    mount_bug_and_padding(&mock, world_readable_bug(7)).await;
    mount_comments(&mock, comments).await;
    let client = client_for("", &mock).await;

    let result = call(&client, "bug_comments", json!({ "id": 7, "tail": 1 })).await;
    let text = text_of(&result);
    assert!(
        !text.contains("canary-private-3f9d"),
        "private stays out (I5)"
    );
    let parsed: Value = serde_json::from_str(&text).expect("bug_comments returns JSON");
    assert_eq!(windowed_ids(&parsed), vec![3]);
    assert_eq!(
        parsed["truncation"],
        json!({ "omitted_comments": 1, "shown_comments": 1 }),
        "counts are computed after the private filter, never from the raw list"
    );
}

#[tokio::test]
async fn bug_comments_window_runs_after_duplicate_marker_scrubbing() {
    // I14 ordering: a duplicate marker naming a policy-hidden bug is
    // scrubbed BEFORE the window closes — it must not consume a window
    // slot, and the hidden id must not appear anywhere in the response.
    let policy = concat!(
        "[[rule]]\nname = \"hide-secret\"\naction = \"deny\"\n",
        "[rule.match]\nproducts = [\"Secret*\"]\n",
    );
    let comments = vec![
        json!({ "id": 1, "bug_id": 7, "is_private": false,
                "text": "*** Bug 666 has been marked as a duplicate of this bug ***" }),
        json!({ "id": 2, "bug_id": 7, "is_private": false, "text": "the real answer" }),
    ];
    let mock = MockServer::start().await;
    mount_bug_and_padding(&mock, world_readable_bug(7)).await;
    // The disclosure assessment for 666: absent from the response, which is
    // indistinguishable from policy-hidden — not disclosable either way (I4).
    Mock::given(method("GET"))
        .and(path("/rest/bug"))
        .and(query_param("id", "666"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "bugs": [] })))
        .expect(1)
        .mount(&mock)
        .await;
    mount_comments(&mock, comments).await;
    let client = client_for(policy, &mock).await;

    let result = call(&client, "bug_comments", json!({ "id": 7, "tail": 1 })).await;
    let text = text_of(&result);
    assert!(!text.contains("666"), "the hidden id never appears (I14)");
    let parsed: Value = serde_json::from_str(&text).expect("bug_comments returns JSON");
    assert_eq!(
        windowed_ids(&parsed),
        vec![2],
        "the scrubbed marker did not consume the window slot"
    );
    assert_eq!(
        parsed["truncation"],
        json!({ "omitted_comments": 0, "shown_comments": 1 })
    );
}

#[tokio::test]
async fn bug_comments_max_comment_chars_caps_and_marks() {
    let long = "a".repeat(300);
    let multibyte = "日本語".repeat(40); // 120 chars, 360 bytes
    let comments = vec![
        json!({ "id": 1, "bug_id": 7, "is_private": false, "text": long }),
        json!({ "id": 2, "bug_id": 7, "is_private": false, "text": multibyte }),
        json!({ "id": 3, "bug_id": 7, "is_private": false, "text": "short" }),
    ];
    let mock = MockServer::start().await;
    mount_bug_and_padding(&mock, world_readable_bug(7)).await;
    mount_comments(&mock, comments).await;
    let client = client_for("", &mock).await;

    let result = call(
        &client,
        "bug_comments",
        json!({ "id": 7, "max_comment_chars": 100 }),
    )
    .await;
    let parsed: Value = serde_json::from_str(&text_of(&result)).expect("bug_comments returns JSON");
    let comments = parsed["comments"].as_array().expect("comments array");

    let first = &comments[0];
    assert_eq!(first["text"].as_str().unwrap().chars().count(), 100);
    assert_eq!(
        first["text_truncated"],
        json!({ "shown_chars": 100, "total_chars": 300 })
    );

    let second = &comments[1];
    // Chars, not bytes: the multibyte cap lands on a char boundary and
    // carries the true character count.
    assert_eq!(second["text"].as_str().unwrap().chars().count(), 100);
    assert_eq!(
        second["text_truncated"],
        json!({ "shown_chars": 100, "total_chars": 120 })
    );

    let third = &comments[2];
    assert_eq!(third["text"], json!("short"));
    assert!(
        third.get("text_truncated").is_none(),
        "an uncapped comment carries no marker"
    );
    assert_eq!(
        parsed["truncation"],
        json!({ "omitted_comments": 0, "shown_comments": 3 })
    );
}

// ---------- upstream failures of the write tools ----------

/// The upstream message every refusal below carries: it names a bug and
/// holds a forged logfmt pair, neither of which may reach a client.
const UPSTREAM_MESSAGE: &str = "Bug 424242 does not exist. status=HACKED";

/// The 109 hint, the one every bug-update tool may carry at any reach.
const PRODUCT_EDIT_DENIED: &str =
    "The Bugzilla account in use may not edit bugs in this bug's product.";

/// A Bugzilla error envelope under `status`, with `code` when given.
fn bugzilla_refusal(status: u16, code: Option<i64>) -> ResponseTemplate {
    let mut body = json!({ "error": true, "message": UPSTREAM_MESSAGE });
    if let Some(code) = code {
        body["code"] = json!(code);
    }
    ResponseTemplate::new(status).set_body_json(body)
}

/// Serve `tool` with `args` against world-readable bugs 7 and 8, with
/// Bugzilla answering the write with `response`; returns the failure text.
/// The write mock expects exactly one request, so the text under test is
/// the answer to an upstream refusal and never a local gate's.
async fn refused_write(tool: &str, args: Value, response: ResponseTemplate) -> String {
    let mock = MockServer::start().await;
    // A write carrying custom_fields first learns their kinds; answering
    // free text lets the request under test reach Bugzilla's refusal.
    Mock::given(method("GET"))
        .and(path("/rest/field/bug"))
        .respond_with(|req: &wiremock::Request| {
            let fields: Vec<Value> = req
                .url
                .query_pairs()
                .filter(|(k, _)| k == "names")
                .map(|(_, name)| json!({ "name": name, "type": 1 }))
                .collect();
            ResponseTemplate::new(200).set_body_json(json!({ "fields": fields }))
        })
        .mount(&mock)
        .await;
    for id in [7u64, 8] {
        Mock::given(method("GET"))
            .and(path("/rest/bug"))
            .and(query_param("id", id.to_string()))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({ "bugs": [world_readable_bug(id)] })),
            )
            .mount(&mock)
            .await;
    }
    let (http_method, route) = if tool == "add_comment" {
        ("POST", "/rest/bug/7/comment")
    } else {
        ("PUT", "/rest/bug/7")
    };
    Mock::given(method(http_method))
        .and(path(route))
        .respond_with(response)
        .expect(1)
        .mount(&mock)
        .await;
    let client = client_for("", &mock).await;
    let result = call(&client, tool, args).await;
    assert!(is_error(&result), "{tool} must fail: {}", text_of(&result));
    text_of(&result)
}

fn comment_args() -> Value {
    json!({ "bug_id": 7, "comment": "hi" })
}

fn deps_args() -> Value {
    json!({ "bug_id": 7, "depends_on_add": [8] })
}

#[tokio::test]
async fn write_tools_answer_a_refusal_with_their_line_and_a_hint_never_bugzillas_text() {
    let rows = [
        (
            "add_comment",
            comment_args(),
            114,
            "Failed to create a comment",
            "The comment is longer than Bugzilla accepts; shorten or split it.",
        ),
        (
            "update_bug_status",
            json!({ "bug_id": 7, "status": "CLOSED" }),
            121,
            "Failed to update bug status",
            "Closing this bug needs a resolution.",
        ),
        (
            "assign_bug",
            json!({ "bug_id": 7, "assignee": "nobody@example.com" }),
            504,
            "Failed to assign bug",
            "Bugzilla did not accept this assignee: the login is unknown or may not be assigned bugs in this product.",
        ),
        (
            "update_bug_fields",
            json!({ "bug_id": 7, "priority": "P9" }),
            51,
            "Failed to update bug fields",
            "Bugzilla does not know one of the values given (priority, severity, version, target milestone or keyword); bug_fields and bugzilla_products list the legal values where discovery is enabled.",
        ),
        (
            "update_bug_dependencies",
            deps_args(),
            109,
            "Failed to update bug dependencies",
            PRODUCT_EDIT_DENIED,
        ),
        (
            "add_cc_to_bug",
            json!({ "bug_id": 7, "cc_email": "nobody@example.com" }),
            51,
            "Failed to add CC",
            "Bugzilla did not accept this CC address: the login is unknown or may not be added in this product.",
        ),
        (
            "mark_as_duplicate",
            json!({ "bug_id": 7, "duplicate_of": 8 }),
            109,
            "Failed to mark as duplicate",
            PRODUCT_EDIT_DENIED,
        ),
    ];
    for (tool, args, code, line, hint) in rows {
        let text = refused_write(tool, args, bugzilla_refusal(400, Some(code))).await;
        assert_eq!(text, format!("{line}\n{hint}"), "{tool} with code {code}");
        assert!(
            !text.contains("424242")
                && !text.contains("HACKED")
                && !text.contains("bugzilla error"),
            "{tool}: upstream text reached the client: {text}"
        );
    }
}

#[tokio::test]
async fn withheld_codes_give_exactly_the_line() {
    // The existence oracle, the loop codes, the unlisted-error fallbacks
    // and an authentication code: no hint, and no shared "withheld" line.
    for code in [100, 101, 102, 116, 118, 32000, -32000, 306] {
        let text = refused_write(
            "add_comment",
            comment_args(),
            bugzilla_refusal(400, Some(code)),
        )
        .await;
        assert_eq!(text, "Failed to create a comment", "code {code}");
    }
    // The scenario that opened this: a dependency loop whose message
    // names a bug the client was never shown.
    let loop_text = refused_write(
        "update_bug_dependencies",
        deps_args(),
        ResponseTemplate::new(400).set_body_json(json!({
            "error": true,
            "code": 116,
            "message": "The following bugs are involved in the dependency loop: 666, 7, 8",
        })),
    )
    .await;
    assert_eq!(loop_text, "Failed to update bug dependencies");
}

#[tokio::test]
async fn the_hint_lookup_is_keyed_on_the_tool() {
    // 114 is hinted on add_comment and 123 on update_bug_status; neither
    // row may answer for another tool.
    let text = refused_write(
        "add_cc_to_bug",
        json!({ "bug_id": 7, "cc_email": "nobody@example.com" }),
        bugzilla_refusal(400, Some(114)),
    )
    .await;
    assert_eq!(text, "Failed to add CC");
    let text = refused_write(
        "add_comment",
        comment_args(),
        bugzilla_refusal(400, Some(123)),
    )
    .await;
    assert_eq!(text, "Failed to create a comment");
}

#[tokio::test]
async fn the_http_status_never_selects_a_hint() {
    // The same code under three statuses is the same bytes ...
    let mut texts = Vec::new();
    for status in [200, 400, 500] {
        texts.push(
            refused_write(
                "add_comment",
                comment_args(),
                bugzilla_refusal(status, Some(114)),
            )
            .await,
        );
    }
    assert_eq!(
        texts[0],
        "Failed to create a comment\nThe comment is longer than Bugzilla accepts; shorten or split it."
    );
    assert!(
        texts.iter().all(|t| t == &texts[0]),
        "the status must not change the text: {texts:?}"
    );
    // ... and the statuses Bugzilla's REST layer gives the existence
    // oracle, with or without a code, select nothing.
    for (status, code) in [
        (404, Some(101)),
        (401, Some(102)),
        (401, None),
        (404, None),
        (500, None),
    ] {
        let text = refused_write(
            "add_comment",
            comment_args(),
            bugzilla_refusal(status, code),
        )
        .await;
        assert_eq!(text, "Failed to create a comment", "{status} {code:?}");
    }
    let html = refused_write(
        "add_comment",
        comment_args(),
        ResponseTemplate::new(502).set_body_string("<html>gateway</html>"),
    )
    .await;
    assert_eq!(html, "Failed to create a comment");
}

#[tokio::test]
async fn an_unassessed_request_gets_no_hint_but_the_product_one() {
    // Dependencies are always Unassessed: the comment-too-long and
    // illegal-change codes the Assessed tools hint stay bare here.
    for code in [114, 115] {
        let text = refused_write(
            "update_bug_dependencies",
            deps_args(),
            bugzilla_refusal(400, Some(code)),
        )
        .await;
        assert_eq!(text, "Failed to update bug dependencies", "code {code}");
    }
    // A status change with a resolution is Unassessed; without one, or
    // with an empty one (never sent), it is Assessed and 123 is hinted.
    let transition = "Failed to update bug status\nBugzilla does not allow this status change from the bug's current status: its workflow forbids the transition, or the account in use may not make it.";
    let text = refused_write(
        "update_bug_status",
        json!({ "bug_id": 7, "status": "RESOLVED", "resolution": "FIXED" }),
        bugzilla_refusal(400, Some(123)),
    )
    .await;
    assert_eq!(text, "Failed to update bug status");
    for args in [
        json!({ "bug_id": 7, "status": "RESOLVED" }),
        json!({ "bug_id": 7, "status": "RESOLVED", "resolution": "" }),
    ] {
        let text = refused_write("update_bug_status", args, bugzilla_refusal(400, Some(123))).await;
        assert_eq!(text, transition);
    }
    // Fields: a custom field or a resolution makes the request Unassessed,
    // see_also makes it Unhintable; the summary alone keeps it Assessed.
    let empty_summary = "Failed to update bug fields\nThe summary is empty once Bugzilla trims it.";
    for args in [
        json!({ "bug_id": 7, "summary": " ", "see_also_add": ["https://tracker.example/1"] }),
        json!({ "bug_id": 7, "summary": " ", "custom_fields": { "cf_fixed_in": "x" } }),
        json!({ "bug_id": 7, "summary": " ", "resolution": "FIXED" }),
    ] {
        let text = refused_write("update_bug_fields", args, bugzilla_refusal(400, Some(107))).await;
        assert_eq!(text, "Failed to update bug fields");
    }
    let text = refused_write(
        "update_bug_fields",
        json!({ "bug_id": 7, "summary": " " }),
        bugzilla_refusal(400, Some(107)),
    )
    .await;
    assert_eq!(text, empty_summary);
    // 109 is hinted at any reach: a custom-field request still gets it.
    let text = refused_write(
        "update_bug_fields",
        json!({ "bug_id": 7, "custom_fields": { "cf_fixed_in": "x" } }),
        bugzilla_refusal(401, Some(109)),
    )
    .await;
    assert_eq!(
        text,
        format!("Failed to update bug fields\n{PRODUCT_EDIT_DENIED}")
    );
    // A see_also link is Unhintable: even 109 stays bare, because BMO
    // checks a local target's product with that very code.
    let text = refused_write(
        "update_bug_fields",
        json!({
            "bug_id": 7,
            "see_also_add": ["https://bugzilla.other.example/show_bug.cgi?id=5"],
        }),
        bugzilla_refusal(401, Some(109)),
    )
    .await;
    assert_eq!(text, "Failed to update bug fields");
    // A duplicate is always Unassessed.
    let text = refused_write(
        "mark_as_duplicate",
        json!({ "bug_id": 7, "duplicate_of": 8 }),
        bugzilla_refusal(400, Some(114)),
    )
    .await;
    assert_eq!(text, "Failed to mark as duplicate");
}

// ---------- Bug ID custom fields (I14 on bodies) ----------

/// Mount `GET /rest/field/bug` expecting it never to be hit: a served body
/// is judged by JSON type and must not trigger a field-type lookup.
async fn mount_no_field_lookup(mock: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/rest/field/bug"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "fields": [] })))
        .expect(0)
        .mount(mock)
        .await;
}

#[tokio::test]
async fn bug_info_scrubs_a_bug_id_custom_field_naming_a_hidden_bug() {
    // A "Bug ID" custom field is a link like depends_on. Stock Bugzilla
    // renders exactly that custom type as a JSON number and every other one
    // as a string (or a string list), so a body is judged by JSON type: the
    // hidden 9 is blanked, the visible 8 is kept, a digit string stays text,
    // and no field-type lookup is made for a body.
    let mock = MockServer::start().await;
    let mut linked = world_readable_bug(7);
    linked["cf_regression_of"] = json!(9);
    linked["cf_fixed_by"] = json!(8);
    linked["cf_related"] = json!([8, 9, "n/a"]);
    linked["cf_build"] = json!("9");
    mount_bug_and_padding(&mock, linked).await;
    let mut secret = world_readable_bug(9);
    secret["product"] = json!("SecretSauce");
    Mock::given(method("GET"))
        .and(path("/rest/bug"))
        .and(query_param("id", "8,9"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "bugs": [world_readable_bug(8), secret]
        })))
        .expect(1)
        .mount(&mock)
        .await;
    mount_no_field_lookup(&mock).await;
    let client = client_for(HIDE_SECRET_POLICY, &mock).await;

    let served = call(&client, "bug_info", json!({ "bug_ids": [7] })).await;
    assert!(!is_error(&served), "bug 7 is served: {}", text_of(&served));
    let parsed: Value = serde_json::from_str(&text_of(&served)).expect("bug_info returns JSON");
    let bug = &parsed["bugs"][0];
    assert_eq!(bug["id"], json!(7));
    assert_eq!(
        bug["cf_regression_of"],
        Value::Null,
        "a hidden bug id in a custom field is blanked (I14): {bug}"
    );
    assert_eq!(bug["cf_fixed_by"], json!(8), "a disclosable one is kept");
    assert_eq!(
        bug["cf_related"],
        json!([8, "n/a"]),
        "hidden number items go, string items stay"
    );
    assert_eq!(
        bug["cf_build"],
        json!("9"),
        "a digit string is text, not a link"
    );
}

#[tokio::test]
async fn quicksearch_projected_bug_id_custom_field_is_scrubbed() {
    // The client picks the projection, so it can ask for a Bug ID custom
    // field and read hidden ids out of a search wholesale. The projected
    // body takes the same JSON-type rule as bug_info, again with no
    // field-type lookup.
    let mock = MockServer::start().await;
    let mut secret = world_readable_bug(9);
    secret["product"] = json!("SecretSauce");
    Mock::given(method("GET"))
        .and(path("/rest/bug"))
        .and(query_param("id", "9"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "bugs": [secret] })))
        .expect(1)
        .mount(&mock)
        .await;
    mount_no_field_lookup(&mock).await;
    let mut linked = world_readable_bug(101);
    linked["cf_regression_of"] = json!(9);
    mount_search(&mock, vec![linked]).await;
    let client = client_for(HIDE_SECRET_POLICY, &mock).await;

    let served = quicksearch_json_args(
        &client,
        json!({ "query": "kernel", "include_fields": "id,cf_regression_of" }),
    )
    .await;
    let bug = &served["bugs"][0];
    assert_eq!(bug["id"], json!(101));
    assert!(
        bug.as_object()
            .is_some_and(|o| o.contains_key("cf_regression_of")),
        "the projected field is still present: {served}"
    );
    assert_eq!(
        bug["cf_regression_of"],
        Value::Null,
        "the hidden id is blanked from the projection (I14): {served}"
    );
}

// ---------- Bug ID custom fields (I14 on history) ----------

/// Mount `GET /rest/field/bug` answering like stock Bugzilla's `Bug.fields`:
/// every requested name in `table` with its type code, or 404 / code 51 for
/// the whole request on the first name it does not know.
async fn mount_field_types(mock: &MockServer, table: &[(&'static str, u64)]) {
    let table: Vec<(&'static str, u64)> = table.to_vec();
    Mock::given(method("GET"))
        .and(path("/rest/field/bug"))
        .respond_with(move |req: &wiremock::Request| {
            let mut fields = Vec::new();
            for (_, name) in req.url.query_pairs().filter(|(k, _)| k == "names") {
                match table.iter().find(|(n, _)| *n == name) {
                    Some((n, t)) => fields.push(json!({ "name": n, "type": t })),
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
        })
        .mount(mock)
        .await;
}

/// The `names` each `/rest/field/bug` request asked for, in arrival order.
async fn field_lookups(mock: &MockServer) -> Vec<Vec<String>> {
    mock.received_requests()
        .await
        .expect("wiremock records requests by default")
        .iter()
        .filter(|r| r.url.path() == "/rest/field/bug")
        .map(|r| {
            r.url
                .query_pairs()
                .filter(|(k, _)| k == "names")
                .map(|(_, v)| v.into_owned())
                .collect()
        })
        .collect()
}

/// Mount bug 7's classify fetch, a world-readable bug 8, a policy-hidden
/// bug 9 (disclosure fetches for `9` alone and for `8,9`), and a history of
/// bug 7 holding `changes`.
async fn mount_history_naming_hidden_9(mock: &MockServer, changes: Value) {
    mount_bug_and_padding(mock, world_readable_bug(7)).await;
    let mut secret = world_readable_bug(9);
    secret["product"] = json!("SecretSauce");
    Mock::given(method("GET"))
        .and(path("/rest/bug"))
        .and(query_param("id", "9"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "bugs": [secret.clone()] })))
        .mount(mock)
        .await;
    Mock::given(method("GET"))
        .and(path("/rest/bug"))
        .and(query_param("id", "8,9"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "bugs": [world_readable_bug(8), secret]
        })))
        .mount(mock)
        .await;
    Mock::given(method("GET"))
        .and(path("/rest/bug/7/history"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "bugs": [{ "id": 7, "history": [{
                "when": "2020-01-01T00:00:00Z",
                "who": "dev@example.org",
                "changes": changes,
            }] }]
        })))
        .mount(mock)
        .await;
}

#[tokio::test]
async fn bug_history_scrubs_a_bug_id_custom_field_change_and_keeps_other_kinds() {
    // A change to a Bug ID custom field names another bug exactly as a
    // depends_on change does. The field's kind is learned by name: the
    // type-6 change naming the hidden 9 is dropped and the one naming the
    // visible 8 kept, the same "9" under a free-text field is kept, and the
    // lookup asks for exactly the cf_ names the history carries.
    let mock = MockServer::start().await;
    mount_history_naming_hidden_9(
        &mock,
        json!([
            { "field_name": "cf_regression_of", "removed": "", "added": "9" },
            { "field_name": "cf_regression_of", "removed": "9", "added": "8" },
            { "field_name": "cf_build", "removed": "", "added": "9" },
            { "field_name": "status", "removed": "NEW", "added": "CONFIRMED" },
        ]),
    )
    .await;
    mount_field_types(&mock, &[("cf_regression_of", 6), ("cf_build", 1)]).await;
    let client = client_for(HIDE_SECRET_POLICY, &mock).await;

    let served = call(&client, "bug_history", json!({ "id": 7 })).await;
    assert!(
        !is_error(&served),
        "the history is served: {}",
        text_of(&served)
    );
    assert_eq!(
        history_json(&served)[0]["changes"],
        json!([
            { "field_name": "cf_regression_of", "removed": "", "added": "8" },
            { "field_name": "cf_build", "removed": "", "added": "9" },
            { "field_name": "status", "removed": "NEW", "added": "CONFIRMED" },
        ]),
        "the Bug ID change naming only the hidden bug is dropped, the one \
         naming the visible bug is edited down to it, and the free-text \
         digits are kept (I14)"
    );
    let mut asked = field_lookups(&mock).await;
    assert_eq!(asked.len(), 1, "one lookup for the whole history");
    asked[0].sort();
    assert_eq!(
        asked[0],
        vec!["cf_build".to_string(), "cf_regression_of".to_string()],
        "exactly the history's cf_ names are looked up"
    );
}

#[tokio::test]
async fn bug_history_fails_closed_when_the_type_lookup_fails() {
    // With every kind unknown, a cf_ value that is all digits is judged as
    // a bug id — scrubbed unless disclosable — and free text is kept
    // verbatim: an unanswered lookup narrows what is served, never widens.
    let mock = MockServer::start().await;
    mount_history_naming_hidden_9(
        &mock,
        json!([
            { "field_name": "cf_regression_of", "removed": "", "added": "9" },
            { "field_name": "cf_build", "removed": "", "added": "9" },
            { "field_name": "cf_notes", "removed": "", "added": "fixed in 9" },
        ]),
    )
    .await;
    Mock::given(method("GET"))
        .and(path("/rest/field/bug"))
        .respond_with(ResponseTemplate::new(500))
        .expect(1)
        .mount(&mock)
        .await;
    let client = client_for(HIDE_SECRET_POLICY, &mock).await;

    let served = call(&client, "bug_history", json!({ "id": 7 })).await;
    assert!(
        !is_error(&served),
        "a failed lookup does not fail the call: {}",
        text_of(&served)
    );
    assert_eq!(
        history_json(&served)[0]["changes"],
        json!([
            { "field_name": "cf_notes", "removed": "", "added": "fixed in 9" },
        ]),
        "both digit values are scrubbed and the free text kept (I4)"
    );
}

#[tokio::test]
async fn bug_history_without_custom_field_changes_makes_no_lookup() {
    let mock = MockServer::start().await;
    mount_history_window_fixture(&mock, five_history_entries()).await;
    mount_no_field_lookup(&mock).await;
    let client = client_for("", &mock).await;

    let served = call(&client, "bug_history", json!({ "id": 7 })).await;
    assert!(!is_error(&served), "{}", text_of(&served));
    assert_eq!(history_json(&served).as_array().map(Vec::len), Some(5));
}

#[tokio::test]
async fn bug_history_looks_a_custom_field_up_once_per_process() {
    // A field's kind is instance schema: the first history naming it pays
    // the lookup, the next is answered from the cache.
    let mock = MockServer::start().await;
    mount_history_window_fixture(
        &mock,
        json!([{
            "when": "2020-01-01T00:00:00Z",
            "who": "dev@example.org",
            "changes": [
                { "field_name": "cf_build", "removed": "", "added": "20200101" },
            ],
        }]),
    )
    .await;
    Mock::given(method("GET"))
        .and(path("/rest/field/bug"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "fields": [{ "name": "cf_build", "type": 1 }]
        })))
        .expect(1)
        .mount(&mock)
        .await;
    let client = client_for("", &mock).await;

    for _ in 0..2 {
        let served = call(&client, "bug_history", json!({ "id": 7 })).await;
        assert!(!is_error(&served), "{}", text_of(&served));
        assert_eq!(
            history_json(&served)[0]["changes"][0]["added"],
            json!("20200101"),
            "a free-text field's digits are not a bug id once its kind is known"
        );
    }
    assert_eq!(field_lookups(&mock).await.len(), 1);
}

// ---------- Bug ID custom fields (I8 on writes) ----------

/// The fixed refusal for a custom field value the guard cannot judge.
fn unassessable_refusal(field: &str) -> String {
    format!(
        "Custom field '{field}' may hold a bug id: give a numeric bug id, or an empty value \
         to clear it"
    )
}

/// Mount the world-readable bug 7, the policy-hidden bug 999, and a PUT on
/// bug 7 expected `puts` times.
async fn mount_update_target(mock: &MockServer, puts: u64) {
    mount_bug_and_padding(mock, world_readable_bug(7)).await;
    let mut secret = world_readable_bug(999);
    secret["product"] = json!("SecretSauce");
    Mock::given(method("GET"))
        .and(path("/rest/bug"))
        .and(query_param("id", "999"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "bugs": [secret] })))
        .mount(mock)
        .await;
    Mock::given(method("PUT"))
        .and(path("/rest/bug/7"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "bugs": [{ "id": 7 }] })))
        .expect(puts)
        .mount(mock)
        .await;
}

/// The `id` of every classify fetch (`GET /rest/bug?id=..`) wiremock saw.
async fn classified_ids(mock: &MockServer) -> Vec<String> {
    mock.received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| r.method == "GET" && r.url.path() == "/rest/bug")
        .flat_map(|r| {
            r.url
                .query_pairs()
                .filter(|(k, _)| k == "id")
                .map(|(_, v)| v.into_owned())
                .collect::<Vec<_>>()
        })
        .collect()
}

#[tokio::test]
async fn update_fields_bug_id_custom_field_targets_respect_the_guard() {
    // The issue's scenario: a Bug ID custom field is a link like see_also,
    // so its target takes the Summary bar (I8/I14) and a hidden one draws
    // the uniform denial (I2) with nothing PUT — in every spelling Bugzilla
    // resolves to the same bug.
    let mock = MockServer::start().await;
    mount_update_target(&mock, 0).await;
    mount_field_types(&mock, &[("cf_regression_of", 6)]).await;
    let client = client_for(HIDE_SECRET_POLICY, &mock).await;

    for value in [json!(999), json!("#999"), json!(" 999 ")] {
        let result = call(
            &client,
            "update_bug_fields",
            json!({ "bug_id": 7, "custom_fields": { "cf_regression_of": value } }),
        )
        .await;
        assert!(is_error(&result), "{value}");
        assert_eq!(
            text_of(&result),
            "Bug 999 is not accessible through this server",
            "a hidden Bug ID custom field target takes the uniform denial: {value}"
        );
    }
}

#[tokio::test]
async fn update_fields_unassessable_bug_id_custom_field_value_is_refused() {
    // Bugzilla resolves anything that is not an id as an alias, and an
    // object by its id: the guard cannot judge those, so it refuses with a
    // fixed text after the type lookup and before any classification.
    let mock = MockServer::start().await;
    mount_update_target(&mock, 0).await;
    mount_field_types(&mock, &[("cf_regression_of", 6)]).await;
    let client = client_for(HIDE_SECRET_POLICY, &mock).await;

    let values = [
        json!("CVE-x"),
        json!(999.0),
        json!({ "id": 999 }),
        json!([999]),
        json!(true),
    ];
    for value in &values {
        let result = call(
            &client,
            "update_bug_fields",
            json!({ "bug_id": 7, "custom_fields": { "cf_regression_of": value } }),
        )
        .await;
        assert!(is_error(&result), "{value}");
        assert_eq!(
            text_of(&result),
            unassessable_refusal("cf_regression_of"),
            "{value}"
        );
    }
    let paths: Vec<String> = mock
        .received_requests()
        .await
        .unwrap()
        .iter()
        .map(|r| r.url.path().to_string())
        .collect();
    let per_call: Vec<String> = (0..values.len())
        .flat_map(|_| ["/rest/field/bug".to_string(), "/rest/bug".to_string()])
        .collect();
    assert_eq!(
        paths, per_call,
        "each call costs the lookup and the bug's own check, and nothing is PUT"
    );
}

#[tokio::test]
async fn update_fields_custom_field_refusal_never_precedes_the_bugs_own_denial() {
    // The fixed refusal names a field's kind, so it must come after the
    // named bug's own check: against a hidden bug every probe — a field
    // Bugzilla does not know, a free-text field, a numeric value — draws
    // the uniform denial (I2), with the bug classified all the same and
    // nothing PUT. Issued first, the refusal would be a field-name and
    // field-kind oracle open to a caller with no access at all.
    let mock = MockServer::start().await;
    let mut secret = world_readable_bug(999);
    secret["product"] = json!("SecretSauce");
    Mock::given(method("GET"))
        .and(path("/rest/bug"))
        .and(query_param("id", "999"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "bugs": [secret] })))
        .mount(&mock)
        .await;
    Mock::given(method("GET"))
        .and(path("/rest/bug"))
        .and(query_param("id", "8"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({ "bugs": [world_readable_bug(8)] })),
        )
        .mount(&mock)
        .await;
    Mock::given(method("PUT"))
        .and(path("/rest/bug/999"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "bugs": [{ "id": 999 }] })))
        .expect(0)
        .mount(&mock)
        .await;
    mount_field_types(&mock, &[("cf_foundby", 1)]).await;
    let client = client_for(HIDE_SECRET_POLICY, &mock).await;

    for (fields, classified) in [
        (json!({ "cf_bogus": "x" }), 1),
        (json!({ "cf_foundby": "x" }), 1),
        (json!({ "cf_foundby": 8 }), 1),
        (json!({ "cf_bogus": 8 }), 2),
    ] {
        let before = mock.received_requests().await.unwrap().len();
        let result = call(
            &client,
            "update_bug_fields",
            json!({ "bug_id": 999, "custom_fields": fields }),
        )
        .await;
        assert!(is_error(&result), "{fields}");
        assert_eq!(
            text_of(&result),
            "Bug 999 is not accessible through this server",
            "the bug's uniform denial wins over any custom field verdict: {fields}"
        );
        let paths: Vec<String> = mock.received_requests().await.unwrap()[before..]
            .iter()
            .map(|r| r.url.path().to_string())
            .collect();
        let mut expected = vec!["/rest/field/bug".to_string()];
        expected.extend(vec!["/rest/bug".to_string(); classified]);
        assert_eq!(
            paths, expected,
            "the lookup, then the bug and every target classified: {fields}"
        );
    }
}

#[tokio::test]
async fn update_fields_non_link_custom_field_is_not_assessed() {
    // A field Bugzilla reports as some other type never names a bug: its
    // value is not classified, whatever digits it holds, and reaches the PUT.
    let mock = MockServer::start().await;
    mount_bug_and_padding(&mock, world_readable_bug(7)).await;
    Mock::given(method("GET"))
        .and(path("/rest/bug"))
        .and(query_param("id", "999"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "bugs": [] })))
        .expect(0)
        .mount(&mock)
        .await;
    Mock::given(method("PUT"))
        .and(path("/rest/bug/7"))
        .and(body_partial_json(json!({ "cf_build": 999 })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "bugs": [{ "id": 7 }] })))
        .expect(1)
        .mount(&mock)
        .await;
    mount_field_types(&mock, &[("cf_build", 1)]).await;
    let client = client_for(HIDE_SECRET_POLICY, &mock).await;

    let result = call(
        &client,
        "update_bug_fields",
        json!({ "bug_id": 7, "custom_fields": { "cf_build": 999 } }),
    )
    .await;
    assert!(!is_error(&result), "{}", text_of(&result));
}

#[tokio::test]
async fn update_fields_fails_closed_when_the_type_lookup_fails() {
    // With the kinds unknown every custom field may hold a bug id: a numeric
    // value is assessed as one, and text — which Bugzilla would resolve as
    // an alias — is refused. Nothing is PUT either way.
    let mock = MockServer::start().await;
    mount_update_target(&mock, 0).await;
    Mock::given(method("GET"))
        .and(path("/rest/field/bug"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&mock)
        .await;
    let client = client_for(HIDE_SECRET_POLICY, &mock).await;

    let numeric = call(
        &client,
        "update_bug_fields",
        json!({ "bug_id": 7, "custom_fields": { "cf_build": 999 } }),
    )
    .await;
    assert!(is_error(&numeric));
    assert_eq!(
        text_of(&numeric),
        "Bug 999 is not accessible through this server",
        "a numeric value is assessed as a bug id when the kind is unknown"
    );
    let text = call(
        &client,
        "update_bug_fields",
        json!({ "bug_id": 7, "custom_fields": { "cf_notes": "fixed" } }),
    )
    .await;
    assert!(is_error(&text));
    assert_eq!(
        text_of(&text),
        unassessable_refusal("cf_notes"),
        "text is refused when the kind is unknown"
    );
}

#[tokio::test]
async fn update_fields_fails_closed_when_bugzilla_does_not_know_a_name() {
    // One name Bugzilla does not know fails the whole lookup (404, code
    // 51), so every key of that write reads Unknown, the real free-text
    // field included: a numeric value is assessed as a bug id and text is
    // refused — naming the first field in key order it could not judge,
    // which here is the legitimate one — both after the bug's own check
    // and with nothing PUT.
    let mock = MockServer::start().await;
    mount_update_target(&mock, 0).await;
    Mock::given(method("GET"))
        .and(path("/rest/bug"))
        .and(query_param("id", "8"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({ "bugs": [world_readable_bug(8)] })),
        )
        .mount(&mock)
        .await;
    mount_field_types(&mock, &[("cf_build", 1)]).await;
    let client = client_for(HIDE_SECRET_POLICY, &mock).await;

    let numeric = call(
        &client,
        "update_bug_fields",
        json!({ "bug_id": 7, "custom_fields": { "cf_build": 999, "cf_zz": 8 } }),
    )
    .await;
    assert!(is_error(&numeric));
    assert_eq!(
        text_of(&numeric),
        "Bug 999 is not accessible through this server",
        "the free-text field's number is assessed once its kind is unknown"
    );
    let text = call(
        &client,
        "update_bug_fields",
        json!({ "bug_id": 7, "custom_fields": { "cf_build": "fixed", "cf_zz": "x" } }),
    )
    .await;
    assert!(is_error(&text));
    assert_eq!(
        text_of(&text),
        unassessable_refusal("cf_build"),
        "the refusal names the first field it could not judge, not the bogus one"
    );
    let paths: Vec<String> = mock
        .received_requests()
        .await
        .unwrap()
        .iter()
        .map(|r| r.url.path().to_string())
        .collect();
    assert_eq!(
        paths,
        [
            "/rest/field/bug",
            "/rest/bug",
            "/rest/bug",
            "/rest/bug",
            "/rest/field/bug",
            "/rest/bug"
        ]
        .map(String::from),
        "a lookup, then bug 7, 8 and 999 classified; a lookup, then bug 7 classified"
    );
}

#[tokio::test]
async fn update_fields_clearing_a_bug_id_custom_field_assesses_nothing() {
    // null, "" and 0 are how Bugzilla clears the field: no target, so only
    // the bug itself is classified and the PUT carries the clear.
    let mock = MockServer::start().await;
    mount_update_target(&mock, 3).await;
    mount_field_types(&mock, &[("cf_regression_of", 6)]).await;
    let client = client_for(HIDE_SECRET_POLICY, &mock).await;

    for value in [json!(null), json!(""), json!(0)] {
        let result = call(
            &client,
            "update_bug_fields",
            json!({ "bug_id": 7, "custom_fields": { "cf_regression_of": value } }),
        )
        .await;
        assert!(!is_error(&result), "{value}: {}", text_of(&result));
    }
    let ids = classified_ids(&mock).await;
    assert_eq!(
        ids,
        vec!["7".to_string(); 3],
        "only the bug itself is classified"
    );
}

#[tokio::test]
async fn update_fields_without_custom_fields_makes_no_lookup() {
    let mock = MockServer::start().await;
    mount_update_target(&mock, 1).await;
    mount_no_field_lookup(&mock).await;
    let client = client_for(HIDE_SECRET_POLICY, &mock).await;

    let result = call(
        &client,
        "update_bug_fields",
        json!({ "bug_id": 7, "priority": "P1" }),
    )
    .await;
    assert!(!is_error(&result), "{}", text_of(&result));
}

#[tokio::test]
async fn update_fields_looks_custom_field_kinds_up_afresh_on_every_write() {
    // A write judges the field as it is now, never as an earlier call saw
    // it: two writes, two lookups.
    let mock = MockServer::start().await;
    mount_update_target(&mock, 2).await;
    mount_field_types(&mock, &[("cf_build", 1)]).await;
    let client = client_for(HIDE_SECRET_POLICY, &mock).await;

    for _ in 0..2 {
        let result = call(
            &client,
            "update_bug_fields",
            json!({ "bug_id": 7, "custom_fields": { "cf_build": "1" } }),
        )
        .await;
        assert!(!is_error(&result), "{}", text_of(&result));
    }
    assert_eq!(field_lookups(&mock).await.len(), 2);
}

#[tokio::test]
async fn custom_field_targets_count_toward_the_id_cap_at_zero_requests() {
    // The cap is judged on every custom field value that could name a bug,
    // before any lookup, so both refusals are decided from the request
    // alone and contact Bugzilla not at all.
    let mock = MockServer::start().await;
    let client = client_for("", &mock).await;

    let see_also: Vec<String> = (101..=124)
        .map(|id| format!("{}/show_bug.cgi?id={id}", mock.uri()))
        .collect();
    let update = call(
        &client,
        "update_bug_fields",
        json!({
            "bug_id": 7,
            "see_also_add": see_also,
            "custom_fields": { "cf_regression_of": "999" },
        }),
    )
    .await;
    assert!(is_error(&update));
    assert_eq!(
        text_of(&update),
        "At most 25 bug ids may be named in one call, got 26",
        "bug 7, 24 see_also targets and the custom field value are 26"
    );

    let mut args = create_args("openSUSE");
    let links: serde_json::Map<String, Value> = (1..=26)
        .map(|i| (format!("cf_link{i}"), json!(i)))
        .collect();
    args["custom_fields"] = Value::Object(links);
    let create = call(&client, "create_bug", args).await;
    assert!(is_error(&create));
    assert_eq!(
        text_of(&create),
        "At most 25 bug ids may be named in one call, got 26"
    );
    assert!(
        mock.received_requests().await.unwrap().is_empty(),
        "both refusals cost zero requests"
    );
}

/// Mount the create refusal's padding classify against bug id 0, expected
/// `hits` times.
async fn mount_pad(mock: &MockServer, hits: u64) {
    Mock::given(method("GET"))
        .and(path("/rest/bug"))
        .and(query_param("id", "0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "bugs": [] })))
        .expect(hits)
        .mount(mock)
        .await;
}

/// Mount `POST /rest/bug` answering `status` with `body`, expected `hits`
/// times.
async fn mount_post(mock: &MockServer, status: u16, body: Value, hits: u64) {
    Mock::given(method("POST"))
        .and(path("/rest/bug"))
        .respond_with(ResponseTemplate::new(status).set_body_json(body))
        .expect(hits)
        .mount(mock)
        .await;
}

#[tokio::test]
async fn create_bug_bug_id_custom_field_refusals_are_one_refusal() {
    // Four ways a create carrying a Bug ID custom field is refused — the
    // policy withholds the product, the target is hidden, Bugzilla rejects
    // the POST, a value is unassessable beside a visible target — all give
    // CREATE_DENIAL after the same three requests: the type lookup, the
    // target classify, then the POST or the padding classify. The target is
    // classified even when the policy already refused, so neither text nor
    // count tells the legs apart.
    let types: &[(&str, u64)] = &[("cf_regression_of", 6), ("cf_alias", 6)];
    let bad_version = json!({
        "error": true,
        "message": "There is no version named '1.0' in the 'openSUSE' product."
    });

    // Leg 1: policy refusal, visible target — classified all the same.
    let leg1 = MockServer::start().await;
    mount_classify(&leg1, world_readable_bug(8)).await;
    mount_pad(&leg1, 1).await;
    mount_post(&leg1, 200, json!({ "id": 1 }), 0).await;
    mount_field_types(&leg1, types).await;
    let client = client_for(HIDE_SECRET_POLICY, &leg1).await;
    let mut args = create_args("SecretSauce");
    args["custom_fields"] = json!({ "cf_regression_of": 8 });
    let refused = call(&client, "create_bug", args).await;
    assert!(is_error(&refused));
    assert_eq!(text_of(&refused), CREATE_DENIAL);
    assert_eq!(leg1.received_requests().await.unwrap().len(), 3);

    // Leg 2: hidden target.
    let leg2 = MockServer::start().await;
    let mut secret = world_readable_bug(999);
    secret["product"] = json!("SecretSauce");
    mount_classify(&leg2, secret).await;
    mount_pad(&leg2, 1).await;
    mount_post(&leg2, 200, json!({ "id": 1 }), 0).await;
    mount_field_types(&leg2, types).await;
    let client = client_for(HIDE_SECRET_POLICY, &leg2).await;
    let mut args = create_args("openSUSE");
    args["custom_fields"] = json!({ "cf_regression_of": 999 });
    let refused = call(&client, "create_bug", args).await;
    assert!(is_error(&refused));
    assert_eq!(
        text_of(&refused),
        CREATE_DENIAL,
        "a hidden target is the create refusal, never the bug's own denial"
    );
    assert_eq!(leg2.received_requests().await.unwrap().len(), 3);

    // Leg 3: visible target, Bugzilla rejects the POST.
    let leg3 = MockServer::start().await;
    mount_classify(&leg3, world_readable_bug(8)).await;
    mount_pad(&leg3, 0).await;
    mount_post(&leg3, 400, bad_version, 1).await;
    mount_field_types(&leg3, types).await;
    let client = client_for(HIDE_SECRET_POLICY, &leg3).await;
    let mut args = create_args("openSUSE");
    args["custom_fields"] = json!({ "cf_regression_of": 8 });
    let refused = call(&client, "create_bug", args).await;
    assert!(is_error(&refused));
    assert_eq!(text_of(&refused), CREATE_DENIAL);
    assert_eq!(leg3.received_requests().await.unwrap().len(), 3);

    // Leg 4: an unassessable value beside a visible target.
    let leg4 = MockServer::start().await;
    mount_classify(&leg4, world_readable_bug(8)).await;
    mount_pad(&leg4, 1).await;
    mount_post(&leg4, 200, json!({ "id": 1 }), 0).await;
    mount_field_types(&leg4, types).await;
    let client = client_for(HIDE_SECRET_POLICY, &leg4).await;
    let mut args = create_args("openSUSE");
    args["custom_fields"] = json!({ "cf_regression_of": 8, "cf_alias": "CVE-x" });
    let refused = call(&client, "create_bug", args).await;
    assert!(is_error(&refused));
    assert_eq!(
        text_of(&refused),
        CREATE_DENIAL,
        "an unassessable value folds into the padded refusal on create"
    );
    assert_eq!(leg4.received_requests().await.unwrap().len(), 3);
}

#[tokio::test]
async fn create_bug_fails_closed_when_the_type_lookup_fails() {
    // With the kinds unknown a free-text custom field value is unassessable
    // and the filing is refused — the padded refusal, after the failed
    // lookup and the pad, with nothing POSTed.
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/field/bug"))
        .respond_with(ResponseTemplate::new(500))
        .expect(1)
        .mount(&mock)
        .await;
    mount_pad(&mock, 1).await;
    mount_post(&mock, 200, json!({ "id": 1 }), 0).await;
    let client = client_for("", &mock).await;

    let mut args = create_args("openSUSE");
    args["custom_fields"] = json!({ "cf_fixed_in": "1.2.3" });
    let refused = call(&client, "create_bug", args).await;
    assert!(is_error(&refused));
    assert_eq!(text_of(&refused), CREATE_DENIAL);
    assert_eq!(mock.received_requests().await.unwrap().len(), 2);
}

/// A policy that lets anyone file anywhere while existing group-restricted
/// bugs are readable only by their own reporter.
const FILE_ANYWHERE_OWN_REPORTS_POLICY: &str = concat!(
    "[[rule]]\nname = \"file-anywhere\"\naction = \"restrict\"\n",
    "capabilities = [\"create\"]\noperations = [\"create\"]\n",
    "[rule.match]\nproducts = [\"*\"]\n",
    "[[rule]]\nname = \"my-own-reports\"\naction = \"restrict\"\n",
    "capabilities = [\"read\"]\noperations = [\"access\"]\n",
    "[rule.match]\ncreated_by_me = true\n",
    "[[rule]]\nname = \"group-restricted\"\naction = \"deny\"\n",
    "[rule.match]\ngroup_restricted = true\n",
);

#[tokio::test]
async fn create_bug_assesses_a_custom_field_target_as_the_caller() {
    // The create gate never resolves the caller (it forces created_by_me
    // itself), but a link target is an existing bug the caller may see only
    // as their own report: one whoami for the targets, and the filing goes
    // through.
    let mock = MockServer::start().await;
    mount_whoami(&mock, "reporter@example.com", 1).await;
    mount_classify(&mock, restricted_bug(8, "reporter@example.com")).await;
    mount_field_types(&mock, &[("cf_regression_of", 6)]).await;
    Mock::given(method("POST"))
        .and(path("/rest/bug"))
        .and(body_partial_json(json!({ "cf_regression_of": 8 })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "id": 4245 })))
        .expect(1)
        .mount(&mock)
        .await;
    let client = client_for(FILE_ANYWHERE_OWN_REPORTS_POLICY, &mock).await;

    let mut args = create_args("openSUSE");
    args["custom_fields"] = json!({ "cf_regression_of": 8 });
    let result = call(&client, "create_bug", args).await;
    assert!(!is_error(&result), "{}", text_of(&result));
    assert!(text_of(&result).contains("4245"));
    assert_eq!(
        mock.received_requests().await.unwrap().len(),
        4,
        "the lookup, one whoami, the target classify and the POST"
    );
}

/// Mount `GET /rest/field/bug` answering type 1 (free text) for every name
/// asked, expected `hits` times.
async fn mount_free_text_fields(mock: &MockServer, hits: u64) {
    Mock::given(method("GET"))
        .and(path("/rest/field/bug"))
        .respond_with(|req: &wiremock::Request| {
            let fields: Vec<Value> = req
                .url
                .query_pairs()
                .filter(|(k, _)| k == "names")
                .map(|(_, name)| json!({ "name": name, "type": 1 }))
                .collect();
            ResponseTemplate::new(200).set_body_json(json!({ "fields": fields }))
        })
        .expect(hits)
        .mount(mock)
        .await;
}

/// `n` free-text custom fields, `cf_f00` onwards.
fn free_text_fields(n: usize) -> Value {
    Value::Object(
        (0..n)
            .map(|i| (format!("cf_f{i:02}"), json!("x")))
            .collect(),
    )
}

#[tokio::test]
async fn update_fields_caps_the_custom_field_count_at_one_lookup() {
    // Every key costs lookup work, so the count is capped at one lookup's
    // worth and refused at zero requests like the id cap: 51 keys never
    // reach Bugzilla, 50 cost exactly one lookup and reach the PUT.
    let mock = MockServer::start().await;
    mount_update_target(&mock, 1).await;
    mount_free_text_fields(&mock, 1).await;
    let client = client_for(HIDE_SECRET_POLICY, &mock).await;

    // Keys are counted, not values: a null value is still a key, and a
    // list value is still one key.
    let mut over = free_text_fields(51);
    over["cf_f00"] = Value::Null;
    let refused = call(
        &client,
        "update_bug_fields",
        json!({ "bug_id": 7, "custom_fields": over }),
    )
    .await;
    assert!(is_error(&refused));
    assert_eq!(
        text_of(&refused),
        "At most 50 custom fields may be set in one call, got 51"
    );
    assert!(
        mock.received_requests().await.unwrap().is_empty(),
        "the cap refuses before any request"
    );

    let mut at_cap = free_text_fields(50);
    at_cap["cf_f00"] = json!(["a", "b"]);
    let accepted = call(
        &client,
        "update_bug_fields",
        json!({ "bug_id": 7, "custom_fields": at_cap }),
    )
    .await;
    assert!(!is_error(&accepted), "{}", text_of(&accepted));
    assert_eq!(
        field_lookups(&mock).await.len(),
        1,
        "50 keys cost exactly one lookup"
    );
}

#[tokio::test]
async fn create_bug_caps_the_custom_field_count_at_one_lookup() {
    let mock = MockServer::start().await;
    mount_free_text_fields(&mock, 1).await;
    mount_post(&mock, 200, json!({ "id": 4247 }), 1).await;
    let client = client_for("", &mock).await;

    let mut args = create_args("openSUSE");
    let mut over = free_text_fields(51);
    over["cf_f00"] = Value::Null;
    args["custom_fields"] = over;
    let refused = call(&client, "create_bug", args).await;
    assert!(is_error(&refused));
    assert_eq!(
        text_of(&refused),
        "At most 50 custom fields may be set in one call, got 51"
    );
    assert!(
        mock.received_requests().await.unwrap().is_empty(),
        "the cap refuses before any request"
    );

    let mut args = create_args("openSUSE");
    let mut at_cap = free_text_fields(50);
    at_cap["cf_f00"] = json!(["a", "b"]);
    args["custom_fields"] = at_cap;
    let accepted = call(&client, "create_bug", args).await;
    assert!(!is_error(&accepted), "{}", text_of(&accepted));
    assert_eq!(
        field_lookups(&mock).await.len(),
        1,
        "50 keys cost exactly one lookup"
    );
}

#[tokio::test]
async fn create_bug_without_custom_fields_makes_no_whoami() {
    let mock = MockServer::start().await;
    mount_whoami(&mock, "reporter@example.com", 0).await;
    mount_no_field_lookup(&mock).await;
    mount_post(&mock, 200, json!({ "id": 4246 }), 1).await;
    let client = client_for(FILE_ANYWHERE_OWN_REPORTS_POLICY, &mock).await;

    let result = call(&client, "create_bug", create_args("openSUSE")).await;
    assert!(!is_error(&result), "{}", text_of(&result));
    assert_eq!(mock.received_requests().await.unwrap().len(), 1);
}
