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
//! - deleting the upload size-cap call from add_attachment;
//! - attaching the quicksearch id-list advisory only when the served `bugs`
//!   array is non-empty;
//! - suppressing the quicksearch id-list advisory when I14 link scrubbing
//!   removed anything.

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
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "bugs": rows })))
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
