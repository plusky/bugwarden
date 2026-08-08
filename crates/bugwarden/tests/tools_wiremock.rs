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
//! - dropping the local see_also targets from update_bug_fields' assessed
//!   id set (or lowering their Capability::Summary bar to nothing);
//! - attaching the quicksearch id-list advisory only when the served `bugs`
//!   array is non-empty;
//! - suppressing the quicksearch id-list advisory when I14 link scrubbing
//!   removed anything.

use std::sync::Arc;

use bugwarden::config::Cli;
use bugwarden::server::{BugWarden, USER_AGENT, WRITE_TOOLS};
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
    let mut cli = Cli::parse_from([
        "bugwarden",
        "--bugzilla-server",
        &mock.uri(),
        "--transport",
        "stdio",
        "--api-key",
        "test-key",
    ]);
    // The ambient environment (BUGZILLA_API_KEY_FILE) must not leak into
    // what these tests resolve.
    cli.api_key_file = None;
    let cfg = Arc::new(cli);
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
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "bugs": [bug] })))
        .expect(1)
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
    assert!(
        text_of(&search).contains("\"id\": 7"),
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

/// Tool names a client sees when it lists the server's tools — a real
/// `tools/list` request over the wire, so the handler's own listing path
/// is what answers.
async fn listed_tools(client: &RunningService<RoleClient, ()>) -> Vec<String> {
    client
        .list_all_tools()
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
    // Point the server at a closed port: the whoami lookup (and everything
    // after it) fails at the transport level, where the unsanitized error
    // would carry the request URL with api_key=... in it. Nothing the
    // client sees may contain the key.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    drop(listener); // free the port so every connection is refused

    let mut cli = Cli::parse_from([
        "bugwarden",
        "--bugzilla-server",
        &format!("http://{addr}"),
        "--transport",
        "stdio",
        "--api-key",
        "SUPERSECRETKEY123",
    ]);
    cli.api_key_file = None; // the ambient environment must not leak in
    let cfg = Arc::new(cli);
    let guard = Arc::new(Guard {
        policy: Policy::from_toml_str(IDENTITY_POLICY).expect("test policy must parse"),
    });
    let bz = Arc::new(
        BugzillaClient::new(&format!("http://{addr}"), false, USER_AGENT)
            .expect("client must build"),
    );
    let server = BugWarden::new(cfg, guard, bz).expect("server must build");
    let (client_io, server_io) = tokio::io::duplex(1 << 16);
    tokio::spawn(async move {
        if let Ok(running) = server.serve(server_io).await {
            let _ = running.waiting().await;
        }
    });
    let client: RunningService<RoleClient, ()> =
        ().serve(client_io)
            .await
            .expect("MCP handshake must succeed");

    let result = call(&client, "bug_info", json!({ "bug_ids": [7] })).await;
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
async fn bug_fields_detail_includes_legal_value_names() {
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
                "values": [{ "name": "NEW" }, { "name": "CONFIRMED" }],
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
    assert_eq!(envelope["fields"][0]["values"], json!(["NEW", "CONFIRMED"]));
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
async fn discovery_tools_absent_from_the_listing_by_default() {
    let mock = MockServer::start().await;
    let client = client_for("", &mock).await;
    let tools = client
        .list_all_tools()
        .await
        .expect("list_tools must succeed");
    let names: Vec<&str> = tools.iter().map(|t| t.name.as_ref()).collect();
    assert!(!names.contains(&"bugzilla_products"));
    assert!(!names.contains(&"bug_fields"));

    let client = client_for(DISCOVERY_POLICY, &mock).await;
    let tools = client
        .list_all_tools()
        .await
        .expect("list_tools must succeed");
    let names: Vec<&str> = tools.iter().map(|t| t.name.as_ref()).collect();
    assert!(names.contains(&"bugzilla_products"));
    assert!(names.contains(&"bug_fields"));
}
