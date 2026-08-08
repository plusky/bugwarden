//! End-to-end tests of the audit stream against a mock Bugzilla.
//!
//! Each test builds a real [`BugWarden`] with auditing enabled, serves it
//! over an in-memory duplex transport, and calls the tools through an rmcp
//! MCP client — the same dispatch path a production client takes, so the
//! record-per-call guarantee is proven where it is enforced (the handler
//! wrapper), not in a helper. The sink writes a real JSONL file in a
//! tempdir; every assertion about "the record exists" reads that file
//! immediately after the call future resolves, which is the
//! persisted-before-response guarantee exercised end to end.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use bugwarden::audit::{
    AuditConfig, AuditEvent, AuditEventKind, AuditSink, AuditState, FailMode, OutcomeClass,
    TransportKind, Verdict,
};
use bugwarden::config::Cli;
use bugwarden::server::{BugWarden, USER_AGENT};
use bugwarden_core::client::BugzillaClient;
use bugwarden_core::guard::Guard;
use bugwarden_core::policy::Policy;
use clap::Parser as _;
use rmcp::model::{CallToolRequestParams, CallToolResult};
use rmcp::service::{RoleClient, RunningService};
use rmcp::ServiceExt as _;
use serde_json::{json, Value};
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// A served, audited server plus the handles the assertions need.
struct Audited {
    client: RunningService<RoleClient, ()>,
    audit_path: PathBuf,
    /// Owns the audit directory for the test's lifetime.
    _dir: tempfile::TempDir,
}

/// Serve a [`BugWarden`] built from `policy` with auditing on
/// (fail_mode = open, so nothing in here depends on refusal behavior),
/// and connect an MCP client over an in-memory duplex transport.
async fn audited_client_for(policy: &str, mock: &MockServer, api_key: &str) -> Audited {
    audited_client_with(policy, mock, api_key, true).await
}

/// As [`audited_client_for`], with the `suppressed_ids` record knob under
/// the test's control.
async fn audited_client_with(
    policy: &str,
    mock: &MockServer,
    api_key: &str,
    suppressed_ids: bool,
) -> Audited {
    let dir = tempfile::tempdir().expect("tempdir");
    let audit_path = dir.path().join("audit.jsonl");
    let sink = AuditSink::open(AuditConfig {
        path: audit_path.clone(),
        fsync: false,
        fail_mode: None,
        rotate_max_bytes: 0,
        rotate_keep: 8,
        suppressed_ids,
    })
    .expect("audit sink must open");
    let audit = Arc::new(AuditState::new(
        sink,
        FailMode::Open,
        Some("sha256:policy-under-test".to_string()),
    ));

    let mut cli = Cli::parse_from([
        "bugwarden",
        "--bugzilla-server",
        &mock.uri(),
        "--transport",
        "stdio",
        "--api-key",
        api_key,
    ]);
    // The ambient environment (BUGZILLA_API_KEY_FILE) must not leak in.
    cli.api_key_file = None;
    let cfg = Arc::new(cli);
    let guard = Arc::new(Guard {
        policy: Policy::from_toml_str(policy).expect("test policy must parse"),
    });
    let bz =
        Arc::new(BugzillaClient::new(&mock.uri(), false, USER_AGENT).expect("client must build"));
    let server = BugWarden::new(cfg, guard, bz)
        .expect("server must build")
        .with_audit(audit);

    let (client_io, server_io) = tokio::io::duplex(1 << 16);
    tokio::spawn(async move {
        if let Ok(running) = server.serve(server_io).await {
            let _ = running.waiting().await;
        }
    });
    let client = ().serve(client_io).await.expect("MCP handshake must succeed");
    Audited {
        client,
        audit_path,
        _dir: dir,
    }
}

/// An un-audited server over the same transport, for comparisons.
async fn plain_client_for(policy: &str, mock: &MockServer) -> RunningService<RoleClient, ()> {
    let mut cli = Cli::parse_from([
        "bugwarden",
        "--bugzilla-server",
        &mock.uri(),
        "--transport",
        "stdio",
        "--api-key",
        "test-key",
    ]);
    // The ambient environment (BUGZILLA_API_KEY_FILE) must not leak in.
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

async fn call(client: &RunningService<RoleClient, ()>, tool: &str, args: Value) -> CallToolResult {
    let Value::Object(args) = args else {
        panic!("tool arguments must be a JSON object");
    };
    client
        .call_tool(CallToolRequestParams::new(tool.to_string()).with_arguments(args))
        .await
        .expect("tool call must not be a protocol error")
}

/// Parse every line of the audit file (empty lines skipped, as the sink's
/// self-healing documents).
fn read_events(path: &Path) -> Vec<AuditEvent> {
    let s = std::fs::read_to_string(path).expect("audit file must be readable");
    s.lines()
        .filter(|l| !l.is_empty())
        .map(|l| serde_json::from_str(l).expect("every audit line must parse as AuditEvent"))
        .collect()
}

fn last_tool_call(events: &[AuditEvent]) -> &bugwarden::audit::ToolCallEvent {
    match &events.last().expect("at least one event").kind {
        AuditEventKind::ToolCall(tc) => tc,
        other => panic!("expected a tool_call record, got {other:?}"),
    }
}

fn world_bug(id: u64) -> Value {
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

/// Mount a full fixture upstream: bug 7 (classify + bodies), the id=0
/// padding fetch, history/comments/attachments for 7, attachment 55,
/// write endpoints, server-info endpoints, and the quicksearch doc page.
/// Mounted so that every routed tool has a workable happy path.
async fn mount_fixture(mock: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/rest/bug"))
        .and(query_param("id", "0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "bugs": [] })))
        .mount(mock)
        .await;
    // Catch-all for /rest/bug: classification and body fetches for id=7
    // and the quicksearch scan all serve bug 7.
    Mock::given(method("GET"))
        .and(path("/rest/bug"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "bugs": [world_bug(7)] })))
        .mount(mock)
        .await;
    Mock::given(method("GET"))
        .and(path("/rest/bug/7/history"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({ "bugs": [{ "history": [] }] })),
        )
        .mount(mock)
        .await;
    Mock::given(method("GET"))
        .and(path("/rest/bug/7/comment"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "bugs": { "7": { "comments": [
                { "id": 1, "bug_id": 7, "is_private": false, "text": "public comment" },
            ] } }
        })))
        .mount(mock)
        .await;
    Mock::given(method("GET"))
        .and(path("/rest/bug/7/attachment"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "bugs": { "7": [] } })))
        .mount(mock)
        .await;
    Mock::given(method("GET"))
        .and(path("/rest/bug/attachment/55"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "attachments": { "55": {
                "id": 55,
                "bug_id": 7,
                "is_private": false,
                "size": 3,
                "file_name": "log.txt",
                "content_type": "text/plain",
                "data": "QUFB",
            } }
        })))
        .mount(mock)
        .await;
    Mock::given(method("PUT"))
        .and(path("/rest/bug/7"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "bugs": [] })))
        .mount(mock)
        .await;
    Mock::given(method("POST"))
        .and(path("/rest/bug/7/comment"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "id": 11 })))
        .mount(mock)
        .await;
    Mock::given(method("POST"))
        .and(path("/rest/bug/7/attachment"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "ids": [31] })))
        .mount(mock)
        .await;
    Mock::given(method("POST"))
        .and(path("/rest/bug"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "id": 4242 })))
        .mount(mock)
        .await;
    for (endpoint, body) in [
        ("/rest/version", json!({ "version": "5.0" })),
        ("/rest/extensions", json!({ "extensions": {} })),
        (
            "/rest/time",
            json!({ "web_time": "2026-01-01T00:00:00Z", "tz_name": "UTC" }),
        ),
        ("/rest/parameters", json!({ "parameters": {} })),
    ] {
        Mock::given(method("GET"))
            .and(path(endpoint))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(mock)
            .await;
    }
    Mock::given(method("GET"))
        .and(path("/page.cgi"))
        .respond_with(ResponseTemplate::new(200).set_body_string("<html>quicksearch</html>"))
        .mount(mock)
        .await;
    Mock::given(method("GET"))
        .and(path("/rest/product_enterable"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "ids": [] })))
        .mount(mock)
        .await;
    Mock::given(method("GET"))
        .and(path("/rest/field/bug"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "fields": [] })))
        .mount(mock)
        .await;
}

/// Minimal valid arguments for each routed tool against [`mount_fixture`].
/// A new tool must be added here before the one-record-per-call test can
/// pass.
fn minimal_args(tool: &str) -> Value {
    match tool {
        "bug_info" => json!({ "bug_ids": [7] }),
        "bug_history" => json!({ "id": 7 }),
        "bug_comments" => json!({ "id": 7 }),
        "bugs_quicksearch" => json!({ "query": "kernel" }),
        "create_bug" => json!({
            "product": "openSUSE",
            "component": "core",
            "summary": "crash on start",
            "version": "1.0",
        }),
        "add_attachment" => json!({
            "bug_id": 7,
            "data": "QUFB",
            "file_name": "log.txt",
            "summary": "boot log",
            "content_type": "text/plain",
        }),
        "add_comment" => json!({ "bug_id": 7, "comment": "hello" }),
        "update_bug_status" => json!({ "bug_id": 7, "status": "NEW" }),
        "assign_bug" => json!({ "bug_id": 7, "assignee": "dev@example.org" }),
        "update_bug_fields" => json!({ "bug_id": 7, "priority": "P1" }),
        "update_bug_dependencies" => json!({ "bug_id": 7, "blocks_add": [7] }),
        "add_cc_to_bug" => json!({ "bug_id": 7, "cc_email": "cc@example.org" }),
        "mark_as_duplicate" => json!({ "bug_id": 7, "duplicate_of": 7 }),
        "list_attachments" => json!({ "bug_id": 7 }),
        "download_attachment" => json!({ "attachment_id": 55 }),
        "bug_url" => json!({ "bug_id": 7 }),
        "bugzilla_server_info" => json!({}),
        "bugzilla_products" => json!({}),
        "bug_fields" => json!({}),
        "quicksearch_syntax" => json!({}),
        "mcp_server_info" => json!({}),
        "summarize_bug" => json!({ "id": 7 }),
        other => panic!("no minimal args for tool {other} — extend the map"),
    }
}

#[tokio::test]
async fn every_routed_tool_writes_exactly_one_record_per_call() {
    let mock = MockServer::start().await;
    mount_fixture(&mock).await;
    // allow_discovery = true so the full router — discovery tools included
    // (I16) — is exercised by this one-record-per-call guarantee (I15).
    let audited = audited_client_for("[global]\nallow_discovery = true\n", &mock, "test-key").await;

    let tools = audited
        .client
        .list_all_tools()
        .await
        .expect("list_tools must succeed");
    assert!(!tools.is_empty(), "the router lists the tool surface");

    // The handshake wrote the initialize record.
    let mut expected = 1;
    assert_eq!(read_events(&audited.audit_path).len(), expected);
    for tool in &tools {
        let _ = call(&audited.client, &tool.name, minimal_args(&tool.name)).await;
        expected += 1;
        // Read IMMEDIATELY after the response future resolves: the
        // record must already be on disk (persisted before response).
        let events = read_events(&audited.audit_path);
        assert_eq!(
            events.len(),
            expected,
            "calling {} must grow the file by exactly one record",
            tool.name
        );
        assert_eq!(last_tool_call(&events).request.tool, tool.name);
    }
}

#[tokio::test]
async fn refusal_paths_write_exactly_one_record_each() {
    // hide-secret first (it decides bug 99); the group_restricted rule
    // makes may_create refuse ALL creation — the documented behaviour of
    // such a policy.
    let policy = concat!(
        "[[rule]]\nname = \"hide-secret\"\naction = \"deny\"\n",
        "[rule.match]\nproducts = [\"Secret*\"]\n",
        "[[rule]]\nname = \"group-restricted\"\naction = \"deny\"\n",
        "[rule.match]\ngroup_restricted = true\n",
    );
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/bug"))
        .and(query_param("id", "0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "bugs": [] })))
        .mount(&mock)
        .await;
    let mut secret = world_bug(99);
    secret["product"] = json!("SecretSauce");
    Mock::given(method("GET"))
        .and(path("/rest/bug"))
        .and(query_param("id", "99"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "bugs": [secret] })))
        .mount(&mock)
        .await;
    let audited = audited_client_for(policy, &mock, "test-key").await;

    let mut expected = 1; // initialize
    let mut check = |events: Vec<AuditEvent>, verdict: Verdict, rule: Option<&str>| {
        expected += 1;
        assert_eq!(events.len(), expected, "exactly one new record");
        let tc = last_tool_call(&events);
        let guard = tc.guard.as_ref().expect("the guard was consulted");
        assert_eq!(guard.verdict, verdict);
        assert_eq!(guard.rule.as_deref(), rule);
    };

    // too_many_ids: 26 distinct ids.
    let ids: Vec<u64> = (1..=26).collect();
    let refused = call(&audited.client, "bug_info", json!({ "bug_ids": ids })).await;
    assert_eq!(refused.is_error, Some(true));
    check(read_events(&audited.audit_path), Verdict::Refused, None);

    // Empty id list.
    let refused = call(&audited.client, "bug_info", json!({ "bug_ids": [] })).await;
    assert_eq!(refused.is_error, Some(true));
    check(read_events(&audited.audit_path), Verdict::Refused, None);

    // A guard denial names its rule in the record — and nowhere else.
    let denied = call(&audited.client, "bug_history", json!({ "id": 99 })).await;
    assert_eq!(denied.is_error, Some(true));
    check(
        read_events(&audited.audit_path),
        Verdict::Denied,
        Some("hide-secret"),
    );
    // The denial is a well-formed response: outcome class stays ok.
    let events = read_events(&audited.audit_path);
    assert_eq!(last_tool_call(&events).outcome.class, OutcomeClass::Ok);

    // create_bug under a group_restricted policy: refused as requested.
    let refused = call(
        &audited.client,
        "create_bug",
        json!({
            "product": "openSUSE",
            "component": "core",
            "summary": "crash on start",
            "version": "1.0",
        }),
    )
    .await;
    assert_eq!(refused.is_error, Some(true));
    check(read_events(&audited.audit_path), Verdict::Refused, None);
}

#[tokio::test]
async fn unknown_and_stripped_tools_error_identically_and_still_record() {
    let mock = MockServer::start().await;
    let read_only = "[global]\nread_only = true\n";
    let audited = audited_client_for(read_only, &mock, "test-key").await;
    let plain = plain_client_for(read_only, &mock).await;

    // Unknown tool: the same protocol error with auditing on or off,
    // plus exactly one record with outcome error.
    let with_audit = audited
        .client
        .call_tool(CallToolRequestParams::new("no_such_tool".to_string()))
        .await
        .expect_err("unknown tool is a protocol error");
    let without = plain
        .call_tool(CallToolRequestParams::new("no_such_tool".to_string()))
        .await
        .expect_err("unknown tool is a protocol error");
    assert_eq!(
        format!("{with_audit:?}"),
        format!("{without:?}"),
        "auditing must not change the protocol error"
    );
    let events = read_events(&audited.audit_path);
    assert_eq!(events.len(), 2, "initialize + the failed call");
    let tc = last_tool_call(&events);
    assert_eq!(tc.request.tool, "no_such_tool");
    assert_eq!(tc.outcome.class, OutcomeClass::Error);
    assert!(tc.guard.is_none(), "no guard ran for an unknown tool");

    // A write tool stripped by read-only mode (I13) is an unknown tool.
    let with_audit = audited
        .client
        .call_tool(
            CallToolRequestParams::new("add_comment".to_string()).with_arguments(
                serde_json::Map::from_iter([
                    ("bug_id".to_string(), json!(7)),
                    ("comment".to_string(), json!("hi")),
                ]),
            ),
        )
        .await
        .expect_err("a stripped tool is a protocol error");
    let without = plain
        .call_tool(
            CallToolRequestParams::new("add_comment".to_string()).with_arguments(
                serde_json::Map::from_iter([
                    ("bug_id".to_string(), json!(7)),
                    ("comment".to_string(), json!("hi")),
                ]),
            ),
        )
        .await
        .expect_err("a stripped tool is a protocol error");
    assert_eq!(format!("{with_audit:?}"), format!("{without:?}"));
    let events = read_events(&audited.audit_path);
    assert_eq!(events.len(), 3, "one more record for the stripped call");
    let tc = last_tool_call(&events);
    assert_eq!(tc.request.tool, "add_comment");
    assert_eq!(tc.outcome.class, OutcomeClass::Error);
    // The comment body is not allowlisted even on this path.
    assert_eq!(tc.request.params["comment"], json!({ "_len": 4 }));
}

/// Policy hiding every bug in a `Secret*` product.
const HIDE_SECRET_POLICY: &str = concat!(
    "[[rule]]\nname = \"hide-secret\"\naction = \"deny\"\n",
    "[rule.match]\nproducts = [\"Secret*\"]\n",
);

/// Bug 7 names the [`HIDE_SECRET_POLICY`]-hidden bug 666 twice: its
/// `depends_on` links it, and its history records the link being added.
/// Both are I14 scrub sites, so both must enrich the record.
async fn mount_hidden_link(mock: &MockServer) {
    let mut linked = world_bug(7);
    linked["depends_on"] = json!([666]);
    Mock::given(method("GET"))
        .and(path("/rest/bug"))
        .and(query_param("id", "7"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "bugs": [linked] })))
        .mount(mock)
        .await;
    let mut secret = world_bug(666);
    secret["product"] = json!("SecretSauce");
    Mock::given(method("GET"))
        .and(path("/rest/bug"))
        .and(query_param("id", "666"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "bugs": [secret] })))
        .mount(mock)
        .await;
    Mock::given(method("GET"))
        .and(path("/rest/bug/7/history"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "bugs": [{ "history": [{
                "when": "2020-01-02T00:00:00Z",
                "who": "dev@example.org",
                "changes": [
                    { "field_name": "depends_on", "added": "666", "removed": "" },
                ],
            }] }]
        })))
        .mount(mock)
        .await;
}

#[tokio::test]
async fn suppressed_ids_reach_the_log_never_the_envelope() {
    // Bug 7 depends on the policy-hidden bug 666: I14 scrubs the link
    // from the served envelope; the audit record carries the id.
    let mock = MockServer::start().await;
    mount_hidden_link(&mock).await;
    let audited = audited_client_for(HIDE_SECRET_POLICY, &mock, "test-key").await;

    let result = call(&audited.client, "bug_info", json!({ "bug_ids": [7] })).await;
    assert_ne!(result.is_error, Some(true), "bug 7 itself is served");
    let envelope = serde_json::to_string(&result).unwrap();
    assert!(
        !envelope.contains("666"),
        "the hidden id must be scrubbed from the client envelope (I14): {envelope}"
    );

    let events = read_events(&audited.audit_path);
    let tc = last_tool_call(&events);
    let guard = tc.guard.as_ref().expect("guard info recorded");
    assert_eq!(guard.verdict, Verdict::ServedFiltered);
    assert!(
        guard.suppressed_ids.contains(&666),
        "the audit record must carry the suppressed id: {:?}",
        guard.suppressed_ids
    );
    assert!(guard.suppressed_count >= 1);
    assert_eq!(
        guard.policy_hash.as_deref(),
        Some("sha256:policy-under-test"),
        "records tie to the policy in force"
    );

    // The history of bug 7 names 666 too: the scrub site is a different
    // one, and its record must carry the id all the same.
    let result = call(&audited.client, "bug_history", json!({ "id": 7 })).await;
    assert_ne!(result.is_error, Some(true), "the history itself is served");
    let envelope = serde_json::to_string(&result).unwrap();
    assert!(
        !envelope.contains("666"),
        "the hidden id must be scrubbed from the served history (I14): {envelope}"
    );
    let events = read_events(&audited.audit_path);
    let tc = last_tool_call(&events);
    assert_eq!(tc.request.tool, "bug_history");
    let guard = tc.guard.as_ref().expect("guard info recorded");
    assert!(
        guard.suppressed_ids.contains(&666),
        "the bug_history record must carry the scrubbed id: {:?}",
        guard.suppressed_ids
    );
}

#[tokio::test]
async fn suppressed_ids_off_records_the_count_never_the_ids() {
    // The same scenario with `suppressed_ids = false` in the audit config:
    // the record still counts the suppression but names no id — and the
    // served envelope is exactly as clean as with the knob on.
    let mock = MockServer::start().await;
    mount_hidden_link(&mock).await;
    let audited = audited_client_with(HIDE_SECRET_POLICY, &mock, "test-key", false).await;

    let result = call(&audited.client, "bug_info", json!({ "bug_ids": [7] })).await;
    assert_ne!(result.is_error, Some(true), "bug 7 itself is served");
    let envelope = serde_json::to_string(&result).unwrap();
    assert!(
        !envelope.contains("666"),
        "the hidden id must be scrubbed from the client envelope (I14): {envelope}"
    );

    let events = read_events(&audited.audit_path);
    let tc = last_tool_call(&events);
    let guard = tc.guard.as_ref().expect("guard info recorded");
    assert_eq!(guard.verdict, Verdict::ServedFiltered);
    assert!(
        guard.suppressed_count >= 1,
        "the count survives the elision: {guard:?}"
    );
    assert!(
        guard.suppressed_ids.is_empty(),
        "ids are elided when the knob is off: {:?}",
        guard.suppressed_ids
    );
}

/// Serve a quicksearch corpus (issue #29 tests): search requests are paged
/// by limit/offset the way Bugzilla pages them, and the I14 link-disclosure
/// classify fetch — which addresses bugs by id, not by query — gets an
/// empty answer (the corpus rows carry no link fields to disclose).
async fn mount_search_corpus(mock: &MockServer, rows: Vec<Value>) {
    Mock::given(method("GET"))
        .and(path("/rest/bug"))
        .respond_with(move |req: &wiremock::Request| {
            let q: std::collections::HashMap<_, _> = req.url.query_pairs().collect();
            if !q.contains_key("quicksearch") {
                return ResponseTemplate::new(200).set_body_json(json!({ "bugs": [] }));
            }
            let get = |k: &str| q.get(k).and_then(|v| v.parse::<usize>().ok());
            let offset = get("offset").unwrap_or(0);
            let limit = get("limit").unwrap_or(rows.len());
            let page: Vec<_> = rows.iter().skip(offset).take(limit).cloned().collect();
            ResponseTemplate::new(200).set_body_json(json!({ "bugs": page }))
        })
        .mount(mock)
        .await;
}

/// A [`world_bug`] in the `Secret*` product the [`HIDE_SECRET_POLICY`]
/// denies.
fn secret_bug(id: u64) -> Value {
    let mut bug = world_bug(id);
    bug["product"] = json!("SecretSauce");
    bug
}

#[tokio::test]
async fn quicksearch_scan_accounting_reaches_the_record_never_the_envelope() {
    // Five upstream rows, two of them hidden: the record must say the scan
    // examined 5 and dropped 2 — and which two, through the existing
    // suppressed-ids machinery — while the envelope shows three bugs and
    // not a hint of accounting (I3).
    let mock = MockServer::start().await;
    mount_search_corpus(
        &mock,
        vec![
            world_bug(1),
            secret_bug(2),
            world_bug(3),
            secret_bug(4),
            world_bug(5),
        ],
    )
    .await;
    let audited = audited_client_for(HIDE_SECRET_POLICY, &mock, "test-key").await;

    let result = call(&audited.client, "bugs_quicksearch", json!({ "query": "q" })).await;
    assert_ne!(result.is_error, Some(true), "the search is served");
    let envelope = serde_json::to_string(&result).unwrap();
    for leak in ["scanned", "dropped", "\"scan\""] {
        assert!(
            !envelope.contains(leak),
            "scan accounting leaked into the envelope: {envelope}"
        );
    }

    let events = read_events(&audited.audit_path);
    let tc = last_tool_call(&events);
    let guard = tc.guard.as_ref().expect("guard info recorded");
    let scan = guard.scan.expect("a search records its scan");
    assert_eq!(scan.scanned, 5, "every upstream row was examined");
    assert_eq!(scan.dropped, 2, "the two hidden rows were dropped");
    assert_eq!(guard.verdict, Verdict::ServedFiltered);
    assert_eq!(
        guard.suppressed_ids,
        vec![2, 4],
        "the dropped ids ride the suppressed-ids machinery"
    );
    assert_eq!(guard.suppressed_count, 2);
}

#[tokio::test]
async fn quicksearch_response_is_byte_identical_whether_or_not_rows_were_dropped() {
    // Acceptance (b) of issue #29, at the tool level with auditing ON: a
    // window that dropped hidden rows serializes byte-identically to the
    // same window over an upstream where those rows simply do not exist.
    let visible: Vec<u64> = vec![1, 3, 5, 6, 8, 9, 10, 11, 12];
    let mock_mixed = MockServer::start().await;
    mount_search_corpus(
        &mock_mixed,
        (1..=12)
            .map(|id| {
                if [2, 4, 7].contains(&id) {
                    secret_bug(id)
                } else {
                    world_bug(id)
                }
            })
            .collect(),
    )
    .await;
    let mock_clean = MockServer::start().await;
    mount_search_corpus(
        &mock_clean,
        visible.iter().map(|&id| world_bug(id)).collect(),
    )
    .await;

    let mixed = audited_client_for(HIDE_SECRET_POLICY, &mock_mixed, "test-key").await;
    let clean = audited_client_for(HIDE_SECRET_POLICY, &mock_clean, "test-key").await;
    let args = json!({ "query": "q", "limit": 4, "offset": 2 });
    let from_mixed = call(&mixed.client, "bugs_quicksearch", args.clone()).await;
    let from_clean = call(&clean.client, "bugs_quicksearch", args).await;
    assert_eq!(
        serde_json::to_string(&from_mixed).unwrap(),
        serde_json::to_string(&from_clean).unwrap(),
        "dropped rows must not change a single response byte (I3)"
    );

    // The difference lives in the records alone: the mixed scan dropped,
    // the clean scan did not.
    let mixed_events = read_events(&mixed.audit_path);
    let mixed_guard = last_tool_call(&mixed_events).guard.as_ref().unwrap();
    assert!(mixed_guard.scan.expect("scan recorded").dropped > 0);
    let clean_events = read_events(&clean.audit_path);
    let clean_guard = last_tool_call(&clean_events).guard.as_ref().unwrap();
    assert_eq!(clean_guard.scan.expect("scan recorded").dropped, 0);
}

#[tokio::test]
async fn quicksearch_drop_count_survives_the_suppressed_ids_knob() {
    // Acceptance (c) of issue #29: with `suppressed_ids = false` the
    // record still counts what the scan dropped — it just names no id.
    let mock = MockServer::start().await;
    mount_search_corpus(&mock, vec![world_bug(1), secret_bug(2), world_bug(3)]).await;
    let audited = audited_client_with(HIDE_SECRET_POLICY, &mock, "test-key", false).await;

    let result = call(&audited.client, "bugs_quicksearch", json!({ "query": "q" })).await;
    assert_ne!(result.is_error, Some(true), "the search is served");

    let events = read_events(&audited.audit_path);
    let guard = last_tool_call(&events).guard.as_ref().unwrap();
    let scan = guard.scan.expect("a search records its scan");
    assert_eq!(scan.dropped, 1, "the count survives the elision");
    assert_eq!(scan.scanned, 3);
    assert!(guard.suppressed_count >= 1, "so does suppressed_count");
    assert!(
        guard.suppressed_ids.is_empty(),
        "ids are elided when the knob is off: {:?}",
        guard.suppressed_ids
    );
}

#[tokio::test]
async fn quicksearch_clean_scan_records_zero_drops_and_stays_served() {
    // A search that hid nothing still accounts for its scan — dropped = 0
    // is a statement, not an omission — and keeps the clean verdict.
    let mock = MockServer::start().await;
    mount_search_corpus(&mock, vec![world_bug(1), world_bug(2), world_bug(3)]).await;
    let audited = audited_client_for(HIDE_SECRET_POLICY, &mock, "test-key").await;

    let result = call(&audited.client, "bugs_quicksearch", json!({ "query": "q" })).await;
    assert_ne!(result.is_error, Some(true), "the search is served");

    let events = read_events(&audited.audit_path);
    let guard = last_tool_call(&events).guard.as_ref().unwrap();
    assert_eq!(
        guard.scan,
        Some(bugwarden::audit::ScanInfo {
            scanned: 3,
            dropped: 0
        })
    );
    assert_eq!(guard.verdict, Verdict::Served, "a clean scan stays served");
    assert!(guard.suppressed_ids.is_empty());
    assert_eq!(guard.suppressed_count, 0);
}

#[tokio::test]
async fn canary_content_never_reaches_the_audit_file() {
    const KEY_CANARY: &str = "canary-api-key-5c9e02";
    const SUMMARY_CANARY: &str = "canary-summary-77aa01";
    const COMMENT_CANARY: &str = "canary-comment-b3f604";
    const OUTGOING_CANARY: &str = "canary-outgoing-19dd08";

    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/bug"))
        .and(query_param("id", "0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "bugs": [] })))
        .mount(&mock)
        .await;
    let mut bug = world_bug(7);
    bug["summary"] = json!(SUMMARY_CANARY);
    Mock::given(method("GET"))
        .and(path("/rest/bug"))
        .and(query_param("id", "7"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "bugs": [bug] })))
        .mount(&mock)
        .await;
    Mock::given(method("GET"))
        .and(path("/rest/bug/7/comment"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "bugs": { "7": { "comments": [
                { "id": 1, "bug_id": 7, "is_private": false, "text": COMMENT_CANARY },
            ] } }
        })))
        .mount(&mock)
        .await;
    Mock::given(method("POST"))
        .and(path("/rest/bug/7/comment"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "id": 11 })))
        .mount(&mock)
        .await;
    let audited = audited_client_for("", &mock, KEY_CANARY).await;

    let _ = call(&audited.client, "bug_info", json!({ "bug_ids": [7] })).await;
    let _ = call(&audited.client, "bug_comments", json!({ "id": 7 })).await;
    let _ = call(
        &audited.client,
        "add_comment",
        json!({ "bug_id": 7, "comment": OUTGOING_CANARY }),
    )
    .await;

    let raw = std::fs::read_to_string(&audited.audit_path).expect("audit file readable");
    for canary in [KEY_CANARY, SUMMARY_CANARY, COMMENT_CANARY, OUTGOING_CANARY] {
        assert!(
            !raw.contains(canary),
            "canary {canary} leaked into the audit file"
        );
    }
    // The outgoing comment appears as presence + size only.
    let events = read_events(&audited.audit_path);
    let tc = last_tool_call(&events);
    assert_eq!(tc.request.tool, "add_comment");
    let expected_len = serde_json::to_vec(&json!(OUTGOING_CANARY)).unwrap().len();
    assert_eq!(
        tc.request.params["comment"],
        json!({ "_len": expected_len })
    );
}

#[tokio::test]
async fn initialize_writes_exactly_one_record_with_the_client_identity() {
    // Recorded unconditionally: auditing on means session starts are in
    // the stream — there is no configuration knob that turns this off.
    let mock = MockServer::start().await;
    let audited = audited_client_for("", &mock, "test-key").await;

    let events = read_events(&audited.audit_path);
    assert_eq!(events.len(), 1, "the handshake writes exactly one record");
    let init = match &events[0].kind {
        AuditEventKind::Initialize(init) => init,
        other => panic!("expected an initialize record, got {other:?}"),
    };
    assert!(
        init.client.name.as_deref().is_some_and(|n| !n.is_empty()),
        "client name recorded: {init:?}"
    );
    assert!(
        init.client.version.is_some(),
        "client version recorded: {init:?}"
    );
    assert!(
        init.protocol_version.is_some(),
        "protocol version recorded: {init:?}"
    );
    // Session info anchors the stdio session to the process.
    assert_eq!(events[0].session.transport, TransportKind::Stdio);
    let id = events[0].session.id.as_deref().expect("stdio session id");
    let (pid, _) = id.split_once('-').expect("session id is <pid>-<epoch>");
    assert_eq!(pid, std::process::id().to_string());
    assert_eq!(events[0].session.remote, None);
}
