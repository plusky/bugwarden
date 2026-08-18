//! End-to-end tests of the OTLP audit export (issue #31).
//!
//! Each test drives a real [`BugWarden`] over an in-memory duplex MCP
//! transport against a mock Bugzilla, with the audit sink writing a real
//! JSONL file and an exporter pointed at a mock OTLP collector. The
//! assertions read the bytes that arrived at the collector and decode them
//! as protobuf, so the wire format is proven on the wire rather than
//! against the encoder's own idea of it.
//!
//! The diagnostics half of the export lives in `otel_diagnostics.rs`,
//! which needs a process-wide subscriber of its own.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use bugwarden::audit::{AuditConfig, AuditSink, AuditState, FailMode};
use bugwarden::config::Cli;
use bugwarden::otel::{OtelEnv, Pipeline};
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

const TRACEPARENT: &str = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01";
const TRACE_ID: [u8; 16] = [
    0x0a, 0xf7, 0x65, 0x19, 0x16, 0xcd, 0x43, 0xdd, 0x84, 0x48, 0xeb, 0x21, 0x1c, 0x80, 0x31, 0x9c,
];
const SPAN_ID: [u8; 8] = [0xb7, 0xad, 0x6b, 0x71, 0x69, 0x20, 0x33, 0x31];

// ---------------------------------------------------------------------------
// A minimal protobuf reader, so the assertions read the wire and not the
// encoder. Field numbers come from the OTLP logs schema.
// ---------------------------------------------------------------------------

fn read_varint(buf: &[u8]) -> Option<(u64, usize)> {
    let mut value = 0u64;
    for (i, byte) in buf.iter().enumerate().take(10) {
        value |= u64::from(byte & 0x7f) << (7 * i);
        if byte & 0x80 == 0 {
            return Some((value, i + 1));
        }
    }
    None
}

/// `(field number, wire type, payload)` for every field in `buf`.
fn fields(buf: &[u8]) -> Vec<(u32, u32, Vec<u8>)> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < buf.len() {
        let (tag, used) = read_varint(&buf[i..]).expect("a field tag");
        i += used;
        let field = u32::try_from(tag >> 3).expect("a field number");
        let wire_type = u32::try_from(tag & 7).expect("a wire type");
        match wire_type {
            0 => {
                let (value, used) = read_varint(&buf[i..]).expect("a varint");
                out.push((field, wire_type, value.to_le_bytes().to_vec()));
                i += used;
            }
            1 => {
                out.push((field, wire_type, buf[i..i + 8].to_vec()));
                i += 8;
            }
            2 => {
                let (len, used) = read_varint(&buf[i..]).expect("a length");
                i += used;
                let len = usize::try_from(len).expect("a sane length");
                out.push((field, wire_type, buf[i..i + len].to_vec()));
                i += len;
            }
            5 => {
                out.push((field, wire_type, buf[i..i + 4].to_vec()));
                i += 4;
            }
            other => panic!("unexpected protobuf wire type {other}"),
        }
    }
    out
}

fn first(buf: &[u8], field: u32) -> Option<Vec<u8>> {
    fields(buf)
        .into_iter()
        .find(|(f, _, _)| *f == field)
        .map(|(_, _, v)| v)
}

fn every(buf: &[u8], field: u32) -> Vec<Vec<u8>> {
    fields(buf)
        .into_iter()
        .filter(|(f, _, _)| *f == field)
        .map(|(_, _, v)| v)
        .collect()
}

/// One decoded OTel log record.
#[derive(Debug, Clone)]
struct Record {
    body: String,
    attrs: BTreeMap<String, String>,
    trace_id: Option<Vec<u8>>,
    span_id: Option<Vec<u8>>,
    severity: u64,
    service_name: String,
}

/// Decode an `ExportLogsServiceRequest` into its log records.
fn decode_records(payload: &[u8]) -> Vec<Record> {
    let mut out = Vec::new();
    for resource_logs in every(payload, 1) {
        let service_name = first(&resource_logs, 1)
            .and_then(|resource| {
                every(&resource, 1).into_iter().find_map(|kv| {
                    let key = String::from_utf8(first(&kv, 1)?).ok()?;
                    (key == "service.name")
                        .then(|| String::from_utf8(first(&first(&kv, 2)?, 1)?).ok())
                        .flatten()
                })
            })
            .unwrap_or_default();
        for scope_logs in every(&resource_logs, 2) {
            for record in every(&scope_logs, 2) {
                let mut attrs = BTreeMap::new();
                for kv in every(&record, 6) {
                    let key = String::from_utf8(first(&kv, 1).expect("an attribute key"))
                        .expect("a utf-8 key");
                    let any = first(&kv, 2).expect("an attribute value");
                    let value = match (first(&any, 1), first(&any, 3)) {
                        (Some(s), _) => String::from_utf8(s).expect("a utf-8 value"),
                        (None, Some(i)) => {
                            u64::from_le_bytes(i.try_into().expect("8 bytes")).to_string()
                        }
                        _ => String::new(),
                    };
                    attrs.insert(key, value);
                }
                out.push(Record {
                    body: String::from_utf8(
                        first(&first(&record, 5).expect("a body"), 1).expect("a string body"),
                    )
                    .expect("a utf-8 body"),
                    attrs,
                    trace_id: first(&record, 9),
                    span_id: first(&record, 10),
                    severity: first(&record, 2)
                        .map(|v| u64::from_le_bytes(v.try_into().expect("8 bytes")))
                        .unwrap_or_default(),
                    service_name: service_name.clone(),
                });
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

/// A served, audited, exporting server plus the handles assertions need.
struct Exported {
    client: RunningService<RoleClient, ()>,
    audit: Arc<AuditState>,
    pipeline: Option<Arc<Pipeline>>,
    /// The audit file, `None` for an OTLP-only (fileless) sink.
    audit_path: Option<PathBuf>,
    dir: tempfile::TempDir,
}

impl Exported {
    /// The audit file of a file-bearing server.
    fn file(&self) -> &std::path::Path {
        self.audit_path
            .as_deref()
            .expect("this server has an audit file")
    }
}

/// [`server_with_sinks`] in the shape most tests need: a file, an
/// exporter when `endpoint` names a collector, and the `open` fail mode.
async fn exporting_server(mock: &MockServer, endpoint: Option<&str>) -> Exported {
    server_with_sinks(mock, endpoint, true, FailMode::Open).await
}

/// Build a server with the given sink shape: an audit file or a fileless
/// (OTLP-only) sink, an exporter when `endpoint` names a collector, and
/// the fail mode the audit gate applies.
async fn server_with_sinks(
    mock: &MockServer,
    endpoint: Option<&str>,
    with_file: bool,
    fail_mode: FailMode,
) -> Exported {
    let dir = tempfile::tempdir().expect("tempdir");
    let (audit_cfg, audit_path) = if with_file {
        let path = dir.path().join("audit.jsonl");
        (
            AuditConfig {
                path: Some(path.clone()),
                fsync: false,
                fail_mode: None,
                rotate_max_bytes: 0,
                rotate_keep: 8,
                suppressed_ids: true,
            },
            Some(path),
        )
    } else {
        (AuditConfig::fileless(), None)
    };
    let sink = AuditSink::open(audit_cfg).expect("audit sink must open");

    let pipeline = endpoint.map(|endpoint| {
        let cfg = bugwarden::otel::resolve(&OtelEnv {
            endpoint: Some(endpoint.to_string()),
            ..OtelEnv::default()
        })
        .expect("the endpoint must resolve")
        .expect("an endpoint means export is on");
        Arc::new(Pipeline::start(cfg).expect("the pipeline must start"))
    });
    let sink = match &pipeline {
        Some(pipeline) => sink.with_export(pipeline.audit_exporter()),
        None => sink,
    };
    let audit = Arc::new(AuditState::new(sink, fail_mode, None));

    let mut cli = Cli::parse_from([
        "bugwarden",
        "--bugzilla-server",
        &mock.uri(),
        "--transport",
        "stdio",
        "--api-key",
        "test-key",
    ]);
    cli.api_key_file = None;
    let cfg = Arc::new(cli);
    let guard = Arc::new(Guard {
        policy: Policy::default(),
    });
    let bz =
        Arc::new(BugzillaClient::new(&mock.uri(), false, USER_AGENT).expect("client must build"));
    let server = BugWarden::new(cfg, guard, bz)
        .expect("server must build")
        .with_audit(audit.clone());

    let (client_io, server_io) = tokio::io::duplex(1 << 16);
    tokio::spawn(async move {
        if let Ok(running) = server.serve(server_io).await {
            let _ = running.waiting().await;
        }
    });
    let client = ().serve(client_io).await.expect("MCP handshake must succeed");
    Exported {
        client,
        audit,
        pipeline,
        audit_path,
        dir,
    }
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

/// Wait (bounded) until the audit sink's `failing()` reads `want`, so a
/// broken health transition fails the test instead of hanging the suite.
async fn wait_failing(audit: &Arc<AuditState>, want: bool) {
    for _ in 0..80 {
        if audit.sink.failing() == want {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("the audit sink did not reach failing()={want} within 8s");
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

async fn mount_bugzilla(mock: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/rest/bug"))
        .and(query_param("id", "0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "bugs": [] })))
        .mount(mock)
        .await;
    Mock::given(method("GET"))
        .and(path("/rest/bug"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "bugs": [world_bug(7)] })))
        .mount(mock)
        .await;
}

async fn mount_collector(collector: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/v1/logs"))
        .respond_with(ResponseTemplate::new(200))
        .mount(collector)
        .await;
}

/// Call a tool, optionally stamping the request `_meta` with a
/// `traceparent` the way a traced client does.
async fn call(
    client: &RunningService<RoleClient, ()>,
    tool: &str,
    args: Value,
    traceparent: Option<&str>,
) -> CallToolResult {
    let Value::Object(args) = args else {
        panic!("tool arguments must be a JSON object");
    };
    let mut params = CallToolRequestParams::new(tool.to_string()).with_arguments(args);
    if let Some(traceparent) = traceparent {
        let mut meta = rmcp::model::RequestMetaObject::new();
        meta.set_traceparent(traceparent);
        params.meta = Some(meta);
    }
    client
        .call_tool(params)
        .await
        .expect("tool call must not be a protocol error")
}

/// Wait until the collector has been posted to, and return everything it
/// received. Bounded, so a broken exporter fails the test instead of
/// hanging the suite.
async fn exported(collector: &MockServer) -> Vec<wiremock::Request> {
    for _ in 0..80 {
        let requests = collector
            .received_requests()
            .await
            .expect("request recording is on");
        if !requests.is_empty() {
            return requests;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("no OTLP export reached the collector within 8s");
}

fn audit_lines(path: &std::path::Path) -> Vec<String> {
    std::fs::read_to_string(path)
        .expect("audit file must be readable")
        .lines()
        .filter(|l| !l.is_empty())
        .map(str::to_owned)
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_tool_call_is_exported_as_an_otlp_log_record() {
    let mock = MockServer::start().await;
    mount_bugzilla(&mock).await;
    let collector = MockServer::start().await;
    mount_collector(&collector).await;

    let served = exporting_server(&mock, Some(&collector.uri())).await;
    call(
        &served.client,
        "bug_info",
        json!({ "bug_ids": [7] }),
        Some(TRACEPARENT),
    )
    .await;

    let requests = exported(&collector).await;
    for request in &requests {
        assert_eq!(
            request
                .headers
                .get("content-type")
                .and_then(|v| v.to_str().ok()),
            Some("application/x-protobuf"),
            "OTLP/HTTP protobuf is the declared transport"
        );
        assert!(!request.body.is_empty(), "an empty export carries nothing");
    }

    let records: Vec<_> = requests
        .iter()
        .flat_map(|r| decode_records(&r.body))
        .collect();
    let call_record = records
        .iter()
        .find(|r| r.attrs.get("bugwarden.event").map(String::as_str) == Some("tool_call"))
        .expect("the tool call must be exported");

    assert_eq!(
        call_record
            .attrs
            .get("bugwarden.stream")
            .map(String::as_str),
        Some("audit")
    );
    assert_eq!(
        call_record.attrs.get("bugwarden.tool").map(String::as_str),
        Some("bug_info")
    );
    assert_eq!(
        call_record
            .attrs
            .get("bugwarden.verdict")
            .map(String::as_str),
        Some("served")
    );
    assert_eq!(
        call_record
            .attrs
            .get("bugwarden.transport")
            .map(String::as_str),
        Some("stdio")
    );
    assert!(
        call_record.attrs.contains_key("bugwarden.seq"),
        "records carry the sequence number that orders them: {:?}",
        call_record.attrs
    );
    assert_eq!(call_record.service_name, "bugwarden");
    assert_eq!(call_record.severity, 9, "a tool call is an INFO record");

    // The client's own trace ids, as raw bytes, so a collector can join
    // this record to the client trace that caused it.
    assert_eq!(
        call_record.trace_id.as_deref(),
        Some(&TRACE_ID[..]),
        "the traceparent's trace id must reach the wire as bytes"
    );
    assert_eq!(call_record.span_id.as_deref(), Some(&SPAN_ID[..]));

    // The handshake is a record too, and it is exported like any other.
    assert!(
        records
            .iter()
            .any(|r| r.attrs.get("bugwarden.event").map(String::as_str) == Some("initialize")),
        "the initialize record must be exported as well"
    );
}

#[tokio::test]
async fn the_exported_body_is_the_file_record_byte_for_byte() {
    let mock = MockServer::start().await;
    mount_bugzilla(&mock).await;
    let collector = MockServer::start().await;
    mount_collector(&collector).await;

    let served = exporting_server(&mock, Some(&collector.uri())).await;
    call(&served.client, "bug_info", json!({ "bug_ids": [7] }), None).await;

    let requests = exported(&collector).await;
    let records: Vec<_> = requests
        .iter()
        .flat_map(|r| decode_records(&r.body))
        .collect();
    let call_record = records
        .iter()
        .find(|r| r.attrs.get("bugwarden.event").map(String::as_str) == Some("tool_call"))
        .expect("the tool call must be exported");

    let lines = audit_lines(served.file());
    let file_line = lines
        .iter()
        .find(|l| l.contains("\"event\":\"tool_call\""))
        .expect("the file must hold the tool_call record");
    assert_eq!(
        call_record.body.as_bytes(),
        file_line.as_bytes(),
        "the exported payload must carry exactly what the file carries (I12)"
    );
    // And nothing else: no second copy, no re-serialization with extra
    // fields.
    assert_eq!(
        records
            .iter()
            .filter(|r| r.attrs.get("bugwarden.event").map(String::as_str) == Some("tool_call"))
            .count(),
        1,
        "one record per call, in the export as in the file"
    );
}

/// A port nothing listens on: bind it, learn the number, drop it.
fn dead_endpoint() -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a free port");
    let addr = listener.local_addr().expect("an address");
    drop(listener);
    format!("http://{addr}")
}

#[tokio::test]
async fn a_dead_collector_fails_the_sink_and_open_mode_accounts_with_gaps() {
    // Revised 2026-08-18: a configured collector is load-bearing. Under
    // the `open` fail mode (the stdio default) serving continues — as it
    // does for a failing FILE — but the sink reports failure and the
    // undelivered window lands in `audit_gap` records, never silently.
    let mock = MockServer::start().await;
    mount_bugzilla(&mock).await;
    let served = exporting_server(&mock, Some(&dead_endpoint())).await;

    let result = call(&served.client, "bug_info", json!({ "bug_ids": [7] }), None).await;
    assert_ne!(
        result.is_error,
        Some(true),
        "the open fail mode keeps serving through a collector outage"
    );
    // The failed delivery puts the SINK into failure — the same state a
    // failed file write produces, feeding the same gate.
    wait_failing(&served.audit, true).await;

    // A later call is still served under `open`, and its record's write
    // is preceded by an audit_gap accounting for the undelivered copies.
    let again = call(&served.client, "bug_info", json!({ "bug_ids": [7] }), None).await;
    assert_ne!(again.is_error, Some(true));
    let lines = audit_lines(served.file());
    assert!(
        lines
            .iter()
            .filter(|l| l.contains("\"event\":\"tool_call\""))
            .count()
            >= 2,
        "the file keeps every record through an export outage: {lines:?}"
    );
    assert!(
        lines
            .iter()
            .any(|l| l.contains("\"event\":\"audit_gap\"") && l.contains("\"write_error\"")),
        "the undelivered window must be accounted in an audit_gap: {lines:?}"
    );
    // Audit losses are gap-accounted, not drop-counted: the drop counter
    // is the diagnostics stream's alone.
    let pipeline = served.pipeline.clone().expect("export is on");
    assert_eq!(
        pipeline.dropped(),
        0,
        "audit records must never ride the diagnostics drop counter"
    );

    // Shutdown returns rather than waiting on a collector that is gone.
    let started = std::time::Instant::now();
    pipeline.shutdown().await;
    assert!(
        started.elapsed() < Duration::from_secs(30),
        "the shutdown flush must be bounded"
    );
}

#[tokio::test]
async fn a_mid_serve_collector_death_gates_uniformly_and_recovery_clears() {
    // The task list's core scenario: collector dies while serving under
    // `closed_all` (the http default) → uniform-text refusals; collector
    // recovers → the gate reopens and the gap record accounts the window.
    let mock = MockServer::start().await;
    mount_bugzilla(&mock).await;
    let collector = MockServer::start().await;
    mount_collector(&collector).await;

    let served = server_with_sinks(&mock, Some(&collector.uri()), true, FailMode::ClosedAll).await;
    let ok = call(&served.client, "bug_info", json!({ "bug_ids": [7] }), None).await;
    assert_ne!(ok.is_error, Some(true), "a healthy collector serves");
    exported(&collector).await;

    // The collector dies mid-serve: every post is now refused (404).
    collector.reset().await;
    // Force a delivery attempt so the outage is noticed without waiting
    // for organic traffic (served or refused depending on how the reset
    // races the last flush — either way it queues delivery work), then
    // wait for the sink to report failure.
    let _racing = call(&served.client, "bug_info", json!({ "bug_ids": [7] }), None).await;
    wait_failing(&served.audit, true).await;

    // Refused with the tool's uniform failure text — the same wording a
    // failing FILE produces, chosen by tool name alone (no fingerprint).
    let refused = call(&served.client, "bug_info", json!({ "bug_ids": [7] }), None).await;
    assert_eq!(refused.is_error, Some(true));
    assert_eq!(
        text_of(&refused),
        "Failed to fetch bug information",
        "an OTLP outage must reuse the audit gate's uniform refusal text"
    );

    // Recovery. The refusal above was recorded and queued; once the
    // collector answers again the queue flushes, delivery health clears,
    // and — exactly as with a recovered file — the first call after
    // recovery writes the audit_gap and reopens the gate.
    mount_collector(&collector).await;
    let edge = call(&served.client, "bug_info", json!({ "bug_ids": [7] }), None).await;
    // The edge call may still be refused (it is what carries the gap
    // record out); after it the sink must clear within the batch bound.
    let _ = edge;
    wait_failing(&served.audit, false).await;
    let after = call(&served.client, "bug_info", json!({ "bug_ids": [7] }), None).await;
    assert_ne!(
        after.is_error,
        Some(true),
        "recovered delivery must reopen the gate"
    );
    let lines = audit_lines(served.file());
    assert!(
        lines
            .iter()
            .any(|l| l.contains("\"event\":\"audit_gap\"") && l.contains("\"write_error\"")),
        "the undelivered window must be accounted in an audit_gap: {lines:?}"
    );
}

#[tokio::test]
async fn an_otlp_only_server_serves_and_creates_no_file() {
    let mock = MockServer::start().await;
    mount_bugzilla(&mock).await;
    let collector = MockServer::start().await;
    mount_collector(&collector).await;

    // Fileless sink under the strictest fail mode: with the collector
    // healthy, serving works and every record goes to the collector.
    let served = server_with_sinks(&mock, Some(&collector.uri()), false, FailMode::ClosedAll).await;
    let result = call(&served.client, "bug_info", json!({ "bug_ids": [7] }), None).await;
    assert_ne!(result.is_error, Some(true), "an OTLP-only server serves");

    let requests = exported(&collector).await;
    let records: Vec<_> = requests
        .iter()
        .flat_map(|r| decode_records(&r.body))
        .collect();
    assert!(
        records
            .iter()
            .any(|r| r.attrs.get("bugwarden.event").map(String::as_str) == Some("tool_call")),
        "the tool call must reach the collector"
    );
    assert!(
        records
            .iter()
            .any(|r| r.attrs.get("bugwarden.event").map(String::as_str) == Some("initialize")),
        "the handshake must reach the collector"
    );

    // No file created anywhere: the sink has no path and the working
    // directory it could have written into holds nothing.
    assert!(served.audit_path.is_none());
    assert_eq!(
        std::fs::read_dir(served.dir.path())
            .expect("the tempdir is readable")
            .count(),
        0,
        "an OTLP-only sink must touch no filesystem"
    );
}

#[tokio::test]
async fn the_startup_probe_retries_until_a_racing_collector_answers() {
    // A collector that starts alongside the server may lose the race by
    // a few seconds; the probe's bounded retry absorbs that, and only a
    // collector that never answers refuses startup (unit-tested in
    // `otel.rs` with the refusal's wording).
    let collector = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/logs"))
        .respond_with(ResponseTemplate::new(503))
        .up_to_n_times(2)
        .mount(&collector)
        .await;
    mount_collector(&collector).await;

    let cfg = bugwarden::otel::resolve(&OtelEnv {
        endpoint: Some(collector.uri()),
        ..OtelEnv::default()
    })
    .expect("the endpoint must resolve")
    .expect("an endpoint means export is on");
    let pipeline = Arc::new(Pipeline::start(cfg).expect("the pipeline must start"));
    pipeline
        .probe()
        .await
        .expect("bounded retry must outlast a boot race");
    assert!(
        collector
            .received_requests()
            .await
            .expect("request recording is on")
            .len()
            >= 3,
        "the probe must have retried through the failures"
    );
    pipeline.shutdown().await;
}

#[tokio::test]
async fn without_an_endpoint_nothing_is_exported() {
    // The off switch is the absence of a configuration: `resolve` returns
    // nothing, so main builds no pipeline, and a sink with no exporter
    // attached reaches no collector even when one is listening.
    assert!(
        bugwarden::otel::resolve(&OtelEnv::default())
            .expect("an empty environment resolves")
            .is_none(),
        "no endpoint must mean no export configuration"
    );
    assert!(
        bugwarden::otel::resolve(&OtelEnv {
            endpoint: Some(String::new()),
            ..OtelEnv::default()
        })
        .expect("an emptied endpoint resolves")
        .is_none(),
        "an emptied endpoint must mean no export configuration"
    );

    let mock = MockServer::start().await;
    mount_bugzilla(&mock).await;
    let collector = MockServer::start().await;
    mount_collector(&collector).await;

    let served = exporting_server(&mock, None).await;
    assert!(served.pipeline.is_none(), "no exporter is attached");
    call(&served.client, "bug_info", json!({ "bug_ids": [7] }), None).await;
    assert!(
        audit_lines(served.file())
            .iter()
            .any(|l| l.contains("\"event\":\"tool_call\"")),
        "the record is still written to the file"
    );

    // Long enough that an exporter running at the batch interval would
    // have sent something.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert!(
        collector
            .received_requests()
            .await
            .expect("request recording is on")
            .is_empty(),
        "with export off the collector must never be contacted"
    );
}
