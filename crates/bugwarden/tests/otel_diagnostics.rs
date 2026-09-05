//! The diagnostics half of the OTLP export (issue #31).
//!
//! ONE test on purpose, in a test binary of its own: the layer under test
//! only works through a process-wide `tracing` subscriber, and a process
//! has exactly one. Put new diagnostics cases inside this test rather than
//! beside it, and keep this file free of anything else.
//!
//! The subscriber here runs at `debug`, not `info`, and that is the point
//! rather than an accident: the export's own HTTP stack only becomes
//! talkative at debug, and the feedback loop it can start is invisible at
//! any lower level.
//!
//! Coverage contract (each of these mutations must fail this test):
//! - dropping the OTLP layer from the subscriber, or never filling its
//!   pipeline slot;
//! - exporting an event's message without its fields;
//! - forwarding this module's OWN diagnostics, which would make a failing
//!   exporter its own source of records to export;
//! - narrowing the skip back to this module's target, which lets the
//!   exporter's `reqwest`/`hyper` events be exported and turns one flush
//!   into an endless self-feeding one;
//! - exporting a field's value without the sink's per-field budget or
//!   without its escaping (#260, #266) — the collector is reached by the
//!   same rmcp lines stderr is, and a bound only stderr has is not one;
//! - swapping which of `message` and the other fields leads the body,
//!   on either the `Debug` path or the `&str` one;
//! - dropping the separator a second body field opens with, which a
//!   one-field record cannot see.

use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use bugwarden::otel::{OtelEnv, Pipeline};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;
use tracing_subscriber::EnvFilter;

/// Bodies posted to the collector, newest last.
type Posted = Arc<Mutex<Vec<Vec<u8>>>>;

/// The sink's per-field cap, spelled out: a test that reads the constant
/// it is testing agrees with any value.
const CAP: usize = 1024;

/// The byte a terminal reads as the start of a control sequence.
const ESC: char = '\u{1b}';

/// A collector that answers OTLP posts and LOGS NOTHING ITSELF.
///
/// Deliberately hand-rolled rather than a `MockServer`: this test asserts
/// that an idle server stops exporting, and wiremock runs in this process
/// and logs a line per request through the `log` crate, which would appear
/// in the export as a record and feed exactly the loop under test. A real
/// deployment's collector is another process and contributes no events
/// here, so a socket that answers and says nothing is the faithful stand-in.
async fn silent_collector() -> (String, Posted) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a free port");
    let addr = listener.local_addr().expect("an address");
    let posted: Posted = Arc::new(Mutex::new(Vec::new()));
    let sink = posted.clone();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let sink = sink.clone();
            tokio::spawn(async move {
                let mut buf: Vec<u8> = Vec::new();
                let mut chunk = [0u8; 8192];
                // Keep-alive: reqwest reuses the connection, so one task
                // serves however many requests arrive on it.
                loop {
                    let head_end = loop {
                        if let Some(at) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            break at + 4;
                        }
                        match stream.read(&mut chunk).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        }
                    };
                    let head = String::from_utf8_lossy(&buf[..head_end]).to_ascii_lowercase();
                    let len = head
                        .split("content-length:")
                        .nth(1)
                        .and_then(|rest| rest.split("\r\n").next())
                        .and_then(|value| value.trim().parse::<usize>().ok())
                        .unwrap_or(0);
                    while buf.len() < head_end + len {
                        match stream.read(&mut chunk).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        }
                    }
                    sink.lock()
                        .expect("the posted-bodies lock")
                        .push(buf[head_end..head_end + len].to_vec());
                    if stream
                        .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n")
                        .await
                        .is_err()
                    {
                        return;
                    }
                    buf.drain(..head_end + len);
                }
            });
        }
    });
    (format!("http://{addr}"), posted)
}

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
                let (_, used) = read_varint(&buf[i..]).expect("a varint");
                out.push((field, wire_type, buf[i..i + used].to_vec()));
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

/// `(body, attributes)` of every log record in an
/// `ExportLogsServiceRequest`.
fn decode(payload: &[u8]) -> Vec<(String, Vec<(String, String)>)> {
    let mut out = Vec::new();
    for resource_logs in every(payload, 1) {
        for scope_logs in every(&resource_logs, 2) {
            for record in every(&scope_logs, 2) {
                let body = String::from_utf8(
                    first(&first(&record, 5).expect("a body"), 1).expect("a string body"),
                )
                .expect("a utf-8 body");
                let attrs = every(&record, 6)
                    .into_iter()
                    .map(|kv| {
                        let key = String::from_utf8(first(&kv, 1).expect("a key")).expect("utf-8");
                        let value = first(&kv, 2)
                            .and_then(|any| first(&any, 1))
                            .map(|s| String::from_utf8(s).expect("utf-8"))
                            .unwrap_or_default();
                        (key, value)
                    })
                    .collect();
                out.push((body, attrs));
            }
        }
    }
    out
}

#[tokio::test]
async fn the_servers_diagnostics_reach_the_collector_but_the_exporters_own_do_not() {
    let (endpoint, posted) = silent_collector().await;

    // The subscriber under test: the OTLP layer beside the filter, exactly
    // the shape `main` installs when export is on.
    let slot: Arc<OnceLock<Arc<Pipeline>>> = Arc::new(OnceLock::new());
    // `init()` and not `set_global_default`, because it is what `main`
    // calls and because it also installs the `log` bridge: reqwest and
    // hyper log through `log`, so without the bridge their events would
    // never reach the layer and the assertions below would hold
    // vacuously.
    tracing_subscriber::registry()
        // debug, so the exporter's own HTTP stack is loud enough to feed
        // itself if the skip below does not stop it.
        .with(EnvFilter::new("debug"))
        .with(Pipeline::diagnostics_layer(slot.clone()))
        .init();

    // Before the pipeline exists the layer is inert; this event is emitted
    // into an empty slot and must simply be dropped rather than panic.
    tracing::info!("otel-diagnostics-before-start");

    let cfg = bugwarden::otel::resolve(&OtelEnv {
        endpoint: Some(endpoint),
        ..OtelEnv::default()
    })
    .expect("the endpoint must resolve")
    .expect("an endpoint means export is on");
    let pipeline = Arc::new(Pipeline::start(cfg).expect("the pipeline must start"));
    slot.set(pipeline.clone()).expect("the slot fills once");

    tracing::info!(answer = 42, "otel-diagnostics-probe");
    // The body answers to the same per-field bound and the same escaping
    // the stderr layer applies (#260, #266). Multi-byte after the ESC, so
    // a byte budget cannot pass for a character one.
    let over_cap = format!("{ESC}{}", "é".repeat(CAP * 4));
    // Two fields, so the assertion below also pins that a cut field
    // leaves the separator and the field after it intact.
    tracing::info!(probe = %over_cap, next = "after", "otel-diagnostics-cap-probe");
    // A `&str` value reaches the visitor through `record_str`, not
    // `record_debug`, and only an explicit `message` field takes that
    // path for the body's leading text — so this is the one shape that
    // tells the two apart.
    tracing::info!(
        message = "otel-diagnostics-str-probe",
        tag = "reached-as-a-str"
    );
    // What the exporter says about itself never goes on the wire: this is
    // the shape of the drop warning, and exporting it would feed a failing
    // exporter its own failures.
    tracing::warn!(target: "bugwarden::otel", "otel-diagnostics-self-target");
    // And what its HTTP stack says about itself, which is the expensive
    // case. These are the real shapes: `hyper_util`'s pool line carries
    // the collector authority, and both are emitted on every flush, so
    // exporting them makes each flush the cause of the next one. Emitted
    // synthetically as well as by the live client, so the assertion does
    // not depend on the timing of a real connection.
    tracing::debug!(
        target: "hyper_util::client::legacy::pool",
        "pooling idle connection for otel-diagnostics-http-stack"
    );
    tracing::debug!(target: "reqwest::connect", "starting new connection 'otel-diagnostics-http-stack'");
    tracing::debug!(target: "rustls::client::hs", "otel-diagnostics-http-stack");
    tracing::debug!(target: "h2::codec::framed_write", "otel-diagnostics-http-stack");
    tracing::debug!(target: "tower::buffer::worker", "otel-diagnostics-http-stack");

    let bodies = {
        let mut found = Vec::new();
        for _ in 0..80 {
            found = posted.lock().expect("the posted-bodies lock").clone();
            if !found.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(
            !found.is_empty(),
            "no diagnostics export reached the collector within 8s"
        );
        found
    };

    let records: Vec<_> = bodies.iter().flat_map(|body| decode(body)).collect();
    let probe = records
        .iter()
        .find(|(body, _)| body.contains("otel-diagnostics-probe"))
        .expect("the diagnostic must be exported");
    assert!(
        probe.0.contains("answer=42"),
        "an event's fields must survive into the body, not just its message: {:?}",
        probe.0
    );
    assert!(
        probe
            .1
            .iter()
            .any(|(k, v)| k == "bugwarden.stream" && v == "diagnostics"),
        "the diagnostics stream must be tagged apart from the audit one: {:?}",
        probe.1
    );
    assert!(
        probe.1.iter().any(|(k, _)| k == "log.target"),
        "the emitting target must ride along: {:?}",
        probe.1
    );

    let by_str = records
        .iter()
        .find(|(body, _)| body.contains("otel-diagnostics-str-probe"))
        .expect("the record_str diagnostic must be exported");
    assert_eq!(
        by_str.0, "otel-diagnostics-str-probe tag=reached-as-a-str",
        "a `&str` message leads the body and a `&str` field follows it \
         as `name=value`, the same way a `Debug` one does"
    );

    let capped = records
        .iter()
        .find(|(body, _)| body.starts_with("otel-diagnostics-cap-probe"))
        .expect("the capped diagnostic must be exported");
    assert_eq!(
        capped.0,
        format!(
            "otel-diagnostics-cap-probe probe=\\x1b{} next=after",
            "é".repeat(CAP - 1)
        ),
        "the body's field is cut at {CAP} characters as handed in, the \
         ESC among them and escaped on the way out, and the field after \
         it still opens with its own separator"
    );

    assert!(
        !records
            .iter()
            .any(|(body, _)| body.contains("otel-diagnostics-self-target")),
        "the exporter's own diagnostics must never be exported: {records:?}"
    );
    assert!(
        !records
            .iter()
            .any(|(body, _)| body.contains("otel-diagnostics-before-start")),
        "an event emitted before the pipeline existed cannot be exported: {records:?}"
    );

    // The export stack's own chatter never rides the export. Checked two
    // ways: by the marker the synthetic events carry, and by the target
    // attribute of every record that arrived — which also catches the
    // LIVE client's events, whose text this test does not control.
    assert!(
        !records
            .iter()
            .any(|(body, _)| body.contains("otel-diagnostics-http-stack")),
        "the export's own HTTP stack must never be exported: {records:?}"
    );
    for (body, attrs) in &records {
        let target = attrs
            .iter()
            .find(|(k, _)| k == "log.target")
            .map(|(_, v)| v.as_str())
            .unwrap_or_default();
        assert!(
            ![
                "bugwarden::otel",
                "reqwest",
                "hyper",
                "rustls",
                "h2",
                "tower"
            ]
            .iter()
            .any(|prefix| target.starts_with(prefix)),
            "a record from the export's own stack reached the collector: \
             target {target:?}, body {body:?}"
        );
    }

    // And the loop is dead, not merely quiet: with the export stack's
    // events exported, every flush logs and those lines become the next
    // batch, so an idle server posts forever at the batch interval. Four
    // intervals of silence is the evidence that nothing feeds itself.
    let settled = posted.lock().expect("the posted-bodies lock").len();
    tokio::time::sleep(Duration::from_millis(2500)).await;
    let after_idle = posted.lock().expect("the posted-bodies lock").len();
    assert_eq!(
        after_idle,
        settled,
        "an idle server must stop exporting; {} further request(s) means a flush \
         is producing the records for the next one",
        after_idle - settled
    );

    pipeline.shutdown().await;
}
