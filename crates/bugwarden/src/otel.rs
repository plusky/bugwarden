//! OTLP export of the audit stream and of the server's own diagnostics
//! (issue #31).
//!
//! Revised 2026-08-18: a configured collector is a LOAD-BEARING audit
//! sink, not a best-effort copy. Delivery is proven at startup
//! ([`Pipeline::probe`], bounded retry, refusing to serve on failure) and
//! watched while serving: a delivery failure or a refused record marks
//! the audit sink failing ([`AuditExport::delivery_failing`]), which feeds
//! the same [`FailMode`] gate a failed file write does, until a delivery
//! succeeds again. When a file is also configured, the record still
//! reaches it FIRST and the exporter only afterwards.
//!
//! Only the DIAGNOSTICS stream stays best-effort: a dropped log line is
//! counted and never halts the guard. Neither stream changes what a
//! client sees on a served call (I15) — the gate refusals are the
//! audit machinery's own, uniform per tool.
//!
//! # What is exported
//!
//! Two streams, tagged apart by the `bugwarden.stream` attribute:
//!
//! - `audit` — one OTel log record per [`AuditEvent`] the sink persisted.
//!   The record body is the audit line VERBATIM — when a file is
//!   configured, the same bytes it carries minus the newline, so the
//!   exported payload and the file record are byte-equal (I12: nothing
//!   extra is exported, and nothing is exported that the file does not
//!   hold); a fileless (OTLP-only) sink exports the line it would have
//!   written.
//! - `diagnostics` — the server's ordinary `tracing` output, the same
//!   events the stderr layer formats, under the same `RUST_LOG` filter.
//!
//! # Transport
//!
//! OTLP/HTTP with protobuf payloads, posted with the workspace's existing
//! reqwest/rustls stack. The protobuf encoder below is hand-written
//! against the OTLP logs schema; the alternative — the OpenTelemetry SDK —
//! was measured and rejected, see `docs/DESIGN.md`.
//!
//! # Secrets (I12)
//!
//! [`OTEL_EXPORTER_OTLP_HEADERS`] carries whatever credential the
//! collector wants, so it is treated exactly like the http bearer tokens:
//! read from the environment only, never a command-line option, and no
//! type that holds it derives `Debug`. The resolved endpoint is weaker:
//! this crate never writes it to a log line, an error, or an audit
//! record, but at `RUST_LOG=debug` the HTTP stack may print the
//! authority. That is why the drop diagnostic carries a count and a
//! closed-vocabulary reason and nothing else, and why a failed request's
//! `reqwest::Error` — which would carry the URL — is discarded rather
//! than logged.
//!
//! [`AuditEvent`]: crate::audit::AuditEvent
//! [`AuditExport::delivery_failing`]: crate::audit::AuditExport::delivery_failing
//! [`FailMode`]: crate::audit::FailMode
//! [`OTEL_EXPORTER_OTLP_HEADERS`]: crate::otel::HEADERS_VAR
//! [`Pipeline::probe`]: crate::otel::Pipeline::probe

use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use tracing_subscriber::layer::Context as LayerContext;
use tracing_subscriber::Layer;

use crate::audit::{AuditEvent, AuditEventKind, AuditExport, ExportRefused};

/// Collector base URL; [`LOGS_PATH`] is appended to it. Unset or empty —
/// with [`LOGS_ENDPOINT_VAR`] unset or empty too — turns the whole feature
/// off.
pub const ENDPOINT_VAR: &str = "OTEL_EXPORTER_OTLP_ENDPOINT";

/// Comma-separated `key=value` headers added to every export request.
/// Secret material (I12).
pub const HEADERS_VAR: &str = "OTEL_EXPORTER_OTLP_HEADERS";

/// OTLP transport selector; this build speaks [`PROTOCOL_HTTP_PROTOBUF`]
/// and rejects every other value at startup.
pub const PROTOCOL_VAR: &str = "OTEL_EXPORTER_OTLP_PROTOCOL";

/// `service.name` on the exported resource; defaults to `bugwarden`.
pub const SERVICE_NAME_VAR: &str = "OTEL_SERVICE_NAME";

/// Logs-specific endpoint. Per the OTLP specification it OVERRIDES
/// [`ENDPOINT_VAR`] and is used as given — the signal path is NOT appended,
/// because the operator wrote the whole URL.
pub const LOGS_ENDPOINT_VAR: &str = "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT";

/// Logs-specific headers; overrides [`HEADERS_VAR`]. Secret material (I12).
pub const LOGS_HEADERS_VAR: &str = "OTEL_EXPORTER_OTLP_LOGS_HEADERS";

/// Logs-specific protocol; overrides [`PROTOCOL_VAR`].
pub const LOGS_PROTOCOL_VAR: &str = "OTEL_EXPORTER_OTLP_LOGS_PROTOCOL";

/// Every environment variable this module reads.
///
/// These are read by the module, not by `Cli`, so clap's own
/// `get_env` sweep cannot see them. `tests/binary_user_agent.rs` holds its
/// environment scrub list to this list as well, so a variable added here
/// cannot go on reaching a spawned test binary from the developer's shell.
pub const ENV_VARS: [&str; 7] = [
    ENDPOINT_VAR,
    HEADERS_VAR,
    PROTOCOL_VAR,
    SERVICE_NAME_VAR,
    LOGS_ENDPOINT_VAR,
    LOGS_HEADERS_VAR,
    LOGS_PROTOCOL_VAR,
];

/// The one OTLP transport this build speaks.
pub const PROTOCOL_HTTP_PROTOBUF: &str = "http/protobuf";

/// `service.name` when [`SERVICE_NAME_VAR`] says nothing.
const DEFAULT_SERVICE_NAME: &str = "bugwarden";

/// Signal path appended to the configured base endpoint, per the OTLP
/// specification for `OTEL_EXPORTER_OTLP_ENDPOINT`.
const LOGS_PATH: &str = "/v1/logs";

/// Records the queue holds before it starts dropping. Bounded on purpose:
/// an unreachable collector must cost a bounded amount of memory and a
/// counter, never unbounded growth behind a socket nobody is reading.
const QUEUE_CAPACITY: usize = 2048;

/// Most records in one export request.
const MAX_BATCH: usize = 512;

/// How long the exporter waits for a batch to fill before sending what it
/// has.
const BATCH_INTERVAL: Duration = Duration::from_millis(500);

/// Bound on a single export request, so a collector that accepts a
/// connection and then stalls cannot pin the exporter task forever.
const EXPORT_TIMEOUT: Duration = Duration::from_secs(10);

/// Bound on the best-effort flush at shutdown. Long enough for a live
/// collector to take the tail of the queue, short enough that a dead one
/// does not hold the process open.
pub const SHUTDOWN_FLUSH_TIMEOUT: Duration = Duration::from_secs(5);

/// Startup probe attempts before the deployment refuses to start
/// ([`Pipeline::probe`]). Bounded retry, not one shot: a collector and a
/// server that start together race, and losing that race by half a second
/// is not a misconfiguration.
const PROBE_ATTEMPTS: u32 = 5;

/// Base backoff between probe attempts; attempt `n` waits `n` times this,
/// so the five attempts span about five seconds of sleep (each attempt
/// itself bounded by [`EXPORT_TIMEOUT`]).
const PROBE_BACKOFF: Duration = Duration::from_millis(500);

/// This module's own tracing target — the first entry of
/// [`NEVER_EXPORTED_TARGETS`], named once so the probe record and the
/// skip list cannot drift apart.
const SELF_TARGET: &str = "bugwarden::otel";

/// Target prefixes whose events are never exported.
///
/// Exporting these would make the export its own input. This module's own
/// drop warning is the obvious case, but the expensive one is the HTTP
/// stack underneath: at `RUST_LOG=debug` a single flush makes
/// `hyper_util`'s connection pool log "pooling idle connection for
/// <authority>" and `reqwest::connect` log "starting new connection", each
/// of which would become a record in the NEXT batch, whose flush logs
/// again — a loop that sustains itself at one export per batch interval
/// forever, on an idle server, and puts the collector authority on the
/// wire as a side effect.
///
/// Matched as prefixes against the event target, which for the log-crate
/// events `tracing-log` forwards is the emitting module path
/// (`hyper_util::client::legacy::pool`, `reqwest::connect`). `"hyper"`
/// therefore covers `hyper_util` as well.
///
/// The cost is real and accepted: these targets also carry the BUGZILLA
/// client's HTTP diagnostics, and those stop being exported too. They
/// still reach stderr, which is where a debugging operator reads them, and
/// no filter that can tell the two clients apart exists at the layer —
/// both are the same crates on the same targets.
const NEVER_EXPORTED_TARGETS: [&str; 6] = [
    SELF_TARGET,
    "reqwest",
    // Covers `hyper_util` too.
    "hyper",
    "rustls",
    "h2",
    "tower",
];

/// Whether an event's target is one the export must never carry.
fn never_exported(target: &str) -> bool {
    NEVER_EXPORTED_TARGETS
        .iter()
        .any(|prefix| target.starts_with(prefix))
}

/// Instrumentation scope name on every exported record.
const SCOPE_NAME: &str = "bugwarden";

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// What the four OTLP variables held when the process started.
///
/// A plain struct rather than a direct read of `std::env`, so resolution is
/// a function of its argument and a test states its own world instead of
/// mutating the process. No `Debug`: [`OtelEnv::headers`] is secret (I12).
#[derive(Default, Clone)]
pub struct OtelEnv {
    /// [`ENDPOINT_VAR`], if it held anything.
    pub endpoint: Option<String>,
    /// [`HEADERS_VAR`], if it held anything. Secret.
    pub headers: Option<String>,
    /// [`PROTOCOL_VAR`], if it held anything.
    pub protocol: Option<String>,
    /// [`SERVICE_NAME_VAR`], if it held anything.
    pub service_name: Option<String>,
    /// [`LOGS_ENDPOINT_VAR`], if it held anything. Overrides `endpoint`.
    pub logs_endpoint: Option<String>,
    /// [`LOGS_HEADERS_VAR`], if it held anything. Overrides `headers`.
    /// Secret.
    pub logs_headers: Option<String>,
    /// [`LOGS_PROTOCOL_VAR`], if it held anything. Overrides `protocol`.
    pub logs_protocol: Option<String>,
}

impl OtelEnv {
    /// Read the four variables out of the process environment.
    ///
    /// A variable set to the empty string counts as one that was never set,
    /// the same "cleared" idiom unit files and container specs use for
    /// `BUGZILLA_API_KEY_FILE` and `MCP_ALLOWED_HOSTS`. For
    /// [`ENDPOINT_VAR`] that idiom is the off switch.
    #[must_use]
    pub fn from_env() -> Self {
        Self {
            endpoint: env_value(ENDPOINT_VAR),
            headers: env_value(HEADERS_VAR),
            protocol: env_value(PROTOCOL_VAR),
            service_name: env_value(SERVICE_NAME_VAR),
            logs_endpoint: env_value(LOGS_ENDPOINT_VAR),
            logs_headers: env_value(LOGS_HEADERS_VAR),
            logs_protocol: env_value(LOGS_PROTOCOL_VAR),
        }
    }
}

/// One environment variable, with the empty string read as absence.
fn env_value(var: &str) -> Option<String> {
    match std::env::var(var) {
        Ok(value) if !value.is_empty() => Some(value),
        _ => None,
    }
}

/// A resolved, usable export configuration.
///
/// No `Debug` and no accessor for the endpoint or the headers: the only
/// code that may see either is the exporter task that puts them on the
/// wire (I12).
#[derive(Clone)]
pub struct ExportConfig {
    /// Full URL of the logs endpoint, base plus [`LOGS_PATH`].
    logs_url: String,
    /// Headers added to every request. Secret.
    headers: Vec<(String, String)>,
    /// `service.name` for the exported resource.
    service_name: String,
    /// Which endpoint variable actually won. Named in probe refusals
    /// (I12: the name, never the URL).
    endpoint_var: &'static str,
    /// Which headers variable actually won. Named in probe refusals.
    headers_var: &'static str,
}

impl ExportConfig {
    /// The `service.name` records are exported under. Safe to log — it is
    /// operator-chosen labelling, not credential material.
    #[must_use]
    pub fn service_name(&self) -> &str {
        &self.service_name
    }

    /// The resolved logs URL. Crate-visible for this module's own tests;
    /// nothing in the request path may print it (I12).
    #[cfg(test)]
    pub(crate) fn logs_url(&self) -> &str {
        &self.logs_url
    }

    /// The resolved headers. Crate-visible for this module's own tests.
    #[cfg(test)]
    pub(crate) fn headers(&self) -> &[(String, String)] {
        &self.headers
    }
}

/// Resolve the environment into an export configuration, or into `None`
/// when export is off.
///
/// Off is the default and the whole feature: with no endpoint set — from
/// either [`ENDPOINT_VAR`] or [`LOGS_ENDPOINT_VAR`], and an emptied
/// variable counts as unset — this returns `None`, no exporter task is
/// started, no diagnostics layer is installed, and the process behaves
/// exactly as a build without this module. That is also why the protocol
/// is validated only once an endpoint exists: a fleet-wide
/// `OTEL_EXPORTER_OTLP_*` environment must not refuse to start a
/// deployment that exports nothing.
///
/// The three logs-specific variables override their general counterparts,
/// as the OTLP specification requires. [`LOGS_ENDPOINT_VAR`] is used
/// exactly as given — [`LOGS_PATH`] is appended only to [`ENDPOINT_VAR`],
/// because the signal-specific form is the operator's whole URL.
///
/// # Errors
///
/// - A protocol naming anything but [`PROTOCOL_HTTP_PROTOBUF`].
/// - An endpoint that is not an `http://` or `https://` URL.
/// - A header entry that is not a usable `key=value` HTTP header.
///
/// Every message names the variable that carried the offending value —
/// the specific one where it was the specific one that lost — and, for a
/// header list, the position of the offending entry, never a value: a
/// mispasted credential is exactly what lands in the wrong position
/// (I12).
pub fn resolve(env: &OtelEnv) -> anyhow::Result<Option<ExportConfig>> {
    // The logs-specific variable wins where it is set, and is used as the
    // operator wrote it — the signal path is appended only to the general
    // one. Honouring it is not optional decoration: a fleet that sets only
    // `_LOGS_ENDPOINT` is a fleet that expects logs to be exported, and
    // reading just the general variable would leave export silently off.
    let (endpoint_var, endpoint, append_path) = match logs_override(env.logs_endpoint.as_deref()) {
        Some(endpoint) => (LOGS_ENDPOINT_VAR, endpoint, false),
        None => (
            ENDPOINT_VAR,
            env.endpoint.as_deref().unwrap_or_default().trim(),
            true,
        ),
    };
    if endpoint.is_empty() {
        return Ok(None);
    }
    let (protocol_var, protocol) = match logs_override(env.logs_protocol.as_deref()) {
        Some(protocol) => (LOGS_PROTOCOL_VAR, Some(protocol)),
        None => (PROTOCOL_VAR, env.protocol.as_deref().map(str::trim)),
    };
    match protocol {
        None | Some(PROTOCOL_HTTP_PROTOBUF) => {}
        Some(_) => anyhow::bail!(
            "{protocol_var} selects an OTLP transport this build does not speak; \
             only \"{PROTOCOL_HTTP_PROTOBUF}\" is supported"
        ),
    }
    if !(endpoint.starts_with("http://") || endpoint.starts_with("https://")) {
        anyhow::bail!("{endpoint_var} must be an http:// or https:// URL");
    }
    let (headers_var, raw_headers) = match logs_override(env.logs_headers.as_deref()) {
        Some(raw) => (LOGS_HEADERS_VAR, Some(raw)),
        None => (HEADERS_VAR, env.headers.as_deref()),
    };
    let headers = match raw_headers {
        Some(raw) => parse_headers(headers_var, raw)?,
        None => Vec::new(),
    };
    let service_name = match env.service_name.as_deref().map(str::trim) {
        Some(name) if !name.is_empty() => name.to_owned(),
        _ => DEFAULT_SERVICE_NAME.to_owned(),
    };
    let logs_url = if append_path {
        format!("{}{LOGS_PATH}", endpoint.trim_end_matches('/'))
    } else {
        endpoint.to_owned()
    };
    Ok(Some(ExportConfig {
        logs_url,
        headers,
        service_name,
        endpoint_var,
        headers_var,
    }))
}

/// A signal-specific variable's value, if it holds one. An emptied
/// variable is an unset one here as everywhere, so it falls back to the
/// general variable rather than turning the export off on its own.
fn logs_override(value: Option<&str>) -> Option<&str> {
    match value.map(str::trim) {
        Some(value) if !value.is_empty() => Some(value),
        _ => None,
    }
}

/// Parse `key=value,key=value` into headers, naming `var` in any refusal.
///
/// Empty entries are skipped, so a trailing or doubled comma is not an
/// error — `a=1,` and `a=1,,b=2` parse as the pairs they obviously mean.
///
/// Values are taken VERBATIM. The OTLP specification describes the list as
/// percent-encoded; decoding it here would rewrite any credential
/// containing a `%`, and silently mangling a secret is worse than not
/// implementing an encoding nobody's collector requires. The deviation is
/// deliberate and documented in DESIGN.md.
fn parse_headers(var: &str, raw: &str) -> anyhow::Result<Vec<(String, String)>> {
    let mut headers = Vec::new();
    for (index, entry) in raw.split(',').enumerate() {
        let position = index + 1;
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let Some((key, value)) = entry.split_once('=') else {
            anyhow::bail!("{var} entry {position} is not `key=value`");
        };
        let key = key.trim();
        let value = value.trim();
        if key.is_empty() || !key.bytes().all(is_header_token) {
            anyhow::bail!("{var} entry {position} has no usable header name");
        }
        if value.is_empty()
            || !value
                .bytes()
                .all(|b| b == b'\t' || (0x20..=0x7e).contains(&b))
        {
            anyhow::bail!("{var} entry {position} has no usable header value");
        }
        headers.push((key.to_owned(), value.to_owned()));
    }
    Ok(headers)
}

/// RFC 9110 `token` characters, the alphabet of a header field name.
fn is_header_token(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

// ---------------------------------------------------------------------------
// Records
// ---------------------------------------------------------------------------

/// OTLP severity numbers, at the base of each severity range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Severity {
    Trace = 1,
    Debug = 5,
    Info = 9,
    Warn = 13,
    Error = 17,
}

impl Severity {
    /// The `severity_text` accompanying the number.
    fn text(self) -> &'static str {
        match self {
            Severity::Trace => "TRACE",
            Severity::Debug => "DEBUG",
            Severity::Info => "INFO",
            Severity::Warn => "WARN",
            Severity::Error => "ERROR",
        }
    }

    fn of_level(level: &tracing::Level) -> Severity {
        match *level {
            tracing::Level::TRACE => Severity::Trace,
            tracing::Level::DEBUG => Severity::Debug,
            tracing::Level::INFO => Severity::Info,
            tracing::Level::WARN => Severity::Warn,
            tracing::Level::ERROR => Severity::Error,
        }
    }
}

/// An attribute value; the two shapes the exported streams need.
#[derive(Debug, Clone, PartialEq, Eq)]
enum AttrValue {
    Str(String),
    Int(i64),
}

/// One OTel log record, queued for export.
#[derive(Debug, Clone, PartialEq, Eq)]
struct LogEntry {
    time_unix_nano: u64,
    severity: Severity,
    body: String,
    attrs: Vec<(&'static str, AttrValue)>,
    trace: Option<([u8; 16], [u8; 8])>,
}

/// Wall clock as OTLP wants it.
fn now_unix_nano() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
}

/// Build the log record for one persisted audit event.
///
/// `line` is the record as the file holds it, without the terminating
/// newline; it becomes the record body unchanged (I12: the exported
/// payload carries exactly what the file carries).
fn audit_entry(event: &AuditEvent, line: &[u8]) -> LogEntry {
    let mut attrs: Vec<(&'static str, AttrValue)> = Vec::with_capacity(10);
    attrs.push(("bugwarden.stream", AttrValue::Str("audit".to_owned())));
    let (kind, severity) = match &event.kind {
        AuditEventKind::ToolCall(_) => ("tool_call", Severity::Info),
        AuditEventKind::Initialize(_) => ("initialize", Severity::Info),
        // The one kind that reports a loss of the record stream itself.
        AuditEventKind::AuditGap(_) => ("audit_gap", Severity::Error),
    };
    attrs.push(("bugwarden.event", AttrValue::Str(kind.to_owned())));
    attrs.push((
        "bugwarden.seq",
        AttrValue::Int(i64::try_from(event.seq).unwrap_or(i64::MAX)),
    ));
    attrs.push((
        "bugwarden.transport",
        AttrValue::Str(
            match event.session.transport {
                crate::audit::TransportKind::Stdio => "stdio",
                crate::audit::TransportKind::Http => "http",
            }
            .to_owned(),
        ),
    ));
    if let Some(id) = &event.session.id {
        attrs.push(("bugwarden.session.id", AttrValue::Str(id.clone())));
    }
    let mut trace = None;
    if let AuditEventKind::ToolCall(call) = &event.kind {
        attrs.push(("bugwarden.tool", AttrValue::Str(call.request.tool.clone())));
        if let Some(guard) = &call.guard {
            attrs.push((
                "bugwarden.verdict",
                AttrValue::Str(verdict_name(guard.verdict).to_owned()),
            ));
            if let Some(rule) = &guard.rule {
                attrs.push(("bugwarden.rule", AttrValue::Str(rule.clone())));
            }
        }
        // Projected out of the body so a collector can aggregate response
        // size per tool without parsing every record (issue #145). Left off
        // when the record carries no size, rather than exported as zero.
        if let Some(bytes) = call.outcome.response_bytes {
            attrs.push((
                "bugwarden.response_bytes",
                AttrValue::Int(i64::try_from(bytes).unwrap_or(i64::MAX)),
            ));
        }
        // Correlation ids the client claimed; unauthenticated, exactly as
        // the audit record documents them. Anything that does not decode
        // to the two fixed widths is left off rather than exported wrong.
        if let Some(ctx) = &call.trace {
            if let (Some(t), Some(s)) =
                (hex_bytes::<16>(&ctx.trace_id), hex_bytes::<8>(&ctx.span_id))
            {
                trace = Some((t, s));
            }
        }
    }
    LogEntry {
        time_unix_nano: now_unix_nano(),
        severity,
        body: String::from_utf8_lossy(line).into_owned(),
        attrs,
        trace,
    }
}

/// Wire spelling of a verdict, matching the audit schema's own.
fn verdict_name(verdict: crate::audit::Verdict) -> &'static str {
    match verdict {
        crate::audit::Verdict::Served => "served",
        crate::audit::Verdict::ServedFiltered => "served_filtered",
        crate::audit::Verdict::Denied => "denied",
        crate::audit::Verdict::Refused => "refused",
    }
}

/// Decode exactly `N` bytes of lowercase or uppercase hex, or nothing.
fn hex_bytes<const N: usize>(value: &str) -> Option<[u8; N]> {
    let bytes = value.as_bytes();
    if bytes.len() != N * 2 {
        return None;
    }
    let mut out = [0u8; N];
    for (i, slot) in out.iter_mut().enumerate() {
        let hi = (bytes[i * 2] as char).to_digit(16)?;
        let lo = (bytes[i * 2 + 1] as char).to_digit(16)?;
        *slot = u8::try_from(hi * 16 + lo).ok()?;
    }
    Some(out)
}

// ---------------------------------------------------------------------------
// Protobuf encoding (OTLP logs)
// ---------------------------------------------------------------------------

/// Minimal protobuf writer for the handful of OTLP logs messages this
/// module emits. Field numbers come from
/// `opentelemetry/proto/logs/v1/logs.proto` and
/// `opentelemetry/proto/collector/logs/v1/logs_service.proto`.
mod wire {
    /// Length-delimited wire type.
    pub(super) const LEN: u32 = 2;
    /// 64-bit fixed wire type.
    pub(super) const I64: u32 = 1;
    /// Varint wire type.
    pub(super) const VARINT: u32 = 0;

    pub(super) fn put_varint(buf: &mut Vec<u8>, mut value: u64) {
        loop {
            let byte = u8::try_from(value & 0x7f).unwrap_or(0);
            value >>= 7;
            if value == 0 {
                buf.push(byte);
                return;
            }
            buf.push(byte | 0x80);
        }
    }

    pub(super) fn put_tag(buf: &mut Vec<u8>, field: u32, wire_type: u32) {
        put_varint(buf, u64::from(field << 3 | wire_type));
    }

    pub(super) fn put_bytes(buf: &mut Vec<u8>, field: u32, value: &[u8]) {
        put_tag(buf, field, LEN);
        put_varint(buf, value.len() as u64);
        buf.extend_from_slice(value);
    }

    pub(super) fn put_str(buf: &mut Vec<u8>, field: u32, value: &str) {
        put_bytes(buf, field, value.as_bytes());
    }

    pub(super) fn put_varint_field(buf: &mut Vec<u8>, field: u32, value: u64) {
        put_tag(buf, field, VARINT);
        put_varint(buf, value);
    }

    pub(super) fn put_fixed64(buf: &mut Vec<u8>, field: u32, value: u64) {
        put_tag(buf, field, I64);
        buf.extend_from_slice(&value.to_le_bytes());
    }
}

/// `AnyValue { string_value = 1 }`.
fn encode_any_string(value: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(value.len() + 8);
    wire::put_str(&mut buf, 1, value);
    buf
}

/// `AnyValue { int_value = 3 }`.
fn encode_any_int(value: i64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(12);
    wire::put_varint_field(&mut buf, 3, value as u64);
    buf
}

/// `KeyValue { key = 1, value = 2 }`.
fn encode_kv(key: &str, value: &AttrValue) -> Vec<u8> {
    let encoded = match value {
        AttrValue::Str(s) => encode_any_string(s),
        AttrValue::Int(i) => encode_any_int(*i),
    };
    let mut buf = Vec::with_capacity(key.len() + encoded.len() + 8);
    wire::put_str(&mut buf, 1, key);
    wire::put_bytes(&mut buf, 2, &encoded);
    buf
}

/// `LogRecord`.
fn encode_log_record(entry: &LogEntry) -> Vec<u8> {
    let mut buf = Vec::with_capacity(entry.body.len() + 128);
    wire::put_fixed64(&mut buf, 1, entry.time_unix_nano);
    wire::put_varint_field(&mut buf, 2, entry.severity as u64);
    wire::put_str(&mut buf, 3, entry.severity.text());
    wire::put_bytes(&mut buf, 5, &encode_any_string(&entry.body));
    for (key, value) in &entry.attrs {
        wire::put_bytes(&mut buf, 6, &encode_kv(key, value));
    }
    if let Some((trace_id, span_id)) = &entry.trace {
        wire::put_bytes(&mut buf, 9, trace_id);
        wire::put_bytes(&mut buf, 10, span_id);
    }
    wire::put_fixed64(&mut buf, 11, entry.time_unix_nano);
    buf
}

/// A whole `ExportLogsServiceRequest` for one batch.
fn encode_request(service_name: &str, entries: &[LogEntry]) -> Vec<u8> {
    let mut scope = Vec::new();
    {
        let mut inner = Vec::new();
        wire::put_str(&mut inner, 1, SCOPE_NAME);
        wire::put_str(&mut inner, 2, env!("CARGO_PKG_VERSION"));
        wire::put_bytes(&mut scope, 1, &inner);
    }
    for entry in entries {
        wire::put_bytes(&mut scope, 2, &encode_log_record(entry));
    }

    let mut resource = Vec::new();
    wire::put_bytes(
        &mut resource,
        1,
        &encode_kv("service.name", &AttrValue::Str(service_name.to_owned())),
    );

    let mut resource_logs = Vec::new();
    wire::put_bytes(&mut resource_logs, 1, &resource);
    wire::put_bytes(&mut resource_logs, 2, &scope);

    let mut request = Vec::new();
    wire::put_bytes(&mut request, 1, &resource_logs);
    request
}

// ---------------------------------------------------------------------------
// The exporter
// ---------------------------------------------------------------------------

/// Why records were dropped. A closed vocabulary, for the same reason the
/// audit schema's [`GapReason`] is one: a free-text reason built from a
/// transport error is how an endpoint gets into a log line (I12).
///
/// [`GapReason`]: crate::audit::GapReason
const REASON_QUEUE_FULL: &str = "queue_full";
const REASON_NETWORK: &str = "network";
const REASON_HTTP_STATUS: &str = "http_status";
/// The exporter has shut down and the queue is closed; a record offered
/// after that is lost for a different reason than a full queue, and saying
/// so keeps the vocabulary honest.
const REASON_SHUTDOWN: &str = "shutdown";

/// The running export pipeline: a bounded queue, one task draining it, and
/// the drop accounting.
///
/// Created only when [`resolve`] returned a configuration. `main` starts
/// it after the identity preflight and probes it BEFORE the audit file
/// is created, so a collector that will not take records refuses without
/// leaving a file behind.
pub struct Pipeline {
    /// Audit records. Load-bearing: a record this queue will not take is
    /// REFUSED, never dropped, so the refusal reaches the fail-mode gate.
    audit_tx: mpsc::Sender<LogEntry>,
    /// Diagnostics. Best-effort and deliberately a separate queue: a log
    /// storm must not fill the audit queue and take the server down, and
    /// a dropped diagnostic must not stop the guard.
    diag_tx: mpsc::Sender<LogEntry>,
    /// The client the drain task and the startup probe share.
    client: reqwest::Client,
    cfg: ExportConfig,
    /// DIAGNOSTICS dropped. Audit records are never counted here — they
    /// are never dropped in the first place.
    dropped: Arc<AtomicU64>,
    /// Next drop total that earns a log line; doubles each time, so the
    /// diagnostic appears at 1, 2, 4, 8 … drops and not once per record.
    log_threshold: Arc<AtomicU64>,
    /// Audit records accepted and then not delivered, awaiting the
    /// `audit_gap` that reports them. Read and reset by the sink.
    lost: Arc<AtomicU64>,
    /// Whether delivery is known to work: false from a failed request
    /// until one succeeds. This, not the counter, is what holds the gate
    /// closed for a whole outage.
    healthy: Arc<AtomicBool>,
    shutdown: CancellationToken,
    /// Taken once, by [`Pipeline::shutdown`].
    finished: Mutex<Option<oneshot::Receiver<()>>>,
}

impl fmt::Debug for Pipeline {
    /// Hand-written and deliberately content-free: the pipeline owns the
    /// endpoint and the export headers, and it is reachable from
    /// [`AuditSink`]'s derived `Debug` (I12).
    ///
    /// [`AuditSink`]: crate::audit::AuditSink
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pipeline")
            .field("dropped", &self.dropped.load(Ordering::Relaxed))
            .field("healthy", &self.healthy.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl Pipeline {
    /// Start the exporter: spawn the drain task and return its handle.
    ///
    /// Must be called from within a Tokio runtime. Nothing is delivered
    /// yet and delivery is not yet known to work — [`Pipeline::probe`]
    /// decides that, before the server serves anything.
    ///
    /// # Errors
    ///
    /// The HTTP client could not be built. Reported here rather than
    /// swallowed in the task, because an exporter that can never deliver
    /// must refuse startup, not run.
    pub fn start(cfg: ExportConfig) -> anyhow::Result<Pipeline> {
        let client = reqwest::Client::builder()
            .timeout(EXPORT_TIMEOUT)
            // A 3xx would forward the audit body and any non-Authorization
            // collector credential to a host the operator did not name.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            // The error is dropped rather than reported: a reqwest builder
            // error can name the proxy URL it choked on (I12).
            .map_err(|_| anyhow::anyhow!("the OTLP export HTTP client could not be built"))?;
        let (audit_tx, audit_rx) = mpsc::channel(QUEUE_CAPACITY);
        let (diag_tx, diag_rx) = mpsc::channel(QUEUE_CAPACITY);
        let dropped = Arc::new(AtomicU64::new(0));
        let log_threshold = Arc::new(AtomicU64::new(1));
        let lost = Arc::new(AtomicU64::new(0));
        let healthy = Arc::new(AtomicBool::new(true));
        let shutdown = CancellationToken::new();
        let (done_tx, done_rx) = oneshot::channel();
        let task = ExportTask {
            cfg: cfg.clone(),
            client: client.clone(),
            audit_rx,
            diag_rx,
            dropped: dropped.clone(),
            log_threshold: log_threshold.clone(),
            lost: lost.clone(),
            healthy: healthy.clone(),
            shutdown: shutdown.clone(),
            done: done_tx,
        };
        tokio::spawn(task.run());
        Ok(Pipeline {
            audit_tx,
            diag_tx,
            client,
            cfg,
            dropped,
            log_threshold,
            lost,
            healthy,
            shutdown,
            finished: Mutex::new(Some(done_rx)),
        })
    }

    /// Prove the collector takes records, before the server serves any.
    ///
    /// The same philosophy as the identity preflight: a dependency this
    /// deployment cannot run without is checked while a startup failure
    /// is still a startup failure, rather than discovered as a wave of
    /// refusals under load. One real diagnostics record is posted — not
    /// an empty request, which some collectors accept without looking, and
    /// not an audit record, which would mean inventing an event kind the
    /// schema does not have — so this exercises the whole path: DNS, TCP,
    /// TLS, the headers, the protocol and the collector's own acceptance.
    ///
    /// Bounded retry, because a collector and a server that start together
    /// race, and losing that race by half a second is not a
    /// misconfiguration.
    ///
    /// # Errors
    ///
    /// Every attempt failed. The message names no endpoint and no header
    /// (I12) — the operator knows what they configured; what they need to
    /// be told is that it does not answer.
    pub async fn probe(&self) -> anyhow::Result<()> {
        let entry = LogEntry {
            time_unix_nano: now_unix_nano(),
            severity: Severity::Info,
            body: format!(
                "bugwarden {} starting: audit records are exported to this collector \
                 and the server refuses to serve while they cannot be delivered",
                env!("CARGO_PKG_VERSION")
            ),
            attrs: vec![
                ("bugwarden.stream", AttrValue::Str("diagnostics".to_owned())),
                ("log.target", AttrValue::Str(SELF_TARGET.to_owned())),
            ],
            trace: None,
        };
        let batch = std::slice::from_ref(&entry);
        let mut attempt = 1;
        loop {
            if post_batch(&self.client, &self.cfg, batch).await.is_ok() {
                self.healthy.store(true, Ordering::Relaxed);
                return Ok(());
            }
            if attempt >= PROBE_ATTEMPTS {
                self.healthy.store(false, Ordering::Relaxed);
                anyhow::bail!(
                    "the OTLP collector did not accept the startup record after \
                     {PROBE_ATTEMPTS} attempts; audit records are exported to it and \
                     this deployment refuses to serve without them — check that the \
                     endpoint in {} is reachable and that any credential \
                     in {} is the one it expects",
                    self.cfg.endpoint_var,
                    self.cfg.headers_var,
                );
            }
            tokio::time::sleep(PROBE_BACKOFF * attempt).await;
            attempt += 1;
        }
    }

    /// How many DIAGNOSTICS records this pipeline has dropped. Audit
    /// records never appear here: they are refused or delivered, and a
    /// refusal is the sink's to account for.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Whether delivery is currently known to work. False from a failed
    /// request until one succeeds.
    #[must_use]
    pub fn healthy(&self) -> bool {
        self.healthy.load(Ordering::Relaxed)
    }

    /// This pipeline as one of the audit sink's destinations.
    #[must_use]
    pub fn audit_exporter(self: &Arc<Self>) -> Arc<dyn AuditExport> {
        self.clone()
    }

    /// A tracing layer feeding this pipeline the server's diagnostics.
    #[must_use]
    pub fn diagnostics_layer(slot: Arc<OnceLock<Arc<Pipeline>>>) -> DiagnosticsLayer {
        DiagnosticsLayer { slot }
    }

    /// Stop accepting records, flush what is queued, and return.
    ///
    /// Bounded by [`SHUTDOWN_FLUSH_TIMEOUT`]: a collector that has gone
    /// away costs the timeout once, not the process. Anything still
    /// queued when that expires is lost — see the module docs on what a
    /// fileless deployment does and does not durably keep.
    pub async fn shutdown(&self) {
        self.shutdown.cancel();
        let finished = self
            .finished
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(rx) = finished {
            let _ = tokio::time::timeout(SHUTDOWN_FLUSH_TIMEOUT, rx).await;
        }
    }

    /// Queue one diagnostic, or account for the drop. Never blocks.
    fn emit(&self, entry: LogEntry) {
        let reason = match self.diag_tx.try_send(entry) {
            Ok(()) => return,
            Err(mpsc::error::TrySendError::Full(_)) => REASON_QUEUE_FULL,
            Err(mpsc::error::TrySendError::Closed(_)) => REASON_SHUTDOWN,
        };
        note_drops(&self.dropped, &self.log_threshold, 1, reason);
    }
}

impl AuditExport for Pipeline {
    fn accept(&self, event: &AuditEvent, line: &[u8]) -> Result<(), ExportRefused> {
        match self.audit_tx.try_send(audit_entry(event, line)) {
            Ok(()) => Ok(()),
            Err(_) => {
                // Refused, not dropped. The sink turns this into a failed
                // record and the fail mode decides what the caller sees;
                // marking delivery unhealthy keeps the gate shut until a
                // request actually succeeds, rather than reopening it the
                // moment one queue slot frees up.
                self.healthy.store(false, Ordering::Relaxed);
                Err(ExportRefused)
            }
        }
    }

    fn delivery_failing(&self) -> bool {
        !self.healthy.load(Ordering::Relaxed)
    }

    fn take_lost(&self) -> u64 {
        self.lost.swap(0, Ordering::Relaxed)
    }
}

/// Add `count` drops to the running total and log if the total crossed a
/// power of two.
///
/// The line carries the count and a closed-vocabulary reason and nothing
/// else — no endpoint, no header, no transport error (I12).
fn note_drops(dropped: &AtomicU64, threshold: &AtomicU64, count: u64, reason: &'static str) {
    if count == 0 {
        return;
    }
    let total = dropped.fetch_add(count, Ordering::Relaxed) + count;
    let current = threshold.load(Ordering::Relaxed);
    if total < current {
        return;
    }
    let next = if total.is_power_of_two() {
        total.saturating_mul(2)
    } else {
        total.checked_next_power_of_two().unwrap_or(u64::MAX)
    };
    // A lost race means another reporter is logging this crossing; one
    // line per crossing is the point.
    if threshold
        .compare_exchange(current, next, Ordering::Relaxed, Ordering::Relaxed)
        .is_ok()
    {
        tracing::warn!(
            dropped = total,
            reason,
            "otlp export is dropping diagnostic records"
        );
    }
}

/// Post one batch of entries: the one request path, shared by the drain
/// task and the startup probe so the probe proves exactly what delivery
/// uses — the client, the URL, the headers and the encoding.
///
/// # Errors
///
/// The closed-vocabulary reason. The transport error itself is
/// deliberately dropped rather than returned or logged: it carries the
/// request URL, and the endpoint may not reach a log line (I12, the same
/// rule `.without_url()` exists for).
async fn post_batch(
    client: &reqwest::Client,
    cfg: &ExportConfig,
    batch: &[LogEntry],
) -> Result<(), &'static str> {
    let body = encode_request(&cfg.service_name, batch);
    let mut request = client
        .post(&cfg.logs_url)
        .header("content-type", "application/x-protobuf")
        .body(body);
    for (name, value) in &cfg.headers {
        request = request.header(name.as_str(), value.as_str());
    }
    match request.send().await {
        Ok(response) if response.status().is_success() => Ok(()),
        Ok(_) => Err(REASON_HTTP_STATUS),
        Err(_) => Err(REASON_NETWORK),
    }
}

/// Record one delivery attempt's outcome in the health flag the fail-mode
/// gate reads, logging TRANSITIONS only: one line per outage, one per
/// recovery, never one per batch. Audit success opens the latch; either
/// stream's failure closes it; a successful diagnostics flush is ignored.
fn note_delivery(healthy: &AtomicBool, ok: bool) {
    let was = healthy.swap(ok, Ordering::Relaxed);
    if was && !ok {
        tracing::warn!(
            "otlp delivery is failing; the audit fail mode now gates tool calls \
             until a delivery succeeds"
        );
    } else if !was && ok {
        tracing::info!("otlp delivery recovered");
    }
}

/// The drain task's own state.
struct ExportTask {
    cfg: ExportConfig,
    /// Built by [`Pipeline::start`] and shared with the probe.
    client: reqwest::Client,
    /// Audit records: refused at the queue rather than dropped, and
    /// counted in `lost` when a send fails after acceptance.
    audit_rx: mpsc::Receiver<LogEntry>,
    /// Diagnostics: dropped and counted when the queue is full or a send
    /// fails.
    diag_rx: mpsc::Receiver<LogEntry>,
    dropped: Arc<AtomicU64>,
    log_threshold: Arc<AtomicU64>,
    /// Audit records accepted and then not delivered; drained into the
    /// sink's gap accounting through [`AuditExport::take_lost`].
    lost: Arc<AtomicU64>,
    /// Whether the last delivery attempt worked; read by the fail-mode
    /// gate through [`AuditExport::delivery_failing`].
    healthy: Arc<AtomicBool>,
    shutdown: CancellationToken,
    done: oneshot::Sender<()>,
}

impl ExportTask {
    async fn run(mut self) {
        let mut audit_batch: Vec<LogEntry> = Vec::with_capacity(MAX_BATCH);
        let mut diag_batch: Vec<LogEntry> = Vec::with_capacity(MAX_BATCH);
        loop {
            let deadline = tokio::time::Instant::now() + BATCH_INTERVAL;
            let mut stopping = false;
            loop {
                tokio::select! {
                    biased;
                    () = self.shutdown.cancelled() => { stopping = true; break; }
                    entry = self.audit_rx.recv() => match entry {
                        Some(entry) => {
                            audit_batch.push(entry);
                            if audit_batch.len() >= MAX_BATCH {
                                break;
                            }
                        }
                        None => { stopping = true; break; }
                    },
                    entry = self.diag_rx.recv() => match entry {
                        Some(entry) => {
                            diag_batch.push(entry);
                            if diag_batch.len() >= MAX_BATCH {
                                break;
                            }
                        }
                        None => { stopping = true; break; }
                    },
                    () = tokio::time::sleep_until(deadline) => break,
                }
            }
            // Audit first, always: when both sinks run, export order is
            // seq order, and a diagnostic about an outage must not
            // overtake the records of the calls it describes.
            self.flush_audit(&mut audit_batch).await;
            self.flush_diag(&mut diag_batch).await;
            if stopping {
                // Bounded tail: whatever is already queued, in batches,
                // bounded by EXPORT_TIMEOUT per request and by the
                // caller's SHUTDOWN_FLUSH_TIMEOUT overall. Anything this
                // does not deliver is gone — in a fileless deployment,
                // gone entirely.
                self.audit_rx.close();
                self.diag_rx.close();
                while let Ok(entry) = self.audit_rx.try_recv() {
                    audit_batch.push(entry);
                    if audit_batch.len() >= MAX_BATCH {
                        self.flush_audit(&mut audit_batch).await;
                    }
                }
                while let Ok(entry) = self.diag_rx.try_recv() {
                    diag_batch.push(entry);
                    if diag_batch.len() >= MAX_BATCH {
                        self.flush_diag(&mut diag_batch).await;
                    }
                }
                self.flush_audit(&mut audit_batch).await;
                self.flush_diag(&mut diag_batch).await;
                break;
            }
        }
        let _ = self.done.send(());
    }

    /// Post one audit batch. A failed batch is LOST, never retried (a
    /// retry queue is another unbounded buffer in front of a collector
    /// that is already not answering) — but never silently: the count
    /// reaches the sink's `audit_gap` accounting via `lost`, and the
    /// failure flips the health flag that holds the fail-mode gate
    /// closed until a delivery succeeds.
    async fn flush_audit(&self, batch: &mut Vec<LogEntry>) {
        if batch.is_empty() {
            return;
        }
        match post_batch(&self.client, &self.cfg, batch).await {
            Ok(()) => note_delivery(&self.healthy, true),
            Err(_) => {
                self.lost.fetch_add(batch.len() as u64, Ordering::Relaxed);
                note_delivery(&self.healthy, false);
            }
        }
        batch.clear();
    }

    /// Post one diagnostics batch. A failed batch costs the batch and a
    /// counted warning — best-effort. A failure still marks delivery
    /// unhealthy (the same collector will refuse audit records too); a
    /// success does not clear the latch. Only a successful AUDIT flush
    /// proves the load-bearing sink works again.
    async fn flush_diag(&self, batch: &mut Vec<LogEntry>) {
        if batch.is_empty() {
            return;
        }
        match post_batch(&self.client, &self.cfg, batch).await {
            Ok(()) => {}
            Err(reason) => {
                note_drops(
                    &self.dropped,
                    &self.log_threshold,
                    batch.len() as u64,
                    reason,
                );
                note_delivery(&self.healthy, false);
            }
        }
        batch.clear();
    }
}

// ---------------------------------------------------------------------------
// Diagnostics layer
// ---------------------------------------------------------------------------

/// The tracing layer that copies the server's diagnostics to OTLP.
///
/// It holds a slot rather than a pipeline: the subscriber is installed
/// before anything else runs, while the pipeline may only start after the
/// audit sink has opened. Until the slot is filled the layer does nothing
/// but read one atomic per event, and if export is off it is never
/// installed at all.
pub struct DiagnosticsLayer {
    slot: Arc<OnceLock<Arc<Pipeline>>>,
}

/// Collects an event's fields into the body text, message first, the way
/// the stderr formatter renders them.
///
/// It also picks the `log.target` field out rather than rendering it. The
/// `log` crate's records reach a `tracing` subscriber through
/// `tracing-log`'s bridge with their metadata target set to the literal
/// `"log"` and their real one demoted to that field, so the field is the
/// only place the emitting module is legible — and [`never_exported`] has
/// to read it, or every `reqwest` and `hyper` line sails past a check that
/// only ever sees `"log"`. Its `log.module_path`/`log.file`/`log.line`
/// siblings are dropped for the same reason the stderr formatter drops
/// them: they are bridge bookkeeping, not what the event said.
struct BodyVisitor {
    message: String,
    fields: String,
    /// The `log.target` field's value, for a bridged `log` record.
    log_target: Option<String>,
}

/// Fields `tracing-log` adds to a bridged record, which are metadata about
/// the bridge rather than part of the event.
fn is_log_bridge_field(name: &str) -> bool {
    matches!(
        name,
        "log.target" | "log.module_path" | "log.file" | "log.line"
    )
}

impl tracing::field::Visit for BodyVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn fmt::Debug) {
        use std::fmt::Write as _;
        if field.name() == "log.target" {
            self.log_target = Some(format!("{value:?}").trim_matches('"').to_owned());
            return;
        }
        if is_log_bridge_field(field.name()) {
            return;
        }
        if field.name() == "message" {
            let _ = write!(self.message, "{value:?}");
        } else {
            let _ = write!(
                self.fields,
                "{}{}={value:?}",
                if self.fields.is_empty() { "" } else { " " },
                field.name()
            );
        }
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        use std::fmt::Write as _;
        if field.name() == "log.target" {
            self.log_target = Some(value.to_owned());
            return;
        }
        if is_log_bridge_field(field.name()) {
            return;
        }
        if field.name() == "message" {
            self.message.push_str(value);
        } else {
            let _ = write!(
                self.fields,
                "{}{}={value}",
                if self.fields.is_empty() { "" } else { " " },
                field.name()
            );
        }
    }
}

impl<S: tracing::Subscriber> Layer<S> for DiagnosticsLayer {
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: LayerContext<'_, S>) {
        let meta = event.metadata();
        // The export must never carry what the export itself emits; see
        // NEVER_EXPORTED_TARGETS for why the HTTP stack is in that set and
        // not only this module.
        if never_exported(meta.target()) {
            return;
        }
        let Some(pipeline) = self.slot.get() else {
            return;
        };
        let mut visitor = BodyVisitor {
            message: String::new(),
            fields: String::new(),
            log_target: None,
        };
        event.record(&mut visitor);
        // Second gate, and the load-bearing one: a bridged `log` record
        // only reveals its real target here, in a field, so the cheap
        // metadata check above cannot see the export's own HTTP stack —
        // reqwest and hyper log through `log`, not through `tracing`.
        let target = visitor
            .log_target
            .as_deref()
            .unwrap_or_else(|| meta.target());
        if never_exported(target) {
            return;
        }
        let body = if visitor.fields.is_empty() {
            visitor.message
        } else if visitor.message.is_empty() {
            visitor.fields
        } else {
            format!("{} {}", visitor.message, visitor.fields)
        };
        pipeline.emit(LogEntry {
            time_unix_nano: now_unix_nano(),
            severity: Severity::of_level(meta.level()),
            body,
            attrs: vec![
                ("bugwarden.stream", AttrValue::Str("diagnostics".to_owned())),
                ("log.target", AttrValue::Str(target.to_owned())),
            ],
            trace: None,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{
        AuditEvent, AuditEventKind, ClientInfo, GuardInfo, InitializeEvent, OutcomeClass,
        OutcomeInfo, RequestInfo, SessionInfo, ToolCallEvent, TraceContext, TransportKind, Verdict,
    };
    use crate::testlog::{assert_logged, capture_logs};

    fn env(endpoint: &str) -> OtelEnv {
        OtelEnv {
            endpoint: Some(endpoint.to_owned()),
            ..OtelEnv::default()
        }
    }

    // -- configuration ------------------------------------------------------

    #[test]
    fn unset_endpoint_turns_export_off() {
        let resolved = resolve(&OtelEnv::default()).expect("an empty environment resolves");
        assert!(
            resolved.is_none(),
            "no endpoint must mean no export configuration at all"
        );
    }

    #[test]
    fn empty_endpoint_turns_export_off() {
        // The "cleared variable" idiom of unit files and container specs.
        let resolved = resolve(&OtelEnv {
            endpoint: Some(String::new()),
            ..OtelEnv::default()
        })
        .expect("an emptied endpoint resolves");
        assert!(resolved.is_none(), "an emptied endpoint must read as unset");
        let resolved = resolve(&OtelEnv {
            endpoint: Some("   ".to_owned()),
            ..OtelEnv::default()
        })
        .expect("a blank endpoint resolves");
        assert!(resolved.is_none(), "a blank endpoint must read as unset");
    }

    #[test]
    fn an_endpoint_gains_the_logs_path_and_the_default_service_name() {
        let cfg = resolve(&env("http://collector.example:4318"))
            .expect("resolves")
            .expect("export is on");
        assert_eq!(cfg.logs_url(), "http://collector.example:4318/v1/logs");
        assert_eq!(cfg.service_name(), "bugwarden");
        // A trailing slash must not produce a doubled separator.
        let cfg = resolve(&env("http://collector.example:4318/"))
            .expect("resolves")
            .expect("export is on");
        assert_eq!(cfg.logs_url(), "http://collector.example:4318/v1/logs");
    }

    #[test]
    fn service_name_is_taken_from_the_environment_when_set() {
        let cfg = resolve(&OtelEnv {
            service_name: Some("  bugwarden-edge  ".to_owned()),
            ..env("http://c:4318")
        })
        .expect("resolves")
        .expect("export is on");
        assert_eq!(cfg.service_name(), "bugwarden-edge");
    }

    #[test]
    fn the_only_accepted_protocol_is_http_protobuf() {
        for accepted in [None, Some("http/protobuf".to_owned())] {
            let cfg = resolve(&OtelEnv {
                protocol: accepted.clone(),
                ..env("http://c:4318")
            })
            .expect("http/protobuf and an unset protocol resolve");
            assert!(cfg.is_some(), "{accepted:?} must leave export on");
        }
        for rejected in ["grpc", "http/json", "HTTP/PROTOBUF", ""] {
            let err = resolve(&OtelEnv {
                protocol: Some(rejected.to_owned()),
                ..env("http://c:4318")
            })
            .err()
            .expect("only http/protobuf is spoken");
            let text = format!("{err}");
            assert!(
                text.contains(PROTOCOL_VAR) && text.contains(PROTOCOL_HTTP_PROTOBUF),
                "the error must name the variable and the accepted value: {text}"
            );
        }
    }

    #[test]
    fn a_bad_protocol_without_an_endpoint_is_not_an_error() {
        // Export is off, so nothing about the transport is decided. A
        // fleet-wide OTEL_* environment must not refuse to start a
        // deployment that exports nothing (issue #31: unset endpoint means
        // zero new behaviour).
        let resolved = resolve(&OtelEnv {
            protocol: Some("grpc".to_owned()),
            ..OtelEnv::default()
        })
        .expect("no endpoint decides everything");
        assert!(resolved.is_none());
    }

    #[test]
    fn an_endpoint_must_be_an_http_url() {
        let err = resolve(&env("collector.example:4318"))
            .err()
            .expect("a bare authority is not a URL");
        assert!(format!("{err}").contains(ENDPOINT_VAR));
        assert!(resolve(&env("https://c:4318"))
            .expect("https resolves")
            .is_some());
    }

    #[test]
    fn headers_parse_into_pairs_and_are_taken_verbatim() {
        let cfg = resolve(&OtelEnv {
            headers: Some(" authorization=Bearer abc%20def , x-tenant=acme ".to_owned()),
            ..env("http://c:4318")
        })
        .expect("resolves")
        .expect("export is on");
        assert_eq!(
            cfg.headers(),
            [
                ("authorization".to_owned(), "Bearer abc%20def".to_owned()),
                ("x-tenant".to_owned(), "acme".to_owned()),
            ],
            "values are used as given; percent-encoding is not decoded"
        );

        // A trailing or doubled comma is the shape a generated env file
        // produces; it names no header and is not an error.
        let cfg = resolve(&OtelEnv {
            headers: Some("a=1,,b=2,".to_owned()),
            ..env("http://c:4318")
        })
        .expect("resolves")
        .expect("export is on");
        assert_eq!(
            cfg.headers(),
            [
                ("a".to_owned(), "1".to_owned()),
                ("b".to_owned(), "2".to_owned()),
            ]
        );
    }

    #[test]
    fn the_logs_specific_variables_override_the_general_ones() {
        // The OTLP specification makes the signal-specific form win, and
        // its endpoint is used AS GIVEN — no signal path is appended,
        // because the operator wrote the whole URL.
        let cfg = resolve(&OtelEnv {
            logs_endpoint: Some("http://logs.example:4318/otlp/v1/logs".to_owned()),
            logs_headers: Some("x-logs=1".to_owned()),
            headers: Some("x-general=1".to_owned()),
            ..env("http://general.example:4318")
        })
        .expect("resolves")
        .expect("export is on");
        assert_eq!(cfg.logs_url(), "http://logs.example:4318/otlp/v1/logs");
        assert_eq!(cfg.headers(), [("x-logs".to_owned(), "1".to_owned())]);

        // Set ALONE it still turns export on: a fleet naming only the
        // logs endpoint expects logs, and reading just the general
        // variable would leave the export silently off.
        let cfg = resolve(&OtelEnv {
            logs_endpoint: Some("http://logs.example:4318/v1/logs".to_owned()),
            ..OtelEnv::default()
        })
        .expect("resolves")
        .expect("a logs endpoint alone means export is on");
        assert_eq!(cfg.logs_url(), "http://logs.example:4318/v1/logs");

        // Emptied, it is unset, and the general one is used again.
        let cfg = resolve(&OtelEnv {
            logs_endpoint: Some(String::new()),
            ..env("http://general.example:4318")
        })
        .expect("resolves")
        .expect("export is on");
        assert_eq!(cfg.logs_url(), "http://general.example:4318/v1/logs");

        // A refusal names the variable that actually carried the value.
        let err = resolve(&OtelEnv {
            logs_protocol: Some("grpc".to_owned()),
            protocol: Some(PROTOCOL_HTTP_PROTOBUF.to_owned()),
            ..env("http://c:4318")
        })
        .err()
        .expect("grpc must be refused wherever it came from");
        assert!(
            format!("{err}").contains(LOGS_PROTOCOL_VAR),
            "the error must name the losing variable, not its general twin: {err}"
        );
    }

    #[test]
    fn a_malformed_header_entry_is_refused_without_echoing_it() {
        // The classic paste accident: the whole credential where a
        // `key=value` belongs. The error must not repeat it (I12).
        let secret = "Bearer super-secret-token";
        let err = resolve(&OtelEnv {
            headers: Some(format!("x-a=1,{secret}")),
            ..env("http://c:4318")
        })
        .err()
        .expect("an entry without `=` is refused");
        let text = format!("{err}");
        assert!(
            text.contains(HEADERS_VAR) && text.contains('2'),
            "the error must name the variable and the position: {text}"
        );
        assert!(
            !text.contains("super-secret-token"),
            "the error must never echo header material: {text}"
        );
    }

    #[test]
    fn an_unusable_header_name_or_value_is_refused() {
        // A name with internal whitespace, an empty name or value, an
        // entry with no separator at all, and — the one that matters —
        // a value carrying a newline, which is header injection.
        for bad in ["bad name=1", "x=", "=value", "no-equals-sign", "x=va\nlue"] {
            let err = resolve(&OtelEnv {
                headers: Some(bad.to_owned()),
                ..env("http://c:4318")
            })
            .err()
            .unwrap_or_else(|| panic!("{bad:?} must be refused"));
            assert!(format!("{err}").contains(HEADERS_VAR));
        }
    }

    // -- record shaping -----------------------------------------------------

    fn session() -> SessionInfo {
        SessionInfo {
            id: Some("sess-1".to_owned()),
            transport: TransportKind::Http,
            remote: Some("192.0.2.7:52611".to_owned()),
        }
    }

    fn tool_call(trace: Option<TraceContext>) -> AuditEventKind {
        AuditEventKind::ToolCall(Box::new(ToolCallEvent {
            client: ClientInfo {
                name: Some("agent".to_owned()),
                version: None,
                principal: None,
            },
            trace,
            request: RequestInfo {
                tool: "bug_info".to_owned(),
                id: Some("3".to_owned()),
                params: std::collections::BTreeMap::new(),
            },
            guard: Some(GuardInfo {
                verdict: Verdict::Denied,
                rule: Some("embargo".to_owned()),
                policy_hash: None,
                suppressed_count: 1,
                suppressed_ids: vec![7],
                redacted_fields: Vec::new(),
                scan: None,
            }),
            upstream: None,
            outcome: OutcomeInfo {
                class: OutcomeClass::Ok,
                duration_ms: 3,
                response_bytes: Some(87),
            },
        }))
    }

    fn event(kind: AuditEventKind) -> AuditEvent {
        AuditEvent {
            v: crate::audit::SCHEMA_VERSION,
            ts: "2026-08-18T00:00:00.000Z".to_owned(),
            seq: 42,
            session: session(),
            kind,
        }
    }

    fn attr<'a>(entry: &'a LogEntry, key: &str) -> Option<&'a AttrValue> {
        entry.attrs.iter().find(|(k, _)| *k == key).map(|(_, v)| v)
    }

    #[test]
    fn an_audit_entry_carries_the_line_verbatim_as_its_body() {
        let line = br#"{"v":1,"seq":42}"#;
        let entry = audit_entry(&event(tool_call(None)), line);
        assert_eq!(
            entry.body.as_bytes(),
            line,
            "the body must be the file's bytes, unchanged"
        );
    }

    #[test]
    fn an_audit_entry_carries_the_documented_attributes() {
        let entry = audit_entry(&event(tool_call(None)), b"{}");
        assert_eq!(
            attr(&entry, "bugwarden.stream"),
            Some(&AttrValue::Str("audit".to_owned()))
        );
        assert_eq!(
            attr(&entry, "bugwarden.event"),
            Some(&AttrValue::Str("tool_call".to_owned()))
        );
        assert_eq!(attr(&entry, "bugwarden.seq"), Some(&AttrValue::Int(42)));
        assert_eq!(
            attr(&entry, "bugwarden.transport"),
            Some(&AttrValue::Str("http".to_owned()))
        );
        assert_eq!(
            attr(&entry, "bugwarden.session.id"),
            Some(&AttrValue::Str("sess-1".to_owned()))
        );
        assert_eq!(
            attr(&entry, "bugwarden.tool"),
            Some(&AttrValue::Str("bug_info".to_owned()))
        );
        assert_eq!(
            attr(&entry, "bugwarden.verdict"),
            Some(&AttrValue::Str("denied".to_owned()))
        );
        assert_eq!(
            attr(&entry, "bugwarden.rule"),
            Some(&AttrValue::Str("embargo".to_owned()))
        );
        assert_eq!(
            attr(&entry, "bugwarden.response_bytes"),
            Some(&AttrValue::Int(87))
        );
    }

    #[test]
    fn an_unmeasured_response_exports_no_size_attribute() {
        // Absent, not zero: a collector averaging response size must not
        // see a refusal the gate never sized pulled into the mean.
        let mut kind = tool_call(None);
        let AuditEventKind::ToolCall(call) = &mut kind else {
            unreachable!()
        };
        call.outcome.response_bytes = None;
        let entry = audit_entry(&event(kind), b"{}");
        assert_eq!(attr(&entry, "bugwarden.response_bytes"), None);
    }

    #[test]
    fn severity_follows_the_event_kind() {
        assert_eq!(
            audit_entry(&event(tool_call(None)), b"{}").severity,
            Severity::Info
        );
        assert_eq!(
            audit_entry(
                &event(AuditEventKind::Initialize(InitializeEvent {
                    client: ClientInfo {
                        name: None,
                        version: None,
                        principal: None
                    },
                    protocol_version: None,
                })),
                b"{}"
            )
            .severity,
            Severity::Info
        );
        assert_eq!(
            audit_entry(
                &event(AuditEventKind::AuditGap(crate::audit::AuditGapEvent {
                    dropped: 2,
                    reason: crate::audit::GapReason::WriteError,
                })),
                b"{}"
            )
            .severity,
            Severity::Error,
            "a gap in the record stream is an error, not an info line"
        );
    }

    #[test]
    fn trace_ids_reach_the_record_as_raw_bytes() {
        let entry = audit_entry(
            &event(tool_call(Some(TraceContext {
                trace_id: "4bf92f3577b34da6a3ce929d0e0e4736".to_owned(),
                span_id: "00f067aa0ba902b7".to_owned(),
            }))),
            b"{}",
        );
        let (trace_id, span_id) = entry.trace.expect("a valid traceparent must be exported");
        assert_eq!(
            trace_id,
            [
                0x4b, 0xf9, 0x2f, 0x35, 0x77, 0xb3, 0x4d, 0xa6, 0xa3, 0xce, 0x92, 0x9d, 0x0e, 0x0e,
                0x47, 0x36
            ]
        );
        assert_eq!(span_id, [0x00, 0xf0, 0x67, 0xaa, 0x0b, 0xa9, 0x02, 0xb7]);
    }

    #[test]
    fn a_record_without_trace_context_exports_no_ids() {
        assert!(audit_entry(&event(tool_call(None)), b"{}").trace.is_none());
    }

    #[test]
    fn hex_of_the_wrong_width_or_alphabet_decodes_to_nothing() {
        assert!(hex_bytes::<8>("00f067aa0ba902b").is_none());
        assert!(hex_bytes::<8>("00f067aa0ba902b77").is_none());
        assert!(hex_bytes::<8>("00f067aa0ba902bz").is_none());
        assert!(hex_bytes::<8>("").is_none());
    }

    // -- protobuf encoding --------------------------------------------------

    /// Walk a protobuf message, returning `(field, wire_type, payload)`
    /// triples. Length-delimited payloads come back as byte slices; the
    /// fixed and varint ones as their raw bytes.
    fn fields(buf: &[u8]) -> Vec<(u32, u32, Vec<u8>)> {
        let mut out = Vec::new();
        let mut i = 0usize;
        while i < buf.len() {
            let (tag, used) = read_varint(&buf[i..]).expect("a tag");
            i += used;
            let field = u32::try_from(tag >> 3).expect("field number");
            let wire_type = u32::try_from(tag & 7).expect("wire type");
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
                other => panic!("unexpected wire type {other}"),
            }
        }
        out
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

    fn only(buf: &[u8], field: u32) -> Vec<u8> {
        fields(buf)
            .into_iter()
            .find(|(f, _, _)| *f == field)
            .unwrap_or_else(|| panic!("field {field} must be present"))
            .2
    }

    fn all(buf: &[u8], field: u32) -> Vec<Vec<u8>> {
        fields(buf)
            .into_iter()
            .filter(|(f, _, _)| *f == field)
            .map(|(_, _, v)| v)
            .collect()
    }

    #[test]
    fn varints_encode_the_way_protobuf_reads_them() {
        for value in [0u64, 1, 127, 128, 300, 16_383, 16_384, u64::MAX] {
            let mut buf = Vec::new();
            wire::put_varint(&mut buf, value);
            assert_eq!(read_varint(&buf), Some((value, buf.len())), "{value}");
        }
        // The canonical two-byte example from the protobuf encoding docs.
        let mut buf = Vec::new();
        wire::put_varint(&mut buf, 300);
        assert_eq!(buf, [0xac, 0x02]);
    }

    #[test]
    fn a_request_nests_resource_scope_and_records_as_otlp_expects() {
        let entry = audit_entry(&event(tool_call(None)), b"{\"seq\":42}");
        let request = encode_request("bugwarden", std::slice::from_ref(&entry));

        let resource_logs = only(&request, 1);
        let resource = only(&resource_logs, 1);
        let service_kv = only(&resource, 1);
        assert_eq!(only(&service_kv, 1), b"service.name");
        assert_eq!(only(&only(&service_kv, 2), 1), b"bugwarden");

        let scope_logs = only(&resource_logs, 2);
        let scope = only(&scope_logs, 1);
        assert_eq!(only(&scope, 1), SCOPE_NAME.as_bytes());
        assert_eq!(only(&scope, 2), env!("CARGO_PKG_VERSION").as_bytes());

        let records = all(&scope_logs, 2);
        assert_eq!(records.len(), 1);
        let record = &records[0];
        // severity_number is a varint; the helper hands back little-endian
        // bytes of the decoded value.
        assert_eq!(only(record, 2)[0], Severity::Info as u8);
        assert_eq!(only(record, 3), b"INFO");
        assert_eq!(only(&only(record, 5), 1), b"{\"seq\":42}");
        assert!(
            all(record, 6).len() >= 7,
            "every documented attribute must be encoded"
        );
        // The two timestamps, by FIELD NUMBER: `time_unix_nano` is 1 and
        // `observed_time_unix_nano` is 11, and field 4 is reserved in the
        // schema. Pinning the numbers is what stops a stamp from being
        // written where no reader looks for it.
        let stamp = entry.time_unix_nano.to_le_bytes().to_vec();
        assert_eq!(only(record, 1), stamp, "time_unix_nano is field 1");
        assert_eq!(
            only(record, 11),
            stamp,
            "observed_time_unix_nano is field 11"
        );
        assert!(
            !fields(record).iter().any(|(f, _, _)| *f == 4),
            "field 4 is reserved in the OTLP LogRecord and must carry nothing"
        );
    }

    #[test]
    fn every_severity_keeps_its_otlp_number_and_text() {
        // The numbers are the base of each OTLP severity range and a
        // consumer filters on them, so they are wire contract rather than
        // an internal enum: pinned here, and the ERROR one again through
        // the encoder, since only INFO rides the request test above.
        for (severity, number, text) in [
            (Severity::Trace, 1u8, "TRACE"),
            (Severity::Debug, 5, "DEBUG"),
            (Severity::Info, 9, "INFO"),
            (Severity::Warn, 13, "WARN"),
            (Severity::Error, 17, "ERROR"),
        ] {
            assert_eq!(severity as u8, number, "{text} is OTLP severity {number}");
            assert_eq!(severity.text(), text);
        }

        let gap = audit_entry(
            &event(AuditEventKind::AuditGap(crate::audit::AuditGapEvent {
                dropped: 2,
                reason: crate::audit::GapReason::WriteError,
            })),
            b"{}",
        );
        let record = all(&only(&only(&request_of(&gap), 1), 2), 2).remove(0);
        assert_eq!(only(&record, 2)[0], 17, "an audit_gap is ERROR on the wire");
        assert_eq!(only(&record, 3), b"ERROR");
    }

    #[test]
    fn a_batch_becomes_one_request_with_one_record_each() {
        let entries: Vec<LogEntry> = (0..3)
            .map(|_| audit_entry(&event(tool_call(None)), b"{}"))
            .collect();
        let request = encode_request("bugwarden", &entries);
        let scope_logs = only(&only(&request, 1), 2);
        assert_eq!(all(&scope_logs, 2).len(), 3);
    }

    #[test]
    fn trace_ids_are_encoded_as_the_fixed_width_byte_fields() {
        let entry = audit_entry(
            &event(tool_call(Some(TraceContext {
                trace_id: "4bf92f3577b34da6a3ce929d0e0e4736".to_owned(),
                span_id: "00f067aa0ba902b7".to_owned(),
            }))),
            b"{}",
        );
        let record = all(&only(&only(&request_of(&entry), 1), 2), 2).remove(0);
        assert_eq!(only(&record, 9).len(), 16);
        assert_eq!(only(&record, 10).len(), 8);
        assert_eq!(only(&record, 9)[0], 0x4b);
        assert_eq!(only(&record, 10)[1], 0xf0);
    }

    fn request_of(entry: &LogEntry) -> Vec<u8> {
        encode_request("bugwarden", std::slice::from_ref(entry))
    }

    // -- drop accounting ----------------------------------------------------

    #[test]
    fn drops_are_logged_at_powers_of_two_only() {
        let dropped = AtomicU64::new(0);
        let threshold = AtomicU64::new(1);
        let (_, logs) = capture_logs(|| {
            for _ in 0..16 {
                note_drops(&dropped, &threshold, 1, REASON_QUEUE_FULL);
            }
        });
        assert_eq!(dropped.load(Ordering::Relaxed), 16);
        let lines = logs
            .as_str()
            .matches("otlp export is dropping diagnostic records")
            .count();
        assert_eq!(
            lines,
            5,
            "one line per crossing of 1, 2, 4, 8, 16 — not one per record: {}",
            logs.as_str()
        );
        assert_logged(&logs, "dropped=16");
    }

    #[test]
    fn a_batch_sized_drop_logs_once_and_moves_the_threshold_past_it() {
        let dropped = AtomicU64::new(0);
        let threshold = AtomicU64::new(1);
        let (_, logs) = capture_logs(|| {
            note_drops(&dropped, &threshold, 300, REASON_NETWORK);
            note_drops(&dropped, &threshold, 1, REASON_NETWORK);
        });
        assert_eq!(
            logs.as_str()
                .matches("otlp export is dropping diagnostic records")
                .count(),
            1,
            "a 300-record batch crosses nine powers of two (1..256) and still logs once: {}",
            logs.as_str()
        );
        assert_eq!(threshold.load(Ordering::Relaxed), 512);
    }

    #[test]
    fn the_drop_line_names_no_endpoint_and_no_header() {
        let dropped = AtomicU64::new(0);
        let threshold = AtomicU64::new(1);
        let (_, logs) = capture_logs(|| {
            note_drops(&dropped, &threshold, 1, REASON_NETWORK);
        });
        assert_logged(&logs, "reason=\"network\"");
        for forbidden in ["http://", "https://", "authorization", "Bearer", "4318"] {
            logs.assert_not_contains(forbidden);
        }
    }

    // -- pipeline -----------------------------------------------------------

    #[tokio::test]
    async fn an_unreachable_collector_loses_audit_records_loudly_not_as_drops() {
        // An accepted-then-undelivered audit record is a LOSS the sink
        // must be able to account for (take_lost -> audit_gap), never a
        // silent drop; the diagnostics counter stays at zero for it, and
        // delivery is marked failing so the fail-mode gate closes.
        let cfg = resolve(&env("http://127.0.0.1:1/"))
            .expect("resolves")
            .expect("export is on");
        let pipeline = Arc::new(Pipeline::start(cfg).expect("the pipeline must start"));
        assert!(
            !pipeline.delivery_failing(),
            "before any attempt, delivery is not known to be failing"
        );
        pipeline
            .accept(&event(tool_call(None)), b"{}")
            .expect("an open queue takes custody");
        // The batch interval plus a margin: enough for one failed post.
        tokio::time::sleep(BATCH_INTERVAL * 3).await;
        assert!(
            pipeline.delivery_failing(),
            "a failed delivery must mark the pipeline failing"
        );
        assert_eq!(
            pipeline.dropped(),
            0,
            "audit records never ride the diagnostics drop counter"
        );
        assert_eq!(
            pipeline.take_lost(),
            1,
            "the undelivered record must be surfaced for gap accounting"
        );
        assert_eq!(pipeline.take_lost(), 0, "take_lost drains the count");
        pipeline.shutdown().await;
    }

    #[tokio::test]
    async fn an_unreachable_collector_counts_diagnostics_as_drops() {
        let cfg = resolve(&env("http://127.0.0.1:1/"))
            .expect("resolves")
            .expect("export is on");
        let pipeline = Arc::new(Pipeline::start(cfg).expect("the pipeline must start"));
        pipeline.emit(LogEntry {
            time_unix_nano: now_unix_nano(),
            severity: Severity::Info,
            body: "diagnostic".to_owned(),
            attrs: Vec::new(),
            trace: None,
        });
        tokio::time::sleep(BATCH_INTERVAL * 3).await;
        pipeline.shutdown().await;
        assert!(
            pipeline.dropped() >= 1,
            "an unreachable collector must count the diagnostics it lost"
        );
        assert_eq!(
            pipeline.take_lost(),
            0,
            "a dropped diagnostic is not an audit loss"
        );
    }

    #[tokio::test]
    async fn a_record_offered_after_shutdown_is_refused_not_dropped() {
        // The audit queue REFUSES what it cannot take: the sink turns the
        // refusal into a failed record and the fail mode decides what the
        // caller sees. Only diagnostics are dropped-and-counted.
        let cfg = resolve(&env("http://127.0.0.1:1/"))
            .expect("resolves")
            .expect("export is on");
        let pipeline = Arc::new(Pipeline::start(cfg).expect("the pipeline must start"));
        pipeline.shutdown().await;
        let before = pipeline.dropped();
        assert!(
            pipeline.accept(&event(tool_call(None)), b"{}").is_err(),
            "a shut-down pipeline must refuse custody"
        );
        assert!(
            pipeline.delivery_failing(),
            "a refused record marks delivery failing"
        );
        assert_eq!(
            pipeline.dropped(),
            before,
            "a refused audit record must not be counted as a drop"
        );
    }

    #[tokio::test]
    async fn a_diagnostic_offered_after_shutdown_is_a_shutdown_drop() {
        // The queue is closed, not full, and saying "queue_full" would
        // send an operator looking for a volume problem that is not
        // there. The line is lost either way — this is about the
        // vocabulary being true.
        let cfg = resolve(&env("http://127.0.0.1:1/"))
            .expect("resolves")
            .expect("export is on");
        let pipeline = Arc::new(Pipeline::start(cfg).expect("the pipeline must start"));
        pipeline.shutdown().await;
        let before = pipeline.dropped();
        let (_, logs) = capture_logs(|| {
            pipeline.emit(LogEntry {
                time_unix_nano: now_unix_nano(),
                severity: Severity::Info,
                body: "late diagnostic".to_owned(),
                attrs: Vec::new(),
                trace: None,
            });
        });
        assert_eq!(
            pipeline.dropped(),
            before + 1,
            "a diagnostic offered to a shut-down pipeline is still counted"
        );
        assert_logged(&logs, "reason=\"shutdown\"");
    }

    #[test]
    fn delivery_notes_log_transitions_only() {
        // One line per outage and one per recovery: a collector that is
        // down for an hour must not log once per batch interval.
        let healthy = AtomicBool::new(true);
        let (_, logs) = capture_logs(|| {
            note_delivery(&healthy, false);
            note_delivery(&healthy, false);
            note_delivery(&healthy, false);
        });
        assert_eq!(
            logs.as_str().matches("otlp delivery is failing").count(),
            1,
            "repeated failures log once: {}",
            logs.as_str()
        );
        assert!(!healthy.load(Ordering::Relaxed));
        let (_, logs) = capture_logs(|| {
            note_delivery(&healthy, true);
            note_delivery(&healthy, true);
        });
        assert_eq!(
            logs.as_str().matches("otlp delivery recovered").count(),
            1,
            "repeated successes log once: {}",
            logs.as_str()
        );
        assert!(healthy.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn the_startup_probe_refuses_a_dead_collector_without_naming_it() {
        // The refusal names the variables the operator has to check and
        // never the endpoint they hold (I12) — port 1 would be the tell.
        let cfg = resolve(&env("http://127.0.0.1:1/"))
            .expect("resolves")
            .expect("export is on");
        let pipeline = Arc::new(Pipeline::start(cfg).expect("the pipeline must start"));
        let err = pipeline
            .probe()
            .await
            .expect_err("a dead collector must refuse startup");
        let message = format!("{err}");
        assert!(
            message.contains(ENDPOINT_VAR) && message.contains(HEADERS_VAR),
            "the refusal must point at the configuration: {message}"
        );
        assert!(
            !message.contains(LOGS_ENDPOINT_VAR) && !message.contains(LOGS_HEADERS_VAR),
            "a general-variable config must not blame the logs-specific pair: {message}"
        );
        assert!(
            !message.contains("127.0.0.1") && !message.contains(":1"),
            "the refusal must not carry the endpoint: {message}"
        );
        assert!(
            pipeline.delivery_failing(),
            "a failed probe leaves delivery marked failing"
        );
        pipeline.shutdown().await;
    }

    #[tokio::test]
    async fn the_startup_probe_names_the_logs_specific_variables_when_those_won() {
        let cfg = resolve(&OtelEnv {
            logs_endpoint: Some("http://127.0.0.1:1/v1/logs".to_owned()),
            logs_headers: Some("authorization=Bearer x".to_owned()),
            ..OtelEnv::default()
        })
        .expect("resolves")
        .expect("a logs-specific endpoint turns export on");
        let pipeline = Arc::new(Pipeline::start(cfg).expect("the pipeline must start"));
        let message = format!(
            "{}",
            pipeline
                .probe()
                .await
                .expect_err("a dead collector must refuse startup")
        );
        assert!(
            message.contains(LOGS_ENDPOINT_VAR) && message.contains(LOGS_HEADERS_VAR),
            "the refusal must name the variables that actually won: {message}"
        );
        assert!(
            !message.contains("127.0.0.1") && !message.contains("Bearer"),
            "the refusal must not carry the endpoint or the credential: {message}"
        );
        pipeline.shutdown().await;
    }

    #[tokio::test]
    async fn shutdown_is_idempotent_and_bounded() {
        let cfg = resolve(&env("http://127.0.0.1:1/"))
            .expect("resolves")
            .expect("export is on");
        let pipeline = Arc::new(Pipeline::start(cfg).expect("the pipeline must start"));
        pipeline.shutdown().await;
        pipeline.shutdown().await;
    }

    #[test]
    fn the_pipeline_debug_carries_no_configuration() {
        // Reachable from AuditSink's derived Debug, so it must hold
        // nothing that came out of the environment (I12).
        let rendered = {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("a runtime");
            let _guard = runtime.enter();
            let cfg = resolve(&OtelEnv {
                headers: Some("authorization=Bearer super-secret-token".to_owned()),
                ..env("http://collector.example:4318")
            })
            .expect("resolves")
            .expect("export is on");
            format!(
                "{:?}",
                Pipeline::start(cfg).expect("the pipeline must start")
            )
        };
        for forbidden in [
            "collector.example",
            "super-secret-token",
            "authorization",
            "4318",
        ] {
            assert!(
                !rendered.contains(forbidden),
                "Pipeline's Debug must not carry {forbidden}: {rendered}"
            );
        }
    }
}
