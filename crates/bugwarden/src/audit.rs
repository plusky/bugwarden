//! bugwarden places an operator-written guard policy between an MCP client
//! and Bugzilla. On the client side that guard is invisible by design: a
//! hidden bug is indistinguishable from a nonexistent one, filtered search
//! results are dropped without a trace, and the rules doing either are
//! never named. The audit stream is the other half of that bargain — the
//! operator's own record of what was asked and what the guard decided. Its
//! records carry exactly the facts the client must never see (guard
//! verdicts, matched rule names, suppressed bug ids), so the stream is
//! written only to an operator-controlled local file: it is never exposed
//! through any MCP surface, and it is never mixed into the diagnostic
//! stderr stream. Diagnostics about the sink itself (a full disk, a failed
//! rotation) go to `tracing` as usual, but carry no event content.
//!
//! # File format
//!
//! One JSON object per line (JSONL), schema version 1: see [`AuditEvent`]
//! for the envelope and [`AuditEventKind`] for the record kinds. Records
//! are append-only; [`AuditSink`] optionally rotates the file by size.
//! A failed write can tear the stream: a failed `write(2)` may leave a
//! partial line behind, and the sink heals it by prefixing the next
//! record with a newline. After an outage the file may therefore contain
//! one empty line and possibly one torn (unparsable) line — parsers must
//! skip empty lines and may encounter at most one torn line per outage.
//!
//! # What can never appear in a record
//!
//! The schema is closed on purpose: every struct rejects unknown fields,
//! every enum is a fixed vocabulary, and no dedicated field exists for
//! the Bugzilla API key, incoming request headers, or free-text bug
//! content (summaries, comments, attachments). The one open field is
//! [`RequestInfo::params`]: it is fed exclusively through an allowlist
//! of client-authored parameter keys at the recording call site, and
//! data fetched from Bugzilla never passes through it. [`AuditError`]
//! follows the same rule — it names the failed
//! operation and carries the underlying I/O error, never the record that
//! failed to be written, so it stays safe to surface in diagnostics.
//!
//! # Ordering, durability, and blocking
//!
//! [`AuditSink::record`] is deliberately synchronous: when it returns
//! `Ok`, the record has been handed to the kernel (and, with
//! [`AuditConfig::fsync`], flushed to stable storage), so a caller can
//! guarantee "record persisted before the response is returned". All
//! writes serialize through one mutex; `seq` is assigned under that lock,
//! so file order equals `seq` order — a documented guarantee. Async
//! callers must wrap calls in `tokio::task::block_in_place` or
//! `tokio::task::spawn_blocking` (this module itself has no tokio
//! dependency).
//!
//! One deliberate asymmetry in the loss accounting: with
//! [`AuditConfig::fsync`] enabled, a failed `sync_data` after a
//! successful `write(2)` counts the record as dropped even though its
//! bytes may already be in the file. The same `seq` can then appear
//! twice on disk, and the following `audit_gap` may over-report the
//! loss. The direction is chosen: the accounting may over-report,
//! never under-report.
//!
//! [`AuditConfig::fsync`]: crate::audit::AuditConfig::fsync
//! [`AuditError`]: crate::audit::AuditError
//! [`AuditEvent`]: crate::audit::AuditEvent
//! [`AuditEventKind`]: crate::audit::AuditEventKind
//! [`AuditSink`]: crate::audit::AuditSink
//! [`AuditSink::record`]: crate::audit::AuditSink::record
//! [`RequestInfo::params`]: crate::audit::RequestInfo::params

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::Context as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// The audit record schema version stamped into every event (`v`).
pub const SCHEMA_VERSION: u32 = 1;

/// How often a persistently failing sink repeats its `tracing` diagnostic.
const FAILURE_LOG_INTERVAL: Duration = Duration::from_secs(60);

/// Upper bound for [`AuditConfig::rotate_keep`]: rotation shifts every
/// kept file with one rename syscall each while all audit writes wait on
/// the sink lock, so the kept window must stay small.
const MAX_ROTATE_KEEP: u32 = 10_000;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// What the server does with a tool call whose audit record cannot be
/// persisted.
///
/// This module only parses and stores the choice; enforcement lives with
/// the code that wires the sink into the request path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailMode {
    /// Keep serving. The gap is still visible in the stream afterwards
    /// (see [`AuditGapEvent`]), but requests made while the sink is down
    /// are lost to the record. Availability over accountability.
    Open,
    /// Reads the guard fully allows still proceed unaudited; write
    /// operations and any call where the guard suppressed, denied, or
    /// refused something are refused until their record can be persisted
    /// again.
    ClosedWritesDenials,
    /// Every tool call is refused until its record can be persisted.
    /// Accountability over availability: an unmonitored full disk turns
    /// the server off.
    ClosedAll,
}

fn default_rotate_max_bytes() -> u64 {
    64 * 1024 * 1024
}

fn default_rotate_keep() -> u32 {
    8
}

fn default_suppressed_ids() -> bool {
    true
}

/// Audit sink configuration, loaded from an operator-owned TOML file.
///
/// Parsing is strict: unknown keys anywhere are an error at load time, so
/// a typo cannot silently disable a setting. `examples/audit.toml` in the
/// repository is a fully commented worked example.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditConfig {
    /// The JSONL audit file. Required. The parent directory is created
    /// (mode 0700) if missing; the file itself is created mode 0600 and
    /// only ever appended to.
    pub path: PathBuf,
    /// `sync_data()` after every record. The default `false` still
    /// survives a killed process — `write(2)` puts the record in the page
    /// cache before [`AuditSink::record`] returns — but only `true`
    /// additionally survives power loss, at a per-record latency cost.
    #[serde(default)]
    pub fsync: bool,
    /// What to do with tool calls while records cannot be persisted.
    /// When absent, the server derives the mode from the transport at
    /// wiring time: `stdio` (a local, single-operator session) defaults
    /// to `open`, `http` (remote clients) defaults to `closed_all`.
    #[serde(default)]
    pub fail_mode: Option<FailMode>,
    /// Rotate the live file before a record would push it past this many
    /// bytes. `0` disables built-in rotation entirely — for operators who
    /// run external rotation instead. Default: 67108864 (64 MiB).
    #[serde(default = "default_rotate_max_bytes")]
    pub rotate_max_bytes: u64,
    /// How many rotated files (`<path>.1` … `<path>.N`) are kept; older
    /// ones are deleted at rotation time. Must be at least 1 while
    /// `rotate_max_bytes` is non-zero, and at most 10000 (both validated
    /// at load). Shrinking it between runs strands existing
    /// higher-numbered `<path>.N` files: bugwarden never deletes them —
    /// remove them manually. Default: 8.
    #[serde(default = "default_rotate_keep")]
    pub rotate_keep: u32,
    /// Whether records may carry the ids of guard-suppressed bugs
    /// ([`GuardInfo::suppressed_ids`]). When `false`, records carry only
    /// counts. This module stores the flag; the recording call sites
    /// enforce it when building [`GuardInfo`]. Default: `true`.
    #[serde(default = "default_suppressed_ids")]
    pub suppressed_ids: bool,
}

impl AuditConfig {
    /// Strict parse + validation of an audit configuration document.
    ///
    /// Rejects unknown keys everywhere (`deny_unknown_fields`), then
    /// enforces that `rotate_keep >= 1` whenever built-in rotation is
    /// enabled (`rotate_max_bytes > 0`) and that `rotate_keep` never
    /// exceeds 10000.
    pub fn from_toml_str(s: &str) -> anyhow::Result<AuditConfig> {
        let cfg: AuditConfig =
            toml::from_str(s).context("failed to parse audit configuration TOML")?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Read + [`AuditConfig::from_toml_str`], with the file path in every
    /// error.
    pub fn load(path: &Path) -> anyhow::Result<AuditConfig> {
        let s = std::fs::read_to_string(path).with_context(|| {
            format!("failed to read audit configuration file {}", path.display())
        })?;
        Self::from_toml_str(&s)
            .with_context(|| format!("invalid audit configuration file {}", path.display()))
    }

    fn validate(&self) -> anyhow::Result<()> {
        if self.rotate_max_bytes > 0 && self.rotate_keep == 0 {
            anyhow::bail!(
                "rotate_keep must be at least 1 while rotate_max_bytes is non-zero: \
                 rotation renames the live file to <path>.1, and keeping zero rotated \
                 files would delete the records it just wrote; set rotate_max_bytes = 0 \
                 instead to hand rotation to an external tool"
            );
        }
        if self.rotate_keep > MAX_ROTATE_KEEP {
            anyhow::bail!(
                "rotate_keep must be at most {MAX_ROTATE_KEEP}: every rotation shifts \
                 each kept file with its own rename syscall while all audit writes \
                 wait, so a larger window would stall the server; raise \
                 rotate_max_bytes instead to retain more history"
            );
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Event schema (v1)
// ---------------------------------------------------------------------------

/// One audit record: the envelope common to every kind.
///
/// Serialized as a single JSON object (one line of the JSONL file) with
/// the envelope fields first, then the fields of the [`AuditEventKind`]
/// flattened alongside them under an `event` tag.
///
/// This is the only struct in the schema without `deny_unknown_fields`:
/// serde cannot combine that attribute with `flatten`. Unknown top-level
/// keys are still rejected — they flow into the flattened kind, whose
/// structs are closed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Schema version; always [`SCHEMA_VERSION`].
    pub v: u32,
    /// Wall-clock record time, RFC 3339 UTC with millisecond precision.
    /// Stamped by the sink. `seq`, not `ts`, is the ordering authority —
    /// the wall clock can step backwards.
    pub ts: String,
    /// Per-process monotonic sequence number, assigned by the sink under
    /// its write lock, starting at 1. File order equals `seq` order, and
    /// only records that reached the file consume a number, so the seqs
    /// on disk are contiguous — with one exception: under
    /// [`AuditConfig::fsync`], a failed sync after a successful write
    /// counts the record as dropped even though its bytes may be on
    /// disk, so a seq can appear twice and the next `audit_gap` may
    /// over-report (never under-report) the loss. A restarted process
    /// starts again at 1; across restarts, ordering comes from file
    /// order and `ts`.
    pub seq: u64,
    /// The MCP session this record belongs to.
    pub session: SessionInfo,
    /// The record kind and its payload, flattened into the envelope.
    #[serde(flatten)]
    pub kind: AuditEventKind,
}

/// The audit record kinds, tagged `event` in the serialized form.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum AuditEventKind {
    /// A tool call reached the server (whatever the guard then decided).
    /// Boxed: this payload dwarfs the other variants, and boxing keeps the
    /// enum small on the stack; the serialized form is unaffected.
    ToolCall(Box<ToolCallEvent>),
    /// An MCP session performed the `initialize` handshake.
    Initialize(InitializeEvent),
    /// One or more records could not be persisted; see [`AuditGapEvent`].
    AuditGap(AuditGapEvent),
}

/// Payload of a `tool_call` record: one MCP tool invocation, from request
/// to outcome, including what the guard decided about it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolCallEvent {
    /// The calling client as it introduced itself.
    pub client: ClientInfo,
    /// Distributed-trace correlation ids, when the transport carried any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace: Option<TraceContext>,
    /// The request as the client made it (allowlisted parameters only).
    pub request: RequestInfo,
    /// What the guard decided. Absent for tools that perform no guard
    /// assessment (`bug_url` computes a URL locally and contacts nothing).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guard: Option<GuardInfo>,
    /// The Bugzilla side of the call. Absent when Bugzilla was never
    /// contacted (denied before any upstream request, or a local tool).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream: Option<UpstreamInfo>,
    /// How the call ended, from the client's point of view.
    pub outcome: OutcomeInfo,
}

/// Payload of an `initialize` record: a client opened an MCP session.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InitializeEvent {
    /// The client as it introduced itself in the handshake.
    pub client: ClientInfo,
    /// The MCP protocol version the client requested, when it sent one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol_version: Option<String>,
}

/// Payload of an `audit_gap` record: the sink failed to persist records
/// and has recovered. Written as the first record after the first
/// successful write, so a gap in the stream is always visible in the
/// stream itself.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditGapEvent {
    /// How many records were lost while the sink was failing.
    pub dropped: u64,
    /// Why the most recent of them was lost. A closed vocabulary on
    /// purpose: a free-text reason would be a hole in the schema's
    /// no-secrets guarantee.
    pub reason: GapReason,
}

/// Why records were lost. See [`AuditGapEvent`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GapReason {
    /// Serializing or writing a record failed.
    WriteError,
    /// Rotating the file failed.
    RotationError,
}

/// The MCP session a record belongs to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionInfo {
    /// Server-assigned session identifier, when the transport has one
    /// (streamable HTTP does; a stdio session is the process itself).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Which transport carried the session.
    pub transport: TransportKind,
    /// Remote peer address for network transports, absent for stdio.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote: Option<String>,
}

/// The transport a session arrived over.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportKind {
    /// Local stdin/stdout session.
    Stdio,
    /// Streamable-HTTP session.
    Http,
}

/// The calling client's identity, as far as one exists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientInfo {
    /// Client name from the `initialize` handshake. Self-declared and
    /// therefore untrusted: treat it as a label, never as an identity.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Client version from the `initialize` handshake. Untrusted, as
    /// `name` is.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Reserved for a future authenticated identity. Always `None` for
    /// now; nothing self-declared may ever be promoted into it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub principal: Option<String>,
}

/// W3C-style trace correlation ids, when the transport carried any.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TraceContext {
    /// Trace id (hex, as received).
    pub trace_id: String,
    /// Span id (hex, as received).
    pub span_id: String,
}

impl TraceContext {
    /// Parse a W3C `traceparent` header value (version 00 only) into
    /// trace ids.
    ///
    /// Strict by design: anything not exactly
    /// `00-<32 lowercase hex>-<16 lowercase hex>-<2 lowercase hex>`
    /// (55 bytes) with non-zero trace and span ids is `None`. In
    /// particular:
    ///
    /// - The length check comes FIRST, on bytes — a cheap rejection of
    ///   oversized input, and no later step slices a string, so
    ///   multibyte unicode can never panic the parser.
    /// - The version must be exactly `00`. That rejects `ff` (forbidden
    ///   by W3C) AND every future version: W3C allows lenient forward
    ///   parsing, but this parser refuses to store ids from a format
    ///   revision it cannot fully validate.
    /// - Hex means ASCII lowercase `[0-9a-f]` only; uppercase is invalid
    ///   per W3C.
    /// - An all-zero trace id or span id is invalid per W3C.
    /// - The flags byte pair is validated as hex but not stored — the
    ///   schema has no field for it.
    ///
    /// The input is client-controlled bytes headed for operator logs, so
    /// it is never logged here, valid or not: rejection is silent
    /// (I12-adjacent hygiene).
    pub(crate) fn from_traceparent(value: &str) -> Option<TraceContext> {
        fn lower_hex(bytes: &[u8]) -> bool {
            bytes
                .iter()
                .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
        }
        let bytes = value.as_bytes();
        if bytes.len() != 55 {
            return None;
        }
        // Fixed layout: bytes 0-1 version, byte 2 `-`, bytes 3-34
        // trace-id, byte 35 `-`, bytes 36-51 span-id, byte 52 `-`,
        // bytes 53-54 flags.
        if &bytes[0..2] != b"00" {
            return None;
        }
        if bytes[2] != b'-' || bytes[35] != b'-' || bytes[52] != b'-' {
            return None;
        }
        let trace_id = &bytes[3..35];
        let span_id = &bytes[36..52];
        let flags = &bytes[53..55];
        if !lower_hex(trace_id) || !lower_hex(span_id) || !lower_hex(flags) {
            return None;
        }
        if trace_id.iter().all(|&b| b == b'0') || span_id.iter().all(|&b| b == b'0') {
            return None;
        }
        // Both ranges are validated ASCII hex, so the conversions cannot
        // fail; going through `from_utf8` keeps the parser panic-free by
        // construction.
        Some(TraceContext {
            trace_id: std::str::from_utf8(trace_id).ok()?.to_owned(),
            span_id: std::str::from_utf8(span_id).ok()?.to_owned(),
        })
    }
}

/// The request as the client made it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestInfo {
    /// MCP tool name.
    pub tool: String,
    /// JSON-RPC request id, when the transport exposes one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// CLIENT-authored request parameters, passed through an allowlist
    /// by the recording call site: identifiers, projections, switches —
    /// parameters whose values the client chose. Bug content fetched
    /// from Bugzilla must never be placed here; a tool result is not a
    /// parameter.
    pub params: BTreeMap<String, serde_json::Value>,
}

/// What the guard decided about a tool call.
///
/// Everything in here is server-side-only fact: verdicts, rule names, and
/// suppression counts are precisely what the guard withholds from the
/// client, and they reach the operator only through this stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuardInfo {
    /// The overall verdict for the call.
    pub verdict: Verdict,
    /// Name of the policy rule that decided the verdict, when one did
    /// (absent when the policy default decided).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    /// Digest of the policy document in force, so a record can be tied to
    /// the exact policy that produced it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_hash: Option<String>,
    /// How many bugs the guard removed from the response. This count is
    /// authoritative: [`GuardInfo::suppressed_ids`] may be elided
    /// (empty) or a subset by configuration, so consumers must never
    /// infer the count from the id list.
    pub suppressed_count: u64,
    /// The removed bug ids. Left empty by the recording call sites when
    /// [`AuditConfig::suppressed_ids`] is `false`.
    pub suppressed_ids: Vec<u64>,
    /// Names of fields the guard redacted from served bugs (field names
    /// only, never their values).
    pub redacted_fields: Vec<String>,
}

/// The guard's overall verdict for one tool call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// Served in full.
    Served,
    /// Served, but with results suppressed or fields redacted.
    ServedFiltered,
    /// Denied: the client saw the uniform not-accessible response.
    Denied,
    /// Refused before any assessment (invalid arguments, disabled tool,
    /// or a fail-closed audit outage).
    Refused,
}

/// The Bugzilla side of a tool call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamInfo {
    /// How many Bugzilla REST requests the call made.
    pub requests: u32,
    /// HTTP status of the final upstream response, when one was received.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    /// Total time spent waiting on Bugzilla, in milliseconds.
    pub latency_ms: u64,
}

/// How a tool call ended, from the client's point of view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutcomeInfo {
    /// Coarse outcome class.
    pub class: OutcomeClass,
    /// Total request handling time, in milliseconds.
    pub duration_ms: u64,
}

/// Coarse outcome of a tool call. Note that a guard denial is `ok` here:
/// the client received a well-formed response (the uniform not-accessible
/// text); the denial itself lives in [`GuardInfo::verdict`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutcomeClass {
    /// A well-formed result was returned.
    Ok,
    /// The call was refused (invalid arguments, disabled tool, audit
    /// outage under a closed fail mode).
    Refused,
    /// The call failed (upstream or internal error).
    Error,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// A record could not be persisted.
///
/// Deliberately content-free: an `AuditError` may end up in diagnostics,
/// so it names the failed operation and carries the underlying error, but
/// never the record that was being written.
#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    /// Serializing the record to JSON failed.
    #[error("audit record serialization failed")]
    Serialize(#[source] serde_json::Error),
    /// Writing the record (or syncing it, under `fsync = true`) failed.
    #[error("audit write failed")]
    Write(#[source] std::io::Error),
    /// Rotating the audit file failed.
    #[error("audit rotation failed")]
    Rotation(#[source] std::io::Error),
}

impl AuditError {
    fn gap_reason(&self) -> GapReason {
        match self {
            AuditError::Serialize(_) | AuditError::Write(_) => GapReason::WriteError,
            AuditError::Rotation(_) => GapReason::RotationError,
        }
    }
}

// ---------------------------------------------------------------------------
// Sink
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct SinkState {
    file: File,
    /// Current size of the live file, maintained across writes so
    /// rotation needs no `stat` per record.
    size: u64,
    /// Last assigned sequence number; 0 before the first record.
    seq: u64,
    /// Records lost since the last successful write; reported by the next
    /// `audit_gap` record.
    dropped: u64,
    /// Why the most recent record was lost (meaningful while
    /// `dropped > 0`).
    gap_reason: GapReason,
    /// A failed write (or sync) may have left a torn, unterminated line
    /// at the end of the live file. While set, the next written line
    /// carries a leading newline that terminates the debris —
    /// self-healing, at worst one empty line, which parsers skip (see
    /// the module docs). Cleared by the next fully successful write.
    torn: bool,
    /// When the failing-sink diagnostic was last emitted.
    last_failure_log: Option<Instant>,
}

/// Append-only JSONL writer for [`AuditEvent`] records.
///
/// All writes go through one internal mutex: `seq` assignment, rotation,
/// and the write itself are a single critical section, which is what makes
/// "file order equals `seq` order" a guarantee rather than a likelihood.
/// The API is synchronous by design (see the module docs); async callers
/// use `tokio::task::block_in_place` or `tokio::task::spawn_blocking`.
///
/// The sink assumes it is the only writer: run exactly one live sink per
/// path. Concurrent sinks on one path — in the same process or in
/// several — interleave their rename shifts and corrupt rotation.
#[derive(Debug)]
pub struct AuditSink {
    cfg: AuditConfig,
    state: Mutex<SinkState>,
    /// Test-only fault injection: when set, the write step fails without
    /// touching the file. Lets the gap-marker path be exercised without
    /// weakening the production API.
    #[cfg(test)]
    fail_writes: std::sync::atomic::AtomicBool,
    /// Test-only fault injection: when set, the write step writes
    /// roughly half the line and then fails — a deterministic stand-in
    /// for `ENOSPC` tearing a line mid-write.
    #[cfg(test)]
    fail_writes_partial: std::sync::atomic::AtomicBool,
    /// Test-only fault injection: when set, rotation fails before
    /// touching any file. Lets the rotation-failure gap path be
    /// exercised.
    #[cfg(test)]
    fail_rotation: std::sync::atomic::AtomicBool,
}

impl AuditSink {
    /// Open (or create) the audit file and return a ready sink.
    ///
    /// - Refuses if `cfg.path` exists and is a symlink. Best-effort by
    ///   design: the audit directory is expected to be operator-owned, so
    ///   the pre-check catches misconfiguration (a link left behind, a
    ///   path pointed somewhere surprising) rather than defending against
    ///   a racing local attacker.
    /// - Creates the parent directory (mode 0700) if missing.
    /// - Opens the file append-only (`O_WRONLY|O_APPEND|O_CREAT`), mode
    ///   0600 when created.
    ///
    /// Errors carry the offending path; they never carry record content
    /// (there is none yet).
    pub fn open(cfg: AuditConfig) -> anyhow::Result<AuditSink> {
        // A hand-constructed config could bypass load-time validation, so
        // re-validate here; the check is free.
        cfg.validate()?;
        if let Ok(meta) = std::fs::symlink_metadata(&cfg.path) {
            if meta.file_type().is_symlink() {
                anyhow::bail!(
                    "audit file {} is a symlink; refusing to follow it — point `path` \
                     at a regular file in an operator-owned directory",
                    cfg.path.display()
                );
            }
        }
        if let Some(parent) = cfg.path.parent() {
            if !parent.as_os_str().is_empty() {
                let mut builder = std::fs::DirBuilder::new();
                builder.recursive(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::DirBuilderExt as _;
                    builder.mode(0o700);
                }
                builder.create(parent).with_context(|| {
                    format!("failed to create audit directory {}", parent.display())
                })?;
            }
        }
        let file = open_live_file(&cfg.path)
            .with_context(|| format!("failed to open audit file {}", cfg.path.display()))?;
        let size = file
            .metadata()
            .with_context(|| format!("failed to stat audit file {}", cfg.path.display()))?
            .len();
        Ok(AuditSink {
            cfg,
            state: Mutex::new(SinkState {
                file,
                size,
                seq: 0,
                dropped: 0,
                gap_reason: GapReason::WriteError,
                torn: false,
                last_failure_log: None,
            }),
            #[cfg(test)]
            fail_writes: std::sync::atomic::AtomicBool::new(false),
            #[cfg(test)]
            fail_writes_partial: std::sync::atomic::AtomicBool::new(false),
            #[cfg(test)]
            fail_rotation: std::sync::atomic::AtomicBool::new(false),
        })
    }

    /// Persist one record; returns its assigned `seq`.
    ///
    /// Blocks until the record is written (and synced, under `fsync`). If
    /// earlier records were lost, an `audit_gap` record reporting them is
    /// written first — and must itself succeed — before the loss counter
    /// resets; the gap record is stamped with this call's `session`.
    ///
    /// On failure the record is counted as dropped, a rate-limited
    /// `tracing::error!` diagnostic is emitted (first failure immediately,
    /// then at most one per minute), and the error is
    /// returned so the caller can apply the configured [`FailMode`]. A
    /// failed record consumes no `seq` — with one deliberate exception:
    /// under [`AuditConfig::fsync`], a `sync_data` failure after a
    /// successful write counts the record as dropped even though its
    /// bytes (seq included) may already be in the file, so that seq can
    /// appear twice on disk and the following `audit_gap` may
    /// over-report the loss. Over-reporting, never under-reporting, is
    /// the chosen direction.
    pub fn record(&self, kind: AuditEventKind, session: SessionInfo) -> Result<u64, AuditError> {
        // A poisoned mutex means a writer panicked; the size/seq state is
        // still usable (worst case an early rotation), so keep going —
        // dropping audit coverage over a bookkeeping wobble would be the
        // worse trade.
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.dropped > 0 {
            let gap = AuditEventKind::AuditGap(AuditGapEvent {
                dropped: state.dropped,
                reason: state.gap_reason,
            });
            match self.write_event(&mut state, gap, session.clone()) {
                Ok(_) => state.dropped = 0,
                Err(err) => {
                    // The gap record did not make it out either. The
                    // caller's record was never attempted, so it is lost
                    // with the rest and joins the count.
                    state.dropped = state.dropped.saturating_add(1);
                    state.gap_reason = err.gap_reason();
                    self.log_failure(&mut state, &err);
                    return Err(err);
                }
            }
        }
        match self.write_event(&mut state, kind, session) {
            Ok(seq) => Ok(seq),
            Err(err) => {
                state.dropped = state.dropped.saturating_add(1);
                state.gap_reason = err.gap_reason();
                self.log_failure(&mut state, &err);
                Err(err)
            }
        }
    }

    /// Stamp, serialize, rotate if due, write, sync, account. Called with
    /// the state lock held.
    fn write_event(
        &self,
        state: &mut SinkState,
        kind: AuditEventKind,
        session: SessionInfo,
    ) -> Result<u64, AuditError> {
        let seq = state.seq + 1;
        let event = AuditEvent {
            v: SCHEMA_VERSION,
            ts: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            seq,
            session,
            kind,
        };
        let mut line = Vec::new();
        // A failed write may have left a torn, unterminated line at the
        // end of the file; a leading newline terminates it so the stream
        // self-heals (worst case one empty line, which parsers skip —
        // see the module docs).
        if state.torn {
            line.push(b'\n');
        }
        serde_json::to_writer(&mut line, &event).map_err(AuditError::Serialize)?;
        line.push(b'\n');
        let len = line.len() as u64;
        // Rotate BEFORE writing, so the limit is never exceeded. A single
        // record larger than the limit is written into an empty live file
        // as-is: rotating an empty file would discard nothing and loop.
        if self.cfg.rotate_max_bytes > 0
            && state.size > 0
            && state.size + len > self.cfg.rotate_max_bytes
        {
            self.rotate(state).map_err(AuditError::Rotation)?;
        }
        #[cfg(test)]
        if self.fail_writes.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(AuditError::Write(std::io::Error::other(
                "injected write failure (test)",
            )));
        }
        #[cfg(test)]
        if self
            .fail_writes_partial
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            // Write roughly half the line, then fail: a deterministic
            // stand-in for ENOSPC tearing a line mid-write.
            state
                .file
                .write_all(&line[..line.len() / 2])
                .map_err(AuditError::Write)?;
            state.torn = true;
            return Err(AuditError::Write(std::io::Error::other(
                "injected partial write failure (test)",
            )));
        }
        state.file.write_all(&line).map_err(|e| {
            // An unknown number of bytes made it out: assume a torn line.
            state.torn = true;
            AuditError::Write(e)
        })?;
        if self.cfg.fsync {
            state.file.sync_data().map_err(|e| {
                // The line is complete in the page cache but may not have
                // reached the disk; treat it as torn so the next record
                // re-terminates whatever survives.
                state.torn = true;
                AuditError::Write(e)
            })?;
        }
        state.torn = false;
        state.size += len;
        state.seq = seq;
        Ok(seq)
    }

    /// Numbered shift rotation: `<path>.N` → `<path>.N+1` from the
    /// highest kept slot down, live file → `<path>.1`, live file
    /// recreated mode 0600, parent directory fsynced so the renames are
    /// durable. Called with the state lock held.
    fn rotate(&self, state: &mut SinkState) -> std::io::Result<()> {
        #[cfg(test)]
        if self
            .fail_rotation
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            return Err(std::io::Error::other("injected rotation failure (test)"));
        }
        let live = &self.cfg.path;
        // The oldest kept slot would shift past the cap: delete it.
        match std::fs::remove_file(rotated_path(live, self.cfg.rotate_keep)) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        for n in (2..=self.cfg.rotate_keep).rev() {
            match std::fs::rename(rotated_path(live, n - 1), rotated_path(live, n)) {
                Ok(()) => {}
                // A slot that does not exist yet has nothing to shift.
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
        match std::fs::rename(live, rotated_path(live, 1)) {
            Ok(()) => {}
            // Recovery from a previous partial rotation (renamed but not
            // recreated): nothing to move, just recreate below.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        state.file = open_live_file(live)?;
        state.size = 0;
        #[cfg(unix)]
        if let Some(parent) = live.parent() {
            let dir = if parent.as_os_str().is_empty() {
                Path::new(".")
            } else {
                parent
            };
            File::open(dir)?.sync_all()?;
        }
        Ok(())
    }

    /// Rate-limited `tracing::error!` about a failing sink. Called with
    /// the state lock held. Carries the error and the drop count — never
    /// record content.
    fn log_failure(&self, state: &mut SinkState, err: &AuditError) {
        let due = state
            .last_failure_log
            .is_none_or(|last| last.elapsed() >= FAILURE_LOG_INTERVAL);
        if due {
            state.last_failure_log = Some(Instant::now());
            tracing::error!(
                error = ?err,
                dropped = state.dropped,
                path = %self.cfg.path.display(),
                "audit record could not be persisted; records are being dropped"
            );
        }
    }

    /// Whether the sink is currently in failure: at least one record has
    /// been dropped since the last successful write. The request path
    /// consults this before dispatching a tool call, so a sink that is
    /// already down can hold back further unaudited work under the closed
    /// fail modes instead of discovering the outage one record at a time.
    pub fn failing(&self) -> bool {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .dropped
            > 0
    }

    /// Whether records may carry suppressed bug ids
    /// ([`AuditConfig::suppressed_ids`]); the recording call site enforces
    /// the flag when building [`GuardInfo`].
    pub fn suppressed_ids(&self) -> bool {
        self.cfg.suppressed_ids
    }

    /// Test-only fault injection; see the `fail_writes` field. Crate
    /// visibility: the request-path fail-mode tests in `server.rs` drive
    /// a real sink into failure through this same hook.
    #[cfg(test)]
    pub(crate) fn set_fail_writes(&self, fail: bool) {
        self.fail_writes
            .store(fail, std::sync::atomic::Ordering::Relaxed);
    }

    /// Test-only fault injection; see the `fail_writes_partial` field.
    #[cfg(test)]
    fn set_fail_writes_partial(&self, fail: bool) {
        self.fail_writes_partial
            .store(fail, std::sync::atomic::Ordering::Relaxed);
    }

    /// Test-only fault injection; see the `fail_rotation` field.
    #[cfg(test)]
    fn set_fail_rotation(&self, fail: bool) {
        self.fail_rotation
            .store(fail, std::sync::atomic::Ordering::Relaxed);
    }
}

/// Open the live audit file append-only, creating it mode 0600 if absent.
fn open_live_file(path: &Path) -> std::io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.append(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    opts.open(path)
}

/// `<path>.<n>`, the n-th rotated file.
fn rotated_path(live: &Path, n: u32) -> PathBuf {
    let mut os = live.as_os_str().to_os_string();
    os.push(format!(".{n}"));
    PathBuf::from(os)
}

// ---------------------------------------------------------------------------
// Request-path wiring
// ---------------------------------------------------------------------------

impl FailMode {
    /// The fail mode in force: the operator's explicit choice when the
    /// configuration sets one, else the transport-derived default.
    pub fn resolve(explicit: Option<FailMode>, transport: TransportKind) -> FailMode {
        explicit.unwrap_or_else(|| FailMode::default_for(transport))
    }

    /// The default fail mode for a transport, used when the audit
    /// configuration leaves `fail_mode` unset: `stdio` (a local,
    /// single-operator session) defaults to `open` — availability for a
    /// single user; `http` (remote clients) defaults to `closed_all` —
    /// accountability for a fleet.
    pub fn default_for(transport: TransportKind) -> FailMode {
        match transport {
            TransportKind::Stdio => FailMode::Open,
            TransportKind::Http => FailMode::ClosedAll,
        }
    }
}

/// Everything the request path needs to write audit records: the open
/// sink, the resolved fail mode, and the startup-computed identifiers
/// records carry. Built once at startup, shared behind an `Arc`.
#[derive(Debug)]
pub struct AuditState {
    /// The open sink; every record goes through it.
    pub sink: AuditSink,
    /// What happens to tool calls while records cannot be persisted.
    /// Already resolved ([`FailMode::resolve`]): the explicit configured
    /// value, else the transport default.
    pub fail_mode: FailMode,
    /// `sha256:<hex>` digest of the policy file in force, stamped into
    /// [`GuardInfo::policy_hash`]. `None` when the built-in default
    /// policy applies (there is no file to hash).
    pub policy_hash: Option<String>,
    /// Session id stamped into stdio records. One process is one stdio
    /// session, so `<pid>-<unix epoch secs at startup>` anchors those
    /// records the way the `mcp-session-id` header anchors http ones.
    pub stdio_session_id: String,
}

/// The `sha256:<hex>` digest of a policy document's bytes — the value
/// [`AuditState::policy_hash`] holds and [`GuardInfo::policy_hash`]
/// carries. The digest is over the raw file bytes, not any parsed form,
/// so a record ties to the exact document the operator deployed.
pub fn policy_hash_of(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

impl AuditState {
    /// Assemble the request-path state around an open sink.
    pub fn new(sink: AuditSink, fail_mode: FailMode, policy_hash: Option<String>) -> AuditState {
        let epoch_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        AuditState {
            sink,
            fail_mode,
            policy_hash,
            stdio_session_id: format!("{}-{epoch_secs}", std::process::id()),
        }
    }
}

/// Severity of a verdict for the worst-wins merge:
/// `Denied > Refused > ServedFiltered > Served`.
fn verdict_rank(verdict: Verdict) -> u8 {
    match verdict {
        Verdict::Served => 0,
        Verdict::ServedFiltered => 1,
        Verdict::Refused => 2,
        Verdict::Denied => 3,
    }
}

#[derive(Debug, Default)]
struct CellState {
    verdict: Option<Verdict>,
    rule: Option<String>,
    suppressed_ids: std::collections::BTreeSet<u64>,
    /// Suppressions that have no bug id (private comments or attachment
    /// metadata filtered out): counted, never named.
    suppressed_extra: u64,
    redacted_fields: std::collections::BTreeSet<String>,
    upstream: Option<UpstreamInfo>,
}

/// Per-request enrichment cell for one tool call's audit record.
///
/// The wrapper that owns the record inserts one cell into the request's
/// extensions before dispatch; the guard call sites inside the tool note
/// what was decided; the wrapper drains the cell into [`GuardInfo`] after
/// the tool returns. A tool that never touches the cell (it performs no
/// guard assessment) yields no `GuardInfo` at all. Multi-id calls note
/// once per id and the cell merges: ONE record per call, worst verdict,
/// with suppression carrying the per-id detail.
///
/// Interior mutability via a `Mutex` with the same poison posture as the
/// sink: a panicked noter loses nothing worth dropping enrichment over.
#[derive(Debug, Default)]
pub struct AuditCell {
    state: Mutex<CellState>,
}

impl AuditCell {
    fn lock(&self) -> std::sync::MutexGuard<'_, CellState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Worst-wins verdict merge. The rule follows the deciding verdict: a
    /// strict upgrade replaces the stored rule with the new one (present
    /// or not — a default-decided verdict has none), an equally severe
    /// verdict may only fill an empty slot (first rule recorded wins),
    /// and a less severe verdict changes nothing.
    fn merge(&self, verdict: Verdict, rule: Option<&str>) {
        let mut state = self.lock();
        match state.verdict {
            None => {
                state.verdict = Some(verdict);
                state.rule = rule.map(str::to_owned);
            }
            Some(current) if verdict_rank(verdict) > verdict_rank(current) => {
                state.verdict = Some(verdict);
                state.rule = rule.map(str::to_owned);
            }
            Some(current) if verdict_rank(verdict) == verdict_rank(current) => {
                if state.rule.is_none() {
                    state.rule = rule.map(str::to_owned);
                }
            }
            Some(_) => {}
        }
    }

    /// Note a verdict with no deciding rule (the policy default, or a
    /// refusal that never consulted a rule).
    pub fn note_verdict(&self, verdict: Verdict) {
        self.merge(verdict, None);
    }

    /// Note a verdict together with the rule that decided it.
    pub fn note_verdict_rule(&self, verdict: Verdict, rule: &str) {
        self.merge(verdict, Some(rule));
    }

    /// Note bug ids the guard hid in this call (unions across notes).
    /// Suppression implies at least a filtered serve, so the verdict is
    /// upgraded to `ServedFiltered` through the worst-wins merge — a
    /// record can never claim a clean `Served` while carrying
    /// suppressions.
    pub fn note_suppressed(&self, ids: impl IntoIterator<Item = u64>) {
        self.merge(Verdict::ServedFiltered, None);
        self.lock().suppressed_ids.extend(ids);
    }

    /// Note `n` suppressions that carry no bug id (private comments or
    /// attachment metadata filtered out). Adds across notes; upgrades the
    /// verdict exactly as [`AuditCell::note_suppressed`] does.
    pub fn note_suppressed_count(&self, n: u64) {
        if n == 0 {
            return;
        }
        self.merge(Verdict::ServedFiltered, None);
        let mut state = self.lock();
        state.suppressed_extra = state.suppressed_extra.saturating_add(n);
    }

    /// Note a field (or view marker) the guard redacted from served
    /// bugs. Upgrades the verdict to `ServedFiltered`.
    pub fn note_redacted(&self, field: &str) {
        self.merge(Verdict::ServedFiltered, None);
        self.lock().redacted_fields.insert(field.to_owned());
    }

    /// Note the Bugzilla side of the call, where the caller has it.
    pub fn note_upstream(&self, upstream: UpstreamInfo) {
        self.lock().upstream = Some(upstream);
    }

    /// Take the noted upstream info, if any.
    pub fn take_upstream(&self) -> Option<UpstreamInfo> {
        self.lock().upstream.take()
    }

    /// Drain the cell into the record's [`GuardInfo`]. `None` when no
    /// verdict was ever noted — the tool performed no guard assessment.
    /// When `suppressed_ids_cfg` is `false` the ids are dropped and only
    /// the count ships ([`AuditConfig::suppressed_ids`]). The count is
    /// the larger of the id set and the id-less counter, so it can only
    /// ever under-name, never under-count.
    pub fn into_guard_info(
        &self,
        policy_hash: Option<&str>,
        suppressed_ids_cfg: bool,
    ) -> Option<GuardInfo> {
        let state = std::mem::take(&mut *self.lock());
        let verdict = state.verdict?;
        let suppressed_count = (state.suppressed_ids.len() as u64).max(state.suppressed_extra);
        Some(GuardInfo {
            verdict,
            rule: state.rule,
            policy_hash: policy_hash.map(str::to_owned),
            suppressed_count,
            suppressed_ids: if suppressed_ids_cfg {
                state.suppressed_ids.into_iter().collect()
            } else {
                Vec::new()
            },
            redacted_fields: state.redacted_fields.into_iter().collect(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ---------- fixtures ----------

    const TS: &str = "2026-02-03T04:05:06.789Z";

    fn session_stdio() -> SessionInfo {
        SessionInfo {
            id: None,
            transport: TransportKind::Stdio,
            remote: None,
        }
    }

    fn session_http() -> SessionInfo {
        SessionInfo {
            id: Some("sess-1".into()),
            transport: TransportKind::Http,
            remote: Some("192.0.2.7:52611".into()),
        }
    }

    /// A `tool_call` with every schema field populated.
    fn sample_tool_call() -> AuditEventKind {
        AuditEventKind::ToolCall(Box::new(ToolCallEvent {
            client: ClientInfo {
                name: Some("example-agent".into()),
                version: Some("1.4.2".into()),
                principal: Some("alice@example.org".into()),
            },
            trace: Some(TraceContext {
                trace_id: "0af7651916cd43dd8448eb211c80319c".into(),
                span_id: "b7ad6b7169203331".into(),
            }),
            request: RequestInfo {
                tool: "bug_info".into(),
                id: Some("3".into()),
                params: BTreeMap::from([
                    ("id".to_string(), json!(1290042)),
                    ("include_private".to_string(), json!(false)),
                ]),
            },
            guard: Some(GuardInfo {
                verdict: Verdict::ServedFiltered,
                rule: Some("group-restricted".into()),
                policy_hash: Some("2b6e8f5d1c9a4e70".into()),
                suppressed_count: 2,
                suppressed_ids: vec![1290040, 1290041],
                redacted_fields: vec!["cc".into(), "flags".into()],
            }),
            upstream: Some(UpstreamInfo {
                requests: 1,
                status: Some(200),
                latency_ms: 48,
            }),
            outcome: OutcomeInfo {
                class: OutcomeClass::Ok,
                duration_ms: 52,
            },
        }))
    }

    fn sample_initialize() -> AuditEventKind {
        AuditEventKind::Initialize(InitializeEvent {
            client: ClientInfo {
                name: Some("example-agent".into()),
                version: Some("1.4.2".into()),
                principal: None,
            },
            protocol_version: Some("2025-06-18".into()),
        })
    }

    fn sample_gap() -> AuditEventKind {
        AuditEventKind::AuditGap(AuditGapEvent {
            dropped: 3,
            reason: GapReason::WriteError,
        })
    }

    fn envelope(seq: u64, session: SessionInfo, kind: AuditEventKind) -> AuditEvent {
        AuditEvent {
            v: SCHEMA_VERSION,
            ts: TS.to_string(),
            seq,
            session,
            kind,
        }
    }

    fn test_cfg(path: PathBuf) -> AuditConfig {
        AuditConfig {
            path,
            fsync: false,
            fail_mode: None,
            rotate_max_bytes: 0,
            rotate_keep: 8,
            suppressed_ids: true,
        }
    }

    /// Parse every line of an audit file. Empty lines are skipped, as
    /// the module docs require of parsers: a recovered write outage may
    /// leave one behind.
    fn read_events(path: &Path) -> Vec<AuditEvent> {
        let s = std::fs::read_to_string(path).expect("audit file must be readable");
        s.lines()
            .filter(|l| !l.is_empty())
            .map(|l| serde_json::from_str(l).expect("every audit line must parse as AuditEvent"))
            .collect()
    }

    /// Assert the live file and every rotated file respect
    /// `rotate_max_bytes`. Rotation happens before the write, so the
    /// limit is a hard bound (a single oversized record is the one
    /// documented exception, tested separately).
    fn assert_files_within_rotate_limit(cfg: &AuditConfig) {
        let mut paths = vec![cfg.path.clone()];
        paths.extend((1..=cfg.rotate_keep).map(|n| rotated_path(&cfg.path, n)));
        for p in paths {
            if let Ok(meta) = std::fs::metadata(&p) {
                assert!(
                    meta.len() <= cfg.rotate_max_bytes,
                    "{} is {} bytes, over rotate_max_bytes = {}",
                    p.display(),
                    meta.len(),
                    cfg.rotate_max_bytes
                );
            }
        }
    }

    // ---------- schema goldens (v1 stability gate) ----------
    //
    // These strings ARE the wire format. A failure here means the schema
    // changed; that requires a version bump and a deliberate decision,
    // not an updated constant.

    const GOLDEN_TOOL_CALL: &str = concat!(
        r#"{"v":1,"ts":"2026-02-03T04:05:06.789Z","seq":7,"#,
        r#""session":{"id":"sess-1","transport":"http","remote":"192.0.2.7:52611"},"#,
        r#""event":"tool_call","#,
        r#""client":{"name":"example-agent","version":"1.4.2","principal":"alice@example.org"},"#,
        r#""trace":{"trace_id":"0af7651916cd43dd8448eb211c80319c","span_id":"b7ad6b7169203331"},"#,
        r#""request":{"tool":"bug_info","id":"3","params":{"id":1290042,"include_private":false}},"#,
        r#""guard":{"verdict":"served_filtered","rule":"group-restricted","policy_hash":"2b6e8f5d1c9a4e70","#,
        r#""suppressed_count":2,"suppressed_ids":[1290040,1290041],"redacted_fields":["cc","flags"]},"#,
        r#""upstream":{"requests":1,"status":200,"latency_ms":48},"#,
        r#""outcome":{"class":"ok","duration_ms":52}}"#,
    );

    const GOLDEN_INITIALIZE: &str = concat!(
        r#"{"v":1,"ts":"2026-02-03T04:05:06.789Z","seq":1,"session":{"transport":"stdio"},"#,
        r#""event":"initialize","client":{"name":"example-agent","version":"1.4.2"},"#,
        r#""protocol_version":"2025-06-18"}"#,
    );

    const GOLDEN_AUDIT_GAP: &str = concat!(
        r#"{"v":1,"ts":"2026-02-03T04:05:06.789Z","seq":9,"session":{"transport":"stdio"},"#,
        r#""event":"audit_gap","dropped":3,"reason":"write_error"}"#,
    );

    #[test]
    fn golden_tool_call_json() {
        let event = envelope(7, session_http(), sample_tool_call());
        assert_eq!(serde_json::to_string(&event).unwrap(), GOLDEN_TOOL_CALL);
    }

    #[test]
    fn golden_initialize_json() {
        let event = envelope(1, session_stdio(), sample_initialize());
        assert_eq!(serde_json::to_string(&event).unwrap(), GOLDEN_INITIALIZE);
    }

    #[test]
    fn golden_audit_gap_json() {
        let event = envelope(9, session_stdio(), sample_gap());
        assert_eq!(serde_json::to_string(&event).unwrap(), GOLDEN_AUDIT_GAP);
    }

    #[test]
    fn events_round_trip() {
        for event in [
            envelope(7, session_http(), sample_tool_call()),
            envelope(1, session_stdio(), sample_initialize()),
            envelope(9, session_stdio(), sample_gap()),
        ] {
            let s = serde_json::to_string(&event).unwrap();
            let back: AuditEvent = serde_json::from_str(&s).unwrap();
            assert_eq!(back, event);
        }
    }

    // ---------- traceparent parsing ----------

    /// The canonical W3C example, 55 bytes; the ids are the same as the
    /// golden serialization fixture's.
    const CANONICAL_TRACEPARENT: &str = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01";

    #[test]
    fn traceparent_canonical_value_parses_into_its_ids() {
        let trace = TraceContext::from_traceparent(CANONICAL_TRACEPARENT)
            .expect("the canonical W3C example must parse");
        assert_eq!(trace.trace_id, "0af7651916cd43dd8448eb211c80319c");
        assert_eq!(trace.span_id, "b7ad6b7169203331");
    }

    #[test]
    fn traceparent_flags_00_parses_and_flags_are_not_stored() {
        // The flags value is irrelevant (validated as hex, never stored):
        // an unsampled request correlates the same as a sampled one.
        let unsampled = CANONICAL_TRACEPARENT.replace("-01", "-00");
        let trace = TraceContext::from_traceparent(&unsampled).expect("flags 00 must parse");
        assert_eq!(trace.trace_id, "0af7651916cd43dd8448eb211c80319c");
        assert_eq!(trace.span_id, "b7ad6b7169203331");
    }

    #[test]
    fn traceparent_rejects_wrong_lengths() {
        assert_eq!(TraceContext::from_traceparent(""), None);
        // 54 bytes: the canonical value minus its last byte.
        let short = &CANONICAL_TRACEPARENT[..54];
        assert_eq!(TraceContext::from_traceparent(short), None);
        // 56 bytes: the canonical value plus one hex byte. A truncating
        // `>= 55` length check would parse this — the exact-length check
        // must not.
        let long = format!("{CANONICAL_TRACEPARENT}0");
        assert_eq!(TraceContext::from_traceparent(&long), None);
        // Oversized input is rejected on length alone (~1 MiB).
        let huge = "a".repeat(1 << 20);
        assert_eq!(TraceContext::from_traceparent(&huge), None);
    }

    #[test]
    fn traceparent_rejects_uppercase_hex() {
        // Uppercase in the trace-id: invalid per W3C.
        let upper_trace = "00-0AF7651916CD43DD8448EB211C80319C-b7ad6b7169203331-01";
        assert_eq!(TraceContext::from_traceparent(upper_trace), None);
        // Uppercase in the span-id.
        let upper_span = "00-0af7651916cd43dd8448eb211c80319c-B7AD6B7169203331-01";
        assert_eq!(TraceContext::from_traceparent(upper_span), None);
        // Uppercase hex in the version position.
        let upper_version = "0A-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01";
        assert_eq!(TraceContext::from_traceparent(upper_version), None);
    }

    #[test]
    fn traceparent_rejects_versions_other_than_00() {
        // `ff` is forbidden by W3C.
        let ff = "ff-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01";
        assert_eq!(TraceContext::from_traceparent(ff), None);
        // A future version is rejected even when it happens to be 55
        // bytes of version-00 shape: strict, no forward parsing.
        let v01 = "01-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01";
        assert_eq!(TraceContext::from_traceparent(v01), None);
        // The forward-format case W3C would allow lenient parsers to
        // accept: a future version with trailing data. Deliberately None.
        let forward = "01-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01-extra";
        assert_eq!(TraceContext::from_traceparent(forward), None);
    }

    #[test]
    fn traceparent_rejects_all_zero_ids() {
        let zero_trace = "00-00000000000000000000000000000000-b7ad6b7169203331-01";
        assert_eq!(TraceContext::from_traceparent(zero_trace), None);
        let zero_span = "00-0af7651916cd43dd8448eb211c80319c-0000000000000000-01";
        assert_eq!(TraceContext::from_traceparent(zero_span), None);
    }

    #[test]
    fn traceparent_rejects_non_hex_in_every_field() {
        for bad in [
            // `g` in the version, trace-id, span-id, and flags.
            "g0-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
            "00-gaf7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
            "00-0af7651916cd43dd8448eb211c80319c-g7ad6b7169203331-01",
            "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-g1",
            // A space in each field.
            " 0-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
            "00- af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
            "00-0af7651916cd43dd8448eb211c80319c- 7ad6b7169203331-01",
            "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331- 1",
        ] {
            assert_eq!(
                TraceContext::from_traceparent(bad),
                None,
                "must reject {bad:?}"
            );
        }
    }

    #[test]
    fn traceparent_rejects_misplaced_separators() {
        // Still 55 bytes each, but a `-` is off its fixed position.
        for bad in [
            // The trace-id/span-id separator shifted right by one.
            "00-0af7651916cd43dd8448eb211c80319cb-7ad6b7169203331-01",
            // The version separator replaced (two ids run together).
            "0000af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
            // The flags separator replaced by a hex byte.
            "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331001",
        ] {
            assert_eq!(bad.len(), 55, "fixture must stay 55 bytes");
            assert_eq!(
                TraceContext::from_traceparent(bad),
                None,
                "must reject {bad:?}"
            );
        }
    }

    #[test]
    fn traceparent_rejects_surrounding_whitespace() {
        // No trimming anywhere: whitespace is rejected, either by the
        // hex/layout checks (55 bytes) or by the length check (56).
        let lead_55 = format!(" {}", &CANONICAL_TRACEPARENT[..54]);
        assert_eq!(TraceContext::from_traceparent(&lead_55), None);
        let lead_56 = format!(" {CANONICAL_TRACEPARENT}");
        assert_eq!(TraceContext::from_traceparent(&lead_56), None);
        let trail_56 = format!("{CANONICAL_TRACEPARENT}\n");
        assert_eq!(TraceContext::from_traceparent(&trail_56), None);
    }

    #[test]
    fn traceparent_multibyte_unicode_returns_none_without_panicking() {
        // 53 ASCII bytes of the canonical value plus one 2-byte char:
        // exactly 55 bytes, so it passes the length check and must fall
        // out of the layout checks — never panic.
        let multibyte = format!("{}\u{e9}", &CANONICAL_TRACEPARENT[..53]);
        assert_eq!(multibyte.len(), 55, "fixture must be 55 bytes");
        assert_eq!(TraceContext::from_traceparent(&multibyte), None);
    }

    #[test]
    fn closed_vocabularies_have_stable_wire_names() {
        assert_eq!(json!(TransportKind::Stdio), json!("stdio"));
        assert_eq!(json!(TransportKind::Http), json!("http"));
        assert_eq!(json!(Verdict::Served), json!("served"));
        assert_eq!(json!(Verdict::ServedFiltered), json!("served_filtered"));
        assert_eq!(json!(Verdict::Denied), json!("denied"));
        assert_eq!(json!(Verdict::Refused), json!("refused"));
        assert_eq!(json!(OutcomeClass::Ok), json!("ok"));
        assert_eq!(json!(OutcomeClass::Refused), json!("refused"));
        assert_eq!(json!(OutcomeClass::Error), json!("error"));
        assert_eq!(json!(GapReason::WriteError), json!("write_error"));
        assert_eq!(json!(GapReason::RotationError), json!("rotation_error"));
    }

    #[test]
    fn unknown_envelope_key_rejected() {
        // An unknown top-level key flows into the flattened kind, whose
        // structs are closed — so the whole record is rejected.
        let with_extra = GOLDEN_AUDIT_GAP.replace("\"dropped\"", "\"bogus\":1,\"dropped\"");
        assert!(serde_json::from_str::<AuditEvent>(&with_extra).is_err());
    }

    // ---------- AuditConfig ----------

    #[test]
    fn config_minimal_file_applies_defaults() {
        let cfg = AuditConfig::from_toml_str("path = \"/var/log/bugwarden/audit.jsonl\"").unwrap();
        assert_eq!(cfg.path, PathBuf::from("/var/log/bugwarden/audit.jsonl"));
        assert!(!cfg.fsync);
        assert_eq!(cfg.fail_mode, None);
        assert_eq!(cfg.rotate_max_bytes, 64 * 1024 * 1024);
        assert_eq!(cfg.rotate_keep, 8);
        assert!(cfg.suppressed_ids);
    }

    #[test]
    fn config_unknown_key_rejected_by_name() {
        let err = AuditConfig::from_toml_str("path = \"/a\"\nfrobnicate = true\n").unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("frobnicate"), "unexpected error: {msg}");
    }

    #[test]
    fn config_rotate_keep_zero_with_rotation_rejected() {
        let err = AuditConfig::from_toml_str("path = \"/a\"\nrotate_keep = 0\n").unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("rotate_keep"), "unexpected error: {msg}");
    }

    #[test]
    fn config_rotate_keep_zero_without_rotation_accepted() {
        let cfg =
            AuditConfig::from_toml_str("path = \"/a\"\nrotate_max_bytes = 0\nrotate_keep = 0\n")
                .unwrap();
        assert_eq!(cfg.rotate_max_bytes, 0);
        assert_eq!(cfg.rotate_keep, 0);
    }

    #[test]
    fn config_rotate_keep_above_cap_rejected() {
        let err = AuditConfig::from_toml_str("path = \"/a\"\nrotate_keep = 10001\n").unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("rotate_keep") && msg.contains("10000"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn config_rotate_keep_at_cap_accepted() {
        let cfg = AuditConfig::from_toml_str("path = \"/a\"\nrotate_keep = 10000\n").unwrap();
        assert_eq!(cfg.rotate_keep, 10_000);
    }

    #[test]
    fn config_every_fail_mode_parses() {
        for (raw, want) in [
            ("open", FailMode::Open),
            ("closed_writes_denials", FailMode::ClosedWritesDenials),
            ("closed_all", FailMode::ClosedAll),
        ] {
            let cfg =
                AuditConfig::from_toml_str(&format!("path = \"/a\"\nfail_mode = \"{raw}\"\n"))
                    .unwrap();
            assert_eq!(cfg.fail_mode, Some(want), "fail_mode = {raw}");
        }
        assert!(AuditConfig::from_toml_str("path = \"/a\"\nfail_mode = \"closed\"\n").is_err());
    }

    #[test]
    fn config_missing_path_rejected() {
        let err = AuditConfig::from_toml_str("fsync = true\n").unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("path"), "unexpected error: {msg}");
    }

    #[test]
    fn shipped_example_audit_config_parses() {
        // The example in the repository must always load through the same
        // strict path operators use. Read at runtime (not include_str!) so
        // the crate stays packageable without the file.
        let path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/audit.toml");
        let cfg = AuditConfig::load(&path).expect("example audit config must exist and parse");
        // The example spells out the defaults it documents; pin them so
        // the file and the code cannot drift apart silently.
        assert!(!cfg.fsync);
        assert_eq!(cfg.fail_mode, None);
        assert_eq!(cfg.rotate_max_bytes, 64 * 1024 * 1024);
        assert_eq!(cfg.rotate_keep, 8);
        assert!(cfg.suppressed_ids);
    }

    // ---------- AuditSink ----------

    #[test]
    #[cfg(unix)]
    fn sink_creates_file_0600_and_parent_0700() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub/audit.jsonl");
        let sink = AuditSink::open(test_cfg(path.clone())).unwrap();
        sink.record(sample_initialize(), session_stdio()).unwrap();
        let file_mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(file_mode & 0o777, 0o600, "audit file must be 0600");
        let dir_mode = std::fs::metadata(dir.path().join("sub"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(dir_mode & 0o777, 0o700, "audit directory must be 0700");
    }

    #[test]
    fn sink_appends_across_open_calls_and_seq_restarts() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = test_cfg(dir.path().join("audit.jsonl"));
        let first = AuditSink::open(cfg.clone()).unwrap();
        assert_eq!(
            first.record(sample_initialize(), session_stdio()).unwrap(),
            1
        );
        assert_eq!(
            first.record(sample_initialize(), session_stdio()).unwrap(),
            2
        );
        drop(first);
        // seq is per-process (per sink), not global: a fresh sink starts
        // at 1 again, but appends — it never truncates what came before.
        let second = AuditSink::open(cfg.clone()).unwrap();
        assert_eq!(
            second.record(sample_initialize(), session_stdio()).unwrap(),
            1
        );
        let seqs: Vec<u64> = read_events(&cfg.path).iter().map(|e| e.seq).collect();
        assert_eq!(seqs, vec![1, 2, 1]);
    }

    #[test]
    #[cfg(unix)]
    fn sink_refuses_symlink_path() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target.jsonl");
        std::fs::write(&target, "").unwrap();
        let link = dir.path().join("link.jsonl");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let err = AuditSink::open(test_cfg(link)).unwrap_err();
        assert!(format!("{err:#}").contains("symlink"));
    }

    #[test]
    fn rotation_shifts_files_and_loses_no_event() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = test_cfg(dir.path().join("audit.jsonl"));
        // Roughly two records per file: multiple rotations over 8 records,
        // while rotate_keep is large enough that nothing gets deleted —
        // so every record written must still be on disk somewhere.
        cfg.rotate_max_bytes = 400;
        cfg.rotate_keep = 5;
        let sink = AuditSink::open(cfg.clone()).unwrap();
        for _ in 0..8 {
            sink.record(sample_initialize(), session_stdio()).unwrap();
        }
        // Oldest first: highest rotated number down to the live file.
        let mut seqs: Vec<u64> = Vec::new();
        let mut rotated = 0;
        for n in (1..=cfg.rotate_keep).rev() {
            let p = rotated_path(&cfg.path, n);
            if p.exists() {
                rotated += 1;
                seqs.extend(read_events(&p).iter().map(|e| e.seq));
            }
        }
        seqs.extend(read_events(&cfg.path).iter().map(|e| e.seq));
        assert!(rotated >= 2, "expected multiple rotations, saw {rotated}");
        assert!(
            rotated <= cfg.rotate_keep,
            "rotated files exceed rotate_keep"
        );
        // No event lost, and seq strictly increasing across every
        // rotation boundary.
        assert_eq!(seqs, (1..=8).collect::<Vec<u64>>());
        // Rotation happens BEFORE the write, so no file — live or
        // rotated — ever exceeds the configured limit.
        assert_files_within_rotate_limit(&cfg);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&cfg.path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "recreated live file must be 0600");
        }
    }

    #[test]
    fn rotation_deletes_files_beyond_rotate_keep() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = test_cfg(dir.path().join("audit.jsonl"));
        cfg.rotate_max_bytes = 400;
        cfg.rotate_keep = 1;
        let sink = AuditSink::open(cfg.clone()).unwrap();
        for _ in 0..8 {
            sink.record(sample_initialize(), session_stdio()).unwrap();
        }
        assert!(rotated_path(&cfg.path, 1).exists());
        assert!(
            !rotated_path(&cfg.path, 2).exists(),
            "rotation must not keep more than rotate_keep files"
        );
        // What survives still parses and stays in order (deletion loses
        // the oldest records — that is the operator's configured trade).
        let mut events = read_events(&rotated_path(&cfg.path, 1));
        events.extend(read_events(&cfg.path));
        let seqs: Vec<u64> = events.iter().map(|e| e.seq).collect();
        assert!(
            seqs.len() < 8,
            "deletion beyond rotate_keep must have happened"
        );
        assert!(
            seqs.windows(2).all(|w| w[1] == w[0] + 1),
            "seqs stay contiguous: {seqs:?}"
        );
        assert_eq!(seqs.last(), Some(&8));
        // The size limit holds for what survives, too: rotation happens
        // before the write.
        assert_files_within_rotate_limit(&cfg);
    }

    #[test]
    fn single_oversized_record_written_alone_then_rotated_out() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = test_cfg(dir.path().join("audit.jsonl"));
        // Smaller than one serialized record: every record is oversized.
        cfg.rotate_max_bytes = 100;
        cfg.rotate_keep = 3;
        let sink = AuditSink::open(cfg.clone()).unwrap();
        assert_eq!(
            sink.record(sample_initialize(), session_stdio()).unwrap(),
            1
        );
        // The oversized record went into the empty live file as-is —
        // the one documented exception to the size bound.
        assert!(
            std::fs::metadata(&cfg.path).unwrap().len() > cfg.rotate_max_bytes,
            "a single oversized record must be written despite the limit"
        );
        assert!(!rotated_path(&cfg.path, 1).exists());
        // The next record must rotate the oversized live file out first.
        assert_eq!(
            sink.record(sample_initialize(), session_stdio()).unwrap(),
            2
        );
        let rotated = read_events(&rotated_path(&cfg.path, 1));
        assert_eq!(rotated.len(), 1, "rotated file holds the first record");
        assert_eq!(rotated[0].seq, 1);
        let live = read_events(&cfg.path);
        assert_eq!(live.len(), 1, "live file holds only the new record");
        assert_eq!(live[0].seq, 2);
    }

    #[test]
    fn reopened_sink_counts_existing_bytes_toward_rotation() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = test_cfg(dir.path().join("audit.jsonl"));
        // One record nearly fills the limit; the next must rotate — but
        // only if the reopened sink counted the bytes already on disk.
        cfg.rotate_max_bytes = 200;
        cfg.rotate_keep = 3;
        let first = AuditSink::open(cfg.clone()).unwrap();
        first.record(sample_initialize(), session_stdio()).unwrap();
        drop(first);
        let second = AuditSink::open(cfg.clone()).unwrap();
        second.record(sample_initialize(), session_stdio()).unwrap();
        assert!(
            rotated_path(&cfg.path, 1).exists(),
            "reopen must count existing bytes toward the rotation limit"
        );
        let live = read_events(&cfg.path);
        assert_eq!(live.len(), 1, "live file holds only the new record");
        assert_eq!(live[0].seq, 1, "a fresh sink assigns seq from 1");
        assert_eq!(read_events(&rotated_path(&cfg.path, 1)).len(), 1);
    }

    #[test]
    fn concurrent_records_are_contiguous_and_in_file_order() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = test_cfg(dir.path().join("audit.jsonl"));
        let sink = AuditSink::open(cfg.clone()).unwrap();
        std::thread::scope(|s| {
            for _ in 0..4 {
                s.spawn(|| {
                    for _ in 0..25 {
                        sink.record(sample_initialize(), session_stdio())
                            .expect("concurrent record must succeed");
                    }
                });
            }
        });
        let seqs: Vec<u64> = read_events(&cfg.path).iter().map(|e| e.seq).collect();
        // Unique, contiguous from 1, and file order equals seq order —
        // all three in one assertion.
        assert_eq!(seqs, (1..=100).collect::<Vec<u64>>());
    }

    #[test]
    fn gap_marker_precedes_next_record_after_write_failures() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = test_cfg(dir.path().join("audit.jsonl"));
        let sink = AuditSink::open(cfg.clone()).unwrap();
        assert_eq!(
            sink.record(sample_initialize(), session_stdio()).unwrap(),
            1
        );
        sink.set_fail_writes(true);
        for _ in 0..2 {
            let err = sink
                .record(sample_initialize(), session_stdio())
                .unwrap_err();
            assert!(matches!(err, AuditError::Write(_)));
        }
        sink.set_fail_writes(false);
        // The next successful record is preceded by an audit_gap carrying
        // the dropped count; the gap consumes a seq of its own.
        assert_eq!(
            sink.record(sample_initialize(), session_stdio()).unwrap(),
            3
        );
        let events = read_events(&cfg.path);
        assert_eq!(events.len(), 3);
        assert_eq!(events[1].seq, 2);
        match &events[1].kind {
            AuditEventKind::AuditGap(gap) => {
                assert_eq!(gap.dropped, 2);
                assert_eq!(gap.reason, GapReason::WriteError);
            }
            other => panic!("expected audit_gap, got {other:?}"),
        }
        assert_eq!(events[2].seq, 3);
    }

    #[test]
    fn gap_marker_after_rotation_failure_reports_rotation_error() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = test_cfg(dir.path().join("audit.jsonl"));
        // One record nearly fills the limit, so every following write
        // wants a rotation first.
        cfg.rotate_max_bytes = 200;
        cfg.rotate_keep = 4;
        let sink = AuditSink::open(cfg.clone()).unwrap();
        assert_eq!(
            sink.record(sample_initialize(), session_stdio()).unwrap(),
            1
        );
        sink.set_fail_rotation(true);
        for _ in 0..2 {
            let err = sink
                .record(sample_initialize(), session_stdio())
                .unwrap_err();
            assert!(matches!(err, AuditError::Rotation(_)));
        }
        sink.set_fail_rotation(false);
        // Recovery: the gap record precedes the next record. Each write
        // may itself rotate, so collect across all generations.
        assert_eq!(
            sink.record(sample_initialize(), session_stdio()).unwrap(),
            3
        );
        let mut raw = String::new();
        let mut events = Vec::new();
        for n in (1..=cfg.rotate_keep).rev() {
            let p = rotated_path(&cfg.path, n);
            if p.exists() {
                raw.push_str(&std::fs::read_to_string(&p).unwrap());
                events.extend(read_events(&p));
            }
        }
        raw.push_str(&std::fs::read_to_string(&cfg.path).unwrap());
        events.extend(read_events(&cfg.path));
        let seqs: Vec<u64> = events.iter().map(|e| e.seq).collect();
        assert_eq!(seqs, vec![1, 2, 3]);
        match &events[1].kind {
            AuditEventKind::AuditGap(gap) => {
                assert_eq!(gap.dropped, 2);
                assert_eq!(gap.reason, GapReason::RotationError);
            }
            other => panic!("expected audit_gap, got {other:?}"),
        }
        assert!(
            raw.contains(r#""reason":"rotation_error""#),
            "the gap record on disk must name the rotation failure"
        );
    }

    #[test]
    fn partial_write_leaves_torn_line_and_stream_self_heals() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = test_cfg(dir.path().join("audit.jsonl"));
        let sink = AuditSink::open(cfg.clone()).unwrap();
        assert_eq!(
            sink.record(sample_initialize(), session_stdio()).unwrap(),
            1
        );
        sink.set_fail_writes_partial(true);
        let err = sink
            .record(sample_initialize(), session_stdio())
            .unwrap_err();
        assert!(matches!(err, AuditError::Write(_)));
        sink.set_fail_writes_partial(false);
        let raw = std::fs::read_to_string(&cfg.path).unwrap();
        assert!(
            !raw.ends_with('\n'),
            "the partial write must have left a torn, unterminated line"
        );
        // Recovery: the healing newline terminates the torn line; the
        // gap record and the caller's record follow, both parsable.
        assert_eq!(
            sink.record(sample_initialize(), session_stdio()).unwrap(),
            3
        );
        let raw = std::fs::read_to_string(&cfg.path).unwrap();
        let mut torn_lines = 0;
        let mut events: Vec<AuditEvent> = Vec::new();
        for line in raw.lines().filter(|l| !l.is_empty()) {
            match serde_json::from_str(line) {
                Ok(event) => events.push(event),
                Err(_) => torn_lines += 1,
            }
        }
        assert_eq!(torn_lines, 1, "at most one torn line per outage");
        let seqs: Vec<u64> = events.iter().map(|e| e.seq).collect();
        assert_eq!(seqs, vec![1, 2, 3], "complete records stay contiguous");
        match &events[1].kind {
            AuditEventKind::AuditGap(gap) => {
                assert_eq!(gap.dropped, 1);
                assert_eq!(gap.reason, GapReason::WriteError);
            }
            other => panic!("expected audit_gap, got {other:?}"),
        }
    }

    #[test]
    fn real_sink_stamps_ts_rfc3339_utc_millis() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = test_cfg(dir.path().join("audit.jsonl"));
        let sink = AuditSink::open(cfg.clone()).unwrap();
        sink.record(sample_initialize(), session_stdio()).unwrap();
        let events = read_events(&cfg.path);
        let ts = &events[0].ts;
        // ^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$, spelled out
        // positionally ('d' = ASCII digit) to avoid a regex dependency.
        const PATTERN: &[u8] = b"dddd-dd-ddTdd:dd:dd.dddZ";
        assert_eq!(ts.len(), PATTERN.len(), "unexpected ts length: {ts:?}");
        for (i, (&got, &want)) in ts.as_bytes().iter().zip(PATTERN).enumerate() {
            match want {
                b'd' => assert!(got.is_ascii_digit(), "byte {i} of ts {ts:?} not a digit"),
                _ => assert_eq!(got, want, "byte {i} of ts {ts:?}"),
            }
        }
    }

    #[test]
    fn api_key_canary_never_reaches_the_file() {
        // Regression tripwire: the schema has no field that could carry
        // the Bugzilla API key, and the sink writes only what the schema
        // holds. Write every record kind with every field populated and
        // grep the file for a secret-shaped canary. The canary is a
        // local constant — nothing in this module reads the environment,
        // and mutating the process environment would race the parallel
        // test harness.
        const CANARY: &str = "bugwarden-canary-3f6d1a-api-key-value";
        let dir = tempfile::tempdir().unwrap();
        let cfg = test_cfg(dir.path().join("audit.jsonl"));
        let sink = AuditSink::open(cfg.clone()).unwrap();
        sink.record(sample_tool_call(), session_http()).unwrap();
        sink.record(sample_initialize(), session_stdio()).unwrap();
        sink.record(sample_gap(), session_stdio()).unwrap();
        let contents = std::fs::read_to_string(&cfg.path).unwrap();
        assert_eq!(contents.lines().count(), 3);
        assert!(
            !contents.contains(CANARY),
            "the API key canary leaked into the audit file"
        );
    }

    // ---------- request-path wiring ----------

    #[test]
    fn fail_mode_transport_defaults_bind_the_documented_wording() {
        // The documented derivation: stdio (a local, single-operator
        // session) defaults to open — availability for a single user;
        // http (remote clients) defaults to closed_all — accountability
        // for a fleet.
        assert_eq!(FailMode::default_for(TransportKind::Stdio), FailMode::Open);
        assert_eq!(
            FailMode::default_for(TransportKind::Http),
            FailMode::ClosedAll
        );
        // An explicit configured value wins over both derivations.
        for transport in [TransportKind::Stdio, TransportKind::Http] {
            assert_eq!(
                FailMode::resolve(Some(FailMode::ClosedWritesDenials), transport),
                FailMode::ClosedWritesDenials
            );
        }
        assert_eq!(
            FailMode::resolve(None, TransportKind::Stdio),
            FailMode::Open
        );
        assert_eq!(
            FailMode::resolve(None, TransportKind::Http),
            FailMode::ClosedAll
        );
    }

    #[test]
    fn audit_state_session_id_is_pid_dash_epoch() {
        let dir = tempfile::tempdir().unwrap();
        let sink = AuditSink::open(test_cfg(dir.path().join("audit.jsonl"))).unwrap();
        let state = AuditState::new(sink, FailMode::Open, None);
        let (pid, epoch) = state
            .stdio_session_id
            .split_once('-')
            .expect("session id is <pid>-<epoch>");
        assert_eq!(pid, std::process::id().to_string());
        assert!(epoch.parse::<u64>().is_ok(), "epoch part is seconds");
    }

    #[test]
    fn cell_verdict_merge_keeps_the_worst_and_its_rule() {
        let cell = AuditCell::default();
        cell.note_verdict_rule(Verdict::Served, "allow-most");
        cell.note_verdict_rule(Verdict::Denied, "embargo");
        // A lesser verdict after the worst changes nothing.
        cell.note_verdict_rule(Verdict::ServedFiltered, "peek");
        let info = cell.into_guard_info(None, true).expect("verdict noted");
        assert_eq!(info.verdict, Verdict::Denied);
        assert_eq!(info.rule.as_deref(), Some("embargo"));
    }

    #[test]
    fn cell_upgrade_by_a_default_decision_clears_the_rule() {
        // The rule names the DECIDING rule of the worst verdict: when a
        // default-decided denial outranks a rule-decided serve, no rule
        // may stay attached.
        let cell = AuditCell::default();
        cell.note_verdict_rule(Verdict::Served, "allow-most");
        cell.note_verdict(Verdict::Denied);
        let info = cell.into_guard_info(None, true).expect("verdict noted");
        assert_eq!(info.verdict, Verdict::Denied);
        assert_eq!(info.rule, None);
    }

    #[test]
    fn cell_first_rule_wins_at_equal_severity() {
        let cell = AuditCell::default();
        cell.note_verdict(Verdict::Served);
        cell.note_verdict_rule(Verdict::Served, "first");
        cell.note_verdict_rule(Verdict::Served, "second");
        let info = cell.into_guard_info(None, true).expect("verdict noted");
        assert_eq!(info.rule.as_deref(), Some("first"));
    }

    #[test]
    fn cell_suppression_implies_a_filtered_serve() {
        let cell = AuditCell::default();
        cell.note_verdict_rule(Verdict::Served, "allow-most");
        cell.note_suppressed([1290040, 1290041, 1290040]);
        let info = cell.into_guard_info(Some("sha256:ab"), true).unwrap();
        assert_eq!(info.verdict, Verdict::ServedFiltered);
        assert_eq!(info.suppressed_ids, vec![1290040, 1290041]);
        assert_eq!(info.suppressed_count, 2);
        assert_eq!(info.policy_hash.as_deref(), Some("sha256:ab"));
    }

    #[test]
    fn cell_suppressed_count_is_max_of_ids_and_counter() {
        let cell = AuditCell::default();
        cell.note_suppressed([7]);
        cell.note_suppressed_count(2);
        cell.note_suppressed_count(1);
        let info = cell.into_guard_info(None, true).unwrap();
        assert_eq!(info.suppressed_count, 3, "id-less counter adds up");
        assert_eq!(info.suppressed_ids, vec![7]);
    }

    #[test]
    fn cell_suppressed_ids_config_ships_the_count_only() {
        let cell = AuditCell::default();
        cell.note_suppressed([40, 41]);
        let info = cell.into_guard_info(None, false).unwrap();
        assert!(info.suppressed_ids.is_empty(), "ids elided by config");
        assert_eq!(info.suppressed_count, 2, "the count still ships");
    }

    #[test]
    fn cell_untouched_yields_no_guard_info() {
        let cell = AuditCell::default();
        assert_eq!(cell.into_guard_info(Some("sha256:ab"), true), None);
        // Upstream info alone is not a guard verdict. It is taken FIRST:
        // into_guard_info drains the whole cell.
        let cell = AuditCell::default();
        cell.note_upstream(UpstreamInfo {
            requests: 1,
            status: Some(200),
            latency_ms: 3,
        });
        assert!(cell.take_upstream().is_some());
        assert_eq!(cell.into_guard_info(None, true), None);
    }

    #[test]
    fn cell_redaction_is_recorded_and_upgrades_the_verdict() {
        let cell = AuditCell::default();
        cell.note_verdict(Verdict::Served);
        cell.note_redacted("summary_view");
        cell.note_redacted("summary_view");
        let info = cell.into_guard_info(None, true).unwrap();
        assert_eq!(info.verdict, Verdict::ServedFiltered);
        assert_eq!(info.redacted_fields, vec!["summary_view".to_string()]);
    }

    #[test]
    fn policy_hash_of_digests_the_given_bytes() {
        // The FIPS 180-2 test vector for sha256("abc"), precomputed:
        // recomputing the expectation with sha2 here would only prove the
        // function calls sha2, not that it hashes the bytes it was given.
        assert_eq!(
            policy_hash_of(b"abc"),
            "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
