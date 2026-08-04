//! MCP tool surface for bugwarden.
//!
//! Every tool that takes a bug id runs guard assessment (`Guard::assess`)
//! BEFORE any side effect or data return (invariant I8; `bug_url` is the
//! documented exception — it computes a URL string locally and contacts
//! nothing). Denials use the uniform text from `Guard::denial` only, so a
//! policy-denied bug and a nonexistent bug are indistinguishable (I2).

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Instant;

use bugwarden_core::client::{BugzillaClient, CLASSIFY_FIELDS};
use bugwarden_core::guard::{Guard, SearchRequest, SearchWindow};
use bugwarden_core::policy::{Access, Action, Capability};
use chrono::{DateTime, Utc};
use rmcp::{
    handler::server::{router::tool::ToolRouter, tool::ToolCallContext, wrapper::Parameters},
    model::*,
    schemars,
    service::RequestContext,
    tool, tool_router,
    transport::streamable_http_server::StreamableHttpServerConfig,
    ErrorData as McpError, RoleServer, ServerHandler,
};
use serde_json::{json, Value};

use crate::audit::{self, AuditCell, AuditState, FailMode, TransportKind, Verdict};
use crate::config::{Cli, KeyCustody, Transport};

/// The MCP revisions this build actually implements, newest last.
///
/// Deliberately not `ProtocolVersion::KNOWN_VERSIONS`: the SDK knows more
/// revisions than it can serve through this handler, and both the rmcp
/// default for `supported_protocol_versions` and the handshake below
/// would otherwise accept `2026-07-28` — a revision whose stateless
/// requests carry no handshake, so audit records would name a client the
/// server never spoke to (issue #34). A client asking for it gets the
/// server default instead, and every rmcp bump has to widen this list
/// deliberately, never by inheriting a longer one.
const SUPPORTED_PROTOCOL_VERSIONS: &[ProtocolVersion] = &[
    ProtocolVersion::V_2024_11_05,
    ProtocolVersion::V_2025_03_26,
    ProtocolVersion::V_2025_06_18,
    ProtocolVersion::V_2025_11_25,
];

/// The revision offered when a client asks for one this build cannot
/// serve, and the one `get_info` advertises. Pinned rather than left to
/// `ProtocolVersion::default()`, whose value moves with the SDK: an
/// rmcp release that advances `LATEST` past what [`SUPPORTED_PROTOCOL_VERSIONS`]
/// lists would otherwise make the fallback a revision this build rejects.
const DEFAULT_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::V_2025_11_25;

/// The name this server reports as its own, in the handshake and in
/// `mcp_server_info`.
const SERVER_NAME: &str = env!("CARGO_PKG_NAME");

/// The version this server reports as its own, in the handshake and in
/// `mcp_server_info`.
const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");

/// This build's identity, as sent in the `initialize` handshake.
///
/// Deliberately not `Implementation::from_build_env()` (nor
/// `Implementation::default()`, which calls it): that constructor expands
/// `env!("CARGO_CRATE_NAME")` and `env!("CARGO_PKG_VERSION")` *inside
/// rmcp*, so it names the SDK — every rmcp-based server then introduces
/// itself identically, and the one question `serverInfo` exists to answer,
/// which build is deployed, becomes unanswerable from the handshake
/// (issue #53). The `env!`s here expand in this crate.
fn server_identity() -> Implementation {
    Implementation::new(SERVER_NAME, SERVER_VERSION)
}

/// Names of the tools that modify bug state. These routes are removed from
/// the router in read-only mode (I13).
pub const WRITE_TOOLS: &[&str] = &[
    "add_comment",
    "update_bug_status",
    "assign_bug",
    "update_bug_fields",
    "update_bug_dependencies",
    "add_cc_to_bug",
    "mark_as_duplicate",
    "create_bug",
    "add_attachment",
];

/// Success result: ONE text block containing pretty-printed JSON.
fn ok_json(value: Value) -> CallToolResult {
    let text = serde_json::to_string_pretty(&value).unwrap_or_else(|_| value.to_string());
    CallToolResult::success(vec![ContentBlock::text(text)])
}

/// Tool-level failure: error result with a text block (NOT a protocol error).
fn err_text(msg: impl Into<String>) -> CallToolResult {
    CallToolResult::error(vec![ContentBlock::text(msg.into())])
}

fn action_name(action: Action) -> &'static str {
    match action {
        Action::Allow => "allow",
        Action::Deny => "deny",
        Action::Restrict => "restrict",
    }
}

/// The name of the policy rule that decided an assessment; both variants
/// carry one.
fn access_rule(access: &Access) -> &str {
    match access {
        Access::Denied { rule } | Access::Granted { rule, .. } => rule,
    }
}

/// The request's audit enrichment cell, when auditing is on. The audit
/// wrapper inserts one before dispatch; with auditing off (or a caller
/// outside the wrapper) there is none and every note is a no-op at the
/// call site — enrichment can never change what a tool returns.
fn audit_cell(ctx: &RequestContext<RoleServer>) -> Option<Arc<AuditCell>> {
    ctx.extensions.get::<Arc<AuditCell>>().cloned()
}

/// Note a `Refused` verdict on the request's audit cell. Mechanical
/// companion for the `return Ok(err_text(..))` refusal sites that answer
/// from the request alone.
fn note_refused(ctx: &RequestContext<RoleServer>) {
    if let Some(cell) = audit_cell(ctx) {
        cell.note_verdict(Verdict::Refused);
    }
}

/// Whether the pre-dispatch audit gate holds `tool` back while the sink is
/// already failing: `Open` never gates, `ClosedWritesDenials` gates the
/// write tools only, `ClosedAll` gates everything.
fn gate_applies(fail_mode: FailMode, tool: &str) -> bool {
    match fail_mode {
        FailMode::Open => false,
        FailMode::ClosedWritesDenials => WRITE_TOOLS.contains(&tool),
        FailMode::ClosedAll => true,
    }
}

/// The refusal text for a tool call refused because its audit record
/// cannot be persisted (the closed fail modes). One fixed text per TOOL —
/// each tool's EXISTING generic failure wording, so an audit outage looks
/// like the failure the client already knows and is not a new fingerprint;
/// tools without a generic failure text get a pattern-consistent one. The
/// text depends on the tool name alone, never on anything the guard
/// decided. `None` only for names outside the tool surface — the map must
/// be total over the full router (tested), and every routed tool must
/// have its own entry here before it can ship.
fn audit_refusal_text(tool: &str) -> Option<String> {
    let text = match tool {
        "bug_info" => "Failed to fetch bug information".to_string(),
        "bug_history" => "Failed to fetch bug history".to_string(),
        "bug_comments" => "Failed to fetch bug comments".to_string(),
        "bugs_quicksearch" => "Search failed".to_string(),
        "summarize_bug" => "Summarize Comments Failed".to_string(),
        "list_attachments" => "Failed to fetch bug attachments".to_string(),
        "download_attachment" => "Failed to fetch attachment".to_string(),
        "bugzilla_server_info" => "Failed to fetch bugzilla server info".to_string(),
        "quicksearch_syntax" => "Failed to fetch quicksearch documentation".to_string(),
        "bug_url" => "Failed to compute the bug url".to_string(),
        "mcp_server_info" => "Failed to compute server info".to_string(),
        // Write tools: the first line of their existing failure text,
        // without the upstream detail — truthfully so: nothing upstream
        // happened when the gate refused before dispatch.
        "add_comment" => "Failed to create a comment".to_string(),
        "update_bug_status" => "Failed to update bug status".to_string(),
        "assign_bug" => "Failed to assign bug".to_string(),
        "update_bug_fields" => "Failed to update bug fields".to_string(),
        "update_bug_dependencies" => "Failed to update bug dependencies".to_string(),
        "add_cc_to_bug" => "Failed to add CC".to_string(),
        "add_attachment" => "Failed to add attachment".to_string(),
        "mark_as_duplicate" => "Failed to mark as duplicate".to_string(),
        "create_bug" => Guard::create_denial(),
        _ => return None,
    };
    Some(text)
}

/// The uniform fail-closed refusal for `tool`. Unknown names fall back to
/// a generic text; unreachable for routed tools (see
/// [`audit_refusal_text`]) — the fallback exists so the map is total.
fn audit_refusal(tool: &str) -> CallToolResult {
    err_text(audit_refusal_text(tool).unwrap_or_else(|| "Request failed".to_string()))
}

/// Keys of client-authored tool parameters whose VALUES may enter an audit
/// record. The bar: identifiers, projections and routing/vocabulary fields
/// yes; free text no. `comment`, `summary`, `description`, `url`,
/// `whiteboard`, `data` (attachment bytes), `custom_fields`
/// (operator-defined values) and the `see_also_add`/`see_also_remove` URL
/// lists never appear by value — a non-allowlisted key is recorded as
/// `{"_len": <serialized byte length>}`, so presence and size are loggable
/// while content is not. Allowlisted string values are truncated to 1024
/// characters.
const PARAM_ALLOWLIST: &[&str] = &[
    "assignee",
    "attachment_id",
    "blocks_add",
    "blocks_remove",
    "bug_id",
    "bug_ids",
    "cc_email",
    "component",
    "content_type",
    "depends_on_add",
    "depends_on_remove",
    "duplicate_of",
    "file_name",
    "groups",
    "id",
    "include_fields",
    "include_private",
    "is_patch",
    "is_private",
    "keywords",
    "keywords_add",
    "keywords_remove",
    "limit",
    "new_since",
    "offset",
    "op_sys",
    "platform",
    "priority",
    "product",
    "query",
    "resolution",
    "severity",
    "status",
    "target_milestone",
    "version",
];

/// Cap on recorded string values; see [`PARAM_ALLOWLIST`].
const PARAM_VALUE_MAX_CHARS: usize = 1024;

/// An allowlisted value with every string (top level or inside a list)
/// truncated to [`PARAM_VALUE_MAX_CHARS`] characters. No marker is
/// appended; the cap is documented at the allowlist.
fn truncated(value: &Value) -> Value {
    match value {
        // A string of at most 1024 BYTES has at most 1024 chars; the
        // cheap length check skips the char walk for the common case.
        Value::String(s) if s.len() > PARAM_VALUE_MAX_CHARS => {
            let capped: String = s.chars().take(PARAM_VALUE_MAX_CHARS).collect();
            Value::String(capped)
        }
        Value::Array(items) => Value::Array(items.iter().map(truncated).collect()),
        other => other.clone(),
    }
}

/// Project a tool call's arguments through [`PARAM_ALLOWLIST`] into the
/// audit record's `params` map.
fn allowlisted(params: Option<&JsonObject>) -> BTreeMap<String, Value> {
    let Some(params) = params else {
        return BTreeMap::new();
    };
    params
        .iter()
        .map(|(key, value)| {
            let recorded = if PARAM_ALLOWLIST.contains(&key.as_str()) {
                truncated(value)
            } else {
                let len = serde_json::to_vec(value).map(|b| b.len()).unwrap_or(0);
                json!({ "_len": len })
            };
            (key.clone(), recorded)
        })
        .collect()
}

/// The calling client as it introduced itself in the handshake, for an
/// audit record. Self-declared, therefore untrusted; `principal` stays
/// `None` (reserved for a future authenticated identity).
fn client_of(ctx: &RequestContext<RoleServer>) -> audit::ClientInfo {
    let peer = ctx.peer.peer_info();
    audit::ClientInfo {
        name: peer.as_ref().map(|p| p.client_info.name.clone()),
        version: peer.as_ref().map(|p| p.client_info.version.clone()),
        principal: None,
    }
}

/// The streamable-HTTP transport configuration this build serves with.
///
/// Lives here rather than in `main` so the integration tests serve the
/// configuration a deployment actually gets. Two rmcp 3.1 defaults are set
/// by name rather than inherited, because inheriting them changes how a
/// deployment behaves without anyone choosing it:
///
/// * `allowed_hosts` defaults to loopback only — a DNS-rebinding defence
///   for MCP servers a browser can reach on `localhost`. bugwarden is
///   reached by MCP clients at whatever address the operator bound and
///   named, so that default would refuse every deployment not addressed as
///   `localhost`, containers included. Disabled deliberately: the access
///   control here is the network boundary, and per-caller authentication
///   when it lands (issue #32).
/// * `max_request_body_bytes` is a 4 MiB POST cap with no rmcp 2.2
///   equivalent. Worth keeping as a memory bound, but it also ceilings
///   `add_attachment` independently of the operator's
///   `global.max_attachment_bytes`, so it is pinned to the SDK's current
///   value: an SDK bump must not move an operator-visible limit. Issue #52
///   reconciles the two ceilings.
pub fn http_server_config() -> StreamableHttpServerConfig {
    StreamableHttpServerConfig::default()
        .disable_allowed_hosts()
        .with_max_request_body_bytes(4 * 1024 * 1024)
}

/// Whether this request took rmcp's handshake-free lifecycle.
///
/// The transport routes on the PRESENCE of
/// `_meta.io.modelcontextprotocol/protocolVersion`, whatever revision that
/// key names — not on the negotiated revision, and not on
/// [`SUPPORTED_PROTOCOL_VERSIONS`]. So excluding `2026-07-28` does not keep
/// a request off that path: a client naming a revision this build does
/// serve reaches the handler with no `initialize` behind it, and rmcp
/// synthesises its peer with the SDK's own build identity as `client_info`.
/// Served, such a call would put a client the server never spoke to into
/// the audit stream, with no session record anchoring it — a plausible
/// wrong attribution, which is the one an audit trail can least afford.
///
/// No revision this build serves defines that lifecycle, so a request
/// carrying it is out of contract and is refused.
fn skips_the_handshake(ctx: &RequestContext<RoleServer>) -> bool {
    ctx.meta.protocol_version().is_some()
}

/// The uniform refusal for a request that skipped the handshake. Names no
/// tool, bug or policy — it is a statement about the request's shape.
fn handshake_required() -> McpError {
    McpError::invalid_request(
        "this server requires the initialize handshake; per-request protocol negotiation is not served",
        None,
    )
}

/// Total elapsed milliseconds since `started`, saturating.
fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// Persist one audit record without blocking the async worker: the sink
/// is synchronous by design (that is what makes "persisted before the
/// response is returned" a guarantee), so the write moves to the blocking
/// pool and is awaited — the response still cannot overtake it. A
/// panicked write counts as a failed one.
async fn record_event(
    audit: &Arc<AuditState>,
    kind: audit::AuditEventKind,
    session: audit::SessionInfo,
) -> Result<u64, ()> {
    let state = Arc::clone(audit);
    match tokio::task::spawn_blocking(move || state.sink.record(kind, session)).await {
        Ok(Ok(seq)) => Ok(seq),
        Ok(Err(_)) | Err(_) => Err(()),
    }
}

/// Assemble the `bug_info` envelope, re-classifying every body before it is
/// served.
///
/// The Read verdict came from the classification fetch; the body comes from a
/// second, later request. Between the two, a bug can be embargoed, moved into
/// a group, or otherwise become something the policy would refuse — and the
/// server's key is privileged enough to keep returning it. So the body is put
/// back through the guard and served on its OWN verdict, never on a verdict
/// about an earlier version of itself. `download_attachment` already re-checks
/// its blob response for the same reason.
///
/// This costs no upstream request: the full fetch returns a superset of the
/// classification fields, so the re-check reads what is already in hand. If
/// the body somehow lacks a field the policy consults, classification fails
/// closed on it (I4) rather than assuming the earlier verdict still holds.
///
/// A downgrade is honoured rather than refused: a body that now classifies
/// summary-only is served as a summary view, matching what a fresh call would
/// return. Anything that no longer classifies at all becomes the uniform
/// restricted entry, byte-identical to a bug that never existed (I2).
///
/// `caller` is the SAME identity the up-front assessment used — resolved
/// once per tool call and threaded here, so a bug the assessment granted on
/// the caller's authorship cannot be dropped by a re-check running without
/// that identity.
fn assemble_bug_info(
    guard: &Guard,
    ids: &[u64],
    assessments: &BTreeMap<u64, (Access, Value)>,
    full: &BTreeMap<u64, Value>,
    caller: Option<&str>,
) -> Value {
    let mut bugs: Vec<Value> = Vec::new();
    let mut restricted: Vec<Value> = Vec::new();
    for id in ids {
        let served = match assessments.get(id) {
            Some((access, _)) if access.allows(Capability::Read) => full
                .get(id)
                // Absent from the body response => fail closed (I4).
                .and_then(|body| {
                    let (kept, dropped) = guard.filter_bug_list(vec![body.clone()], caller);
                    if !dropped.is_empty() {
                        // The verdict flipped between the two fetches — the
                        // anomaly this re-check exists for. Server-side only
                        // (I3): the client just sees the uniform denial.
                        tracing::info!(id, "bug_info: body no longer passes the guard; refusing");
                    }
                    kept.into_iter().next()
                }),
            // Summary grants are served from the classification objects the
            // verdict was made on, so they carry no second-fetch window.
            Some((access, meta)) if access.allows(Capability::Summary) => {
                Some(Guard::summary_view(meta))
            }
            _ => None,
        };
        match served {
            Some(bug) => bugs.push(bug),
            None => restricted.push(json!({ "id": id, "note": Guard::denial(*id) })),
        }
    }
    json!({ "bugs": bugs, "restricted": restricted })
}

/// Refuse a call naming more distinct bug ids than the guard will classify.
///
/// The bound itself is [`Guard::MAX_ASSESS_IDS`], defined next to the loop it
/// bounds. Refusing here rather than letting the guard silently deny the
/// excess turns a confusing partial answer into a clear one, and the check
/// reads only the request — never a verdict — so it discloses nothing about
/// any bug (I1/I2).
fn too_many_ids(ids: &[u64]) -> Option<CallToolResult> {
    let distinct = ids.iter().collect::<BTreeSet<_>>().len();
    (distinct > Guard::MAX_ASSESS_IDS).then(|| {
        err_text(format!(
            "At most {} bug ids may be named in one call, got {distinct}",
            Guard::MAX_ASSESS_IDS
        ))
    })
}

/// Advisory attached to a quicksearch envelope when the query is nothing but
/// bug ids (comma/whitespace-separated numbers, each optionally prefixed
/// with '#').
///
/// With a non-empty `status` the tool prefixes it to the query, so upstream
/// content-matches the whole expression and a client holding an exact set of
/// ids is better served by `bug_info` — this note says so. With an empty
/// `status` the query goes upstream bare, and Bugzilla routes a bare query
/// of nothing but numbers to an exact id lookup instead; the note still
/// steers to `bug_info` there, with wording that is true on that path. A
/// query naming more distinct ids than [`Guard::MAX_ASSESS_IDS`] gets
/// steering that mentions the per-call cap and batching — the cap is already
/// public in bug_info's refusal text and parameter doc — so the advice does
/// not walk the client straight into a refusal.
///
/// The note is computed from the CLIENT'S OWN REQUEST ALONE (the query and
/// status strings): never from search results, guard verdicts, or anything
/// upstream said. That keeps it off the oracle surface — its presence and
/// wording tell the client nothing it did not already know (I2/I3) — and
/// the `bugs` array it accompanies is byte-identical to what the same
/// request returns without it. The query is NOT rerouted: a client genuinely
/// searching for a number still gets the search it asked for.
fn id_list_advisory(query: &str, status: &str) -> Option<String> {
    let mut ids: BTreeSet<&str> = BTreeSet::new();
    for token in query.split(|c: char| c == ',' || c.is_whitespace()) {
        if token.is_empty() {
            continue;
        }
        let digits = token.strip_prefix('#').unwrap_or(token);
        if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        // Distinct ids, not distinct spellings: "07" names bug 7.
        let canonical = digits.trim_start_matches('0');
        ids.insert(if canonical.is_empty() { "0" } else { canonical });
    }
    if ids.is_empty() {
        return None;
    }
    let semantics = if status.is_empty() {
        "This query is only bug ids and, because status is empty, it is \
         passed to Bugzilla bare; Bugzilla treats a bare query of nothing \
         but numbers as an exact id lookup, not a content search."
    } else {
        "This query is only bug ids, but quicksearch matches bug text, so a \
         number also matches bugs that merely mention it."
    };
    let steer = if ids.len() > Guard::MAX_ASSESS_IDS {
        format!(
            "For an exact set of known ids call bug_info with its bug_ids \
             array, at most {} ids per call — batch a longer list across \
             calls: every requested id comes back either as a bug or under \
             'restricted'.",
            Guard::MAX_ASSESS_IDS
        )
    } else {
        "For an exact set of known ids call bug_info with its bug_ids array: \
         every requested id comes back either as a bug or under 'restricted'."
            .to_string()
    };
    Some(format!("{semantics} {steer}"))
}

/// Project a bug object to the requested field set, preserving the
/// `_redacted` marker when present.
fn project_fields(bug: &Value, fields: &BTreeSet<String>) -> Value {
    let mut out = serde_json::Map::new();
    if let Some(obj) = bug.as_object() {
        for field in fields {
            if let Some(v) = obj.get(field) {
                out.insert(field.clone(), v.clone());
            }
        }
        if let Some(marker) = obj.get("_redacted") {
            out.insert("_redacted".to_string(), marker.clone());
        }
    }
    Value::Object(out)
}

/// Add `"comment": {"body": ...}` to a `Bug.update` payload when a comment is
/// set. This is the UPDATE shape only — `Bug.add_attachment` takes `comment`
/// as a plain string and must not use this helper.
fn attach_comment(payload: &mut serde_json::Map<String, Value>, comment: &str) {
    if !comment.is_empty() {
        payload.insert("comment".to_string(), json!({ "body": comment }));
    }
}

/// Build an `{"add": [..], "remove": [..]}` change object; `None` when there
/// is no change.
fn dep_change(add: Option<&Vec<u64>>, remove: Option<&Vec<u64>>) -> Option<Value> {
    let mut obj = serde_json::Map::new();
    if let Some(a) = add.filter(|v| !v.is_empty()) {
        obj.insert("add".to_string(), json!(a));
    }
    if let Some(r) = remove.filter(|v| !v.is_empty()) {
        obj.insert("remove".to_string(), json!(r));
    }
    if obj.is_empty() {
        None
    } else {
        Some(Value::Object(obj))
    }
}

/// [`dep_change`] for string lists (`keywords`, `see_also`): build an
/// `{"add": [..], "remove": [..]}` change object; `None` when there is no
/// change. Empty strings are dropped like the scalar params drop them, and
/// a side that is absent, empty, or becomes empty is omitted. The
/// replace-all `set` variant is never produced — a stale view of the list
/// would silently wipe entries added since it was read.
fn list_change(add: Option<&Vec<String>>, remove: Option<&Vec<String>>) -> Option<Value> {
    fn clean(list: Option<&Vec<String>>) -> Vec<&str> {
        list.into_iter()
            .flatten()
            .map(String::as_str)
            .filter(|s| !s.is_empty())
            .collect()
    }
    let mut obj = serde_json::Map::new();
    let add = clean(add);
    if !add.is_empty() {
        obj.insert("add".to_string(), json!(add));
    }
    let remove = clean(remove);
    if !remove.is_empty() {
        obj.insert("remove".to_string(), json!(remove));
    }
    if obj.is_empty() {
        None
    } else {
        Some(Value::Object(obj))
    }
}

/// Decoded byte length of a base64 payload, counting the `=` padding out.
///
/// Used to re-check an attachment against the size cap without decoding the
/// blob. Whitespace inside the payload (some encoders wrap lines) is ignored,
/// so a wrapped body is not mistaken for a larger one.
fn decoded_len(blob: &str) -> u64 {
    let chars = blob.chars().filter(|c| !c.is_whitespace()).count() as u64;
    let padding = blob
        .trim_end()
        .chars()
        .rev()
        .take_while(|&c| c == '=')
        .count() as u64;
    // 4 encoded chars carry 3 bytes; an unpadded tail of 2 or 3 chars carries
    // 1 or 2 bytes respectively.
    let full = chars / 4 * 3;
    let tail = (chars % 4).saturating_sub(1);
    (full + tail).saturating_sub(padding)
}

/// Upload-side size gate: `Some(refusal)` when the DECODED size of a base64
/// payload exceeds a non-zero cap.
///
/// The same ceiling `download_attachment` enforces, applied to what comes IN:
/// an operator who capped what may leave has not agreed to unbounded uploads
/// through the same server. Measured on the decoded size, so base64 expansion
/// cannot shrink the cap by a third. The refusal says the payload is too big
/// but not by how much: `max_attachment_bytes` is not I1-disclosable, on this
/// path exactly as on the download path.
fn upload_size_refusal(cap: u64, data: &str) -> Option<String> {
    (cap > 0 && decoded_len(data) > cap)
        .then(|| "Attachment exceeds the size limit of this server".to_string())
}

/// Whether attachment content of this media type may be returned as MCP
/// image content rather than an opaque blob resource.
///
/// The media type comes from whoever uploaded the attachment, so this is a
/// strict allowlist of raster formats, not a `image/` prefix test. Anything
/// else — notably `image/svg+xml`, which is script-bearing markup in a client
/// webview — travels as a blob resource, keeping attacker-chosen bytes out of
/// the model's image channel and out of client image renderers.
fn is_inline_image(mime: &str) -> bool {
    let base = mime
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    matches!(
        base.as_str(),
        "image/png" | "image/jpeg" | "image/gif" | "image/webp" | "image/bmp"
    )
}

fn default_status() -> String {
    "ALL".to_string()
}

fn default_include_fields() -> String {
    "id,product,component,assigned_to,status,resolution,summary,last_change_time".to_string()
}

fn default_limit() -> u32 {
    50
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct BugInfoParams {
    /// Bug ids to fetch. At most 25 distinct ids per call.
    pub bug_ids: Vec<u64>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct BugHistoryParams {
    /// Bug id.
    pub id: u64,
    /// Only return history newer than this date.
    #[serde(default)]
    pub new_since: Option<DateTime<Utc>>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct BugCommentsParams {
    /// Bug id.
    pub id: u64,
    /// Include private comments (subject to server policy).
    #[serde(default)]
    pub include_private: bool,
    /// Only return comments newer than this date.
    #[serde(default)]
    pub new_since: Option<DateTime<Utc>>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct QuicksearchParams {
    /// Query in bugzilla quicksearch syntax. Under any non-empty status
    /// (the default is ALL) this is content matching, not id lookup: a
    /// number in the query is matched as text and returns bugs that merely
    /// mention that number. With an empty status the query is sent to
    /// bugzilla bare, and a bare query of nothing but numbers is an exact
    /// id lookup. For an exact set of known bug ids use the bug_info tool
    /// instead.
    pub query: String,
    /// Status filter (e.g., ALL, OPEN, CLOSED), prefixed to the query.
    /// Empty means bugzilla's default search over open bugs — and a bare
    /// query of nothing but numbers then becomes an exact id lookup.
    #[serde(default = "default_status")]
    pub status: String,
    /// Comma-separated list of fields to return for each bug.
    #[serde(default = "default_include_fields")]
    pub include_fields: String,
    /// Maximum number of bugs to return.
    #[serde(default = "default_limit")]
    pub limit: u32,
    /// Offset into the result list (for pagination).
    #[serde(default)]
    pub offset: u32,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct CreateBugParams {
    /// Product to file against.
    pub product: String,
    /// Component within the product.
    pub component: String,
    /// One-line summary.
    pub summary: String,
    /// Version of the product the bug is against.
    pub version: String,
    /// Longer description; becomes the first comment.
    #[serde(default)]
    pub description: String,
    /// Severity (instance-specific vocabulary, e.g. "normal").
    #[serde(default)]
    pub severity: Option<String>,
    /// Priority (instance-specific vocabulary, e.g. "P3").
    #[serde(default)]
    pub priority: Option<String>,
    /// Operating system the bug applies to.
    #[serde(default)]
    pub op_sys: Option<String>,
    /// Platform/architecture the bug applies to.
    #[serde(default)]
    pub platform: Option<String>,
    /// Keywords to set on the new bug.
    #[serde(default)]
    pub keywords: Vec<String>,
    /// Groups to restrict the new bug to.
    #[serde(default)]
    pub groups: Vec<String>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct AddAttachmentParams {
    /// Bug id to attach to.
    pub bug_id: u64,
    /// Attachment content, base64-encoded.
    pub data: String,
    /// File name shown in Bugzilla.
    pub file_name: String,
    /// Short description of the attachment.
    pub summary: String,
    /// MIME type, e.g. "text/plain".
    pub content_type: String,
    /// Comment to add alongside the attachment.
    #[serde(default)]
    pub comment: String,
    /// Mark the attachment private.
    #[serde(default)]
    pub is_private: bool,
    /// Mark the attachment as a patch.
    #[serde(default)]
    pub is_patch: bool,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct AddCommentParams {
    /// Bug id to comment on.
    pub bug_id: u64,
    /// Comment text.
    pub comment: String,
    /// Make the comment private.
    #[serde(default)]
    pub is_private: bool,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct UpdateBugStatusParams {
    /// Bug ID to update.
    pub bug_id: u64,
    /// New status.
    pub status: String,
    /// Resolution (required when status is CLOSED).
    #[serde(default)]
    pub resolution: Option<String>,
    /// Optional comment explaining the change.
    #[serde(default)]
    pub comment: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct AssignBugParams {
    /// Bug ID to assign.
    pub bug_id: u64,
    /// Email address of the assignee.
    pub assignee: String,
    /// Optional comment explaining the assignment.
    #[serde(default)]
    pub comment: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct UpdateBugFieldsParams {
    /// Bug ID to update.
    pub bug_id: u64,
    /// Priority (e.g., urgent, high, medium, low, unspecified).
    #[serde(default)]
    pub priority: Option<String>,
    /// Severity (e.g., urgent, high, medium, low, unspecified).
    #[serde(default)]
    pub severity: Option<String>,
    /// Resolution (e.g., FIXED, WONTFIX, NOTABUG, DUPLICATE) - only for
    /// closed bugs.
    #[serde(default)]
    pub resolution: Option<String>,
    /// New one-line summary (retitles the bug).
    #[serde(default)]
    pub summary: Option<String>,
    /// URL the bug relates to (the bug's "URL" field).
    #[serde(default)]
    pub url: Option<String>,
    /// Status whiteboard text.
    #[serde(default)]
    pub whiteboard: Option<String>,
    /// Version of the product the bug is against (instance-specific
    /// vocabulary).
    #[serde(default)]
    pub version: Option<String>,
    /// Target milestone (instance-specific vocabulary).
    #[serde(default)]
    pub target_milestone: Option<String>,
    /// Keywords to add.
    #[serde(default)]
    pub keywords_add: Option<Vec<String>>,
    /// Keywords to remove.
    #[serde(default)]
    pub keywords_remove: Option<Vec<String>>,
    /// See Also entries to add; each value is a bug URL.
    #[serde(default)]
    pub see_also_add: Option<Vec<String>>,
    /// See Also entries to remove; each value is a bug URL.
    #[serde(default)]
    pub see_also_remove: Option<Vec<String>>,
    /// Custom fields, e.g. {"cf_fixed_in": "1.2.3"}. Keys must start with
    /// 'cf_'.
    #[serde(default)]
    pub custom_fields: Option<JsonObject>,
    /// Optional comment explaining the changes.
    #[serde(default)]
    pub comment: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct UpdateBugDependenciesParams {
    /// Bug ID to update.
    pub bug_id: u64,
    /// List of bug IDs this bug should block.
    #[serde(default)]
    pub blocks_add: Option<Vec<u64>>,
    /// List of bug IDs to remove from blocks.
    #[serde(default)]
    pub blocks_remove: Option<Vec<u64>>,
    /// List of bug IDs this bug should depend on.
    #[serde(default)]
    pub depends_on_add: Option<Vec<u64>>,
    /// List of bug IDs to remove from depends_on.
    #[serde(default)]
    pub depends_on_remove: Option<Vec<u64>>,
    /// Optional comment explaining the changes.
    #[serde(default)]
    pub comment: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct AddCcParams {
    /// Bug ID.
    pub bug_id: u64,
    /// Email address to add to the CC list.
    pub cc_email: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct MarkAsDuplicateParams {
    /// Bug ID to mark as duplicate.
    pub bug_id: u64,
    /// Bug ID this is a duplicate of.
    pub duplicate_of: u64,
    /// Optional comment (default: auto-generated).
    #[serde(default)]
    pub comment: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct ListAttachmentsParams {
    /// Bug ID.
    pub bug_id: u64,
    /// Include metadata of private attachments (subject to server policy).
    #[serde(default)]
    pub include_private: bool,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct DownloadAttachmentParams {
    /// Attachment id (as returned by list_attachments).
    pub attachment_id: u64,
    /// Allow downloading a private attachment (subject to server policy).
    #[serde(default)]
    pub include_private: bool,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct BugUrlParams {
    /// Bug ID.
    pub bug_id: u64,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct SummarizeBugParams {
    /// Bug id whose comments should be summarized.
    pub id: u64,
}

/// The MCP server: guard policy, Bugzilla client, and the pruned tool
/// router (I13). Construct with [`BugWarden::new`]; serve over any rmcp
/// transport.
#[derive(Clone)]
pub struct BugWarden {
    cfg: Arc<Cli>,
    guard: Arc<Guard>,
    bz: Arc<BugzillaClient>,
    tool_router: ToolRouter<Self>,
    /// Who holds the Bugzilla API key — resolved exactly once, at
    /// construction. In `Server` custody the running server owns the key
    /// `String`; it is never re-read from disk per request.
    key_custody: KeyCustody,
    /// Audit wiring; `None` runs the exact pre-audit request path.
    audit: Option<Arc<AuditState>>,
}

impl BugWarden {
    /// Build the server, pruning the tool router per policy (I13).
    ///
    /// Errors when `global.disabled_tools` names a tool that does not exist:
    /// `ToolRouter::remove_route` silently no-ops on unknown names, so a typo
    /// would otherwise leave the tool exposed while the operator believes it
    /// disabled — the policy format's "typos are hard startup errors, never
    /// silent fail-open" rule applies here too.
    ///
    /// Also resolves API key custody ([`Cli::resolve_key_custody`]) — here,
    /// on every construction path, so a missing or unreadable key fails at
    /// startup rather than at the first request.
    pub fn new(cfg: Arc<Cli>, guard: Arc<Guard>, bz: Arc<BugzillaClient>) -> anyhow::Result<Self> {
        let key_custody = cfg.resolve_key_custody()?;
        // Identity collapses under server-held http custody: every client
        // authenticates — and therefore whoamis — as the server's service
        // account. A policy written for per-request custody, where
        // `created_by_me` meant each caller's own reports, silently changes
        // meaning, so say it out loud at startup.
        if cfg.transport == Transport::Http
            && matches!(key_custody, KeyCustody::Server(_))
            && guard.policy.needs_identity()
        {
            tracing::warn!(
                "the policy consults created_by_me, but in server-held key mode every \
                 client resolves to the service account that owns the key: \
                 created_by_me describes that one account's bug reports for ALL \
                 clients, never an individual caller's"
            );
        }
        let mut tool_router = Self::tool_router();
        // Validate disabled_tools against the FULL router, before any route
        // removal: a write-tool name stays a valid entry even when read-only
        // mode removes that route first.
        for name in &guard.policy.global.disabled_tools {
            if !tool_router.has_route(name) {
                let known = tool_router
                    .list_all()
                    .iter()
                    .map(|t| t.name.to_string())
                    .collect::<Vec<_>>()
                    .join(", ");
                anyhow::bail!(
                    "policy global.disabled_tools names unknown tool \"{name}\" \
                     (known tools: {known})"
                );
            }
        }
        if guard.policy.global.read_only {
            for name in WRITE_TOOLS {
                tracing::info!(tool = name, "read-only mode: removing write tool");
                tool_router.remove_route(name);
            }
        }
        for name in &guard.policy.global.disabled_tools {
            tracing::info!(tool = %name, "policy: removing disabled tool");
            tool_router.remove_route(name);
        }
        Ok(Self {
            cfg,
            guard,
            bz,
            tool_router,
            key_custody,
            audit: None,
        })
    }

    /// Enable auditing. Separate from [`BugWarden::new`] so existing
    /// construction sites (and the tests that rely on them) stay valid
    /// with auditing off.
    pub fn with_audit(mut self, audit: Arc<AuditState>) -> Self {
        self.audit = Some(audit);
        self
    }

    /// The session an audit record belongs to. http: the server-assigned
    /// `mcp-session-id` header and, when the listener was built with
    /// connect-info, the remote peer address — both from the HTTP request
    /// parts rmcp copies into the request extensions. stdio: the
    /// process-scoped session id from [`AuditState`].
    fn session_info(
        &self,
        ctx: &RequestContext<RoleServer>,
        audit: &AuditState,
    ) -> audit::SessionInfo {
        match self.cfg.transport {
            Transport::Stdio => audit::SessionInfo {
                id: Some(audit.stdio_session_id.clone()),
                transport: TransportKind::Stdio,
                remote: None,
            },
            Transport::Http => {
                let parts = ctx.extensions.get::<axum::http::request::Parts>();
                audit::SessionInfo {
                    id: parts
                        .and_then(|p| p.headers.get("mcp-session-id"))
                        .and_then(|v| v.to_str().ok())
                        .map(str::to_owned),
                    transport: TransportKind::Http,
                    remote: parts
                        .and_then(|p| {
                            p.extensions
                                .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
                        })
                        .map(|ci| ci.0.to_string()),
                }
            }
        }
    }

    /// Resolve the Bugzilla API key for the current request.
    ///
    /// Server custody (stdio, or http server-held mode): the key resolved at
    /// startup — the per-request header is never consulted, so a request that
    /// carries one is served with the server's key and the header value is
    /// never read. Per-request custody (http): from the configured
    /// (lowercased) header of the underlying HTTP request; a missing key is a
    /// protocol error (`McpError::invalid_request`), not a tool error.
    fn api_key(&self, ctx: &RequestContext<RoleServer>) -> Result<String, McpError> {
        match &self.key_custody {
            KeyCustody::Server(key) => Ok(key.clone()),
            KeyCustody::PerRequest => {
                let header_name = self.cfg.api_key_header.to_lowercase();
                ctx.extensions
                    .get::<axum::http::request::Parts>()
                    .and_then(|parts| parts.headers.get(header_name.as_str()))
                    .and_then(|v| v.to_str().ok())
                    .filter(|v| !v.is_empty())
                    .map(str::to_owned)
                    .ok_or_else(|| {
                        McpError::invalid_request(
                            format!("`{}` header is required", self.cfg.api_key_header),
                            None,
                        )
                    })
            }
        }
    }

    /// Guard assessment for the given ids (fail closed, I4). `caller` is
    /// the identity resolved once at the tool entry
    /// (`Guard::resolve_caller`) — never resolved here, so a tool call
    /// costs at most one whoami lookup however many assessments it runs.
    async fn assess(
        &self,
        key: &str,
        ids: &[u64],
        caller: Option<&str>,
    ) -> BTreeMap<u64, (Access, Value)> {
        self.guard.assess(&self.bz, key, ids, caller).await
    }

    /// Assess a single bug id and require `cap`. Returns `Some(denial)` when
    /// the operation must be refused; the denial text is uniform (I2). The
    /// verdict — either way — and its deciding rule are noted on the
    /// request's audit cell; noting changes nothing the client sees.
    async fn deny_unless(
        &self,
        key: &str,
        id: u64,
        cap: Capability,
        caller: Option<&str>,
        ctx: &RequestContext<RoleServer>,
    ) -> Option<CallToolResult> {
        let assessments = self.assess(key, &[id], caller).await;
        let entry = assessments.get(&id);
        let allowed = entry.is_some_and(|(access, _)| access.allows(cap));
        if let Some(cell) = audit_cell(ctx) {
            let verdict = if allowed {
                Verdict::Served
            } else {
                Verdict::Denied
            };
            match entry {
                Some((access, _)) => cell.note_verdict_rule(verdict, access_rule(access)),
                None => cell.note_verdict(verdict),
            }
        }
        if allowed {
            None
        } else {
            tracing::info!(bug_id = id, capability = ?cap, "guard denied operation");
            Some(err_text(Guard::denial(id)))
        }
    }
}

#[tool_router]
impl BugWarden {
    #[tool(
        description = "Returns the entire information for one or more bugzilla bug ids. Bugs that are not accessible through this server are listed under 'restricted'.",
        annotations(read_only_hint = true, open_world_hint = true)
    )]
    async fn bug_info(
        &self,
        Parameters(p): Parameters<BugInfoParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        tracing::info!(bug_ids = ?p.bug_ids, "tool: bug_info");
        let key = self.api_key(&ctx)?;

        // Deduplicate while preserving request order.
        let mut seen = BTreeSet::new();
        let ids: Vec<u64> = p
            .bug_ids
            .iter()
            .copied()
            .filter(|id| seen.insert(*id))
            .collect();
        if ids.is_empty() {
            note_refused(&ctx);
            return Ok(err_text("At least one bug id must be provided"));
        }
        if let Some(refusal) = too_many_ids(&ids) {
            note_refused(&ctx);
            return Ok(refusal);
        }

        // Resolved at most once per tool call and threaded to EVERY
        // classification below — the assessment, the assemble re-check and
        // the link disclosure — so one verdict cannot be made with the
        // identity and another without it.
        let caller = self.guard.resolve_caller(&self.bz, &key).await;
        let assessments = self.assess(&key, &ids, caller.as_deref()).await;

        // Full fetch only for Read-granted ids.
        let read_ids: Vec<u64> = ids
            .iter()
            .copied()
            .filter(|id| {
                assessments
                    .get(id)
                    .is_some_and(|(access, _)| access.allows(Capability::Read))
            })
            .collect();
        let mut full: BTreeMap<u64, Value> = BTreeMap::new();
        if !read_ids.is_empty() {
            match self.bz.get_bugs(&key, &read_ids, None).await {
                Ok(envelope) => {
                    if let Some(arr) = envelope.get("bugs").and_then(Value::as_array) {
                        for bug in arr {
                            if let Some(id) = bug.get("id").and_then(Value::as_u64) {
                                full.insert(id, bug.clone());
                            }
                        }
                    }
                }
                Err(e) => {
                    // Server-side only. Bugzilla's own message names the bug
                    // and says whether it exists ("Bug #N does not exist."),
                    // so forwarding it would hand the client the very
                    // distinction I2 exists to erase. The ids simply stay
                    // absent from `full` and fall to the uniform denial
                    // below, which is also what a fetch failure should look
                    // like (I4) — one bad body no longer voids the call.
                    tracing::warn!(error = %e, "bug_info: body fetch failed");
                }
            }
        }

        // The bodies name other bugs through blocks/depends_on/dupe_of/
        // see_also/url. Those ids come from Bugzilla, not the client, so one
        // batched assessment covers them all; anything that fails to earn a
        // summary is removed before the body is served (I2, and the same bar
        // update_bug_dependencies applies before WRITING such a link).
        let mut envelope =
            assemble_bug_info(&self.guard, &ids, &assessments, &full, caller.as_deref());
        let base_url = self.bz.base_url();
        // Only ids actually SERVED in this envelope are already answered for.
        // A requested id that was denied must not be whitelisted: asking
        // about a hidden bug would then reveal it through the links of one
        // the client may read.
        let served: BTreeSet<u64> = envelope
            .get("bugs")
            .and_then(Value::as_array)
            .map(|bugs| bugs.iter().filter_map(|b| b["id"].as_u64()).collect())
            .unwrap_or_default();
        let named: BTreeSet<u64> = envelope
            .get("bugs")
            .and_then(Value::as_array)
            .map(|bugs| {
                bugs.iter()
                    .flat_map(|b| Guard::linked_bug_ids(b, base_url))
                    .filter(|id| !served.contains(id))
                    .collect()
            })
            .unwrap_or_default();
        // Always assess, even with nothing to assess: skipping the call when
        // every link is hidden would make "no links" and "links, all hidden"
        // cost different round trips (I2). download_attachment pads the same
        // way.
        let mut allowed = self
            .guard
            .disclosable(&self.bz, &key, &named, caller.as_deref())
            .await;
        allowed.extend(served);
        if let Some(bugs) = envelope.get_mut("bugs").and_then(Value::as_array_mut) {
            for bug in bugs.iter_mut() {
                Guard::scrub_bug_links(bug, base_url, &allowed);
            }
        }
        if let Some(cell) = audit_cell(&ctx) {
            // One record for the whole call: per-id verdicts merge worst-
            // wins. The envelope is the truth (a re-check flip lands a
            // granted id under `restricted`); rules come from the
            // assessments where the variant matches the outcome. A
            // `restricted` entry is a Denied the client was told about;
            // the suppressed set is the scrubbed LINK ids — the ones the
            // client cannot see at all (I14).
            if let Some(bugs) = envelope.get("bugs").and_then(Value::as_array) {
                for bug in bugs {
                    let redacted = bug.get("_redacted").is_some();
                    let verdict = if redacted {
                        Verdict::ServedFiltered
                    } else {
                        Verdict::Served
                    };
                    let rule = bug
                        .get("id")
                        .and_then(Value::as_u64)
                        .and_then(|id| assessments.get(&id));
                    match rule {
                        Some((Access::Granted { rule, .. }, _)) => {
                            cell.note_verdict_rule(verdict, rule);
                        }
                        _ => cell.note_verdict(verdict),
                    }
                    if redacted {
                        cell.note_redacted("summary_view");
                    }
                }
            }
            if let Some(restricted) = envelope.get("restricted").and_then(Value::as_array) {
                for entry in restricted {
                    let rule = entry
                        .get("id")
                        .and_then(Value::as_u64)
                        .and_then(|id| assessments.get(&id));
                    match rule {
                        Some((Access::Denied { rule }, _)) => {
                            cell.note_verdict_rule(Verdict::Denied, rule);
                        }
                        _ => cell.note_verdict(Verdict::Denied),
                    }
                }
            }
            let hidden_links: Vec<u64> = named.difference(&allowed).copied().collect();
            if !hidden_links.is_empty() {
                cell.note_suppressed(hidden_links);
            }
        }
        Ok(ok_json(envelope))
    }

    #[tool(
        description = "Returns the history of given bug id. new_since allows filtering history newer than the given date.",
        annotations(read_only_hint = true, open_world_hint = true)
    )]
    async fn bug_history(
        &self,
        Parameters(p): Parameters<BugHistoryParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        tracing::info!(id = p.id, new_since = ?p.new_since, "tool: bug_history");
        let key = self.api_key(&ctx)?;
        let caller = self.guard.resolve_caller(&self.bz, &key).await;
        if let Some(denied) = self
            .deny_unless(&key, p.id, Capability::History, caller.as_deref(), &ctx)
            .await
        {
            return Ok(denied);
        }
        match self.bz.bug_history(&key, p.id, p.new_since).await {
            Ok(history) => {
                // Dependency, duplicate and see_also changes carry the ids of
                // OTHER bugs in their added/removed values, so history is a
                // way to read out the existence of bugs the policy hides.
                let base_url = self.bz.base_url();
                let named = Guard::history_bug_ids(&history, base_url);
                let disclosable = self
                    .guard
                    .disclosable(&self.bz, &key, &named, caller.as_deref())
                    .await;
                if let Some(cell) = audit_cell(&ctx) {
                    let hidden: Vec<u64> = named.difference(&disclosable).copied().collect();
                    if !hidden.is_empty() {
                        cell.note_suppressed(hidden);
                    }
                }
                Ok(ok_json(Guard::scrub_history(
                    history,
                    base_url,
                    &disclosable,
                )))
            }
            Err(e) => {
                tracing::warn!(id = p.id, error = %e, "bug_history: fetch failed");
                Ok(err_text("Failed to fetch bug history"))
            }
        }
    }

    #[tool(
        description = "Returns the comments of given bug id. Private comments are not included by default but can be explicitly requested (subject to server policy). new_since allows filtering comments newer than the given date.",
        annotations(read_only_hint = true, open_world_hint = true)
    )]
    async fn bug_comments(
        &self,
        Parameters(p): Parameters<BugCommentsParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        tracing::info!(
            id = p.id,
            include_private = p.include_private,
            new_since = ?p.new_since,
            "tool: bug_comments"
        );
        let key = self.api_key(&ctx)?;
        let caller = self.guard.resolve_caller(&self.bz, &key).await;
        if let Some(denied) = self
            .deny_unless(&key, p.id, Capability::Comments, caller.as_deref(), &ctx)
            .await
        {
            return Ok(denied);
        }
        match self.bz.bug_comments(&key, p.id, p.new_since).await {
            Ok(comments) => {
                let total = comments.len();
                let filtered = self.guard.filter_comments(comments, p.include_private);
                // Bugzilla writes "*** Bug N has been marked as a duplicate
                // of this bug ***" itself, so a hidden bug can name itself in
                // the comments of one the client may read (I2).
                let named = Guard::duplicate_marker_ids(&filtered);
                let disclosable = self
                    .guard
                    .disclosable(&self.bz, &key, &named, caller.as_deref())
                    .await;
                if let Some(cell) = audit_cell(&ctx) {
                    // Dropped private comments have no bug id: count only.
                    // Scrubbed duplicate-marker ids are the hidden bugs.
                    cell.note_suppressed_count((total - filtered.len()) as u64);
                    let hidden: Vec<u64> = named.difference(&disclosable).copied().collect();
                    if !hidden.is_empty() {
                        cell.note_suppressed(hidden);
                    }
                }
                let scrubbed = Guard::scrub_duplicate_markers(filtered, &disclosable);
                Ok(ok_json(Value::Array(scrubbed)))
            }
            Err(e) => {
                tracing::warn!(id = p.id, error = %e, "bug_comments: fetch failed");
                Ok(err_text("Failed to fetch bug comments"))
            }
        }
    }

    #[tool(
        description = "Search bugs by CONTENT using bugzilla's quicksearch syntax (full-text matching over bug summaries and text). The status filter is prefixed to the query expression, and under any non-empty status (the default is ALL) a number in the query is matched as text like any other word — it returns bugs that merely MENTION that number, not an id lookup. The one exception: an empty status sends the query to bugzilla bare, and bugzilla treats a bare query of nothing but numbers as an exact id lookup. Either way, for an exact set of known bug ids call bug_info with its bug_ids array instead: every requested id comes back either as a bug or under 'restricted', so an inaccessible id is reported rather than silently missing from a search.\n\nTo reduce the token limit & response time, only returns a subset of fields for each bug. The user can query full details of each bug using the bug_info tool. Returns the top-level bug data envelope containing the matched bugs.",
        annotations(read_only_hint = true, open_world_hint = true)
    )]
    async fn bugs_quicksearch(
        &self,
        Parameters(p): Parameters<QuicksearchParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        tracing::info!(
            query = %p.query,
            status = %p.status,
            include_fields = %p.include_fields,
            limit = p.limit,
            offset = p.offset,
            "tool: bugs_quicksearch"
        );
        let key = self.api_key(&ctx)?;

        // Requested projection; "id" is always part of it.
        let requested: BTreeSet<String> = p
            .include_fields
            .split(',')
            .map(|f| f.trim().to_string())
            .filter(|f| !f.is_empty())
            .chain(std::iter::once("id".to_string()))
            .collect();

        // Fetch requested ∪ CLASSIFY_FIELDS so the guard can classify.
        let mut fetch = requested.clone();
        fetch.extend(CLASSIFY_FIELDS.split(',').map(|f| f.trim().to_string()));
        let fetch_fields = fetch.into_iter().collect::<Vec<_>>().join(",");

        // limit/offset address the bugs the client may see; the guard scans
        // and filters upstream rows to fill that window (I2/I3).
        let caller = self.guard.resolve_caller(&self.bz, &key).await;
        // `scanned`/`dropped` are the scan's accounting for the audit
        // record only (issue #29); the response is built from `kept`
        // alone, so it stays byte-identical whatever they hold (I3).
        let SearchWindow {
            bugs: kept,
            scanned,
            dropped,
        } = match self
            .guard
            .quicksearch_window(
                &self.bz,
                &key,
                &SearchRequest {
                    query: &p.query,
                    status: &p.status,
                    include_fields: &fetch_fields,
                    limit: p.limit,
                    offset: p.offset,
                },
                caller.as_deref(),
            )
            .await
        {
            Ok(window) => window,
            // Uniform: a failing search never says which bug or why (I2).
            Err(e) => {
                tracing::warn!(error = %e, "bugs_quicksearch: upstream search failed");
                return Ok(err_text("Search failed"));
            }
        };
        let mut projected: Vec<Value> = kept
            .iter()
            .map(|bug| project_fields(bug, &requested))
            .collect();

        // The client chooses the projection, so it can ask for depends_on,
        // blocks, dupe_of or see_also here and read out the ids of bugs the
        // policy hides — wholesale, rather than one guessed id at a time
        // (I14). Same treatment as bug_info.
        let base_url = self.bz.base_url();
        let served: BTreeSet<u64> = projected.iter().filter_map(|b| b["id"].as_u64()).collect();
        let named: BTreeSet<u64> = projected
            .iter()
            .flat_map(|b| Guard::linked_bug_ids(b, base_url))
            .filter(|id| !served.contains(id))
            .collect();
        let mut allowed = self
            .guard
            .disclosable(&self.bz, &key, &named, caller.as_deref())
            .await;
        allowed.extend(served);
        for bug in projected.iter_mut() {
            Guard::scrub_bug_links(bug, base_url, &allowed);
        }
        if let Some(cell) = audit_cell(&ctx) {
            cell.note_verdict(Verdict::Served);
            // The window scan's own accounting (issue #29): rows examined
            // and rows dropped by verdict. A dropping scan upgrades the
            // verdict to served_filtered inside note_scan; the dropped
            // ids ride the existing suppressed-ids machinery below —
            // config gate, suppressed_count, and the BTreeSet union with
            // the I14-scrubbed link ids (overlap dedupes, a feature).
            cell.note_scan(u64::from(scanned), dropped.len() as u64);
            if !dropped.is_empty() {
                cell.note_suppressed(dropped.iter().copied());
            }
            // What this site itself sees is the served projection —
            // redacted rows and the linked ids I14 scrubbed out of them.
            for bug in &projected {
                if bug.get("_redacted").is_some() {
                    cell.note_redacted("summary_view");
                }
            }
            let hidden: Vec<u64> = named.difference(&allowed).copied().collect();
            if !hidden.is_empty() {
                cell.note_suppressed(hidden);
            }
        }

        let mut envelope = json!({ "bugs": projected });
        // Steering only, computed from the request the client itself sent
        // (query and status) — never from results or verdicts (see
        // id_list_advisory).
        if let Some(note) = id_list_advisory(&p.query, &p.status) {
            envelope["note"] = json!(note);
        }
        Ok(ok_json(envelope))
    }

    #[tool(
        description = "File a new bug. The bug is checked against server policy AS DESCRIBED before it is created, so a product or component the policy withholds cannot be filed into either. Returns the new bug id on success.",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = false,
            open_world_hint = true
        )
    )]
    async fn create_bug(
        &self,
        Parameters(p): Parameters<CreateBugParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        tracing::info!(
            product = %p.product,
            component = %p.component,
            "tool: create_bug"
        );
        let key = self.api_key(&ctx)?;

        let mut payload = serde_json::Map::new();
        payload.insert("product".to_string(), json!(p.product));
        payload.insert("component".to_string(), json!(p.component));
        payload.insert("summary".to_string(), json!(p.summary));
        payload.insert("version".to_string(), json!(p.version));
        if !p.description.is_empty() {
            payload.insert("description".to_string(), json!(p.description));
        }
        for (field, value) in [
            ("severity", p.severity),
            ("priority", p.priority),
            ("op_sys", p.op_sys),
            ("platform", p.platform),
        ] {
            if let Some(v) = value {
                payload.insert(field.to_string(), json!(v));
            }
        }
        if !p.keywords.is_empty() {
            payload.insert("keywords".to_string(), json!(p.keywords));
        }
        if !p.groups.is_empty() {
            payload.insert("groups".to_string(), json!(p.groups));
        }
        let payload = Value::Object(payload);

        // No bug exists yet, so the bug AS REQUESTED is what the policy
        // judges: the rules that decide what may be seen decide what may be
        // filed. The refusal names no rule (I1) and — crucially — is the
        // SAME text, after the SAME single upstream request, whether the
        // policy or Bugzilla refused. Two distinguishable refusals would be
        // a free policy oracle: send a request Bugzilla is guaranteed to
        // reject (an invalid `version`, say) and read the policy off which
        // refusal comes back, with nothing created and nothing logged
        // upstream. So the refused path burns one classification call
        // against bug id 0 — which never exists and creates nothing —
        // exactly as download_attachment pads its metadata-miss path, so
        // both failure paths cost one upstream request. Honestly residual:
        // a SUCCESSFUL create is still distinguishable (it returns the new
        // bug id — that is the tool working), so a client willing to file a
        // real, attributable bug in an allowed product can still confirm
        // that product is allowed; and the padding equalizes the request
        // COUNT, not the upstream handler's exact latency (a GET classify
        // vs a rejected POST), the same residual the download path accepts.
        if !self.guard.may_create(&payload) {
            // No whoami on the create path, ever: the create gate forces
            // created_by_me itself, and the padding classify against bug id
            // 0 decides nothing — caller identity is deliberately None so
            // the refused path keeps costing exactly one upstream request.
            let _ = self.assess(&key, &[0], None).await;
            tracing::info!(product = %p.product, "guard denied bug creation");
            note_refused(&ctx);
            return Ok(err_text(Guard::create_denial()));
        }
        if let Some(cell) = audit_cell(&ctx) {
            // may_create judges the request as a whole and names no rule.
            cell.note_verdict(Verdict::Served);
        }

        match self.bz.create_bug(&key, payload).await {
            Ok(v) => Ok(ok_json(v)),
            Err(e) => {
                // Uniform with the policy refusal above (see that comment);
                // Bugzilla's message is logged server-side only — it can say
                // whether a product or component exists.
                tracing::warn!(error = %e, "create_bug: upstream refused");
                Ok(err_text(Guard::create_denial()))
            }
        }
    }

    #[tool(
        description = "Attach a file to a bug. Content must be base64-encoded. Subject to server policy on the target bug and to the server's attachment size limit.",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = false,
            open_world_hint = true
        )
    )]
    async fn add_attachment(
        &self,
        Parameters(p): Parameters<AddAttachmentParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        tracing::info!(
            bug_id = p.bug_id,
            file_name = %p.file_name,
            is_private = p.is_private,
            "tool: add_attachment"
        );
        let key = self.api_key(&ctx)?;
        let caller = self.guard.resolve_caller(&self.bz, &key).await;
        if let Some(denied) = self
            .deny_unless(&key, p.bug_id, Capability::Attach, caller.as_deref(), &ctx)
            .await
        {
            return Ok(denied);
        }

        let cap = self.guard.policy.global.max_attachment_bytes;
        if let Some(refusal) = upload_size_refusal(cap, &p.data) {
            note_refused(&ctx);
            return Ok(err_text(refusal));
        }

        let mut payload = serde_json::Map::new();
        payload.insert("ids".to_string(), json!([p.bug_id]));
        payload.insert("data".to_string(), json!(p.data));
        payload.insert("file_name".to_string(), json!(p.file_name));
        payload.insert("summary".to_string(), json!(p.summary));
        payload.insert("content_type".to_string(), json!(p.content_type));
        payload.insert("is_patch".to_string(), json!(p.is_patch));
        payload.insert("is_private".to_string(), json!(p.is_private));
        // Bug.add_attachment takes `comment` as a PLAIN string — unlike
        // Bug.update's `{"comment": {"body": ...}}` shape, so the update
        // helper (attach_comment) must not be reused here.
        if !p.comment.is_empty() {
            payload.insert("comment".to_string(), json!(p.comment));
        }
        let payload = Value::Object(payload);

        match self.bz.add_attachment(&key, p.bug_id, payload).await {
            Ok(v) => Ok(ok_json(v)),
            Err(e) => {
                tracing::warn!(bug_id = p.bug_id, error = %e, "add_attachment: upstream refused");
                Ok(err_text("Failed to add attachment"))
            }
        }
    }

    #[tool(
        description = "Add a comment to a bug. It can optionally be private. If success, returns the created comment id.",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = false,
            open_world_hint = true
        )
    )]
    async fn add_comment(
        &self,
        Parameters(p): Parameters<AddCommentParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        tracing::info!(
            bug_id = p.bug_id,
            is_private = p.is_private,
            comment_len = p.comment.len(),
            "tool: add_comment"
        );
        let key = self.api_key(&ctx)?;
        let caller = self.guard.resolve_caller(&self.bz, &key).await;
        if let Some(denied) = self
            .deny_unless(&key, p.bug_id, Capability::Comment, caller.as_deref(), &ctx)
            .await
        {
            return Ok(denied);
        }
        match self
            .bz
            .add_comment(&key, p.bug_id, &p.comment, p.is_private)
            .await
        {
            Ok(result) => Ok(ok_json(result)),
            Err(e) => Ok(err_text(format!("Failed to create a comment\n{e}"))),
        }
    }

    #[tool(
        description = "Update the status of a bug. Optionally add a comment explaining the status change.\n\nValid statuses: NEW, ASSIGNED, MODIFIED, ON_QA, VERIFIED, CLOSED.\nFor CLOSED, you MUST also provide a resolution (FIXED, WONTFIX, NOTABUG, DUPLICATE, etc.)",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false,
            open_world_hint = true
        )
    )]
    async fn update_bug_status(
        &self,
        Parameters(p): Parameters<UpdateBugStatusParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        tracing::info!(
            bug_id = p.bug_id,
            status = %p.status,
            resolution = ?p.resolution,
            "tool: update_bug_status"
        );
        let has_resolution = p.resolution.as_deref().is_some_and(|r| !r.is_empty());
        if p.status == "CLOSED" && !has_resolution {
            note_refused(&ctx);
            return Ok(err_text(
                "Resolution is required when setting status to CLOSED (e.g., FIXED, WONTFIX, NOTABUG, DUPLICATE)",
            ));
        }
        let key = self.api_key(&ctx)?;
        let caller = self.guard.resolve_caller(&self.bz, &key).await;
        if let Some(denied) = self
            .deny_unless(&key, p.bug_id, Capability::Status, caller.as_deref(), &ctx)
            .await
        {
            return Ok(denied);
        }

        let mut payload = serde_json::Map::new();
        payload.insert("status".to_string(), json!(p.status));
        if has_resolution {
            payload.insert("resolution".to_string(), json!(p.resolution));
        } else if p.status != "CLOSED" && p.status != "VERIFIED" {
            // Clear resolution when reopening.
            payload.insert("resolution".to_string(), json!(""));
        }
        attach_comment(&mut payload, &p.comment);

        match self
            .bz
            .update_bug(&key, p.bug_id, Value::Object(payload))
            .await
        {
            Ok(result) => Ok(ok_json(result)),
            Err(e) => Ok(err_text(format!("Failed to update bug status\n{e}"))),
        }
    }

    #[tool(
        description = "Assign a bug to a user. Optionally add a comment.",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false,
            open_world_hint = true
        )
    )]
    async fn assign_bug(
        &self,
        Parameters(p): Parameters<AssignBugParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        tracing::info!(bug_id = p.bug_id, assignee = %p.assignee, "tool: assign_bug");
        let key = self.api_key(&ctx)?;
        let caller = self.guard.resolve_caller(&self.bz, &key).await;
        if let Some(denied) = self
            .deny_unless(&key, p.bug_id, Capability::Assign, caller.as_deref(), &ctx)
            .await
        {
            return Ok(denied);
        }
        let mut payload = serde_json::Map::new();
        payload.insert("assigned_to".to_string(), json!(p.assignee));
        attach_comment(&mut payload, &p.comment);
        match self
            .bz
            .update_bug(&key, p.bug_id, Value::Object(payload))
            .await
        {
            Ok(result) => Ok(ok_json(result)),
            Err(e) => Ok(err_text(format!("Failed to assign bug\n{e}"))),
        }
    }

    #[tool(
        description = "Update bug fields: priority, severity, resolution, summary, url, whiteboard, version, target_milestone, keywords (add/remove), see_also (add/remove; values are bug URLs), and custom 'cf_*' fields. All fields are optional, but at least one must be specified. Empty strings and empty lists are ignored; clearing a field is not supported. Custom field names must start with 'cf_' (e.g. {\"cf_fixed_in\": \"1.2.3\"}).",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false,
            open_world_hint = true
        )
    )]
    async fn update_bug_fields(
        &self,
        Parameters(p): Parameters<UpdateBugFieldsParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        // priority/severity/resolution are benign instance vocabulary and
        // stay value-logged; every other param is logged as presence or
        // count only — summaries, whiteboards and URLs can carry embargoed
        // content, and the server log must not become a content sink (the
        // audit stream's boundary rule, applied to tracing).
        tracing::info!(
            bug_id = p.bug_id,
            priority = ?p.priority,
            severity = ?p.severity,
            resolution = ?p.resolution,
            summary = p.summary.is_some(),
            url = p.url.is_some(),
            whiteboard = p.whiteboard.is_some(),
            version = p.version.is_some(),
            target_milestone = p.target_milestone.is_some(),
            keywords_add = p.keywords_add.as_ref().map_or(0, Vec::len),
            keywords_remove = p.keywords_remove.as_ref().map_or(0, Vec::len),
            see_also_add = p.see_also_add.as_ref().map_or(0, Vec::len),
            see_also_remove = p.see_also_remove.as_ref().map_or(0, Vec::len),
            custom_field_count = p.custom_fields.as_ref().map_or(0, |cf| cf.len()),
            "tool: update_bug_fields"
        );

        let mut payload = serde_json::Map::new();
        for (field, value) in [
            ("priority", &p.priority),
            ("severity", &p.severity),
            ("resolution", &p.resolution),
            ("summary", &p.summary),
            ("url", &p.url),
            ("whiteboard", &p.whiteboard),
            ("version", &p.version),
            ("target_milestone", &p.target_milestone),
        ] {
            if let Some(v) = value.as_deref().filter(|s| !s.is_empty()) {
                payload.insert(field.to_string(), json!(v));
            }
        }
        if let Some(keywords) = list_change(p.keywords_add.as_ref(), p.keywords_remove.as_ref()) {
            payload.insert("keywords".to_string(), keywords);
        }
        if let Some(see_also) = list_change(p.see_also_add.as_ref(), p.see_also_remove.as_ref()) {
            payload.insert("see_also".to_string(), see_also);
        }
        if let Some(custom_fields) = &p.custom_fields {
            // I7: only cf_* keys may pass through the generic updater. Error
            // without calling Bugzilla otherwise.
            for k in custom_fields.keys() {
                if !k.starts_with("cf_") {
                    note_refused(&ctx);
                    return Ok(err_text(format!(
                        "Invalid custom field '{k}': custom field names must start with 'cf_'"
                    )));
                }
            }
            for (k, v) in custom_fields {
                payload.insert(k.clone(), v.clone());
            }
        }
        if payload.is_empty() {
            note_refused(&ctx);
            return Ok(err_text("At least one field must be specified"));
        }
        attach_comment(&mut payload, &p.comment);

        // I8/I14: a see_also entry that points at THIS Bugzilla is a bug-id
        // link, so writing one is judged like the other link-writing paths
        // (update_bug_dependencies, mark_as_duplicate/I11): the bug being
        // updated needs `fields`, and every LOCAL see_also target must allow
        // at least `summary` before the PUT. Without this, a see_also change
        // would write links into policy-denied bugs — Bugzilla records the
        // reciprocal entry on the target — and leak their existence through
        // the difference between its success and "does not exist" responses
        // (I2). Entries for other trackers carry no local bug id and are
        // somebody else's to disclose; they pass through unassessed.
        let base_url = self.bz.base_url();
        let mut ids: Vec<u64> = vec![p.bug_id];
        for list in [&p.see_also_add, &p.see_also_remove].into_iter().flatten() {
            ids.extend(
                list.iter()
                    .filter_map(|entry| Guard::see_also_local_id(entry, base_url)),
            );
        }
        let mut seen = BTreeSet::new();
        ids.retain(|id| seen.insert(*id));
        if let Some(refusal) = too_many_ids(&ids) {
            note_refused(&ctx);
            return Ok(refusal);
        }

        let key = self.api_key(&ctx)?;
        let caller = self.guard.resolve_caller(&self.bz, &key).await;
        let cell = audit_cell(&ctx);
        let assessments = self.assess(&key, &ids, caller.as_deref()).await;
        let note = |id: u64, verdict: Verdict| {
            if let Some(cell) = &cell {
                match assessments.get(&id) {
                    Some((access, _)) => cell.note_verdict_rule(verdict, access_rule(access)),
                    None => cell.note_verdict(verdict),
                }
            }
        };
        let fields_ok = assessments
            .get(&p.bug_id)
            .is_some_and(|(access, _)| access.allows(Capability::Fields));
        if !fields_ok {
            tracing::info!(bug_id = p.bug_id, "guard denied operation");
            note(p.bug_id, Verdict::Denied);
            return Ok(err_text(Guard::denial(p.bug_id)));
        }
        for &id in ids.iter().filter(|&&id| id != p.bug_id) {
            let target_ok = assessments
                .get(&id)
                .is_some_and(|(access, _)| access.allows(Capability::Summary));
            if !target_ok {
                tracing::info!(bug_id = id, "guard denied see_also target");
                note(id, Verdict::Denied);
                return Ok(err_text(Guard::denial(id)));
            }
        }
        note(p.bug_id, Verdict::Served);

        match self
            .bz
            .update_bug(&key, p.bug_id, Value::Object(payload))
            .await
        {
            Ok(result) => Ok(ok_json(result)),
            Err(e) => Ok(err_text(format!("Failed to update bug fields\n{e}"))),
        }
    }

    #[tool(
        description = "Update bug dependency relationships (blocks/depends_on). At least one change must be specified. Optionally add a comment explaining the changes.",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false,
            open_world_hint = true
        )
    )]
    async fn update_bug_dependencies(
        &self,
        Parameters(p): Parameters<UpdateBugDependenciesParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        tracing::info!(
            bug_id = p.bug_id,
            blocks_add = ?p.blocks_add,
            blocks_remove = ?p.blocks_remove,
            depends_on_add = ?p.depends_on_add,
            depends_on_remove = ?p.depends_on_remove,
            "tool: update_bug_dependencies"
        );

        let mut payload = serde_json::Map::new();
        if let Some(blocks) = dep_change(p.blocks_add.as_ref(), p.blocks_remove.as_ref()) {
            payload.insert("blocks".to_string(), blocks);
        }
        if let Some(depends_on) =
            dep_change(p.depends_on_add.as_ref(), p.depends_on_remove.as_ref())
        {
            payload.insert("depends_on".to_string(), depends_on);
        }
        if payload.is_empty() {
            note_refused(&ctx);
            return Ok(err_text("At least one dependency change must be specified"));
        }
        attach_comment(&mut payload, &p.comment);

        // I8: every bug id in the payload — the bug being updated AND every
        // dependency target — must pass guard assessment before the PUT.
        // Without this, blocks/depends_on changes would write links into
        // policy-denied bugs and leak their existence through the difference
        // between Bugzilla's success and "does not exist" responses (I2).
        // Targets require at least `summary`, mirroring how I11 treats
        // `duplicate_of`.
        let mut ids: Vec<u64> = vec![p.bug_id];
        for list in [
            &p.blocks_add,
            &p.blocks_remove,
            &p.depends_on_add,
            &p.depends_on_remove,
        ]
        .into_iter()
        .flatten()
        {
            ids.extend(list.iter().copied());
        }
        let mut seen = BTreeSet::new();
        ids.retain(|id| seen.insert(*id));
        if let Some(refusal) = too_many_ids(&ids) {
            note_refused(&ctx);
            return Ok(refusal);
        }

        let key = self.api_key(&ctx)?;
        let caller = self.guard.resolve_caller(&self.bz, &key).await;
        let cell = audit_cell(&ctx);
        let assessments = self.assess(&key, &ids, caller.as_deref()).await;
        let note = |id: u64, verdict: Verdict| {
            if let Some(cell) = &cell {
                match assessments.get(&id) {
                    Some((access, _)) => cell.note_verdict_rule(verdict, access_rule(access)),
                    None => cell.note_verdict(verdict),
                }
            }
        };
        let deps_ok = assessments
            .get(&p.bug_id)
            .is_some_and(|(access, _)| access.allows(Capability::Deps));
        if !deps_ok {
            tracing::info!(bug_id = p.bug_id, "guard denied operation");
            note(p.bug_id, Verdict::Denied);
            return Ok(err_text(Guard::denial(p.bug_id)));
        }
        for &id in ids.iter().filter(|&&id| id != p.bug_id) {
            let target_ok = assessments
                .get(&id)
                .is_some_and(|(access, _)| access.allows(Capability::Summary));
            if !target_ok {
                tracing::info!(bug_id = id, "guard denied dependency target");
                note(id, Verdict::Denied);
                return Ok(err_text(Guard::denial(id)));
            }
        }
        note(p.bug_id, Verdict::Served);

        match self
            .bz
            .update_bug(&key, p.bug_id, Value::Object(payload))
            .await
        {
            Ok(result) => Ok(ok_json(result)),
            Err(e) => Ok(err_text(format!("Failed to update bug dependencies\n{e}"))),
        }
    }

    #[tool(
        description = "Add an email address to the CC list of a bug.",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn add_cc_to_bug(
        &self,
        Parameters(p): Parameters<AddCcParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        tracing::info!(bug_id = p.bug_id, cc_email = %p.cc_email, "tool: add_cc_to_bug");
        let key = self.api_key(&ctx)?;
        let caller = self.guard.resolve_caller(&self.bz, &key).await;
        if let Some(denied) = self
            .deny_unless(&key, p.bug_id, Capability::Cc, caller.as_deref(), &ctx)
            .await
        {
            return Ok(denied);
        }
        let payload = json!({ "cc": { "add": [p.cc_email] } });
        match self.bz.update_bug(&key, p.bug_id, payload).await {
            Ok(result) => Ok(ok_json(result)),
            Err(e) => Ok(err_text(format!("Failed to add CC\n{e}"))),
        }
    }

    #[tool(
        description = "Mark a bug as a duplicate of another bug and close it.",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false,
            open_world_hint = true
        )
    )]
    async fn mark_as_duplicate(
        &self,
        Parameters(p): Parameters<MarkAsDuplicateParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        tracing::info!(
            bug_id = p.bug_id,
            duplicate_of = p.duplicate_of,
            "tool: mark_as_duplicate"
        );
        let key = self.api_key(&ctx)?;

        // I11: `status` on bug_id AND at least `summary` on duplicate_of.
        let ids = if p.bug_id == p.duplicate_of {
            vec![p.bug_id]
        } else {
            vec![p.bug_id, p.duplicate_of]
        };
        let caller = self.guard.resolve_caller(&self.bz, &key).await;
        let cell = audit_cell(&ctx);
        let assessments = self.assess(&key, &ids, caller.as_deref()).await;
        let note = |id: u64, verdict: Verdict| {
            if let Some(cell) = &cell {
                match assessments.get(&id) {
                    Some((access, _)) => cell.note_verdict_rule(verdict, access_rule(access)),
                    None => cell.note_verdict(verdict),
                }
            }
        };
        let status_ok = assessments
            .get(&p.bug_id)
            .is_some_and(|(access, _)| access.allows(Capability::Status));
        if !status_ok {
            note(p.bug_id, Verdict::Denied);
            return Ok(err_text(Guard::denial(p.bug_id)));
        }
        let duplicate_ok = assessments
            .get(&p.duplicate_of)
            .is_some_and(|(access, _)| access.allows(Capability::Summary));
        if !duplicate_ok {
            note(p.duplicate_of, Verdict::Denied);
            return Ok(err_text(Guard::denial(p.duplicate_of)));
        }
        note(p.bug_id, Verdict::Served);

        let comment = if p.comment.is_empty() {
            format!("Marking as duplicate of bug {}", p.duplicate_of)
        } else {
            p.comment.clone()
        };
        let mut payload = serde_json::Map::new();
        payload.insert("status".to_string(), json!("CLOSED"));
        payload.insert("resolution".to_string(), json!("DUPLICATE"));
        payload.insert("dupe_of".to_string(), json!(p.duplicate_of));
        attach_comment(&mut payload, &comment);

        match self
            .bz
            .update_bug(&key, p.bug_id, Value::Object(payload))
            .await
        {
            Ok(result) => Ok(ok_json(result)),
            Err(e) => Ok(err_text(format!("Failed to mark as duplicate\n{e}"))),
        }
    }

    #[tool(
        description = "List the metadata of all attachments of a bug. Attachment data itself is excluded. Metadata of private attachments is not included by default but can be explicitly requested (subject to server policy).",
        annotations(read_only_hint = true, open_world_hint = true)
    )]
    async fn list_attachments(
        &self,
        Parameters(p): Parameters<ListAttachmentsParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        tracing::info!(
            bug_id = p.bug_id,
            include_private = p.include_private,
            "tool: list_attachments"
        );
        let key = self.api_key(&ctx)?;
        let caller = self.guard.resolve_caller(&self.bz, &key).await;
        if let Some(denied) = self
            .deny_unless(
                &key,
                p.bug_id,
                Capability::Attachments,
                caller.as_deref(),
                &ctx,
            )
            .await
        {
            return Ok(denied);
        }
        match self.bz.attachments(&key, p.bug_id).await {
            Ok(attachments) => {
                // Private attachment metadata is gated by the same double
                // opt-in as private comments (I5): the policy must allow it
                // AND the call must ask for it.
                let items = match attachments {
                    Value::Array(items) => items,
                    // Unexpected envelope shape: fail closed (I4) rather
                    // than passing unfiltered metadata through.
                    _ => Vec::new(),
                };
                let total = items.len();
                let filtered = self.guard.filter_attachments(items, p.include_private);
                if let Some(cell) = audit_cell(&ctx) {
                    // Filtered private attachments have no bug id of
                    // their own: count only.
                    cell.note_suppressed_count((total - filtered.len()) as u64);
                }
                Ok(ok_json(Value::Array(filtered)))
            }
            Err(e) => Ok(err_text(format!(
                "Failed to fetch bug attachments\nReason: {e}"
            ))),
        }
    }

    #[tool(
        description = "Download the content of a single attachment by its attachment id (see list_attachments). Raster images are returned as image content, everything else as a base64 blob resource. Subject to server policy: a size limit applies, and private attachments must be requested explicitly.",
        annotations(read_only_hint = true, open_world_hint = true)
    )]
    async fn download_attachment(
        &self,
        Parameters(p): Parameters<DownloadAttachmentParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        tracing::info!(
            attachment_id = p.attachment_id,
            include_private = p.include_private,
            "tool: download_attachment"
        );
        let key = self.api_key(&ctx)?;

        // Metadata first, never the blob: it names the owning bug for guard
        // assessment and feeds the private/size gates, all BEFORE any content
        // is pulled (I8). Every refusal on this path is the uniform
        // attachment denial (I2) — a fetch error, an unknown id, a denied
        // owning bug and a private attachment must be indistinguishable.
        let meta = match self.bz.attachment_meta(&key, p.attachment_id).await {
            Ok(Some(meta)) => Some(meta),
            Ok(None) => None,
            Err(e) => {
                tracing::debug!(
                    attachment_id = p.attachment_id,
                    error = %e,
                    "attachment metadata fetch failed"
                );
                None
            }
        };
        // Bug id 0 never exists, so the classification below is a pure
        // constant-cost stand-in when there is no metadata. Without it the
        // "no metadata" paths would issue one upstream request and the
        // "metadata found" paths two, letting a client time its calls to
        // learn which attachment ids exist — the very oracle the uniform
        // denial closes (I2).
        let assess_id = meta
            .as_ref()
            .and_then(|m| m.get("bug_id"))
            .and_then(Value::as_u64)
            .unwrap_or(0);
        // Resolved whatever `assess_id` turned out to be: the whoami count
        // is a function of the policy alone, never of what the metadata
        // fetch found (I2).
        let caller = self.guard.resolve_caller(&self.bz, &key).await;
        let assessments = self.assess(&key, &[assess_id], caller.as_deref()).await;
        let allowed = assessments
            .get(&assess_id)
            .is_some_and(|(access, _)| access.allows(Capability::Attachments));
        if let Some(cell) = audit_cell(&ctx) {
            // Every uniform-denial path below upgrades this to Denied;
            // the padding assessment against bug id 0 decides nothing,
            // so no rule is attached there.
            match assessments.get(&assess_id) {
                _ if assess_id == 0 => cell.note_verdict(Verdict::Denied),
                Some((access, _)) => cell.note_verdict_rule(
                    if allowed {
                        Verdict::Served
                    } else {
                        Verdict::Denied
                    },
                    access_rule(access),
                ),
                None => cell.note_verdict(Verdict::Denied),
            }
        }

        let Some(meta) = meta.filter(|_| allowed && assess_id != 0) else {
            // Missing metadata, missing bug id, or a denied owning bug: one
            // uniform denial. The bug-level denial text is deliberately NOT
            // reused — it would confirm which bug owns the attachment.
            return Ok(err_text(Guard::attachment_denial(p.attachment_id)));
        };
        // Withheld content after a granted assessment is still the guard
        // deciding: every refusal below upgrades the noted verdict to
        // Denied (the note changes no response byte).
        let note_denied = || {
            if let Some(cell) = audit_cell(&ctx) {
                cell.note_verdict(Verdict::Denied);
            }
        };
        if let Some(refusal) = self.guard.attachment_gate(&meta, p.include_private) {
            note_denied();
            return Ok(err_text(refusal));
        }

        let attachment = match self.bz.attachment_data(&key, p.attachment_id).await {
            Ok(Some(att)) => att,
            // A failed blob fetch gets the same uniform denial as an unknown
            // id: the upstream status and message would otherwise distinguish
            // the two and disclose server detail.
            Ok(None) => {
                note_denied();
                return Ok(err_text(Guard::attachment_denial(p.attachment_id)));
            }
            Err(e) => {
                tracing::debug!(
                    attachment_id = p.attachment_id,
                    error = %e,
                    "attachment data fetch failed"
                );
                note_denied();
                return Ok(err_text(Guard::attachment_denial(p.attachment_id)));
            }
        };
        // The gate ran on the metadata response; the bytes come from a second,
        // later request. Re-run it on what actually arrived and re-check the
        // owning bug, so an attachment that turns private (or moves to another
        // bug) between the two calls cannot be served.
        if attachment.get("bug_id").and_then(Value::as_u64) != Some(assess_id) {
            note_denied();
            return Ok(err_text(Guard::attachment_denial(p.attachment_id)));
        }
        if let Some(refusal) = self.guard.attachment_gate(&attachment, p.include_private) {
            note_denied();
            return Ok(err_text(refusal));
        }

        let Some(blob) = attachment
            .get("data")
            .and_then(Value::as_str)
            .map(str::to_owned)
        else {
            note_refused(&ctx);
            return Ok(err_text("Attachment has no data"));
        };
        // Defense in depth: the size gate trusted the upstream-REPORTED size;
        // re-check the payload itself so a wrong or lying `size` cannot
        // smuggle an oversized blob past the cap. The decoded length is
        // computed exactly (4 base64 chars per 3 bytes, minus the padding)
        // so the cap stays inclusive, matching the metadata gate.
        let cap = self.guard.policy.global.max_attachment_bytes;
        if cap > 0 && decoded_len(&blob) > cap {
            note_denied();
            return Ok(err_text(format!(
                "Attachment {} exceeds the size limit of this server",
                p.attachment_id
            )));
        }

        let mime = attachment
            .get("content_type")
            .and_then(Value::as_str)
            .unwrap_or("application/octet-stream")
            .to_string();
        let file_name = attachment
            .get("file_name")
            .and_then(Value::as_str)
            .unwrap_or("attachment")
            .to_string();
        let summary = json!({
            "id": p.attachment_id,
            "bug_id": assess_id,
            "file_name": file_name,
            "content_type": mime,
            "size": attachment.get("size").cloned().unwrap_or(Value::Null),
        });
        let content = if is_inline_image(&mime) {
            ContentBlock::image(blob, mime)
        } else {
            // The uri carries only the attachment id: `file_name` is chosen by
            // whoever uploaded the attachment and may contain `../`, control
            // characters, or query/fragment syntax. It is reported in the
            // summary block above, where it is inert.
            ContentBlock::resource(ResourceContents::BlobResourceContents {
                uri: format!("bugzilla://attachment/{}", p.attachment_id),
                mime_type: Some(mime),
                blob,
                meta: None,
            })
        };
        Ok(CallToolResult::success(vec![
            ContentBlock::text(serde_json::to_string_pretty(&summary).unwrap_or_default()),
            content,
        ]))
    }

    #[tool(
        description = "Returns the bug url",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    fn bug_url(&self, Parameters(p): Parameters<BugUrlParams>) -> Result<CallToolResult, McpError> {
        tracing::info!(bug_id = p.bug_id, "tool: bug_url");
        // I8 exception: computes a URL string locally, contacts nothing.
        let url = format!("{}/show_bug.cgi?id={}", self.bz.base_url(), p.bug_id);
        Ok(ok_json(json!({ "url": url })))
    }

    #[tool(
        description = "Returns comprehensive bugzilla server information (url, version, extensions, timezone, time, parameters).",
        annotations(read_only_hint = true, open_world_hint = true)
    )]
    async fn bugzilla_server_info(
        &self,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        tracing::info!("tool: bugzilla_server_info");
        let key = self.api_key(&ctx)?;
        match self.bz.server_info(&key).await {
            Ok(info) => Ok(ok_json(info)),
            Err(e) => Ok(err_text(format!(
                "Failed to fetch bugzilla server info\nReason: {e}"
            ))),
        }
    }

    #[tool(
        description = "Access the documentation of the bugzilla quicksearch syntax. LLM can learn using this tool. Response is in HTML. Note: through this server's bugs_quicksearch the status filter is prefixed to the query, so under any non-empty status (the default is ALL) a number in the query is content-matched as text; the syntax page's jump-to-bug-number shortcut applies only when status is empty and the query is nothing but numbers. Look up known bug ids with the bug_info tool.",
        annotations(read_only_hint = true, open_world_hint = true)
    )]
    async fn quicksearch_syntax(&self) -> Result<CallToolResult, McpError> {
        tracing::info!("tool: quicksearch_syntax");
        match self.bz.quicksearch_syntax_html().await {
            Ok(html) => Ok(CallToolResult::success(vec![ContentBlock::text(html)])),
            Err(e) => Ok(err_text(format!(
                "Failed to fetch quicksearch documentation: {e}"
            ))),
        }
    }

    #[tool(
        description = "Returns information about this MCP server instance (name, version, bugzilla server, transport) and a summary of the active guard policy.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    fn mcp_server_info(&self) -> Result<CallToolResult, McpError> {
        tracing::info!("tool: mcp_server_info");
        // I1: expose only rule count, default_action, min_bug_age_days,
        // read_only, and disabled tool names — never rule names or match
        // criteria.
        let policy = &self.guard.policy;
        Ok(ok_json(json!({
            // The same two constants the handshake sends, so a client
            // cannot be told one identity by `initialize` and another by
            // this tool.
            "name": SERVER_NAME,
            "version": SERVER_VERSION,
            "bugzilla_server": self.bz.base_url(),
            "transport": match self.cfg.transport {
                Transport::Http => "http",
                Transport::Stdio => "stdio",
            },
            "policy": {
                "rule_count": policy.rules.len(),
                "default_action": action_name(policy.default_action),
                "min_bug_age_days": policy.global.min_bug_age_days,
                "read_only": policy.global.read_only,
                "disabled_tools": policy.global.disabled_tools,
            },
        })))
    }

    #[tool(
        description = "Summarizes all the comments of a bug. Returns a prompt to be used for summarization.",
        annotations(read_only_hint = true, open_world_hint = true)
    )]
    async fn summarize_bug(
        &self,
        Parameters(p): Parameters<SummarizeBugParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        tracing::info!(id = p.id, "tool: summarize_bug");
        let key = self.api_key(&ctx)?;
        let caller = self.guard.resolve_caller(&self.bz, &key).await;
        if let Some(denied) = self
            .deny_unless(&key, p.id, Capability::Comments, caller.as_deref(), &ctx)
            .await
        {
            return Ok(denied);
        }
        let comments = match self.bz.bug_comments(&key, p.id, None).await {
            Ok(comments) => comments,
            Err(e) => {
                return Ok(err_text(format!("Summarize Comments Failed\nReason: {e}")));
            }
        };
        let total = comments.len();
        let comments = self.guard.filter_comments(comments, false);
        // Same scrub as bug_comments: otherwise a client that would be
        // scrubbed there just asks for a summary instead (I14).
        let named = Guard::duplicate_marker_ids(&comments);
        let disclosable = self
            .guard
            .disclosable(&self.bz, &key, &named, caller.as_deref())
            .await;
        if let Some(cell) = audit_cell(&ctx) {
            cell.note_suppressed_count((total - comments.len()) as u64);
            let hidden: Vec<u64> = named.difference(&disclosable).copied().collect();
            if !hidden.is_empty() {
                cell.note_suppressed(hidden);
            }
        }
        let comments = Guard::scrub_duplicate_markers(comments, &disclosable);
        let comments_json =
            serde_json::to_string_pretty(&comments).unwrap_or_else(|_| "[]".to_string());
        let prompt = format!(
            "You are an expert in summarizing bugzilla comments.\n\
             Rules to follow:\n\
             - Summary must be well structured & eye catching\n\
             - Mention usernames & dates wherever relevant.\n\
             - date field must be in human readable format\n\
             - Usernames must be bold italic (***username***) dates must be bold (**date**)\n\
             \n\
             Comments Data:\n\
             {comments_json}"
        );
        Ok(CallToolResult::success(vec![ContentBlock::text(prompt)]))
    }
}

// Hand-written handler impl. `call_tool`, `list_tools` and `get_tool` keep
// the exact semantics the `#[tool_handler]` macro would generate for them;
// hand-writing exists so `call_tool` can own the audit record and
// `initialize` the initialize record. Dispatch through `self.tool_router`
// is load-bearing: the instance router has the write tools / disabled
// tools removed (I13); the macro default, `Self::tool_router()`, would
// rebuild an unpruned router. `list_tools` is not audited: no event kind
// exists for a listing — deliberate for schema v1.
impl ServerHandler for BugWarden {
    async fn initialize(
        &self,
        request: InitializeRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<InitializeResult, McpError> {
        // The default handler's peer bookkeeping, replicated: the
        // handshake info is stored so later calls (and their audit
        // records) can read it back through `peer_info`.
        context.peer.set_peer_info(request.clone());
        // Negotiate before recording: the record names the revision the
        // session actually speaks, not the one the client asked for.
        // Echo a requested revision this build serves, keep the server
        // default otherwise — the same shape the SDK's own negotiation
        // has, tested against `SUPPORTED_PROTOCOL_VERSIONS` rather than
        // the wider set of revisions the SDK merely knows about.
        let mut info = self.get_info();
        if SUPPORTED_PROTOCOL_VERSIONS.contains(&request.protocol_version) {
            info.protocol_version = request.protocol_version.clone();
        } else {
            tracing::warn!(
                client_requested = %request.protocol_version,
                server_fallback = %info.protocol_version,
                "client requested unsupported protocol version; falling back to server default"
            );
        }
        if let Some(audit) = &self.audit {
            // Every session start is recorded, unconditionally — no
            // configuration knob: a stream that could omit session
            // starts could not anchor its tool records to a client.
            let event = audit::AuditEventKind::Initialize(audit::InitializeEvent {
                client: audit::ClientInfo {
                    name: Some(request.client_info.name.clone()),
                    version: Some(request.client_info.version.clone()),
                    principal: None,
                },
                protocol_version: Some(info.protocol_version.as_str().to_string()),
            });
            let session = self.session_info(&context, audit);
            if record_event(audit, event, session).await.is_err()
                && audit.fail_mode == FailMode::ClosedAll
            {
                // Only ClosedAll refuses the handshake: initialize is
                // neither a write nor a guard verdict, so the other two
                // modes proceed and let the gap marker account for the
                // loss.
                return Err(McpError::internal_error("audit unavailable", None));
            }
        }
        Ok(info)
    }

    /// The revisions this handler serves, narrowing the SDK's default of
    /// every revision it knows (see [`SUPPORTED_PROTOCOL_VERSIONS`]). The
    /// SDK consults this on the handshake, on the stateless request path
    /// and in `server/discover`, so the whole surface narrows with it.
    fn supported_protocol_versions(&self) -> Cow<'static, [ProtocolVersion]> {
        Cow::Borrowed(SUPPORTED_PROTOCOL_VERSIONS)
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        mut context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        let started = Instant::now();
        if skips_the_handshake(&context) {
            // Recorded before it is refused, like every other turned-away
            // call: a stream that went quiet for a whole request class
            // could not be read as a complete account. `client` is left
            // absent rather than carrying the placeholder identity the
            // handshake-free path synthesises — the record says the caller
            // is unknown, because it is.
            if let Some(audit) = self.audit.clone() {
                let event = audit::AuditEventKind::ToolCall(Box::new(audit::ToolCallEvent {
                    client: audit::ClientInfo {
                        name: None,
                        version: None,
                        principal: None,
                    },
                    trace: None,
                    request: audit::RequestInfo {
                        tool: request.name.to_string(),
                        id: Some(context.id.to_string()),
                        params: allowlisted(request.arguments.as_ref()),
                    },
                    guard: None,
                    upstream: None,
                    outcome: audit::OutcomeInfo {
                        class: audit::OutcomeClass::Error,
                        duration_ms: elapsed_ms(started),
                    },
                }));
                let session = self.session_info(&context, &audit);
                let _ = record_event(&audit, event, session).await;
            }
            return Err(handshake_required());
        }
        // Auditing off: byte-identical to the macro-generated dispatch.
        let Some(audit) = self.audit.clone() else {
            return self
                .tool_router
                .call(ToolCallContext::new(self, request, context))
                .await;
        };
        let tool = request.name.to_string();
        let session = self.session_info(&context, &audit);
        let client = client_of(&context);
        let request_id = Some(context.id.to_string());
        // Allowlist BEFORE dispatch: the record needs the params after
        // the router has consumed the request, and allowlisting first
        // avoids cloning free-text and blob values that would be reduced
        // to a byte length anyway.
        let params = allowlisted(request.arguments.as_ref());
        // Trace enrichment (issue #28), extracted BEFORE the router
        // consumes `request`. The rmcp trap: over every serialized
        // transport the wire `params._meta` (SEP-414) does NOT arrive in
        // `CallToolRequestParams.meta` — the SDK's custom `Request`
        // deserializer strips `_meta` out of the params before the
        // params struct sees it, parks it in the request extensions, and
        // the serve loop hands it to the handler as `context.meta`. The
        // params-struct field is populated only by in-process callers
        // that never serialize. Read both, params struct first, so the
        // value is found wherever the SDK put it. Strictly validated,
        // fail-to-absent, never logged; the value enriches the record
        // only — it must never influence the guard, the refusal
        // decision, or the response (I15).
        let trace = request
            .meta
            .as_ref()
            .and_then(|m| m.get_traceparent())
            .or_else(|| context.meta.get_traceparent())
            .and_then(audit::TraceContext::from_traceparent);

        // Pre-dispatch gate: a sink already in failure holds back further
        // unaudited work, scoped by the fail mode. The refusal is
        // recorded best-effort — succeed or not, the call is refused:
        // the gate exists to stop unaudited work, not to retry its way
        // open. The refusal depends on the tool name alone, never on
        // anything the guard decided (the guard never ran).
        if audit.sink.failing() && gate_applies(audit.fail_mode, &tool) {
            let event = audit::AuditEventKind::ToolCall(Box::new(audit::ToolCallEvent {
                client,
                trace: trace.clone(),
                request: audit::RequestInfo {
                    tool: tool.clone(),
                    id: request_id,
                    params,
                },
                guard: Some(audit::GuardInfo {
                    verdict: Verdict::Refused,
                    rule: None,
                    policy_hash: audit.policy_hash.clone(),
                    suppressed_count: 0,
                    suppressed_ids: Vec::new(),
                    redacted_fields: Vec::new(),
                    // The guard never ran, so no window scan did either.
                    scan: None,
                }),
                upstream: None,
                outcome: audit::OutcomeInfo {
                    class: audit::OutcomeClass::Refused,
                    duration_ms: elapsed_ms(started),
                },
            }));
            let _ = record_event(&audit, event, session).await;
            return Ok(audit_refusal(&tool).into());
        }

        let cell = Arc::new(AuditCell::default());
        context.extensions.insert(Arc::clone(&cell));
        let result = self
            .tool_router
            .call(ToolCallContext::new(self, request, context))
            .await;

        // Exactly one record per call, whatever `result` is — including
        // an unknown tool or another protocol error from the router.
        let upstream = cell.take_upstream();
        let guard = cell.into_guard_info(audit.policy_hash.as_deref(), audit.sink.suppressed_ids());
        let guard_verdict = guard.as_ref().map(|g| g.verdict);
        let class = match &result {
            // A guard denial is a well-formed response (the uniform
            // denial text): its `is_error` marker classifies the
            // content, not the call, so the outcome stays `ok` and the
            // denial lives in guard.verdict. Only a completed call
            // carries that marker; the other `CallToolResponse` variants
            // belong to revisions this build does not serve.
            Ok(CallToolResponse::Complete(r))
                if r.is_error == Some(true) && guard_verdict != Some(Verdict::Denied) =>
            {
                audit::OutcomeClass::Refused
            }
            Ok(_) => audit::OutcomeClass::Ok,
            Err(_) => audit::OutcomeClass::Error,
        };
        let event = audit::AuditEventKind::ToolCall(Box::new(audit::ToolCallEvent {
            client,
            trace,
            request: audit::RequestInfo {
                tool: tool.clone(),
                id: request_id,
                params,
            },
            guard,
            upstream,
            outcome: audit::OutcomeInfo {
                class,
                duration_ms: elapsed_ms(started),
            },
        }));
        match record_event(&audit, event, session).await {
            // Persisted before the response is returned.
            Ok(_) => result,
            Err(()) => match (audit.fail_mode, &result) {
                // A protocol error from the router stands under every
                // mode: the record was attempted, an unknown tool is
                // unknown with or without auditing, and swapping the
                // error for a tool-level refusal would CREATE a
                // distinguisher that exists only during an audit outage.
                (_, Err(_)) => result,
                // The sink has rate-limit-logged the failure; the gap
                // marker accounts for the loss after recovery.
                (FailMode::Open, _) => result,
                (FailMode::ClosedWritesDenials, _)
                    if WRITE_TOOLS.contains(&tool.as_str())
                        || matches!(
                            guard_verdict,
                            Some(Verdict::Denied | Verdict::Refused | Verdict::ServedFiltered)
                        ) =>
                {
                    Ok(audit_refusal(&tool).into())
                }
                // A read the guard fully allowed serves unaudited.
                (FailMode::ClosedWritesDenials, _) => result,
                (FailMode::ClosedAll, _) => Ok(audit_refusal(&tool).into()),
            },
        }
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        // Refused on the same terms as a tool call: the listing is pruned
        // per deployment (I13), so serving it to a handshake-free caller
        // would disclose which tools this policy removed. Unrecorded, as
        // every listing is — schema v1 has no event kind for one.
        if skips_the_handshake(&context) {
            return Err(handshake_required());
        }
        Ok(ListToolsResult {
            tools: self.tool_router.list_all(),
            result_type: Some(ResultType::COMPLETE),
            meta: None,
            next_cursor: None,
            // The 2026-07-28 cache hints stay absent, exactly as they
            // were before this SDK had the fields: no revision this
            // build serves defines them, and emitting them anyway would
            // add fields to responses no peer asked for. When the
            // revision is adopted, `cache_scope` is `Private` — the
            // listing is pruned per deployment by policy and by
            // read-only mode (I13), so a shared cache must never serve
            // one deployment's list to another. `CacheScope::default()`
            // is `Public`; this field is always written by name.
            ttl_ms: None,
            cache_scope: None,
        })
    }

    fn get_tool(&self, name: &str) -> Option<Tool> {
        self.tool_router.get(name).cloned()
    }

    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_protocol_version(DEFAULT_PROTOCOL_VERSION)
            .with_server_info(server_identity())
            .with_instructions(
                "MCP server for Bugzilla. Provides tools to search bugs \
                 (bugs_quicksearch), read bug details, comments, history, and \
                 attachment metadata, and — unless running read-only — update \
                 bugs (comments, status, fields, assignee, CC, dependencies, \
                 duplicates). Access is governed by an operator-controlled \
                 policy: some bugs may be unavailable or redacted to a summary \
                 view (marked with '_redacted'), and some operations may be \
                 refused. A reply that a bug 'is not accessible through this \
                 server' is final; it does not indicate whether the bug \
                 exists, and retrying will not help."
                    .to_string(),
            )
    }
}

#[cfg(test)]
mod tests {

    /// Policy denying anything in an embargo group, allowing the rest.
    fn embargo_guard() -> Guard {
        Guard {
            policy: Policy::from_toml_str(concat!(
                "default_action = \"allow\"\n",
                "[[rule]]\nname = \"embargo\"\naction = \"deny\"\n",
                "[rule.match]\ngroups = [\"embargo*\"]\n",
            ))
            .expect("policy parses"),
        }
    }

    fn granted(caps: &[Capability]) -> Access {
        Access::Granted {
            caps: caps.iter().copied().collect(),
            rule: "test".into(),
        }
    }

    fn body(id: u64, groups: &[&str]) -> Value {
        json!({
            "id": id,
            "summary": "a bug",
            "groups": groups,
            "product": "P",
            "component": "C",
            "status": "NEW",
            "creation_time": "2020-01-01T00:00:00Z",
            "depends_on": [1, 2],
        })
    }

    #[test]
    fn bug_info_serves_a_body_that_still_passes() {
        let g = embargo_guard();
        let assessments = BTreeMap::from([(7u64, (granted(&[Capability::Read]), Value::Null))]);
        let full = BTreeMap::from([(7u64, body(7, &[]))]);

        let out = assemble_bug_info(&g, &[7], &assessments, &full, None);
        assert_eq!(out["bugs"].as_array().unwrap().len(), 1);
        assert_eq!(out["bugs"][0]["id"], json!(7));
        // The full body is served intact, not a redacted view.
        assert_eq!(out["bugs"][0]["depends_on"], json!([1, 2]));
        assert!(out["restricted"].as_array().unwrap().is_empty());
    }

    #[test]
    fn bug_info_refuses_a_body_embargoed_after_the_verdict() {
        // The race the re-check exists for: classification said Read, then the
        // bug was moved into an embargo group before the body was fetched.
        // The server's key is privileged enough that Bugzilla still returns
        // it, so only the re-check can catch this.
        let g = embargo_guard();
        let assessments = BTreeMap::from([(7u64, (granted(&[Capability::Read]), Value::Null))]);
        let full = BTreeMap::from([(7u64, body(7, &["embargo-security"]))]);

        let out = assemble_bug_info(&g, &[7], &assessments, &full, None);
        assert!(
            out["bugs"].as_array().unwrap().is_empty(),
            "a body that no longer passes must not be served"
        );
        assert_eq!(out["restricted"][0]["id"], json!(7));
        assert_eq!(out["restricted"][0]["note"], json!(Guard::denial(7)));
    }

    #[test]
    fn bug_info_denial_is_identical_for_hidden_missing_and_nonexistent() {
        // I2: whichever way a bug fails to be served, the client sees the
        // same bytes. Here: re-check refusal, body absent from the response
        // (fetch failure or upstream omission), and a policy denial.
        let g = embargo_guard();
        let assessments = BTreeMap::from([
            (1u64, (granted(&[Capability::Read]), Value::Null)),
            (2u64, (granted(&[Capability::Read]), Value::Null)),
            (
                3u64,
                (
                    Access::Denied {
                        rule: "embargo".into(),
                    },
                    Value::Null,
                ),
            ),
        ]);
        // 1 turns out embargoed, 2 never arrived, 3 was denied up front.
        let full = BTreeMap::from([(1u64, body(1, &["embargo-x"]))]);

        let out = assemble_bug_info(&g, &[1, 2, 3], &assessments, &full, None);
        assert!(out["bugs"].as_array().unwrap().is_empty());
        let entries = out["restricted"].as_array().unwrap();
        assert_eq!(entries.len(), 3);
        for (entry, id) in entries.iter().zip([1u64, 2, 3]) {
            assert_eq!(entry["id"], json!(id));
            assert_eq!(
                entry["note"],
                json!(Guard::denial(id)),
                "every failure mode yields the same note"
            );
            assert_eq!(
                entry.as_object().unwrap().len(),
                2,
                "no extra field distinguishes the cases"
            );
        }
    }

    #[test]
    fn bug_info_downgrades_to_a_summary_view_when_the_body_only_earns_summary() {
        // A body that now classifies summary-only is served as the summary
        // view a fresh call would return — not refused, not served in full.
        let g = Guard {
            policy: Policy::from_toml_str(concat!(
                "default_action = \"allow\"\n",
                "[[rule]]\nname = \"peek\"\naction = \"restrict\"\n",
                "capabilities = [\"summary\"]\n",
                "[rule.match]\ngroups = [\"internal\"]\n",
            ))
            .expect("policy parses"),
        };
        let assessments = BTreeMap::from([(9u64, (granted(&[Capability::Read]), Value::Null))]);
        let full = BTreeMap::from([(9u64, body(9, &["internal"]))]);

        let out = assemble_bug_info(&g, &[9], &assessments, &full, None);
        let served = &out["bugs"][0];
        assert_eq!(served["_redacted"], json!(true), "served redacted");
        assert!(
            served.get("depends_on").is_none(),
            "the full body must not survive a downgrade: {served}"
        );
    }

    #[test]
    fn bug_info_refuses_a_body_that_now_grants_neither_read_nor_summary() {
        // The third outcome of the re-check: a body that still classifies,
        // but to a grant that conveys no way to view it at all.
        let g = Guard {
            policy: Policy::from_toml_str(concat!(
                "default_action = \"allow\"\n",
                "[[rule]]\nname = \"comments-only\"\naction = \"restrict\"\n",
                "capabilities = [\"comments\"]\n",
                "[rule.match]\ngroups = [\"internal\"]\n",
            ))
            .expect("policy parses"),
        };
        let assessments = BTreeMap::from([(3u64, (granted(&[Capability::Read]), Value::Null))]);
        let full = BTreeMap::from([(3u64, body(3, &["internal"]))]);

        let out = assemble_bug_info(&g, &[3], &assessments, &full, None);
        assert!(out["bugs"].as_array().unwrap().is_empty());
        assert_eq!(out["restricted"][0]["note"], json!(Guard::denial(3)));
    }

    #[test]
    fn bug_info_mixes_served_and_restricted_in_request_order() {
        // A realistic call: one body survives the re-check, one does not, one
        // was denied up front. Order follows the request, and every id is
        // accounted for exactly once.
        let g = embargo_guard();
        let assessments = BTreeMap::from([
            (5u64, (granted(&[Capability::Read]), Value::Null)),
            (6u64, (granted(&[Capability::Read]), Value::Null)),
            (
                8u64,
                (
                    Access::Denied {
                        rule: "embargo".into(),
                    },
                    Value::Null,
                ),
            ),
        ]);
        let full = BTreeMap::from([(5u64, body(5, &[])), (6u64, body(6, &["embargo-late"]))]);

        let out = assemble_bug_info(&g, &[5, 6, 8], &assessments, &full, None);
        assert_eq!(out["bugs"].as_array().unwrap().len(), 1);
        assert_eq!(out["bugs"][0]["id"], json!(5));
        let restricted = out["restricted"].as_array().unwrap();
        assert_eq!(
            restricted
                .iter()
                .map(|r| r["id"].as_u64().unwrap())
                .collect::<Vec<_>>(),
            vec![6, 8],
            "restricted follows request order"
        );
    }

    #[test]
    fn bug_info_summary_grants_are_served_from_the_classified_object() {
        // Summary-only grants never involve the second fetch, so there is no
        // window to re-check: the object the verdict was made on is served.
        let g = embargo_guard();
        let meta = body(4, &[]);
        let assessments = BTreeMap::from([(4u64, (granted(&[Capability::Summary]), meta.clone()))]);

        let out = assemble_bug_info(&g, &[4], &assessments, &BTreeMap::new(), None);
        assert_eq!(out["bugs"][0]["id"], json!(4));
        assert_eq!(out["bugs"][0]["_redacted"], json!(true));
    }

    #[test]
    fn id_cap_counts_distinct_ids_and_reads_only_the_request() {
        // The refusal must depend on how many DISTINCT bugs were named and on
        // nothing else — never on which bugs they are (I1/I2).
        let at_cap: Vec<u64> = (1..=Guard::MAX_ASSESS_IDS as u64).collect();
        assert!(
            too_many_ids(&at_cap).is_none(),
            "exactly the bound is allowed"
        );

        let over: Vec<u64> = (1..=Guard::MAX_ASSESS_IDS as u64 + 1).collect();
        let refusal = too_many_ids(&over).expect("over the bound must be refused");
        let text = format!("{:?}", refusal.content);
        assert!(
            text.contains(&Guard::MAX_ASSESS_IDS.to_string()),
            "refusal states the limit: {text}"
        );

        // Repeats cost one fetch, so they must not count towards the bound.
        let repeated = vec![7u64; Guard::MAX_ASSESS_IDS * 4];
        assert!(
            too_many_ids(&repeated).is_none(),
            "naming one bug many times is one bug"
        );
        assert!(too_many_ids(&[]).is_none());
    }

    #[test]
    fn id_list_advisory_fires_on_pure_id_lists_only() {
        // Pure id lists: commas and/or whitespace, optional '#' per id.
        assert!(id_list_advisory("123456", "ALL").is_some());
        assert!(id_list_advisory("#123456", "ALL").is_some());
        assert!(id_list_advisory("111, 222,333", "ALL").is_some());
        assert!(id_list_advisory("#111 #222\t333,", "ALL").is_some());

        // Anything else is a content search and gets no note.
        assert!(id_list_advisory("", "ALL").is_none());
        assert!(id_list_advisory("  ,\t", "ALL").is_none());
        assert!(id_list_advisory("#", "ALL").is_none());
        assert!(id_list_advisory("kernel crash 123", "ALL").is_none());
        assert!(id_list_advisory("123x", "ALL").is_none());
        assert!(id_list_advisory("product:openSUSE 42", "ALL").is_none());
    }

    #[test]
    fn id_list_advisory_wording_tracks_status_and_id_count() {
        // Non-empty status: the tool prefixes it, upstream content-matches.
        let prefixed = id_list_advisory("101, 102", "ALL").expect("note");
        assert!(prefixed.contains("matches bug text"), "{prefixed}");
        assert!(!prefixed.contains("id lookup"), "{prefixed}");

        // Empty status: the query goes upstream bare, where an all-number
        // query is an exact id lookup — no content-matching claim there.
        let bare = id_list_advisory("101, 102", "").expect("note");
        assert!(bare.contains("exact id lookup"), "{bare}");
        assert!(!bare.contains("matches bug text"), "{bare}");
        assert!(bare.contains("bug_info"), "{bare}");

        // Over bug_info's per-call cap the steering mentions batching
        // instead of walking the client into the too_many_ids refusal; the
        // cap value is already public in that refusal's own text.
        let over: Vec<String> = (1..=Guard::MAX_ASSESS_IDS as u64 + 1)
            .map(|i| i.to_string())
            .collect();
        let long = id_list_advisory(&over.join(" "), "ALL").expect("note");
        assert!(
            long.contains(&format!("at most {} ids", Guard::MAX_ASSESS_IDS)),
            "{long}"
        );
        assert!(long.contains("batch"), "{long}");

        // At the cap — and for repeated spellings of one id — no batching
        // talk: the count is of distinct ids, like the refusal it averts.
        let at_cap: Vec<String> = (1..=Guard::MAX_ASSESS_IDS as u64)
            .map(|i| i.to_string())
            .collect();
        let short = id_list_advisory(&at_cap.join(" "), "ALL").expect("note");
        assert!(!short.contains("batch"), "{short}");
        let repeats = id_list_advisory(&"7 07 #7 ".repeat(30), "ALL").expect("note");
        assert!(!repeats.contains("batch"), "{repeats}");
    }
    use super::*;
    use bugwarden_core::policy::Policy;

    fn parts(policy: &str) -> (Arc<Cli>, Arc<Guard>, Arc<BugzillaClient>) {
        use clap::Parser as _;
        let mut cli = Cli::parse_from([
            "bugwarden",
            "--bugzilla-server",
            "https://bugzilla.example.com",
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
        let bz = Arc::new(
            BugzillaClient::new("https://bugzilla.example.com", false).expect("client must build"),
        );
        (cfg, guard, bz)
    }

    #[test]
    fn new_rejects_unknown_disabled_tool() {
        // A typo in disabled_tools must be a hard startup error, never a
        // silent fail-open leaving the tool exposed.
        let (cfg, guard, bz) = parts("[global]\ndisabled_tools = [\"no_such_tool\"]\n");
        let err = match BugWarden::new(cfg, guard, bz) {
            Err(e) => e,
            Ok(_) => panic!("unknown disabled tool must be a startup error"),
        };
        let msg = format!("{err:#}");
        assert!(msg.contains("no_such_tool"), "unexpected error: {msg}");
        assert!(msg.contains("unknown tool"), "unexpected error: {msg}");
    }

    #[test]
    fn new_fails_at_construction_for_stdio_without_a_key() {
        // Key custody is resolved by BugWarden::new on every construction
        // path: stdio without any key source must fail at startup, never at
        // the first request. main.rs no longer duplicates this bail.
        use clap::Parser as _;
        let mut cli = Cli::parse_from([
            "bugwarden",
            "--bugzilla-server",
            "https://bugzilla.example.com",
            "--transport",
            "stdio",
        ]);
        // The ambient environment must not decide this test.
        cli.api_key = None;
        cli.api_key_file = None;
        let guard = Arc::new(Guard {
            policy: Policy::from_toml_str("").expect("empty policy parses"),
        });
        let bz = Arc::new(
            BugzillaClient::new("https://bugzilla.example.com", false).expect("client must build"),
        );
        let err = match BugWarden::new(Arc::new(cli), guard, bz) {
            Err(e) => e,
            Ok(_) => panic!("stdio without a key must fail at construction"),
        };
        let msg = format!("{err:#}");
        assert!(msg.contains("--transport stdio requires"), "{msg}");
    }

    #[test]
    fn server_held_custody_with_identity_policy_warns_at_startup() {
        // Under server-held http custody every client whoamis as the service
        // account that owns the key, so a created_by_me policy written for
        // per-request custody silently changes meaning — construction must
        // say so. A policy that never consults identity stays quiet.
        use clap::Parser as _;
        use std::io::Write as _;
        let mut file = tempfile::NamedTempFile::new().expect("temp key file");
        file.write_all(b"srv-key\n").expect("write key file");
        let identity_policy = concat!(
            "[[rule]]\nname = \"own-reports\"\naction = \"allow\"\n",
            "[rule.match]\ncreated_by_me = true\n",
        );
        for (policy, expect_warn) in [(identity_policy, true), ("", false)] {
            let mut cli = Cli::parse_from([
                "bugwarden",
                "--bugzilla-server",
                "https://bugzilla.example.com",
                "--transport",
                "http",
            ]);
            cli.api_key = None;
            cli.api_key_file = Some(file.path().to_path_buf());
            let guard = Arc::new(Guard {
                policy: Policy::from_toml_str(policy).expect("test policy must parse"),
            });
            let bz = Arc::new(
                BugzillaClient::new("https://bugzilla.example.com", false)
                    .expect("client must build"),
            );
            let (server, logs) =
                crate::testlog::capture_logs(|| BugWarden::new(Arc::new(cli), guard, bz));
            drop(server.expect("server must build"));
            assert_eq!(
                logs.contains("created_by_me describes that one account"),
                expect_warn,
                "startup logs: {logs}"
            );
        }
    }

    #[test]
    fn advertised_protocol_versions_are_the_ones_this_build_serves() {
        let (cfg, guard, bz) = parts("");
        let server = BugWarden::new(cfg, guard, bz).expect("server must build");
        assert_eq!(
            server.supported_protocol_versions().as_ref(),
            SUPPORTED_PROTOCOL_VERSIONS,
            "the handler must advertise this build's list, never inherit the SDK's"
        );
        assert!(
            !SUPPORTED_PROTOCOL_VERSIONS.contains(&ProtocolVersion::V_2026_07_28),
            "2026-07-28 requests carry no handshake, so their records could not \
             name the calling client (issue #34)"
        );
        assert!(
            SUPPORTED_PROTOCOL_VERSIONS.contains(&DEFAULT_PROTOCOL_VERSION),
            "the negotiation fallback must itself be a revision this build serves"
        );
        assert_eq!(
            server.get_info().protocol_version,
            DEFAULT_PROTOCOL_VERSION,
            "the advertised default is pinned here, not taken from the SDK's LATEST"
        );
        for version in SUPPORTED_PROTOCOL_VERSIONS {
            assert!(
                ProtocolVersion::KNOWN_VERSIONS.contains(version),
                "the SDK cannot serve {version}, which this build advertises"
            );
        }
    }

    #[test]
    fn new_removes_valid_disabled_tool_i13() {
        let (cfg, guard, bz) = parts("[global]\ndisabled_tools = [\"update_bug_dependencies\"]\n");
        let server = BugWarden::new(cfg, guard, bz).expect("valid tool name must be accepted");
        assert!(!server.tool_router.has_route("update_bug_dependencies"));
        assert!(server.tool_router.has_route("bug_info"));
    }

    #[test]
    fn new_read_only_removes_write_tools_and_accepts_disabled_write_tool() {
        // A write-tool name stays a valid disabled_tools entry even though
        // read-only mode removes its route first (validation runs against the
        // full router).
        let (cfg, guard, bz) =
            parts("[global]\nread_only = true\ndisabled_tools = [\"add_comment\"]\n");
        let server = BugWarden::new(cfg, guard, bz).expect("write tool name must stay valid");
        for name in WRITE_TOOLS {
            assert!(
                !server.tool_router.has_route(name),
                "write tool {name} must be removed in read-only mode (I13)"
            );
        }
        assert!(server.tool_router.has_route("bug_info"));
    }

    #[test]
    fn read_only_delists_create_bug_and_add_attachment_i13() {
        // The filing tools are writes: read-only mode must remove them from
        // the LISTING — call-time capability stripping alone is not I13.
        let (cfg, guard, bz) = parts("[global]\nread_only = true\n");
        let server = BugWarden::new(cfg, guard, bz).expect("server builds");
        assert!(!server.tool_router.has_route("create_bug"));
        assert!(!server.tool_router.has_route("add_attachment"));
        // A default build serves both.
        let (cfg, guard, bz) = parts("");
        let server = BugWarden::new(cfg, guard, bz).expect("server builds");
        assert!(server.tool_router.has_route("create_bug"));
        assert!(server.tool_router.has_route("add_attachment"));
    }

    #[test]
    fn get_tool_serves_the_pruned_instance_router_i13() {
        // The definition lookup must consult the INSTANCE router `new`
        // pruned, not a freshly built default one: a stripped tool has no
        // definition to serve, exactly as it has no route to call.
        let (cfg, guard, bz) =
            parts("[global]\nread_only = true\ndisabled_tools = [\"bug_history\"]\n");
        let server = BugWarden::new(cfg, guard, bz).expect("server builds");
        assert!(
            server.get_tool("add_comment").is_none(),
            "a write tool stripped by read-only mode has no definition (I13)"
        );
        assert!(
            server.get_tool("bug_history").is_none(),
            "a policy-disabled tool has no definition (I13)"
        );
        assert!(
            server.get_tool("bug_info").is_some(),
            "a live tool keeps its definition"
        );
    }

    #[test]
    fn decoded_len_counts_decoded_bytes_exactly() {
        assert_eq!(decoded_len(""), 0);
        assert_eq!(decoded_len("YQ=="), 1); // "a"
        assert_eq!(decoded_len("YWI="), 2); // "ab"
        assert_eq!(decoded_len("YWJj"), 3); // "abc"
        assert_eq!(decoded_len("YWJjZA"), 4); // "abcd", unpadded tail
        assert_eq!(decoded_len("YWJj\nZGVm"), 6); // wrapped lines do not inflate
    }

    #[test]
    fn upload_size_cap_measures_decoded_not_encoded_bytes() {
        // 100 decoded bytes encode to 136 base64 chars: the cap must judge
        // the former, or encoding overhead would shrink every operator cap
        // by a third.
        let data = "AAAA".repeat(33) + "AA==";
        assert_eq!(data.len(), 136);
        assert_eq!(decoded_len(&data), 100);
        assert!(
            upload_size_refusal(100, &data).is_none(),
            "136 encoded chars must not count against a 100-byte cap"
        );
        assert!(upload_size_refusal(99, &data).is_some());
    }

    #[test]
    fn upload_size_cap_zero_disables_and_refusal_names_no_number() {
        let data = "AAAA".repeat(33) + "AA==";
        assert!(upload_size_refusal(0, &data).is_none(), "0 removes the cap");
        // The refusal must not disclose the configured cap or the payload's
        // size — max_attachment_bytes is not I1-disclosable.
        let refusal = upload_size_refusal(99, &data).expect("over the cap");
        assert!(
            !refusal.contains(|c: char| c.is_ascii_digit()),
            "refusal leaks a number: {refusal}"
        );
    }

    #[test]
    fn inline_image_allowlist_excludes_svg_and_unknown_types() {
        assert!(is_inline_image("image/png"));
        assert!(is_inline_image("IMAGE/PNG"));
        assert!(is_inline_image("image/jpeg; charset=binary"));
        // Script-bearing or unverified media types must travel as blobs.
        assert!(!is_inline_image("image/svg+xml"));
        assert!(!is_inline_image("image/svg+xml; charset=utf-8"));
        assert!(!is_inline_image("text/html"));
        assert!(!is_inline_image("application/octet-stream"));
        assert!(!is_inline_image("image/"));
        assert!(!is_inline_image("imagexpng"));
    }

    // ---------- audit wiring ----------

    #[test]
    fn audit_refusal_map_covers_every_tool_in_the_full_router() {
        // Iterated over the FULL (unpruned) router on purpose: a new tool
        // must get its uniform refusal text before it can ship, or an
        // audit outage would answer it with the generic fallback — a
        // brand-new fingerprint.
        let tools = BugWarden::tool_router().list_all();
        assert!(!tools.is_empty(), "the full router lists the tool surface");
        for tool in tools {
            assert!(
                audit_refusal_text(&tool.name).is_some(),
                "tool {} has no audit refusal mapping — add its uniform \
                 failure text to audit_refusal_text",
                tool.name
            );
        }
        assert_eq!(
            audit_refusal_text("no_such_tool"),
            None,
            "unknown names take the generic fallback"
        );
    }

    #[test]
    fn allowlist_reduces_free_text_to_length_only() {
        let args = json!({
            "bug_id": 7,
            "is_private": true,
            "comment": "definitely secret text",
            "custom_fields": { "cf_fixed_in": "also withheld" },
        });
        let Value::Object(obj) = args else {
            unreachable!()
        };
        let params = allowlisted(Some(&obj));
        assert_eq!(params["bug_id"], json!(7));
        assert_eq!(params["is_private"], json!(true));
        let comment_len = serde_json::to_vec(&json!("definitely secret text"))
            .unwrap()
            .len();
        assert_eq!(params["comment"], json!({ "_len": comment_len }));
        let flat = serde_json::to_string(&params).unwrap();
        assert!(!flat.contains("secret"), "free text leaked: {flat}");
        assert!(!flat.contains("withheld"), "custom field leaked: {flat}");
    }

    #[test]
    fn allowlist_truncates_long_strings_at_1024_chars() {
        let obj: JsonObject = serde_json::from_value(json!({ "query": "q".repeat(5000) })).unwrap();
        let params = allowlisted(Some(&obj));
        assert_eq!(params["query"].as_str().unwrap().chars().count(), 1024);
        // Strings inside allowlisted lists are capped the same way.
        let obj: JsonObject =
            serde_json::from_value(json!({ "keywords": ["k".repeat(2000)] })).unwrap();
        let params = allowlisted(Some(&obj));
        assert_eq!(params["keywords"][0].as_str().unwrap().len(), 1024);
        // A short value is passed through untouched.
        let obj: JsonObject = serde_json::from_value(json!({ "query": "kernel" })).unwrap();
        assert_eq!(allowlisted(Some(&obj))["query"], json!("kernel"));
    }

    // The fail-mode scope tests below drive a REAL sink into failure via
    // its cfg(test) injection hook, which integration tests cannot reach;
    // everything else is the production path: a real MCP session over an
    // in-memory duplex transport against a wiremock Bugzilla.

    use crate::audit::{AuditConfig, AuditEvent, AuditEventKind, AuditSink};
    use rmcp::service::{RoleClient, RunningService};
    use rmcp::ServiceExt as _;
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn audit_state(
        dir: &std::path::Path,
        fail_mode: FailMode,
    ) -> (Arc<AuditState>, std::path::PathBuf) {
        let path = dir.join("audit.jsonl");
        let sink = AuditSink::open(AuditConfig {
            path: path.clone(),
            fsync: false,
            fail_mode: None,
            rotate_max_bytes: 0,
            rotate_keep: 8,
            suppressed_ids: true,
        })
        .expect("audit sink must open");
        (Arc::new(AuditState::new(sink, fail_mode, None)), path)
    }

    fn read_audit_events(path: &std::path::Path) -> Vec<AuditEvent> {
        let s = std::fs::read_to_string(path).expect("audit file must be readable");
        s.lines()
            .filter(|l| !l.is_empty())
            .map(|l| serde_json::from_str(l).expect("every audit line must parse"))
            .collect()
    }

    /// Serve a [`BugWarden`] against `mock` over an in-memory duplex
    /// transport, optionally audited, and connect an MCP client.
    async fn mcp_client(
        policy: &str,
        mock_uri: &str,
        audit: Option<Arc<AuditState>>,
    ) -> RunningService<RoleClient, ()> {
        use clap::Parser as _;
        let mut cli = Cli::parse_from([
            "bugwarden",
            "--bugzilla-server",
            mock_uri,
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
        let bz = Arc::new(BugzillaClient::new(mock_uri, false).expect("client must build"));
        let mut server = BugWarden::new(cfg, guard, bz).expect("server must build");
        if let Some(audit) = audit {
            server = server.with_audit(audit);
        }
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

    async fn call(
        client: &RunningService<RoleClient, ()>,
        tool: &str,
        args: Value,
    ) -> CallToolResult {
        let Value::Object(args) = args else {
            panic!("tool arguments must be a JSON object");
        };
        client
            .call_tool(CallToolRequestParams::new(tool.to_string()).with_arguments(args))
            .await
            .expect("tool call must not be a protocol error")
    }

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

    /// Classify/full fetches for bug 7, the empty id=0 padding fetch, an
    /// empty history, and a comment thread with one private comment.
    async fn mount_bug7(mock: &MockServer) {
        Mock::given(method("GET"))
            .and(path("/rest/bug"))
            .and(query_param("id", "0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "bugs": [] })))
            .mount(mock)
            .await;
        Mock::given(method("GET"))
            .and(path("/rest/bug"))
            .and(query_param("id", "7"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({ "bugs": [world_bug(7)] })),
            )
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
                    { "id": 1, "bug_id": 7, "is_private": false, "text": "public" },
                    { "id": 2, "bug_id": 7, "is_private": true, "text": "private" },
                ] } }
            })))
            .mount(mock)
            .await;
    }

    #[tokio::test]
    async fn closed_all_gates_pre_dispatch_once_the_sink_is_failing() {
        let mock = MockServer::start().await;
        mount_bug7(&mock).await;
        let dir = tempfile::tempdir().unwrap();
        let (audit, audit_path) = audit_state(dir.path(), FailMode::ClosedAll);
        let client = mcp_client("", &mock.uri(), Some(Arc::clone(&audit))).await;

        // Healthy sink: a granted read serves and is recorded.
        let served = call(&client, "bug_history", json!({ "id": 7 })).await;
        assert!(!is_error(&served), "healthy sink must serve");

        audit.sink.set_fail_writes(true);
        // The outage is discovered ON the response path: the tool ran
        // (upstream was contacted), the record failed, and the response
        // became the mapped refusal — the write sits on the response path.
        let discovered = call(&client, "bug_history", json!({ "id": 7 })).await;
        assert!(is_error(&discovered));
        assert_eq!(text_of(&discovered), "Failed to fetch bug history");
        let after_discovery = mock.received_requests().await.unwrap().len();

        // From now on the gate closes BEFORE dispatch: no new upstream
        // request, same refusal text.
        let gated = call(&client, "bug_history", json!({ "id": 7 })).await;
        assert!(is_error(&gated));
        assert_eq!(text_of(&gated), "Failed to fetch bug history");
        assert_eq!(
            mock.received_requests().await.unwrap().len(),
            after_discovery,
            "the pre-dispatch gate must not contact upstream"
        );

        // On disk: only the healthy-phase records made it.
        let events = read_audit_events(&audit_path);
        assert_eq!(events.len(), 2, "initialize + the served call");
    }

    #[tokio::test]
    async fn closed_writes_denials_scopes_refusal_to_writes_and_non_clean_reads() {
        let mock = MockServer::start().await;
        mount_bug7(&mock).await;
        Mock::given(method("POST"))
            .and(path("/rest/bug/7/comment"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "id": 11 })))
            .expect(0)
            .mount(&mock)
            .await;
        let dir = tempfile::tempdir().unwrap();
        let (audit, audit_path) = audit_state(dir.path(), FailMode::ClosedWritesDenials);
        // Failing from the very start; the initialize record is lost but
        // the handshake proceeds (only closed_all refuses it).
        audit.sink.set_fail_writes(true);
        let client = mcp_client("", &mock.uri(), Some(Arc::clone(&audit))).await;

        // A read the guard fully allows serves unaudited.
        let served = call(&client, "bug_history", json!({ "id": 7 })).await;
        assert!(!is_error(&served), "a clean read must serve unaudited");

        // A write refuses BEFORE any upstream request (the sink is
        // already failing, so the gate closes pre-dispatch: no classify,
        // no POST).
        let before_write = mock.received_requests().await.unwrap().len();
        let write = call(
            &client,
            "add_comment",
            json!({ "bug_id": 7, "comment": "hi" }),
        )
        .await;
        assert!(is_error(&write));
        assert_eq!(text_of(&write), "Failed to create a comment");
        assert_eq!(
            mock.received_requests().await.unwrap().len(),
            before_write,
            "a gated write must not contact upstream at all"
        );

        // A read whose guard suppressed something (a private comment
        // filtered out) refuses.
        let filtered = call(&client, "bug_comments", json!({ "id": 7 })).await;
        assert!(is_error(&filtered));
        assert_eq!(text_of(&filtered), "Failed to fetch bug comments");

        // Recovery: the unaudited work shows up as the gap marker's drop
        // count — initialize, the served read, the gated write's refusal
        // record, and the filtered read.
        audit.sink.set_fail_writes(false);
        let again = call(&client, "bug_history", json!({ "id": 7 })).await;
        assert!(!is_error(&again));
        let events = read_audit_events(&audit_path);
        assert_eq!(events.len(), 2, "gap marker + the recovered call");
        match &events[0].kind {
            AuditEventKind::AuditGap(gap) => assert_eq!(gap.dropped, 4),
            other => panic!("expected audit_gap first after recovery, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn responses_byte_identical_with_audit_off_on_and_failing_open() {
        // The same call sequence — a denial, a filtered read, a write —
        // against one upstream, through three servers: audit off, audit
        // on, audit failing under fail_mode = open. The client-visible
        // results must serialize byte-identically (I15).
        let policy = concat!(
            "[[rule]]\nname = \"hide-secret\"\naction = \"deny\"\n",
            "[rule.match]\nproducts = [\"Secret*\"]\n",
        );
        let mock = MockServer::start().await;
        mount_bug7(&mock).await;
        let mut secret = world_bug(99);
        secret["product"] = json!("SecretSauce");
        Mock::given(method("GET"))
            .and(path("/rest/bug"))
            .and(query_param("id", "99"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "bugs": [secret] })))
            .mount(&mock)
            .await;
        Mock::given(method("POST"))
            .and(path("/rest/bug/7/comment"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "id": 11 })))
            .mount(&mock)
            .await;

        let client_off = mcp_client(policy, &mock.uri(), None).await;
        let dir_on = tempfile::tempdir().unwrap();
        let (audit_on, _) = audit_state(dir_on.path(), FailMode::Open);
        let client_on = mcp_client(policy, &mock.uri(), Some(audit_on)).await;
        let dir_fail = tempfile::tempdir().unwrap();
        let (audit_fail, fail_path) = audit_state(dir_fail.path(), FailMode::Open);
        audit_fail.sink.set_fail_writes(true);
        let client_fail = mcp_client(policy, &mock.uri(), Some(Arc::clone(&audit_fail))).await;

        let sequence = [
            ("bug_info", json!({ "bug_ids": [7, 99] })),
            ("bug_comments", json!({ "id": 7 })),
            ("add_comment", json!({ "bug_id": 7, "comment": "hello" })),
        ];
        for (tool, args) in sequence {
            let off = call(&client_off, tool, args.clone()).await;
            let on = call(&client_on, tool, args.clone()).await;
            let failing = call(&client_fail, tool, args).await;
            let off = serde_json::to_string(&off).unwrap();
            assert_eq!(
                off,
                serde_json::to_string(&on).unwrap(),
                "auditing on must not change {tool}"
            );
            assert_eq!(
                off,
                serde_json::to_string(&failing).unwrap(),
                "a failing-open sink must not change {tool}"
            );
        }

        // fail-open accounts for the outage in the stream itself.
        audit_fail.sink.set_fail_writes(false);
        let _ = call(&client_fail, "bug_comments", json!({ "id": 7 })).await;
        let events = read_audit_events(&fail_path);
        assert!(
            events
                .iter()
                .any(|e| matches!(e.kind, AuditEventKind::AuditGap(_))),
            "a gap marker must follow recovery"
        );
    }

    // ---------- trace enrichment (issue #28) ----------

    /// The canonical W3C `traceparent` example; its ids.
    const TRACEPARENT: &str = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01";
    const TRACE_ID: &str = "0af7651916cd43dd8448eb211c80319c";
    const SPAN_ID: &str = "b7ad6b7169203331";

    /// Like [`call`], but with `traceparent` in the request's `_meta`.
    /// The duplex transport serde-roundtrips the bytes, so this exercises
    /// the wire `params._meta` shape, not an in-process shortcut.
    async fn call_with_traceparent(
        client: &RunningService<RoleClient, ()>,
        tool: &str,
        args: Value,
        traceparent: &str,
    ) -> CallToolResult {
        let Value::Object(args) = args else {
            panic!("tool arguments must be a JSON object");
        };
        let mut params = CallToolRequestParams::new(tool.to_string()).with_arguments(args);
        let mut meta = rmcp::model::RequestMetaObject::new();
        meta.set_traceparent(traceparent);
        params.meta = Some(meta);
        client
            .call_tool(params)
            .await
            .expect("tool call must not be a protocol error")
    }

    /// The `tool_call` payloads of `events`, in file order.
    fn tool_calls(events: &[AuditEvent]) -> Vec<&audit::ToolCallEvent> {
        events
            .iter()
            .filter_map(|e| match &e.kind {
                AuditEventKind::ToolCall(ev) => Some(ev.as_ref()),
                _ => None,
            })
            .collect()
    }

    fn assert_trace_is_canonical(trace: Option<&audit::TraceContext>) {
        let trace = trace.expect("the record must carry the sent trace ids");
        assert_eq!(trace.trace_id, TRACE_ID);
        assert_eq!(trace.span_id, SPAN_ID);
    }

    #[tokio::test]
    async fn traceparent_in_meta_lands_in_the_tool_record() {
        let mock = MockServer::start().await;
        mount_bug7(&mock).await;
        let dir = tempfile::tempdir().unwrap();
        let (audit, audit_path) = audit_state(dir.path(), FailMode::Open);
        let client = mcp_client("", &mock.uri(), Some(audit)).await;

        let plain = call(&client, "bug_history", json!({ "id": 7 })).await;
        let traced =
            call_with_traceparent(&client, "bug_history", json!({ "id": 7 }), TRACEPARENT).await;
        // Record enrichment only (I15): the response must not change.
        assert_eq!(
            serde_json::to_string(&plain).unwrap(),
            serde_json::to_string(&traced).unwrap(),
            "a traceparent must not change the response"
        );

        let events = read_audit_events(&audit_path);
        let calls = tool_calls(&events);
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].trace, None, "no meta means no trace field");
        assert_trace_is_canonical(calls[1].trace.as_ref());
    }

    #[tokio::test]
    async fn malformed_traceparent_leaves_the_record_without_trace() {
        let mock = MockServer::start().await;
        mount_bug7(&mock).await;
        let dir = tempfile::tempdir().unwrap();
        let (audit, audit_path) = audit_state(dir.path(), FailMode::Open);
        let client = mcp_client("", &mock.uri(), Some(audit)).await;

        let plain = call(&client, "bug_history", json!({ "id": 7 })).await;
        // Uppercase hex is invalid per W3C; the strict parser records
        // nothing rather than a value it could not fully validate.
        let upper = "00-0AF7651916CD43DD8448EB211C80319C-B7AD6B7169203331-01";
        let traced = call_with_traceparent(&client, "bug_history", json!({ "id": 7 }), upper).await;
        assert_eq!(
            serde_json::to_string(&plain).unwrap(),
            serde_json::to_string(&traced).unwrap(),
            "a malformed traceparent must not change the response"
        );

        // Absent means absent bytes: no serialized line carries a trace
        // key at all — and none echoes the rejected value anywhere.
        let raw = std::fs::read_to_string(&audit_path).expect("audit file must be readable");
        assert!(
            !raw.contains("\"trace\""),
            "a malformed traceparent must leave no trace field: {raw}"
        );
        assert!(
            !raw.contains("0AF76519"),
            "the rejected value must never reach the file: {raw}"
        );
        assert_eq!(tool_calls(&read_audit_events(&audit_path)).len(), 2);
    }

    #[tokio::test]
    async fn traceparent_on_a_denied_call_enriches_but_never_influences() {
        // Correlation matters most on denials — and the trace ids must
        // never leak into the denial itself.
        let policy = concat!(
            "[[rule]]\nname = \"hide-secret\"\naction = \"deny\"\n",
            "[rule.match]\nproducts = [\"Secret*\"]\n",
        );
        let mock = MockServer::start().await;
        mount_bug7(&mock).await;
        let mut secret = world_bug(99);
        secret["product"] = json!("SecretSauce");
        Mock::given(method("GET"))
            .and(path("/rest/bug"))
            .and(query_param("id", "99"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "bugs": [secret] })))
            .mount(&mock)
            .await;
        let dir = tempfile::tempdir().unwrap();
        let (audit, audit_path) = audit_state(dir.path(), FailMode::Open);
        let client = mcp_client(policy, &mock.uri(), Some(audit)).await;

        let denied =
            call_with_traceparent(&client, "bug_comments", json!({ "id": 99 }), TRACEPARENT).await;
        assert!(is_error(&denied), "the hidden bug must be denied");
        assert_eq!(
            text_of(&denied),
            "Bug 99 is not accessible through this server",
            "the denial must be the uniform text (I2), traceparent or not"
        );

        let calls_events = read_audit_events(&audit_path);
        let calls = tool_calls(&calls_events);
        assert_eq!(calls.len(), 1);
        let guard = calls[0].guard.as_ref().expect("a denial has a guard");
        assert_eq!(guard.verdict, Verdict::Denied);
        assert_trace_is_canonical(calls[0].trace.as_ref());
    }

    #[tokio::test]
    async fn failing_sink_gate_record_carries_the_trace() {
        // The pre-dispatch fail-closed gate builds its own record; it
        // must carry the trace too, not only the post-dispatch site.
        let mock = MockServer::start().await;
        mount_bug7(&mock).await;
        let dir = tempfile::tempdir().unwrap();
        let (audit, audit_path) = audit_state(dir.path(), FailMode::ClosedAll);
        let client = mcp_client("", &mock.uri(), Some(Arc::clone(&audit))).await;

        // Discover the outage on the response path, then lift the
        // injected fault: the sink still counts as failing (records were
        // dropped), so the next call takes the pre-dispatch gate — and
        // its best-effort record now persists.
        audit.sink.set_fail_writes(true);
        let discovered = call(&client, "bug_history", json!({ "id": 7 })).await;
        assert!(is_error(&discovered));
        audit.sink.set_fail_writes(false);
        let before_gated = mock.received_requests().await.unwrap().len();

        let gated =
            call_with_traceparent(&client, "bug_history", json!({ "id": 7 }), TRACEPARENT).await;
        assert!(is_error(&gated));
        assert_eq!(text_of(&gated), "Failed to fetch bug history");
        assert_eq!(
            mock.received_requests().await.unwrap().len(),
            before_gated,
            "the gated call must not contact upstream"
        );

        let events = read_audit_events(&audit_path);
        let calls = tool_calls(&events);
        assert_eq!(calls.len(), 1, "only the gate record reached the file");
        let guard = calls[0].guard.as_ref().expect("the gate records a guard");
        assert_eq!(guard.verdict, Verdict::Refused);
        assert_trace_is_canonical(calls[0].trace.as_ref());
    }

    #[tokio::test]
    async fn in_process_params_meta_traceparent_enriches_the_record() {
        // The params-struct arm of the trace extraction (`request.meta`,
        // consulted before the `context.meta` fallback) is reachable ONLY
        // by an in-process caller: over every serialized transport rmcp
        // strips the wire `_meta` into the request extensions before the
        // params struct is built, so `CallToolRequestParams.meta` is
        // always `None` there and the duplex and streamable-http tests
        // all pin the `context.meta` fallback instead. This test invokes
        // `ServerHandler::call_tool` directly, with the traceparent in
        // the params-struct meta and a hand-built `RequestContext` whose
        // meta is empty — killing a mutant that reads only `context.meta`
        // (behavior-preserving over every serialized transport, so no
        // other test can).
        use clap::Parser as _;
        let mock = MockServer::start().await;
        mount_bug7(&mock).await;
        let dir = tempfile::tempdir().unwrap();
        let (audit, audit_path) = audit_state(dir.path(), FailMode::Open);

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
        let guard = Arc::new(Guard {
            policy: Policy::from_toml_str("").expect("test policy must parse"),
        });
        let bz = Arc::new(BugzillaClient::new(&mock.uri(), false).expect("client must build"));
        let server = BugWarden::new(Arc::new(cli), guard, bz)
            .expect("server must build")
            .with_audit(Arc::clone(&audit));

        // A genuine `Peer<RoleServer>` for the hand-built context, minted
        // by serving a clone over a duplex (the SDK exposes no other
        // constructor); no tool call flows through that session, so the
        // direct call below writes the only tool_call record.
        let (client_io, server_io) = tokio::io::duplex(1 << 16);
        let serving = server.clone();
        let server_task = tokio::spawn(async move { serving.serve(server_io).await });
        let _client = ().serve(client_io).await.expect("MCP handshake must succeed");
        let running = server_task
            .await
            .expect("serve task must not panic")
            .expect("server must serve");
        let peer = running.peer().clone();

        let Value::Object(args) = json!({ "id": 7 }) else {
            panic!("tool arguments must be a JSON object");
        };
        let mut params = CallToolRequestParams::new("bug_history".to_string()).with_arguments(args);
        let mut meta = rmcp::model::RequestMetaObject::new();
        meta.set_traceparent(TRACEPARENT);
        params.meta = Some(meta);
        let context = RequestContext::<RoleServer>::new(RequestId::Number(1), peer);
        assert!(
            context.meta.get_traceparent().is_none(),
            "the hand-built context must carry no meta — the params struct is the only source"
        );

        let result = ServerHandler::call_tool(&server, params, context)
            .await
            .expect("the in-process call must not be a protocol error");
        let CallToolResponse::Complete(result) = result else {
            panic!("a served tool call completes; this build serves no other response kind")
        };
        assert!(!is_error(&result), "bug_history must succeed");

        let events = read_audit_events(&audit_path);
        let calls = tool_calls(&events);
        assert_eq!(calls.len(), 1, "exactly the direct call is recorded");
        assert_trace_is_canonical(calls[0].trace.as_ref());
    }

    #[tokio::test]
    async fn initialize_never_echoes_a_revision_this_build_cannot_serve() {
        // A dual-revision client probing for 2026-07-28 must be handed
        // the server default instead. Both halves of the negotiation are
        // exercised here: this handler's own test against
        // `SUPPORTED_PROTOCOL_VERSIONS`, and the SDK's, which runs after
        // the handler returns and takes the handler's value as its
        // fallback — so a handler that echoed the request would make the
        // SDK echo it too.
        use clap::Parser as _;
        let mock = MockServer::start().await;
        let dir = tempfile::tempdir().unwrap();
        let (audit, audit_path) = audit_state(dir.path(), FailMode::Open);
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
        let guard = Arc::new(Guard {
            policy: Policy::from_toml_str("").expect("test policy must parse"),
        });
        let bz = Arc::new(BugzillaClient::new(&mock.uri(), false).expect("client must build"));
        let server = BugWarden::new(Arc::new(cli), guard, bz)
            .expect("server must build")
            .with_audit(Arc::clone(&audit));

        let (client_io, server_io) = tokio::io::duplex(1 << 16);
        tokio::spawn(async move {
            if let Ok(running) = server.serve(server_io).await {
                let _ = running.waiting().await;
            }
        });
        // rmcp serves a `ClientInfo` as its own handler, so this value is
        // what the client asks for on the wire.
        let probe = ClientInfo::default().with_protocol_version(ProtocolVersion::V_2026_07_28);
        let client = probe
            .serve(client_io)
            .await
            .expect("the handshake must succeed");

        assert_eq!(
            client
                .peer_info()
                .expect("the server answers initialize")
                .protocol_version,
            DEFAULT_PROTOCOL_VERSION,
            "a revision this build cannot serve must not be echoed back"
        );

        let events = read_audit_events(&audit_path);
        let recorded = events
            .iter()
            .find_map(|e| match &e.kind {
                AuditEventKind::Initialize(ev) => ev.protocol_version.clone(),
                AuditEventKind::ToolCall(_) | AuditEventKind::AuditGap(_) => None,
            })
            .expect("the handshake is recorded");
        assert_eq!(
            recorded,
            DEFAULT_PROTOCOL_VERSION.as_str(),
            "the record names the revision the session speaks, not the one requested"
        );
    }

    #[test]
    fn mcp_server_info_reports_the_identity_the_handshake_advertises() {
        let (cfg, guard, bz) = parts("");
        let server = BugWarden::new(cfg, guard, bz).expect("server must build");

        // The values, not just the constants: comparing `advertised.name`
        // to `SERVER_NAME` alone would hold for any value either of them
        // took, so an empty or renamed constant would pass.
        let advertised = server.get_info().server_info;
        assert_eq!(advertised.name, "bugwarden");
        assert_eq!(advertised.version, env!("CARGO_PKG_VERSION"));
        // `ServerInfo::new` seeds `server_info` with
        // `Implementation::from_build_env()`, whose `env!`s expand inside
        // rmcp, so `get_info` starts from the SDK's identity and only the
        // explicit `with_server_info` displaces it: dropping that call, or
        // refactoring back to the constructor, must fail here (issue #53).
        assert_ne!(
            advertised.name,
            Implementation::from_build_env().name,
            "the handshake must not borrow the SDK's crate name"
        );

        let reported: Value = serde_json::from_str(&text_of(
            &server.mcp_server_info().expect("the tool answers"),
        ))
        .expect("the tool returns JSON");
        assert_eq!(
            reported["name"], advertised.name,
            "the tool and the handshake must not name two different servers"
        );
        assert_eq!(reported["version"], advertised.version);
    }

    #[test]
    fn rmcp_default_still_names_the_sdk() {
        // A pin on the SDK, not on this build, and the reason inheriting
        // its identity is no substitute for building one: `Default` is
        // `from_build_env()`, which expands its `env!`s inside rmcp. If a
        // future rmcp changes that, this is the notice to rewrite the trap
        // note in DESIGN.md — nothing here is wrong when it fails.
        assert_eq!(
            Implementation::default().name,
            Implementation::from_build_env().name
        );
        assert_ne!(Implementation::default().name, SERVER_NAME);
    }

    #[tokio::test]
    async fn the_handshake_names_this_build_over_a_real_session() {
        // Asserted on a served session rather than on `get_info()` alone:
        // this is the field as a client reads it, which means it survived
        // serialization into `ServerPeerInfo.server_info` — `Option` on
        // that side, so "no identity at all" is a shape the wire allows.
        let (cfg, guard, bz) = parts("");
        let server = BugWarden::new(cfg, guard, bz).expect("server must build");

        let (client_io, server_io) = tokio::io::duplex(1 << 16);
        tokio::spawn(async move {
            if let Ok(running) = server.serve(server_io).await {
                let _ = running.waiting().await;
            }
        });
        // Bounded: a handler that never answers should fail this test, not
        // stall the run until CI's own timeout kills it.
        let client = tokio::time::timeout(std::time::Duration::from_secs(10), ().serve(client_io))
            .await
            .expect("the handshake must not hang")
            .expect("the handshake must succeed");

        let advertised = client
            .peer_info()
            .expect("the server answers initialize")
            .server_info
            .clone()
            .expect("the handshake carries a serverInfo");
        // The name is spelled out — it is meant to be stable, so a package
        // rename should fail here and be noticed — while the version is
        // read from the environment, since it moves every release.
        assert_eq!(
            advertised.name, "bugwarden",
            "a client must be told which server answered, not which SDK it was built on"
        );
        assert_eq!(advertised.version, env!("CARGO_PKG_VERSION"));
        // `title` is the field a client DISPLAYS in preference to `name`,
        // so an SDK identity parked there would reproduce #53 in the only
        // place a human looks, while every assertion above still passed.
        assert_eq!(
            advertised.title, None,
            "nothing may be displayed in place of the name asserted here"
        );
    }
}
