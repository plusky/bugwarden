//! MCP tool surface for bugwarden.
//!
//! Every tool that takes a bug id runs guard assessment (`Guard::assess`)
//! BEFORE any side effect or data return (invariant I8; `bug_url` is the
//! documented exception — it computes a URL string locally and contacts
//! nothing). Denials use the uniform text from `Guard::denial` only, so a
//! policy-denied bug and a nonexistent bug are indistinguishable (I2).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use bugwarden_core::client::{BugzillaClient, CLASSIFY_FIELDS};
use bugwarden_core::guard::Guard;
use bugwarden_core::policy::{Access, Action, Capability};
use chrono::{DateTime, Utc};
use rmcp::{
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::*,
    schemars,
    service::RequestContext,
    tool, tool_handler, tool_router, ErrorData as McpError, RoleServer, ServerHandler,
};
use serde_json::{json, Value};

use crate::config::{Cli, Transport};

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

/// Add `"comment": {"body": ...}` to an update payload when a comment is set.
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
    /// Bug ids to fetch.
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
    /// Query in bugzilla quicksearch syntax.
    pub query: String,
    /// Status filter (e.g., ALL, OPEN, CLOSED).
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

#[derive(Clone)]
pub struct BugWarden {
    cfg: Arc<Cli>,
    guard: Arc<Guard>,
    bz: Arc<BugzillaClient>,
    tool_router: ToolRouter<Self>,
}

impl BugWarden {
    /// Build the server, pruning the tool router per policy (I13).
    ///
    /// Errors when `global.disabled_tools` names a tool that does not exist:
    /// `ToolRouter::remove_route` silently no-ops on unknown names, so a typo
    /// would otherwise leave the tool exposed while the operator believes it
    /// disabled — the policy format's "typos are hard startup errors, never
    /// silent fail-open" rule applies here too.
    pub fn new(cfg: Arc<Cli>, guard: Arc<Guard>, bz: Arc<BugzillaClient>) -> anyhow::Result<Self> {
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
        })
    }

    /// Resolve the Bugzilla API key for the current request.
    ///
    /// stdio: from the startup configuration. http: from the configured
    /// (lowercased) header of the underlying HTTP request. A missing key is a
    /// protocol error (`McpError::invalid_request`), not a tool error.
    fn api_key(&self, ctx: &RequestContext<RoleServer>) -> Result<String, McpError> {
        match self.cfg.transport {
            Transport::Stdio => self
                .cfg
                .api_key
                .as_deref()
                .filter(|k| !k.is_empty())
                .map(str::to_owned)
                .ok_or_else(|| {
                    McpError::invalid_request(
                        "stdio transport requires --api-key or BUGZILLA_API_KEY env var",
                        None,
                    )
                }),
            Transport::Http => {
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

    /// Guard assessment for the given ids (fail closed, I4).
    async fn assess(&self, key: &str, ids: &[u64]) -> BTreeMap<u64, (Access, Value)> {
        self.guard.assess(&self.bz, key, ids).await
    }

    /// Assess a single bug id and require `cap`. Returns `Some(denial)` when
    /// the operation must be refused; the denial text is uniform (I2).
    async fn deny_unless(&self, key: &str, id: u64, cap: Capability) -> Option<CallToolResult> {
        let assessments = self.assess(key, &[id]).await;
        let allowed = assessments
            .get(&id)
            .is_some_and(|(access, _)| access.allows(cap));
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
            return Ok(err_text("At least one bug id must be provided"));
        }

        let assessments = self.assess(&key, &ids).await;

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
                    return Ok(err_text(format!("Failed to fetch bug info\nReason: {e}")));
                }
            }
        }

        let mut bugs: Vec<Value> = Vec::new();
        let mut restricted: Vec<Value> = Vec::new();
        for id in &ids {
            match assessments.get(id) {
                Some((access, _)) if access.allows(Capability::Read) => {
                    // Absent from the full response => fail closed (I4).
                    match full.get(id) {
                        Some(bug) => bugs.push(bug.clone()),
                        None => {
                            restricted.push(json!({ "id": id, "note": Guard::denial(*id) }));
                        }
                    }
                }
                Some((access, meta)) if access.allows(Capability::Summary) => {
                    bugs.push(Guard::summary_view(meta));
                }
                _ => restricted.push(json!({ "id": id, "note": Guard::denial(*id) })),
            }
        }

        Ok(ok_json(json!({ "bugs": bugs, "restricted": restricted })))
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
        if let Some(denied) = self.deny_unless(&key, p.id, Capability::History).await {
            return Ok(denied);
        }
        match self.bz.bug_history(&key, p.id, p.new_since).await {
            Ok(history) => Ok(ok_json(history)),
            Err(e) => Ok(err_text(format!(
                "Failed to fetch bug history\nReason: {e}"
            ))),
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
        if let Some(denied) = self.deny_unless(&key, p.id, Capability::Comments).await {
            return Ok(denied);
        }
        match self.bz.bug_comments(&key, p.id, p.new_since).await {
            Ok(comments) => {
                let filtered = self.guard.filter_comments(comments, p.include_private);
                Ok(ok_json(Value::Array(filtered)))
            }
            Err(e) => Ok(err_text(format!(
                "Failed to fetch bug comments\nReason: {e}"
            ))),
        }
    }

    #[tool(
        description = "Search bugs using bugzilla's quicksearch syntax.\n\nTo reduce the token limit & response time, only returns a subset of fields for each bug. The user can query full details of each bug using the bug_info tool. Returns the top-level bug data envelope containing the matched bugs.",
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

        let envelope = match self
            .bz
            .quicksearch(&key, &p.query, &p.status, &fetch_fields, p.limit, p.offset)
            .await
        {
            Ok(v) => v,
            Err(e) => return Ok(err_text(format!("Search failed: {e}"))),
        };
        let bugs = envelope
            .get("bugs")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();

        let (kept, dropped) = self.guard.filter_bug_list(bugs);
        if dropped > 0 {
            // Server-side logging only — never reported to the client (I3).
            tracing::debug!(dropped, "bugs_quicksearch: dropped policy-denied bugs");
        }
        let projected: Vec<Value> = kept
            .iter()
            .map(|bug| project_fields(bug, &requested))
            .collect();

        Ok(ok_json(json!({ "bugs": projected })))
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
        if let Some(denied) = self.deny_unless(&key, p.bug_id, Capability::Comment).await {
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
            return Ok(err_text(
                "Resolution is required when setting status to CLOSED (e.g., FIXED, WONTFIX, NOTABUG, DUPLICATE)",
            ));
        }
        let key = self.api_key(&ctx)?;
        if let Some(denied) = self.deny_unless(&key, p.bug_id, Capability::Status).await {
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
        if let Some(denied) = self.deny_unless(&key, p.bug_id, Capability::Assign).await {
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
        description = "Update various bug fields. All fields are optional, but at least one must be specified. Custom field names must start with 'cf_' (e.g. {\"cf_fixed_in\": \"1.2.3\"}).",
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
        tracing::info!(
            bug_id = p.bug_id,
            priority = ?p.priority,
            severity = ?p.severity,
            resolution = ?p.resolution,
            custom_field_count = p.custom_fields.as_ref().map_or(0, |cf| cf.len()),
            "tool: update_bug_fields"
        );

        let mut payload = serde_json::Map::new();
        if let Some(priority) = p.priority.as_deref().filter(|s| !s.is_empty()) {
            payload.insert("priority".to_string(), json!(priority));
        }
        if let Some(severity) = p.severity.as_deref().filter(|s| !s.is_empty()) {
            payload.insert("severity".to_string(), json!(severity));
        }
        if let Some(resolution) = p.resolution.as_deref().filter(|s| !s.is_empty()) {
            payload.insert("resolution".to_string(), json!(resolution));
        }
        if let Some(custom_fields) = &p.custom_fields {
            // I7: only cf_* keys may pass through the generic updater. Error
            // without calling Bugzilla otherwise.
            for k in custom_fields.keys() {
                if !k.starts_with("cf_") {
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
            return Ok(err_text("At least one field must be specified"));
        }
        attach_comment(&mut payload, &p.comment);

        let key = self.api_key(&ctx)?;
        if let Some(denied) = self.deny_unless(&key, p.bug_id, Capability::Fields).await {
            return Ok(denied);
        }
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

        let key = self.api_key(&ctx)?;
        let assessments = self.assess(&key, &ids).await;
        let deps_ok = assessments
            .get(&p.bug_id)
            .is_some_and(|(access, _)| access.allows(Capability::Deps));
        if !deps_ok {
            tracing::info!(bug_id = p.bug_id, "guard denied operation");
            return Ok(err_text(Guard::denial(p.bug_id)));
        }
        for &id in ids.iter().filter(|&&id| id != p.bug_id) {
            let target_ok = assessments
                .get(&id)
                .is_some_and(|(access, _)| access.allows(Capability::Summary));
            if !target_ok {
                tracing::info!(bug_id = id, "guard denied dependency target");
                return Ok(err_text(Guard::denial(id)));
            }
        }

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
        if let Some(denied) = self.deny_unless(&key, p.bug_id, Capability::Cc).await {
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
        let assessments = self.assess(&key, &ids).await;
        let status_ok = assessments
            .get(&p.bug_id)
            .is_some_and(|(access, _)| access.allows(Capability::Status));
        if !status_ok {
            return Ok(err_text(Guard::denial(p.bug_id)));
        }
        let duplicate_ok = assessments
            .get(&p.duplicate_of)
            .is_some_and(|(access, _)| access.allows(Capability::Summary));
        if !duplicate_ok {
            return Ok(err_text(Guard::denial(p.duplicate_of)));
        }

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
        if let Some(denied) = self
            .deny_unless(&key, p.bug_id, Capability::Attachments)
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
                let filtered = self.guard.filter_attachments(items, p.include_private);
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
        let assessments = self.assess(&key, &[assess_id]).await;
        let allowed = assessments
            .get(&assess_id)
            .is_some_and(|(access, _)| access.allows(Capability::Attachments));

        let Some(meta) = meta.filter(|_| allowed && assess_id != 0) else {
            // Missing metadata, missing bug id, or a denied owning bug: one
            // uniform denial. The bug-level denial text is deliberately NOT
            // reused — it would confirm which bug owns the attachment.
            return Ok(err_text(Guard::attachment_denial(p.attachment_id)));
        };
        if let Some(refusal) = self.guard.attachment_gate(&meta, p.include_private) {
            return Ok(err_text(refusal));
        }

        let attachment = match self.bz.attachment_data(&key, p.attachment_id).await {
            Ok(Some(att)) => att,
            // A failed blob fetch gets the same uniform denial as an unknown
            // id: the upstream status and message would otherwise distinguish
            // the two and disclose server detail.
            Ok(None) => return Ok(err_text(Guard::attachment_denial(p.attachment_id))),
            Err(e) => {
                tracing::debug!(
                    attachment_id = p.attachment_id,
                    error = %e,
                    "attachment data fetch failed"
                );
                return Ok(err_text(Guard::attachment_denial(p.attachment_id)));
            }
        };
        // The gate ran on the metadata response; the bytes come from a second,
        // later request. Re-run it on what actually arrived and re-check the
        // owning bug, so an attachment that turns private (or moves to another
        // bug) between the two calls cannot be served.
        if attachment.get("bug_id").and_then(Value::as_u64) != Some(assess_id) {
            return Ok(err_text(Guard::attachment_denial(p.attachment_id)));
        }
        if let Some(refusal) = self.guard.attachment_gate(&attachment, p.include_private) {
            return Ok(err_text(refusal));
        }

        let Some(blob) = attachment
            .get("data")
            .and_then(Value::as_str)
            .map(str::to_owned)
        else {
            return Ok(err_text("Attachment has no data"));
        };
        // Defense in depth: the size gate trusted the upstream-REPORTED size;
        // re-check the payload itself so a wrong or lying `size` cannot
        // smuggle an oversized blob past the cap. The decoded length is
        // computed exactly (4 base64 chars per 3 bytes, minus the padding)
        // so the cap stays inclusive, matching the metadata gate.
        let cap = self.guard.policy.global.max_attachment_bytes;
        if cap > 0 && decoded_len(&blob) > cap {
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
        description = "Access the documentation of the bugzilla quicksearch syntax. LLM can learn using this tool. Response is in HTML",
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
        description = "Returns information about this MCP server instance (version, bugzilla server, transport) and a summary of the active guard policy.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    fn mcp_server_info(&self) -> Result<CallToolResult, McpError> {
        tracing::info!("tool: mcp_server_info");
        // I1: expose only rule count, default_action, min_bug_age_days,
        // read_only, and disabled tool names — never rule names or match
        // criteria.
        let policy = &self.guard.policy;
        Ok(ok_json(json!({
            "name": "bugwarden",
            "version": env!("CARGO_PKG_VERSION"),
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
        if let Some(denied) = self.deny_unless(&key, p.id, Capability::Comments).await {
            return Ok(denied);
        }
        let comments = match self.bz.bug_comments(&key, p.id, None).await {
            Ok(comments) => comments,
            Err(e) => {
                return Ok(err_text(format!("Summarize Comments Failed\nReason: {e}")));
            }
        };
        let comments = self.guard.filter_comments(comments, false);
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

// `router = self.tool_router` is load-bearing: the instance router has the
// write tools / disabled tools removed (I13). The macro default,
// `Self::tool_router()`, would rebuild an unpruned router.
#[tool_handler(router = self.tool_router)]
impl ServerHandler for BugWarden {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::from_build_env())
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
    use super::*;
    use bugwarden_core::policy::Policy;

    fn parts(policy: &str) -> (Arc<Cli>, Arc<Guard>, Arc<BugzillaClient>) {
        use clap::Parser as _;
        let cfg = Arc::new(Cli::parse_from([
            "bugwarden",
            "--bugzilla-server",
            "https://bugzilla.example.com",
            "--transport",
            "stdio",
            "--api-key",
            "test-key",
        ]));
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
}
