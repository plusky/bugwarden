# bugwarden — design contract

An MCP server exposing Bugzilla to LLM clients, hardened with
operator-controlled security guards. This document is the binding
contract between modules. If an implementation must deviate, note the deviation
explicitly in your report.

## Architecture

Cargo workspace, two crates:

- `crates/bugwarden-core` — guard policy engine + async Bugzilla REST client.
  MUST NOT depend on rmcp, axum, clap, or any MCP/transport crate.
- `crates/bugwarden` — the binary: clap CLI, rmcp 2.2 MCP server, stdio and
  streamable-HTTP transports. Depends on `bugwarden-core`.

Dependency direction: `bugwarden -> bugwarden-core`, never the reverse.

## Security invariants (normative — reviewers verify these)

- **I1** The guard policy comes ONLY from a TOML file given at startup
  (`--policy` / `BUGWARDEN_POLICY`). It is immutable at runtime. No MCP tool may
  expose rule names or match criteria; `mcp_server_info` may expose only: rule
  count, `default_action`, `min_bug_age_days`, `read_only`, disabled tool names.
- **I2** Uniform denial: a policy-denied bug and a nonexistent bug produce the
  same response text: `Bug {id} is not accessible through this server`. No
  wording/detail difference may reveal existence.
- **I3** Search filtering is silent: counts of dropped/filtered results are
  never returned to the client (server-side debug logging is fine).
- **I4** Fail closed: classification-fetch failure, bug absent from the
  response, or a rule that cannot be decided because the bug object did not
  carry a field that rule asks about (absent, null, wrongly typed, or only
  partially recoverable — including an unparsable `creation_time`) => Denied.
  Unreadable metadata never yields more access than readable metadata would:
  it satisfies no granting rule, and it does not let a bug slip past a rule
  that would otherwise have caught it.
- **I5** Private content (`is_private: true`) is returned only when policy
  `global.allow_private_comments = true` AND the call sets
  `include_private = true`. This one switch governs private comments,
  private attachment metadata, and private attachment content alike; on a
  content download a MISSING flag counts as private (I4). Default policy (no file) has
  `allow_private_comments = false` — private data is strictly opt-in.
- **I6** Capability implication: `read` implies `summary`. Nothing else is
  implied.
- **I7** `update_bug_fields.custom_fields`: every key must start with `cf_`;
  otherwise the tool errors without calling Bugzilla (prevents smuggling
  `groups`/`cc`/`assigned_to` changes through the generic updater).
- **I8** Every tool that takes a bug id performs guard assessment BEFORE any
  side effect or data return. Exception: `bug_url` (computes a URL string
  locally, contacts nothing).
- **I9** CLI/env can only tighten policy: `--read-only` ORs into
  `global.read_only`.
- **I10** No tool may echo incoming request headers back to the client —
  that would leak the API-key header to the model.
- **I11** `mark_as_duplicate` requires capability `status` on `bug_id` AND at
  least `summary` on `duplicate_of`.
- **I12** The Bugzilla API key must never appear in logs, error messages, or
  tool results. Sanitize reqwest errors with `.without_url()` — the key may be
  a URL query parameter.
- **I13** In read-only mode (policy or CLI) write tools are removed from the
  tool listing via `ToolRouter::remove_route`, not merely erroring. Same for
  `global.disabled_tools`.

## bugwarden-core API (exact signatures)

```rust
// src/lib.rs
pub mod client;
pub mod guard;
pub mod policy;
```

### src/policy.rs

All serde structs use `#[serde(deny_unknown_fields)]`; all types derive
`Debug + Clone` (plus what is listed).

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    Read,        // full bug details (implies Summary)
    Summary,     // redacted summary-only view
    Comments,    // read comments
    History,     // read history
    Attachments, // list attachment metadata + download attachment content
    Comment,     // write: add comment
    Status,      // write: status/resolution/duplicate
    Fields,      // write: priority/severity/resolution/custom cf_* fields
    Assign,      // write: assignee
    Cc,          // write: CC list
    Deps,        // write: blocks/depends_on
}
impl Capability {
    pub const ALL: [Capability; 11];
    pub fn is_write(self) -> bool; // Comment|Status|Fields|Assign|Cc|Deps
}

/// Case-insensitive glob; '*' matches any (possibly empty) substring.
pub fn glob_match(pattern: &str, value: &str) -> bool;

#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Matcher {
    // All criteria present must hold (AND); within a list, any element (OR).
    // An empty matcher matches every bug (catch-all rule).
    #[serde(default)] pub products: Vec<String>,           // globs vs product
    #[serde(default)] pub components: Vec<String>,         // globs vs any component
    #[serde(default)] pub groups: Vec<String>,             // globs vs any group name
    #[serde(default)] pub keywords: Vec<String>,           // globs vs any keyword
    #[serde(default)] pub statuses: Vec<String>,           // globs vs status
    #[serde(default)] pub severities: Vec<String>,         // globs vs severity
    #[serde(default)] pub priorities: Vec<String>,         // globs vs priority
    #[serde(default)] pub whiteboard_contains: Vec<String>,// case-insensitive substrings
    #[serde(default)] pub summary_contains: Vec<String>,   // case-insensitive substrings in the one-line summary
    #[serde(default)] pub group_restricted: Option<bool>,  // true: readable only via >=1 Bugzilla group; false: world-readable
    #[serde(default)] pub younger_than_days: Option<i64>,  // creation_time newer than now-N days
}
pub enum MatchOutcome { Yes, No, Unknown }

impl Matcher {
    // Yes: every criterion held. No: one definitively did not (it wins over
    // Unknown — the rule cannot apply either way). Unknown: nothing ruled the
    // bug out but a criterion consulted a None field. classify() maps
    // Unknown to Denied for EVERY action: a deny rule denies, and a granting
    // rule (allow, or restrict under a denying default) may neither grant nor
    // be skipped, since skipping would fall through to a later granting rule
    // or an allowing default. "Present but empty" is knowledge, not Unknown.
    pub fn evaluate(&self, bug: &BugMeta, now: chrono::DateTime<chrono::Utc>) -> MatchOutcome;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action { Allow, Deny, Restrict }

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub name: String,
    #[serde(default)] pub description: String,
    #[serde(rename = "match", default)] pub matcher: Matcher,
    pub action: Action,
    #[serde(default)] pub capabilities: Vec<Capability>, // only for action = "restrict"
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GlobalGuards {
    #[serde(default)] pub min_bug_age_days: i64,        // 0 = disabled
    #[serde(default)] pub allow_private_comments: bool, // default false
    #[serde(default)] pub read_only: bool,
    #[serde(default)] pub disabled_tools: Vec<String>,
    // Cap on download_attachment content (decoded bytes); 0 = no cap.
    // serde default AND the hand-written `Default` impl are BOTH 2 MiB — a
    // derived Default would zero it, silently removing the cap (fail open).
    #[serde(default = "default_max_attachment_bytes")] pub max_attachment_bytes: u64,
}
impl Default for GlobalGuards; // all fields as above, max_attachment_bytes = 2 MiB

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    #[serde(default = "...")] pub default_action: Action, // default Allow
    #[serde(default)] pub global: GlobalGuards,
    #[serde(default, rename = "rule")] pub rules: Vec<Rule>,
}
impl Default for Policy; // allow-all, no rules, defaults
impl Policy {
    pub fn from_toml_str(s: &str) -> anyhow::Result<Policy>; // strict parse + validate
    pub fn load(path: &std::path::Path) -> anyhow::Result<Policy>; // read + from_toml_str; on unix warn (tracing::warn) if file is group/other-writable
    // validate: Restrict rules need >=1 capability; Allow/Deny rules must have
    // empty capabilities; default_action must not be Restrict.
    pub fn classify(&self, bug: &BugMeta, now: chrono::DateTime<chrono::Utc>) -> Access;
    // order: global min_bug_age_days first (missing creation_time => Denied, I4),
    // then rules first-match-wins, then default_action.
    // Every grant (rule or default) strips write caps when global.read_only.
}

// Every field is Option: None means UNKNOWN (absent, null, wrongly typed, or
// only partially recoverable), never "empty". A criterion consulting a None
// field is undecidable, which classify() resolves fail-closed (I4).
#[derive(Debug, Clone, Default)]
pub struct BugMeta {
    pub id: u64,
    pub summary: Option<String>,
    pub product: Option<String>,
    pub components: Option<Vec<String>>, // REST "component" may be string or array
    pub status: Option<String>,
    pub severity: Option<String>,
    pub priority: Option<String>,
    pub keywords: Option<Vec<String>>,
    pub groups: Option<Vec<String>>,     // group names; Some(vec![]) = world-readable
    pub whiteboard: Option<String>,      // "whiteboard", falling back to "status_whiteboard"
    pub creation_time: Option<chrono::DateTime<chrono::Utc>>,
}
impl BugMeta {
    // Tolerant on SHAPE (component as string or array, group elements as
    // names or {name} objects, either whiteboard key) but never invents a
    // value: a list with an unreadable element is None, not a shorter list.
    pub fn from_json(v: &serde_json::Value) -> BugMeta;
}

#[derive(Debug, Clone)]
pub enum Access {
    Denied { rule: String },
    Granted { caps: std::collections::BTreeSet<Capability>, rule: String },
}
impl Access {
    pub fn allows(&self, cap: Capability) -> bool; // Granted+contains, or cap==Summary && contains Read (I6)
}
```

### src/guard.rs

```rust
pub const SUMMARY_FIELDS: &[&str] = &[
    "id","summary","status","resolution","product","component",
    "severity","priority","creation_time","last_change_time",
];

pub struct Guard { pub policy: Policy }
impl Guard {
    /// Exact I2 text.
    pub fn denial(id: u64) -> String; // format!("Bug {id} is not accessible through this server")

    /// Fetch CLASSIFY_FIELDS with exactly ONE request per DISTINCT id,
    /// sequentially, whatever each answer turns out to be: the upstream
    /// request count is a function of the requested ids alone, never of the
    /// verdicts (I2). No batching — Bugzilla signals a nonexistent id by
    /// failing the whole request but a withheld one by omitting it from a
    /// success, so any batch-failure reaction spends different work on "no
    /// such bug" than on "hidden bug". Per-id also makes batch poisoning
    /// impossible, which is what the former retry existed to repair.
    /// A response is credited to an id only when the SERVER labels it with
    /// that id. Any id failing or absent from its own response =>
    /// (Access::Denied{rule:"unavailable".into()}, Value::Null).
    /// Every requested id has an entry in the returned map (fail closed, I4).
    /// Bounded by Guard::MAX_ASSESS_IDS (25): ids past the bound are denied
    /// without being fetched, so a caller that forgets to check cannot turn
    /// one call into an unbounded run of requests. Tools refuse over-long id
    /// lists outright (server::too_many_ids) rather than answering partially.
    pub const MAX_ASSESS_IDS: usize;

    pub async fn assess(&self, bz: &crate::client::BugzillaClient, key: &str, ids: &[u64])
        -> std::collections::BTreeMap<u64, (Access, serde_json::Value)>;

    /// SUMMARY_FIELDS projection of a bug object + "_redacted": true marker.
    pub fn summary_view(bug: &serde_json::Value) -> serde_json::Value;

    /// Classify each bug: full read kept as-is, summary-only replaced by
    /// summary_view, denied dropped. Returns (kept, dropped_count) — the count
    /// is for server-side logging ONLY, never sent to the client (I3).
    pub fn filter_bug_list(&self, bugs: Vec<serde_json::Value>) -> (Vec<serde_json::Value>, usize);

    /// Drops is_private comments unless include_private && policy allows (I5).
    pub fn filter_comments(&self, comments: Vec<serde_json::Value>, include_private: bool) -> Vec<serde_json::Value>;

    /// Same I5 double opt-in for private attachment METADATA (listing).
    pub fn filter_attachments(&self, attachments: Vec<serde_json::Value>, include_private: bool) -> Vec<serde_json::Value>;

    /// Uniform denial text for attachments (I2 analogue): blocked and
    /// nonexistent attachment ids must be indistinguishable.
    pub fn attachment_denial(id: u64) -> String; // "Attachment {id} is not accessible through this server"

    /// Pre-download gate on attachment METADATA (run before the blob fetch,
    /// I8): private needs the I5 double opt-in and a MISSING is_private flag
    /// counts as private on download (stricter than listing; the blob is the
    /// payload, fail closed I4); reported size must fit
    /// global.max_attachment_bytes (0 = no cap; missing size under an active
    /// cap fails closed; the refusal names neither the size nor the cap —
    /// max_attachment_bytes is not I1-disclosable). Returns
    /// Some(refusal_text) when blocked.
    pub fn attachment_gate(&self, attachment: &serde_json::Value, include_private: bool) -> Option<String>;
}
```

### src/client.rs

```rust
pub const CLASSIFY_FIELDS: &str =
    "id,summary,product,component,status,resolution,severity,priority,keywords,groups,whiteboard,creation_time,last_change_time";

pub struct BugzillaClient { /* base_url, api_url = base_url + "/rest", reqwest::Client (30s timeout), use_auth_header */ }
impl BugzillaClient {
    pub fn new(base_url: &str, use_auth_header: bool) -> anyhow::Result<Self>; // trims trailing '/'
    pub fn base_url(&self) -> &str;
    pub async fn version(&self, key: &str) -> anyhow::Result<String>;
    pub async fn server_info(&self, key: &str) -> anyhow::Result<serde_json::Value>;
    pub async fn get_bugs(&self, key: &str, ids: &[u64], include_fields: Option<&str>) -> anyhow::Result<serde_json::Value>;
    pub async fn bug_history(&self, key: &str, id: u64, new_since: Option<chrono::DateTime<chrono::Utc>>) -> anyhow::Result<serde_json::Value>;
    pub async fn bug_comments(&self, key: &str, id: u64, new_since: Option<chrono::DateTime<chrono::Utc>>) -> anyhow::Result<Vec<serde_json::Value>>;
    pub async fn add_comment(&self, key: &str, id: u64, comment: &str, is_private: bool) -> anyhow::Result<serde_json::Value>;
    pub async fn quicksearch(&self, key: &str, query: &str, status: &str, include_fields: &str, limit: u32, offset: u32) -> anyhow::Result<serde_json::Value>;
    pub async fn update_bug(&self, key: &str, id: u64, payload: serde_json::Value) -> anyhow::Result<serde_json::Value>;
    pub async fn attachments(&self, key: &str, id: u64) -> anyhow::Result<serde_json::Value>;
    pub async fn quicksearch_syntax_html(&self) -> anyhow::Result<String>;
    pub async fn attachment_meta(&self, key: &str, attachment_id: u64) -> anyhow::Result<Option<serde_json::Value>>; // exclude_fields=data
    pub async fn attachment_data(&self, key: &str, attachment_id: u64) -> anyhow::Result<Option<serde_json::Value>>; // includes base64 `data`
}
```

Endpoint mapping:

| method | request | returns |
|---|---|---|
| version | GET /rest/version | `.version` string |
| server_info | concurrent GET /rest/version, /rest/extensions, /rest/time, /rest/parameters | `{url, version, extensions, timezone: tz_name, time: web_time, parameters}` |
| get_bugs | GET /rest/bug?id=1,2,3[&include_fields=..] | whole envelope |
| bug_history | GET /rest/bug/{id}/history[?new_since=%Y-%m-%dT%H:%M:%SZ] | `bugs[0].history` array as Value |
| bug_comments | GET /rest/bug/{id}/comment[?new_since=..] | `bugs.{id}.comments` as Vec<Value> |
| add_comment | POST /rest/bug/{id}/comment `{comment, is_private}` | envelope |
| quicksearch | GET /rest/bug?quicksearch={status}+" "+{query}&include_fields=..&limit=..&offset=..&order=relevance | envelope |
| update_bug | PUT /rest/bug/{id} with caller-built payload (caller adds `"comment": {"body": ..}` when set) | envelope |
| attachments | GET /rest/bug/{id}/attachment?exclude_fields=data | `envelope.bugs.{id}` array as Value |
| attachment_meta | GET /rest/bug/attachment/{attachment_id}?exclude_fields=data | `envelope.attachments.{id}` object, `None` when absent |
| attachment_data | GET /rest/bug/attachment/{attachment_id} | `envelope.attachments.{id}` object incl. base64 `data`, `None` when absent |
| quicksearch_syntax_html | GET {base_url}/page.cgi?id=quicksearch.html (no auth needed) | HTML string |

Auth per request: `use_auth_header` ? header `Authorization: Bearer {key}` :
query param `api_key={key}`. Always `Accept: application/json`.
Errors: non-2xx status or body `{"error": true}` => anyhow error containing the
HTTP status and Bugzilla `message` field; reqwest errors sanitized with
`.without_url()` (I12).

## MCP tool surface (crates/bugwarden/src/server.rs)

Result convention: success => `CallToolResult::success` with ONE text block of
pretty-printed JSON. The sole exception is `download_attachment`, which
returns a JSON summary text block PLUS one image or blob-resource block. Guard refusals and input-validation failures =>
`CallToolResult::error` with a text block (NOT a protocol error). Protocol
issues (missing API key header) => `McpError::invalid_request`.

Tool descriptions: concise and action-oriented; state the defaults and
constraints the model must know.

| tool | params (schemars struct) | guard capability | notes |
|---|---|---|---|
| bug_info | bug_ids: Vec<u64> | per-id: Read => full, else Summary => redacted, else restricted entry | envelope `{"bugs":[..], "restricted":[{"id":N,"note":denial(N)}]}`; full fetch only for Read-granted ids. Every fetched body is RE-CLASSIFIED before it is served (assemble_bug_info): the verdict came from the classification fetch and the body from a later request, so a bug embargoed in between must not be served on the stale verdict (TOCTOU; same reason download_attachment re-checks). Costs no request — the body is a superset of CLASSIFY_FIELDS — and a body that now earns only summary is served as the summary view, one that earns nothing becomes the uniform restricted entry. A failed body fetch is logged server-side ONLY and leaves those ids restricted: Bugzilla's message names the bug and says whether it exists, so forwarding it would undo I2 |
| bug_history | id, new_since?: DateTime<Utc> | history | |
| bug_comments | id, include_private: bool = false, new_since? | comments | filter_comments applied (I5) |
| bugs_quicksearch | query, status: String = "ALL", include_fields: String = "id,product,component,assigned_to,status,resolution,summary,last_change_time", limit: u32 = 50, offset: u32 = 0 | post-filter | fetch include_fields = requested ∪ CLASSIFY_FIELDS; after filter, project kept bugs to requested fields (keep `_redacted` marker); envelope `{"bugs":[..]}` only (I3) |
| add_comment | bug_id, comment, is_private: bool = false | comment (write) | |
| update_bug_status | bug_id, status, resolution?, comment: String = "" | status (write) | CLOSED requires resolution (error otherwise); when reopening (status not CLOSED/VERIFIED and no resolution given) set `"resolution": ""` |
| assign_bug | bug_id, assignee (email), comment = "" | assign (write) | payload `{"assigned_to": ..}` |
| update_bug_fields | bug_id, priority?, severity?, resolution?, custom_fields?: JsonObject, comment = "" | fields (write) | at least one field required; custom_fields keys must start with `cf_` (I7) |
| update_bug_dependencies | bug_id, blocks_add?/blocks_remove?/depends_on_add?/depends_on_remove?: Vec<u64>, comment = "" | deps (write) | at least one change required; payload uses `{"blocks": {"add": [..], "remove": [..]}}` shape |
| add_cc_to_bug | bug_id, cc_email | cc (write) | payload `{"cc": {"add": [email]}}` |
| mark_as_duplicate | bug_id, duplicate_of, comment = "" | status on bug_id + summary on duplicate_of (I11) | default comment "Marking as duplicate of bug {duplicate_of}"; payload status CLOSED, resolution DUPLICATE, dupe_of |
| list_attachments | bug_id | attachments | metadata only (`exclude_fields=data`) |
| download_attachment | attachment_id, include_private: bool = false | attachments (on the owning bug) | metadata fetched FIRST (no blob) for guard assessment + attachment_gate; unknown id, metadata OR blob fetch failure, denied owning bug, missing bug_id, and private-without-opt-in all yield the uniform attachment denial. Constant upstream request count on every path (a metadata miss still runs one classify call against bug id 0) so call latency is not an existence oracle. The gate AND the bug-id check re-run on the blob response (TOCTOU), then the actual base64 size is re-checked against the cap (a lying `size` cannot bypass it). Raster image types from a strict allowlist => ContentBlock::image; everything else (incl. image/svg+xml) => BlobResourceContents whose uri carries only the attachment id (uploader-chosen file_name never enters the uri) |
| bug_url | bug_id | none (I8 exception) | `{base_url}/show_bug.cgi?id={id}` |
| bugzilla_server_info | — | none | client.server_info |
| quicksearch_syntax | — | none | HTML doc page |
| mcp_server_info | — | none | version (CARGO_PKG_VERSION), bugzilla server url, transport, and policy summary per I1 |
| summarize_bug | id | comments | fetches comments (private filtered with include_private=false), returns the summarization prompt text (fixed prompt template) |

## CLI (crates/bugwarden/src/config.rs)

clap derive `Cli`, with env fallbacks:

| flag | env | default | notes |
|---|---|---|---|
| --bugzilla-server | BUGZILLA_SERVER | required | base URL |
| --transport | MCP_TRANSPORT | http | http \| stdio (clap ValueEnum) |
| --host | MCP_HOST | 127.0.0.1 | http only |
| --port | MCP_PORT | 8000 | http only |
| --api-key-header | MCP_API_KEY_HEADER | ApiKey | http per-request key header |
| --api-key | BUGZILLA_API_KEY | — | required for stdio; warn-and-ignore for http |
| --use-auth-header | — | false | Bearer to Bugzilla instead of api_key query param |
| --read-only | MCP_READ_ONLY | false | tighten-only (I9) |
| --policy | BUGWARDEN_POLICY | — | path to guard policy TOML |

Startup validation: stdio without api_key => exit with error; http with
api_key => tracing::warn (ignored).

## rmcp 2.2 usage notes

Cached reference files (read them): `/tmp/counter.rs` (tool_router + #[tool] +
Parameters + #[tool_handler] ServerHandler + get_info), `/tmp/cstdio.rs`
(stdio main), `/tmp/chttp.rs` (StreamableHttpService + axum main),
`/tmp/rmcp-toolrouter.rs` (ToolRouter API incl. remove_route/has_route).

- `rmcp = { version = "2.2", features = ["server", "macros", "transport-io", "transport-streamable-http-server"] }`
- axum MUST be 0.8 (rmcp's version — extension extraction breaks otherwise);
  schemars 1.x with feature `chrono04`; tokio 1; tokio-util 0.7.
- Server struct: `#[derive(Clone)] pub struct BugWarden { cfg: Arc<Cli>, guard: Arc<Guard>, bz: Arc<BugzillaClient>, tool_router: ToolRouter<Self> }`
- `BugWarden::new` builds `Self::tool_router()` then `remove_route` for write
  tools when read-only and for every `global.disabled_tools` entry (I13).
  Write tool names: add_comment, update_bug_status, assign_bug,
  update_bug_fields, update_bug_dependencies, add_cc_to_bug, mark_as_duplicate.
- API key resolution: stdio => `cfg.api_key`; http => `ctx.extensions.get::<axum::http::request::Parts>()`, then `parts.headers.get(lowercased_header_name)`.
- HTTP serving: `StreamableHttpService::new(move || Ok(server.clone()), LocalSessionManager::default().into(), StreamableHttpServerConfig::default())`, `axum::Router::new().nest_service("/mcp", service)`, `tokio::net::TcpListener::bind`, graceful shutdown on ctrl_c.
- Tracing to stderr always (stdout belongs to the stdio transport).

## Testing

- Unit tests (#[cfg(test)] in policy.rs/guard.rs): glob matching; first-match
  ordering; embargo group deny; min_bug_age_days incl. missing creation_time
  (fail closed); younger_than_days matcher; restrict caps; read-implies-summary;
  read_only strips write caps; default deny; summary redaction; comment
  filtering; validation errors (unknown TOML keys, restrict without caps).
- Unit tests (#[cfg(test)] in crates/bugwarden/src/server.rs): assemble_bug_info
  re-classification — a body embargoed after the verdict is refused, a body
  that now earns only summary is downgraded, a body granting neither read nor
  summary is refused, and refused/absent/up-front-denied ids yield byte-
  identical restricted entries; the distinct-id bound.
- Integration tests (crates/bugwarden-core/tests/guard_wiremock.rs, wiremock):
  assess() deny for embargoed group; min-age deny; one request per distinct
  id whatever the answer (nonexistent vs withheld cost the same), repeated
  ids fetched once, no batch to poison; per-id
  fallback fail closed; comment privacy; error mapping; API key absent from
  error text (I12).
- CI: `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
  `cargo test --workspace --locked`, `cargo deny check`.
