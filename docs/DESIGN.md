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
  response, or missing/unparsable `creation_time` when an age rule applies =>
  Denied.
- **I5** Private comments (`is_private: true`) are returned only when policy
  `global.allow_private_comments = true` AND the call sets
  `include_private = true`. Default policy (no file) has
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
    Attachments, // list attachment metadata
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
    #[serde(default)] pub younger_than_days: Option<i64>,  // creation_time newer than now-N days; missing creation_time => matches (fail closed)
}
impl Matcher {
    pub fn matches(&self, bug: &BugMeta, now: chrono::DateTime<chrono::Utc>) -> bool;
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

#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GlobalGuards {
    #[serde(default)] pub min_bug_age_days: i64,        // 0 = disabled
    #[serde(default)] pub allow_private_comments: bool, // default false
    #[serde(default)] pub read_only: bool,
    #[serde(default)] pub disabled_tools: Vec<String>,
}

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

#[derive(Debug, Clone, Default)]
pub struct BugMeta {
    pub id: u64,
    pub product: String,
    pub components: Vec<String>, // REST "component" may be string or array
    pub status: String,
    pub severity: String,
    pub priority: String,
    pub keywords: Vec<String>,
    pub groups: Vec<String>,     // group names
    pub whiteboard: String,
    pub creation_time: Option<chrono::DateTime<chrono::Utc>>,
}
impl BugMeta {
    pub fn from_json(v: &serde_json::Value) -> BugMeta; // tolerant: missing fields => defaults
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

    /// Fetch CLASSIFY_FIELDS for ids in one batch; if the batch call fails,
    /// retry each id individually; any id still failing or absent from the
    /// response => (Access::Denied{rule:"unavailable".into()}, Value::Null).
    /// Every requested id has an entry in the returned map (fail closed, I4).
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
| quicksearch_syntax_html | GET {base_url}/page.cgi?id=quicksearch.html (no auth needed) | HTML string |

Auth per request: `use_auth_header` ? header `Authorization: Bearer {key}` :
query param `api_key={key}`. Always `Accept: application/json`.
Errors: non-2xx status or body `{"error": true}` => anyhow error containing the
HTTP status and Bugzilla `message` field; reqwest errors sanitized with
`.without_url()` (I12).

## MCP tool surface (crates/bugwarden/src/server.rs)

Result convention: success => `CallToolResult::success` with ONE text block of
pretty-printed JSON. Guard refusals and input-validation failures =>
`CallToolResult::error` with a text block (NOT a protocol error). Protocol
issues (missing API key header) => `McpError::invalid_request`.

Tool descriptions: concise and action-oriented; state the defaults and
constraints the model must know.

| tool | params (schemars struct) | guard capability | notes |
|---|---|---|---|
| bug_info | bug_ids: Vec<u64> | per-id: Read => full, else Summary => redacted, else restricted entry | envelope `{"bugs":[..], "restricted":[{"id":N,"note":denial(N)}]}`; full fetch only for Read-granted ids |
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
- Integration tests (crates/bugwarden-core/tests/guard_wiremock.rs, wiremock):
  assess() deny for embargoed group; min-age deny; batch failure => per-id
  fallback fail closed; comment privacy; error mapping; API key absent from
  error text (I12).
- CI: `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
  `cargo test --workspace --locked`, `cargo deny check`.
