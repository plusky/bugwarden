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
  streamable-HTTP transports. Depends on `bugwarden-core`. The crate also
  has a lib target (`lib.rs` re-exporting `config` and `server`) consumed by
  `main.rs` and by the integration tests under `crates/bugwarden/tests/`,
  which drive the MCP tools end to end; a binary-only crate would leave the
  tool gates untestable (a mutation deleting a guard call from a tool body
  survived every test while only the pure helpers were covered). The
  supported product remains the binary; the lib API carries no stability
  promise.

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
  response, or a CONSULTED rule that cannot be decided because the bug object
  did not carry a field that rule asks about (absent, null, wrongly typed, or
  only partially recoverable — including an unparsable `creation_time`) =>
  Denied. The identity criterion `created_by_me` extends "field the rule asks
  about" beyond the bug object: it is undecidable when the bug's `creator` is
  unreadable OR the caller's identity did not resolve (whoami failure), and
  it resolves through this same machinery with no special case (see
  "Identity resolution"). The consulted rules are those whose `operations` cover the
  operation being classified (see classify): a rule scoped away from the
  operation is skipped before its matcher runs and can neither grant nor
  deny there — scoping changes which rules are consulted, never how a
  consulted rule resolves. Unreadable metadata never yields more access than
  readable metadata would: it satisfies no granting rule, and it does not let
  a bug slip past a consulted rule that would otherwise have caught it.
- **I14** A bug id the policy would deny must not appear inside something the
  client IS shown: dependency/duplicate/see_also fields of a served bug,
  history changes naming other bugs, or Bugzilla's auto-generated duplicate
  marker comments. The bar is `Capability::Summary` — the same one the write
  paths apply before CREATING such a link (I8/I11), since a link read out and
  a link written in disclose the same fact. Candidate ids come from Bugzilla,
  not the client, so they are assessed in ONE batched request (Guard::
  disclosable) rather than per id; a failed fetch scrubs everything (I4).
  Applies to bug_info, bugs_quicksearch (the client picks the projection, so
  it can ask for link fields), bug_history, bug_comments and summarize_bug.
  Only ids actually SERVED in the same response are exempt — a requested id
  that was DENIED must not be whitelisted, or asking about a hidden bug
  reveals it through the links of one the client may read.
  Known limits, deliberate: free-text comments naming a bug number are not
  touched (unfixable without destroying comments); the duplicate-marker match
  covers both stock templates but not localised/customised ones; and an
  instance reachable under a second hostname is not recognised in see_also
  (scheme and case are).
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
- **I15** The audit stream is never reachable through any MCP surface.
  When auditing is enabled, every tool call produces exactly one audit
  record, persisted before the response is returned. The API key and
  free-text bug content are unrepresentable in the audit event type.
  Client-visible responses are byte-identical with auditing on, off, or
  failing — except the scoped fail-closed refusals, which reuse the tools'
  existing uniform failure texts and never vary with the guard's verdict.

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
    Create,      // write: file a NEW bug (judged against the bug AS REQUESTED)
    Attach,      // write: upload an attachment (read side is Attachments)
}
impl Capability {
    pub const ALL: [Capability; 13];
    pub fn is_write(self) -> bool; // Comment|Status|Fields|Assign|Cc|Deps|Create|Attach
}
```

**Upgrade hazard — Capability::ALL grew from 11 to 13.** `create` and
`attach` joined `ALL`, and every `allow` rule and `default_action = "allow"`
grants ALL: an existing deployment that upgrades WITHOUT touching its policy
file silently starts permitting bug filing (`create_bug`) and attachment
upload (`add_attachment`) wherever it previously granted `allow`. An
operator who wants the pre-upgrade surface must either add
`disabled_tools = ["create_bug", "add_attachment"]` under `[global]`
(removes the tools from the listing outright, I13), or replace `allow`
grants with `restrict` rules enumerating exactly the old eleven
capabilities. `read_only` deployments are unaffected — both new
capabilities are writes and stay stripped. This trade (new capabilities
join `allow` automatically) is deliberate — `allow` means "everything this
server can do", and a frozen enumeration would silently exclude every
future capability instead — but it must be called out in release notes
whenever ALL grows.

```rust

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
    // The one identity-relative criterion: true selects bugs AUTHORED by the
    // requesting account, false everyone else's (see "Identity resolution").
    // TOML spelling `created_by_me = true|false`; absent = not consulted.
    // Older bugwarden versions reject a policy carrying the key at startup
    // (strict parsing fails closed) — same story as `operations`.
    #[serde(default)] pub created_by_me: Option<bool>,
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

// TOML spellings "create" / "access". `create` is the classification of a
// PROSPECTIVE bug performed by Guard::may_create; `access` is every
// classification of an EXISTING bug (retrieval, list filtering, comments,
// history, attachments, link disclosure, updates).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation { Create, Access }

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub name: String,
    #[serde(default)] pub description: String,
    #[serde(rename = "match", default)] pub matcher: Matcher,
    pub action: Action,
    #[serde(default)] pub capabilities: Vec<Capability>, // only for action = "restrict"
    // Operations this rule is consulted for; an ABSENT key means every
    // operation (the behaviour of every pre-existing policy, unchanged).
    // An explicitly written empty list is a validation error.
    #[serde(default)] pub operations: Option<Vec<Operation>>,
}
impl Rule {
    // Absent list, or a list containing `op`. (A hand-constructed empty
    // list — unreachable via from_toml_str, which rejects it — counts as
    // unscoped, exactly like the absent field. No fallback for that invalid
    // state is uniformly fail-closed: honouring "applies nowhere" silently
    // skips a deny rule everywhere AND skips a restrict rule under an
    // allowing default — both fail open. The unscoped reading is canonical
    // because it never skips a rule the author wrote; rejection is
    // validation's job.)
    pub fn applies_to(&self, op: Operation) -> bool;
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
    // empty capabilities; default_action must not be Restrict; a written
    // `operations = []` is an error (a rule applying to no operation is dead
    // configuration); a Restrict rule scoped to ONLY `create` must grant
    // exactly the `create` capability (without it the rule could grant
    // nothing reachable, and any other capability it named would be dead —
    // the create gate consults only `create`); a Restrict rule scoped away
    // from `create` must not grant `create` (nothing outside the create
    // gate consults it, so a typoed scope would otherwise silently lose
    // both the intended filing grant and the reads the capability list
    // withholds). Unknown operation names are rejected by serde.
    pub fn classify(&self, bug: &BugMeta, now: chrono::DateTime<chrono::Utc>, op: Operation) -> Access;
    // Whether any rule consulted for Operation::Access carries a
    // created_by_me criterion — the laziness gate for whoami (see
    // "Identity resolution"). A rule scoped to ONLY `create` does not
    // count: the create gate forces created_by_me without any lookup.
    pub fn needs_identity(&self) -> bool;
    // order: global min_bug_age_days first (missing creation_time => Denied, I4;
    // the gate is global, never operation-scoped — it deliberately refuses
    // creation too, since may_create dates the prospective bug NOW), then
    // rules first-match-wins CONSULTING ONLY the rules whose `operations`
    // cover `op`, then default_action. The operation scope is checked BEFORE
    // the rule's matcher is evaluated: a rule scoped away from `op` is fully
    // invisible to that classification — it can neither match nor fail
    // closed through the MatchOutcome::Unknown path (a create-only rule must
    // never deny a read over unreadable metadata; it is not consulted at
    // all). For the rules that ARE consulted, the Unknown => Denied
    // resolution (I4) is unchanged.
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
    // Some(true/false) = established bug–caller relationship; None = it
    // cannot be known (creator unreadable OR caller identity unresolved).
    pub created_by_me: Option<bool>,
}
impl BugMeta {
    // Tolerant on SHAPE (component as string or array, group elements as
    // names or {name} objects, either whiteboard key) but never invents a
    // value: a list with an unreadable element is None, not a shorter list.
    // `caller` is the requesting account's login (Guard::resolve_caller);
    // created_by_me = Some(login ==(case-insensitively, to_lowercase — the
    // glob normalization) bug "creator") only when BOTH the caller and a
    // string-typed creator are known, else None.
    pub fn from_json(v: &serde_json::Value, caller: Option<&str>) -> BugMeta;
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
    /// verdicts (I2). No batching — how a batch answers for an id it will not
    /// serve is deployment-dependent (stock /rest/bug?id=.. omits it, other
    /// versions and proxies fail the request), and the old retry-on-failure
    /// therefore spent different work on "no such bug" than on "hidden bug"
    /// wherever failure is the behaviour. Per-id also makes batch poisoning
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

    // limit/offset address VISIBLE bugs: scan upstream from row 0 in chunks,
    // classify, fill the window from survivors. Bounded by MAX_SEARCH_WINDOW
    // (1000 addressable) and 2000 scanned rows; truncation looks like the end
    // of results. Returns the classified objects themselves.
    pub struct SearchRequest<'a> { query, status, include_fields: &'a str, limit, offset: u32 }
    pub const MAX_SEARCH_WINDOW: u32;

    // I14 link scrubbing. Candidate ids come from Bugzilla, not the client,
    // so ONE batched classify (bounded, and always issued — an empty set
    // still costs a request, or "no links" and "all links hidden" differ by
    // the clock). Summary bar, the same one the write paths use.
    pub const LINKED_ID_FIELDS: &[&str];
    pub async fn disclosable(&self, bz: &BugzillaClient, key: &str,
        ids: &BTreeSet<u64>, caller: Option<&str>) -> BTreeSet<u64>;
    pub fn linked_bug_ids(bug: &Value, base_url: &str) -> BTreeSet<u64>;
    pub fn scrub_bug_links(bug: &mut Value, base_url: &str, ok: &BTreeSet<u64>);
    pub fn history_bug_ids(history: &Value, base_url: &str) -> BTreeSet<u64>;
    pub fn scrub_history(history: Value, base_url: &str, ok: &BTreeSet<u64>) -> Value;
    pub fn duplicate_marker_id(text: &str) -> Option<u64>;      // both stock templates
    pub fn duplicate_marker_ids(comments: &[Value]) -> BTreeSet<u64>;
    pub fn scrub_duplicate_markers(comments: Vec<Value>, ok: &BTreeSet<u64>) -> Vec<Value>;
    pub async fn quicksearch_window(&self, bz: &BugzillaClient, key: &str,
        req: &SearchRequest<'_>, caller: Option<&str>) -> anyhow::Result<Vec<serde_json::Value>>;

    // The `caller` parameter on assess/quicksearch_window/disclosable/
    // filter_bug_list is the identity resolved ONCE per tool call by
    // resolve_caller and threaded to every classification within that call
    // — none of these methods performs a lookup of its own (see "Identity
    // resolution").
    pub async fn assess(&self, bz: &crate::client::BugzillaClient, key: &str, ids: &[u64],
        caller: Option<&str>)
        -> std::collections::BTreeMap<u64, (Access, serde_json::Value)>;

    /// Lazy per-tool-call identity resolution: None WITHOUT any HTTP
    /// request when !policy.needs_identity(); otherwise exactly one
    /// GET /rest/whoami, with every failure mapped to None (sanitized
    /// error debug-logged only, I12). See "Identity resolution".
    pub async fn resolve_caller(&self, bz: &BugzillaClient, key: &str) -> Option<String>;

    /// SUMMARY_FIELDS projection of a bug object + "_redacted": true marker.
    pub fn summary_view(bug: &serde_json::Value) -> serde_json::Value;

    /// Classify each bug: full read kept as-is, summary-only replaced by
    /// summary_view, denied dropped. Returns (kept, dropped_count) — the count
    /// is for server-side logging ONLY, never sent to the client (I3).
    pub fn filter_bug_list(&self, bugs: Vec<serde_json::Value>, caller: Option<&str>) -> (Vec<serde_json::Value>, usize);

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

    /// Create gate: classify the bug AS REQUESTED (BugMeta::from_json over
    /// the create payload) and require Capability::Create. There is no bug
    /// to fetch yet, so the request is what is judged — the same rules that
    /// hide a product BY NAME refuse filing into it, with no second
    /// vocabulary. A field the request does not carry is unknown, not
    /// empty, and fails closed (I4). The request is evidence only for
    /// fields Bugzilla takes verbatim (the created bug matches the claim or
    /// creation fails upstream); `groups` is NOT one of them — Bugzilla
    /// UNIONS the product's mandatory groups into whatever was claimed, so
    /// the claimed group list is forced to unknown (None) whatever the
    /// payload said. Taking `groups: []` as fact would make claiming a
    /// field strictly MORE permissive than omitting it and file straight
    /// past a group deny rule into a security-* embargo product.
    /// Consequence, deliberate and documented: a rule consulting `groups`
    /// or `group_restricted` refuses every create request that REACHES it —
    /// the answer cannot be known before the bug exists — so creation is
    /// possible only where an earlier rule covering the create operation
    /// grants `create` first, and a policy with no such earlier grant
    /// refuses all creation. The request is classified with Operation::Create: rules
    /// scoped to `operations = ["access"]` are not consulted here, and a
    /// rule scoped to `operations = ["create"]` exists only here, which is
    /// how an operator grants filing into a product ahead of the
    /// group-consulting rules WITHOUT that grant becoming the first-match
    /// rule for the product's existing bugs (issue #26). creation_time is
    /// forced to NOW, whatever the payload claims, so an age rule refuses
    /// creation wherever it would immediately hide the result.
    /// created_by_me is forced to Some(true) unconditionally — the creator
    /// of a bug being filed is definitionally the caller (Bugzilla assigns
    /// `creator` server-side; the typed create params cannot claim it), so
    /// NO whoami is ever performed for the create gate. Consequence: a
    /// create-covering rule with created_by_me = true matches every create
    /// request that reaches it; with created_by_me = false it can never
    /// match a create.
    pub fn may_create(&self, requested: &Value) -> bool;

    /// Uniform refusal for a bug that was not filed: one fixed text, naming
    /// no rule and no criterion (I1), whatever tripped it. Callers MUST
    /// return this same text for a policy refusal AND an upstream failure —
    /// two texts would let a client pair a guaranteed-invalid field with a
    /// probe payload and read the policy off which refusal came back, free
    /// and silent (see the create_bug tool row).
    pub fn create_denial() -> String; // "Filing this bug is not permitted through this server"
}
```

### src/client.rs

```rust
pub const CLASSIFY_FIELDS: &str =
    "id,summary,product,component,status,resolution,severity,priority,keywords,groups,whiteboard,creation_time,last_change_time,creator";

pub struct BugzillaClient { /* base_url, api_url = base_url + "/rest", reqwest::Client (30s timeout), use_auth_header */ }
impl BugzillaClient {
    pub fn new(base_url: &str, use_auth_header: bool) -> anyhow::Result<Self>; // trims trailing '/'
    pub fn base_url(&self) -> &str;
    pub async fn version(&self, key: &str) -> anyhow::Result<String>;
    pub async fn whoami(&self, key: &str) -> anyhow::Result<String>; // login; missing/non-string/blank "name" = failure
    pub async fn server_info(&self, key: &str) -> anyhow::Result<serde_json::Value>;
    pub async fn get_bugs(&self, key: &str, ids: &[u64], include_fields: Option<&str>) -> anyhow::Result<serde_json::Value>;
    pub async fn bug_history(&self, key: &str, id: u64, new_since: Option<chrono::DateTime<chrono::Utc>>) -> anyhow::Result<serde_json::Value>;
    pub async fn bug_comments(&self, key: &str, id: u64, new_since: Option<chrono::DateTime<chrono::Utc>>) -> anyhow::Result<Vec<serde_json::Value>>;
    pub async fn add_comment(&self, key: &str, id: u64, comment: &str, is_private: bool) -> anyhow::Result<serde_json::Value>;
    pub async fn create_bug(&self, key: &str, payload: serde_json::Value) -> anyhow::Result<serde_json::Value>;
    pub async fn add_attachment(&self, key: &str, id: u64, payload: serde_json::Value) -> anyhow::Result<serde_json::Value>;
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
| whoami | GET /rest/whoami | `.name` string (the account's login); missing/non-string/blank = error |
| server_info | sequential GET /rest/version, /rest/extensions, /rest/time, /rest/parameters | `{url, version, extensions, timezone: tz_name, time: web_time, parameters}` |
| get_bugs | GET /rest/bug?id=1,2,3[&include_fields=..] | whole envelope |
| bug_history | GET /rest/bug/{id}/history[?new_since=%Y-%m-%dT%H:%M:%SZ] | `bugs[0].history` array as Value |
| bug_comments | GET /rest/bug/{id}/comment[?new_since=..] | `bugs.{id}.comments` as Vec<Value> |
| add_comment | POST /rest/bug/{id}/comment `{comment, is_private}` | envelope |
| create_bug | POST /rest/bug with caller-built payload | envelope (`{"id": N}`) |
| add_attachment | POST /rest/bug/{id}/attachment with caller-built payload (`ids` names the bug) | envelope (`{"ids": [..]}`) |
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

## Identity resolution (the `created_by_me` matcher)

`created_by_me` is the one identity-relative matcher criterion: it describes
the bug–caller relationship (did the requesting account author this bug?)
where every other criterion describes bug content. Decisions, all deliberate:

- **Source.** The caller's login comes from `GET /rest/whoami` (the `name`
  field; a missing, non-string, or blank — empty or all-whitespace — value
  is a FAILED resolution, never an empty login: a blank identity must not
  compare equal to a blank `creator` and grant on no evidence),
  authenticated and error-sanitized exactly like every other client
  call (I12). It is compared case-insensitively (`to_lowercase`, the same
  normalization the glob matcher applies) against the bug's `creator`
  field, which joined `CLASSIFY_FIELDS` for this purpose. A non-string
  `creator` leaves the relationship unknown. "The requesting account" is
  whatever key custody says authenticates: per-request http custody gives
  each caller their own identity, while `Server` custody (stdio, or http
  server-held mode — see "Key custody") resolves EVERY caller to the one
  account that owns the server's key; under server-held http custody the
  collapse is warned about at startup.
- **Laziness.** `Policy::needs_identity()` = some rule whose `operations`
  cover `Operation::Access` carries a `created_by_me` criterion. When it is
  false, `Guard::resolve_caller` returns `None` without any HTTP request —
  a policy that never consults identity costs ZERO whoami lookups, so
  pre-identity deployments keep their exact upstream request pattern. A
  create-scoped-only identity rule does not trigger lookups either: the
  create gate forces the answer (below).
- **At most once per MCP tool call.** Each tool resolves the caller at most
  once, near its entry, and threads the result to EVERY classification in
  that call — `Guard::assess`, `quicksearch_window`, `disclosable`,
  `filter_bug_list`, including the synchronous re-check inside
  `assemble_bug_info`. The threading is load-bearing: if that re-check ran
  with `caller = None` under an identity policy, a bug the assessment
  granted on the caller's authorship would be dropped by the re-check.
  Nothing is cached across tool calls (uniform for stdio and http; a
  per-session cache is a possible future optimization, deliberately not
  done now). The whoami count is a function of the policy alone — never of
  verdicts or upstream answers — so it opens no timing oracle.
- **Failure => Unknown => I4, no special case.** A whoami failure maps the
  caller to `None`; a `created_by_me` criterion evaluated without a caller
  (or without a readable creator) yields `MatchOutcome::Unknown`, and the
  existing I4 machinery resolves it: a consulted rule that cannot be
  decided denies the bug, whatever its action. Consequence, INTENDED: if
  the policy consults identity and whoami fails, every classification
  consulting the rule denies — a policy that leads with an identity rule
  blacks out on whoami failure. This is the only uniformly fail-closed
  reading. The alternative — resolving identity-unknown as "criterion
  fails" — would let a `created_by_me = true` DENY rule be dodged by
  making whoami fail (fail open), exactly the asymmetry I4 exists to
  forbid.
- **Create gate: forced true, no lookup.** `may_create` forces the
  prospective bug's `created_by_me` to `Some(true)` unconditionally: the
  creator of a bug being filed is definitionally the caller — Bugzilla
  assigns `creator` server-side from the authenticating account, and
  bugwarden's typed `create_bug` parameters cannot claim it. No whoami is
  ever performed for the create gate. So a create-covering rule with
  `created_by_me = true` matches every create request that reaches it, and
  one with `created_by_me = false` can never match a create.
- **Cannot widen exposure beyond the credential.** Bugzilla still enforces
  its own access control on every fetch, so an authorship rule only
  surfaces bugs the API key's account could already read — it narrows the
  guard-credential gap, never escapes it.
- **Deliberately not implemented.** `assigned_to_me` and `cc_me` are the
  natural extensions of this mechanism; they are intentionally absent, not
  forgotten.

## MCP tool surface (crates/bugwarden/src/server.rs)

Result convention: success => `CallToolResult::success` with ONE text block of
pretty-printed JSON. The sole exception is `download_attachment`, which
returns a JSON summary text block PLUS one image or blob-resource block. Guard refusals and input-validation failures =>
`CallToolResult::error` with a text block (NOT a protocol error). Protocol
issues (missing API key header in per-request custody) =>
`McpError::invalid_request`.

### Key custody

Who authenticates to Bugzilla is resolved exactly ONCE, at startup
(`Cli::resolve_key_custody` => `KeyCustody`, stored on the server; called
inside `BugWarden::new` so EVERY construction path fails at startup, never
at first request). The whole table:

| transport | `--api-key` | `--api-key-file` | custody |
|---|---|---|---|
| any | set | set | startup error — mutually exclusive, names both flags |
| stdio | set | — | `Server(key)` |
| stdio | — | set | `Server(key from file)` |
| stdio | — | — | startup error |
| http | — | set | `Server(key from file)` — server-held mode |
| http | set | — | `tracing::warn` + ignored => `PerRequest` |
| http | — | — | `PerRequest` |

An empty `--api-key` counts as absent; so does an empty `--api-key-file`
path (`BUGZILLA_API_KEY_FILE=` is the set-but-empty "unset" idiom of systemd
units and container specs). Decisions, all deliberate:

- **`Server` custody** (stdio, or http server-held mode): the running
  server owns the one key `String`; every request is served with it and the
  per-request key header is NEVER consulted — a request that carries one is
  SERVED (with the server's key), not rejected, and the header value is
  never read. The key file is read once at startup; rotation requires a
  restart (no per-request re-read, no SIGHUP reload).
- **Identity collapses under server-held http custody.** Every client
  authenticates — and therefore resolves identity — as the service account
  that owns the key, so `created_by_me` describes that ONE account's bug
  reports for all clients, never an individual caller's (see "Identity
  resolution"). A policy written for per-request custody changes meaning
  when redeployed with `--api-key-file`, so `BugWarden::new` emits a
  `tracing::warn` when server-held http custody meets a policy that
  consults identity (`Policy::needs_identity`).
- **`PerRequest` custody** (http without a key file): each request must
  carry the key header; a missing key is `McpError::invalid_request`.
- **No fallback between custodies, in either direction.** Server-held mode
  exists so fleet clients can hold NOTHING — a client holding the real key
  could bypass the guard by talking to Bugzilla directly — so falling back
  to a client-supplied header would defeat the mode's point. And http with
  `--api-key` alone stays per-request (warn + ignore, never a silent
  upgrade): `BUGZILLA_API_KEY` is a generic env name other Bugzilla tooling
  sets, and flipping it to server-held would change deployed custody
  semantics.
- **Key file handling**: `read_to_string` then `trim`; empty after trim or
  unreadable => startup error naming the PATH only, never file contents
  (I12). On unix, a file accessible by group or others draws a
  `tracing::warn` recommending 0600 (the read-bit analogue of the policy
  file's write-bit warning). The startup log line states mode and source
  only — never key material (I12).

Tool descriptions: concise and action-oriented; state the defaults and
constraints the model must know.

| tool | params (schemars struct) | guard capability | notes |
|---|---|---|---|
| bug_info | bug_ids: Vec<u64> | per-id: Read => full, else Summary => redacted, else restricted entry | envelope `{"bugs":[..], "restricted":[{"id":N,"note":denial(N)}]}`; full fetch only for Read-granted ids. Every fetched body is RE-CLASSIFIED before it is served (assemble_bug_info): the verdict came from the classification fetch and the body from a later request, so a bug embargoed in between must not be served on the stale verdict (TOCTOU; same reason download_attachment re-checks). Costs no request — the body is a superset of CLASSIFY_FIELDS — and a body that now earns only summary is served as the summary view, one that earns nothing becomes the uniform restricted entry. A failed body fetch is logged server-side ONLY and leaves those ids restricted: Bugzilla's message names the bug and says whether it exists, so forwarding it would undo I2 |
| bug_history | id, new_since?: DateTime<Utc> | history | |
| bug_comments | id, include_private: bool = false, new_since? | comments | filter_comments applied (I5) |
| bugs_quicksearch | query, status: String = "ALL", include_fields: String = "id,product,component,assigned_to,status,resolution,summary,last_change_time", limit: u32 = 50, offset: u32 = 0 | post-filter | fetch include_fields = requested ∪ CLASSIFY_FIELDS; after filter, project kept bugs to requested fields (keep `_redacted` marker); envelope `{"bugs":[..]}` only (I3), except an advisory `note` when the query is nothing but bug ids (comma/whitespace-separated, optional `#` per id) steering exact id sets to bug_info — the note is a pure function of the CLIENT'S REQUEST (the query and status strings), never of results, verdicts, or anything upstream said (no new oracle), and the `bugs` array is byte-identical with or without it (the query is still searched, never rerouted); its wording tracks the request: a non-empty status is prefixed to the query so upstream content-matches the whole expression, while an empty status sends the query bare and Bugzilla routes a bare all-number query to an exact id lookup (bug_id + anyexact) — on that path the note drops the content-matching claim — and a query naming more distinct ids than MAX_ASSESS_IDS steers to batched bug_info calls (the cap is already public in the too_many_ids refusal text) instead of straight into that refusal | **limit/offset address the bugs the client may SEE, not upstream rows** (Guard::quicksearch_window): filtering an already-paginated page left a hole exactly where a hidden bug sat — a short page the next offset contradicted — and since quicksearch matches summary text that hole was a probe for the hidden title, one word at a time. The guard now scans upstream from row 0 in 200-row chunks, classifies each, and fills the window from the survivors; rows are deduped on the server-reported id (relevance order is not stable between calls) and an id-less row is dropped (I4). Bounds: MAX_SEARCH_WINDOW=1000 addressable, 2000 rows scanned (<=10 sequential requests); hitting either truncates, which looks exactly like the end of results. The objects returned are the ones classified. The scan target is quantised to whole chunks so the stopping point does not track the client's `limit`; without that, `limit` could be binary-searched against the clock to recover each block's exact hidden count. Residual, accepted: filling a window of VISIBLE bugs needs more rows when bugs are hidden, so a stopwatch still learns one bit per scanned block ("not entirely visible"). Removing that would mean scanning the worst case on every search, or letting pages go short again. Search failure returns a bare "Search failed"; the upstream text is logged server-side only (it can name a bug and say whether it exists) |
| create_bug | product, component, summary, version, description = "", severity?, priority?, op_sys?, platform?, keywords?: Vec<String>, groups?: Vec<String> | create (write), judged on the bug AS REQUESTED (Guard::may_create) | there is no bug id to assess, so the request itself is classified BEFORE any upstream call (I8): the rules that hide a product by name refuse filing into it, a field the request omits fails closed (I4), and a client-claimed `groups` list is never trusted — Bugzilla unions the product's mandatory groups in server-side, so may_create forces groups to unknown, which means a group-consulting rule refuses every create request that REACHES it — creation is possible only where an earlier rule covering the create operation grants it (a rule carrying `operations = ["create"]`, placed ahead of the group-consulting rules, is how an operator permits filing without that grant shadowing reads of existing bugs — issue #26), and a policy with no such grant refuses all creation. **Both refusals are one refusal**: a policy refusal and an upstream failure return the same fixed create_denial text after the same single upstream request — the refused path burns one classify call against bug id 0 (never a valid id, creates nothing; download_attachment's padding precedent) instead of the POST. Two texts, or 0 vs 1 requests, would be a free policy-enumeration oracle: send a guaranteed-invalid `version` plus a probe product and read the policy off which refusal (or which latency) comes back, with nothing created. Residual, accepted: a SUCCESSFUL create still confirms the product is allowed — that is the tool doing its job, and it costs a real, attributable bug; and the padding equalizes request count, not the upstream handler's exact latency (GET classify vs rejected POST). Bugzilla's failure message is logged server-side only (it can say whether a product/component exists) |
| add_attachment | bug_id, data (base64), file_name, summary, content_type, comment = "", is_private = false, is_patch = false | attach (write) on bug_id | guard assessment before the upload (I8), uniform denial (I2); then global.max_attachment_bytes caps the DECODED size of `data` (0 = no cap) — the ceiling the operator set on downloads binds uploads through the same server too, measured after base64 expansion is stripped so encoding overhead cannot shrink it. The refusal names neither the payload's size nor the cap value (max_attachment_bytes is not I1-disclosable, exactly as on the download path). `comment` travels as a PLAIN string — Bug.add_attachment documents it so; the `{"comment": {"body": ..}}` shape belongs to Bug.update only |
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
| --api-key | BUGZILLA_API_KEY | — | required for stdio unless --api-key-file provides it; warn-and-ignore for http (never a silent upgrade to server-held) |
| --api-key-file | BUGZILLA_API_KEY_FILE | — | file holding the key (container secret / systemd LoadCredential path); mutually exclusive with --api-key; over http selects server-held key mode (see Key custody) |
| --use-auth-header | — | false | Bearer to Bugzilla instead of api_key query param |
| --read-only | MCP_READ_ONLY | false | tighten-only (I9) |
| --policy | BUGWARDEN_POLICY | — | path to guard policy TOML |
| --audit-config | BUGWARDEN_AUDIT_CONFIG | — | path to audit configuration TOML; without it no audit stream is written |

Startup validation: key custody is resolved by `Cli::resolve_key_custody`
inside `BugWarden::new` (see Key custody) — --api-key together with
--api-key-file, stdio without any key source, and an empty or unreadable
key file all exit with an error (the key-file errors name the path only,
I12); http with api_key => tracing::warn (ignored). main.rs adds: http
without audit_config => tracing::warn (remote tool calls leave no audit
record).

## Audit stream (crates/bugwarden/src/audit.rs + the server.rs wrapper)

The operator-side record of what was asked and what the guard decided —
the counterpart of the client-side invisibility the invariants mandate.
Decisions, all deliberate:

- **One record per call (I15).** The hand-written `call_tool` owns the
  record; tools only enrich it through a per-request cell in the request
  extensions (verdict worst-wins merged, suppressed ids unioned). An
  unknown tool, a protocol error, or a missed enrichment still yields
  exactly one record — a poorer record is possible, an audit gap is not.
  The record is persisted (sink is synchronous) before the response is
  returned. `initialize` is always recorded, with no configuration knob
  to turn it off; `list_tools` is not recorded in schema v1 — no event
  kind exists for a listing, deliberately.
- **Boundary.** Records go only to the operator's JSONL file (0600,
  parent 0700) — never stderr, never any MCP surface. The schema has no
  field that could carry the API key or free-text bug content; client
  parameters pass a key allowlist (identifiers and routing/vocabulary
  fields by value, strings capped at 1024 chars) and every other key is
  recorded as `{"_len": N}` — presence and size, never content.
- **Fail modes** (`fail_mode` in audit.toml): `open` keeps serving and
  accounts for the outage with an `audit_gap` record; `closed_writes_denials`
  refuses writes and any call where the guard suppressed, denied, or
  refused something; `closed_all` refuses every call. Unset, the mode derives
  from the transport: stdio → `open` (availability for a single local
  user), http → `closed_all` (accountability for a fleet). A sink
  already in failure also gates matching calls BEFORE dispatch, so an
  outage cannot be farmed for unaudited upstream work.
- **Refusals are not a fingerprint.** A fail-closed refusal reuses the
  tool's existing uniform failure text, chosen by tool name alone; a
  protocol error from the router stands unchanged (swapping it would
  create an outage-only distinguisher). Every routed tool must have a
  refusal mapping (tested against the full router).
- **Record provenance.** `guard.policy_hash` is `sha256:<hex>` over the
  policy file bytes, so a record ties to the exact policy that produced
  it (`None` under the built-in default policy). stdio sessions are
  anchored by `<pid>-<startup epoch>`; http sessions by the
  `mcp-session-id` header, with the remote address when the listener
  provides connect-info.

## rmcp 2.2 usage notes

Cached reference files (read them): `/tmp/counter.rs` (tool_router + #[tool] +
Parameters + #[tool_handler] ServerHandler + get_info), `/tmp/cstdio.rs`
(stdio main), `/tmp/chttp.rs` (StreamableHttpService + axum main),
`/tmp/rmcp-toolrouter.rs` (ToolRouter API incl. remove_route/has_route).

- `rmcp = { version = "2.2", features = ["server", "macros", "transport-io", "transport-streamable-http-server"] }`
- axum MUST be 0.8 (rmcp's version — extension extraction breaks otherwise);
  schemars 1.x with feature `chrono04`; tokio 1; tokio-util 0.7.
- Server struct: `#[derive(Clone)] pub struct BugWarden { cfg: Arc<Cli>, guard: Arc<Guard>, bz: Arc<BugzillaClient>, tool_router: ToolRouter<Self>, key_custody: KeyCustody, audit: Option<Arc<AuditState>> }`
- `BugWarden::new` builds `Self::tool_router()` then `remove_route` for write
  tools when read-only and for every `global.disabled_tools` entry (I13).
  Write tool names: add_comment, update_bug_status, assign_bug,
  update_bug_fields, update_bug_dependencies, add_cc_to_bug, mark_as_duplicate,
  create_bug, add_attachment.
- API key resolution: a match on `key_custody` (resolved once at startup, see Key custody — never re-read per request): `Server(key)` => the server's key, without touching the request at all; `PerRequest` => `ctx.extensions.get::<axum::http::request::Parts>()`, then `parts.headers.get(lowercased_header_name)`.
- HTTP serving: `StreamableHttpService::new(move || Ok(server.clone()), LocalSessionManager::default().into(), StreamableHttpServerConfig::default())`, `axum::Router::new().nest_service("/mcp", service)`, `tokio::net::TcpListener::bind`, graceful shutdown on ctrl_c.
- Tracing to stderr always (stdout belongs to the stdio transport).

## Testing

- Unit tests (#[cfg(test)] in policy.rs/guard.rs): glob matching; first-match
  ordering; embargo group deny; min_bug_age_days incl. missing creation_time
  (fail closed); younger_than_days matcher; restrict caps; read-implies-summary;
  read_only strips write caps — create and attach named explicitly, and a
  restrict grant of comment grants neither; default deny; summary redaction;
  comment filtering; validation errors (unknown TOML keys, restrict without
  caps); may_create — a hidden product refuses filing, an omitted field the
  policy consults fails closed (I4), a claimed group list NEVER decides a
  group rule (omitted, `[]`, and non-matching claims are all refused alike;
  a group_restricted policy refuses all creation; a group rule ruled out by
  another criterion does not block), a creation_time claimed by the payload
  is ignored in favour of NOW, restrict must name "create", and the
  create_denial text is fixed; operation scoping — the issue-#26
  reproduction fixed (a create-scoped restrict rule ahead of a
  group-restricted deny rule under an allowing default: existing
  non-restricted bugs in matched products fall through to a full grant,
  group-restricted bugs stay denied, may_create succeeds for the matched
  product and still fails closed elsewhere, and a preceding name-deny rule
  still refuses creation), a create-scoped rule is skipped BEFORE its
  matcher runs so it never denies access classification through the
  Unknown fail-closed path while the same rule without `operations` still
  does (I4 unchanged), an access-scoped rule is invisible to may_create,
  the global age gate is not operation-scoped, read_only strips a
  create-scoped grant so may_create refuses (I9), the TOML spellings
  "create"/"access" are pinned, a hand-constructed `operations` list that
  is EMPTY (unreachable via from_toml_str) is pinned unscoped for both
  operations — a deny rule carrying it still denies instead of being
  skipped into an allowing default — and validation rejects
  `operations = []`, unknown operation names, a restrict rule scoped to
  only `create` whose capabilities are not exactly `create`, and a
  restrict rule scoped away from `create` that grants `create`; the
  shipped examples/policy.toml is pinned end to end against its own
  header: it parses, accepts filing into the desktop products, refuses an
  embargo-marked title everywhere, refuses filing elsewhere (omitted and
  claimed group lists alike), keeps existing world-readable desktop bugs
  fully readable (the issue-#26 regression surface), and keeps
  group-restricted desktop bugs denied; created_by_me — the TOML spelling
  `created_by_me = true|false` is pinned and an absent key is None;
  evaluate semantics ((true, Some(true)) holds, (true, Some(false)) fails,
  (true, None) is Unknown and a consulted rule then denies for a deny rule
  AND a restrict rule alike — the uniformity is pinned — and
  (false, Some(false)) holds); BugMeta::from_json establishes
  created_by_me only from a string creator plus a resolved caller (equal,
  unequal, case-insensitively equal; absent/non-string creator and a None
  caller are all None); needs_identity is false for a policy without
  identity criteria, true for an access-covering identity rule, and FALSE
  when the only identity rule is operations = ["create"]; may_create
  forces created_by_me true without any client or whoami (a create-covering
  deny rule on created_by_me = true refuses creation, one on
  created_by_me = false never matches a create); and the shipped-example
  pin extends to identity: with the caller known, a group-restricted bug
  the caller authored grants exactly read/comments/history/attachments and
  no write, the same bug authored by someone else stays Denied, and with
  identity UNKNOWN both it and a world-readable desktop bug are Denied —
  the whoami-failure blackout is pinned so it cannot be "fixed" into
  fail-open later.
- Unit tests (#[cfg(test)] in crates/bugwarden/src/server.rs): assemble_bug_info
  re-classification — a body embargoed after the verdict is refused, a body
  that now earns only summary is downgraded, a body granting neither read nor
  summary is refused, and refused/absent/up-front-denied ids yield byte-
  identical restricted entries; the distinct-id bound; read-only delists
  create_bug and add_attachment (I13); the upload size gate measures decoded
  (never base64-encoded) bytes, is disabled at 0, and its refusal names no
  number; and stdio without any key source fails at `BugWarden::new`
  construction, never at first request.
- Unit tests (#[cfg(test)] in crates/bugwarden/src/config.rs): the key
  custody table — the mutual-exclusion error names both flags (each pinned
  with its env var, since `--api-key` is a substring of `--api-key-file`);
  empty, whitespace-only, and unreadable key files error naming the path;
  the file's content is trimmed (`"the-key\n"` => `Server("the-key")`);
  stdio resolves the key from the file as well as from --api-key; http with
  --api-key alone stays `PerRequest` (warn-and-ignore pinned against a
  silent upgrade to server-held custody); an empty --api-key-file value
  counts as absent; the startup log line states mode and source, never key
  material (I12); `Cli`'s Debug redacts the startup key (I12); and
  server-held http custody under an identity-consulting policy warns at
  construction (crates/bugwarden/src/server.rs) that created_by_me now
  describes the service account for every client.
- Integration tests (crates/bugwarden-core/tests/guard_wiremock.rs, wiremock):
  quicksearch_window — pages stay full while visible bugs remain (no hole),
  consecutive pages tile the visible sequence disjointly (against a stable
  upstream order; an unstable one can drop a bug from every page, which hides
  more rather than less), a hidden bug never shortens a page, a deep offset is
  an empty page whether or not bugs were hidden, the scan bound is counted in
  requests, the scan target does not track `limit`, id-less rows are dropped,
  rows repeated across chunks are served once, exhaustion and scan truncation look alike, zero limit
  touches nothing, and the returned objects are the classified ones;
  assess() deny for embargoed group; min-age deny; one request per distinct
  id whatever the answer (nonexistent vs withheld cost the same), repeated
  ids fetched once, no batch to poison; per-id
  fallback fail closed; comment privacy; error mapping; API key absent from
  error text (I12); create_bug and add_attachment endpoint mapping (payload
  travels untouched to POST /rest/bug and /rest/bug/{id}/attachment);
  whoami endpoint mapping (GET /rest/whoami => the `name` login; a missing,
  non-string, or blank — empty/whitespace-only — name is a failure), the
  API key absent from a whoami transport error (I12), resolve_caller's
  laziness (zero requests without an identity criterion, one request with,
  failure mapped to None), and the classify projection itself — the bug
  mock answers only an include_fields carrying `creator`, so dropping the
  field from CLASSIFY_FIELDS fails the caller's-own-bug classification
  instead of passing on a fixture that volunteers fields nobody requested.
- Integration tests (crates/bugwarden/tests/tools_wiremock.rs, wiremock +
  rmcp client over an in-memory duplex transport): the tools are CALLED
  through a real MCP session, so a tool that stops calling its guard fails
  a test rather than only a helper suite. Minimum bar: create_bug policy
  refusal and upstream refusal are byte-identical and each cost exactly one
  upstream request (nothing POSTed on the refused path, which instead burns
  a classify call against bug id 0); a claimed `groups` list never defeats
  a group deny rule and a group_restricted policy refuses all creation;
  an allowed create reaches POST /rest/bug; a create-scoped rule placed
  ahead of a group-restricted deny rule both files into its products (the
  POST is reached) and leaves existing bugs in them searchable
  (issue #26); add_attachment refuses on a
  grant carrying `attachments` (read) without `attach` (write) and uploads
  on `attach`; the upload size cap refuses before anything is POSTed; the
  attachment `comment` travels as a plain string (Bug.add_attachment
  API shape), pinned by a wiremock body matcher; and identity end to end —
  issue #33's exact scenario (a my-own-reports restrict rule above a
  group_restricted deny: with whoami answering the caller, a
  group-restricted bug the caller authored is readable through bug_info
  while the same bug under a foreign creator takes the uniform denial), a
  whoami 500 makes the caller's own bug byte-identical to the
  foreign-creator denial (no oracle), the call-count contract (wiremock
  expect(1) whoami hits for one tool call under an identity policy,
  expect(0) under a policy without identity criteria), the caller threading
  beyond bug_info (the caller's own group-restricted bug stays in a
  bugs_quicksearch window while a foreign one is dropped, and serves its
  comments through bug_comments and its history through bug_history while
  a foreign one takes the uniform denial — every tool threads the caller
  by hand, so each pinned tool is its own mutation surface), the caller
  reaching a write gate (a carve-out granting `comment` on the caller's
  own reports POSTs the comment for the caller's bug and refuses a
  foreign one with nothing POSTed), and a whoami transport error leaking
  no API key into any client-visible text (I12).
- Integration tests (crates/bugwarden/tests/http_transport_wiremock.rs,
  wiremock + rmcp client over REAL streamable HTTP — the only harness in
  which the per-request key header physically exists; the wiremock upstream
  proves WHICH key served a request through an `api_key` query-param
  matcher): server-held mode serves a client presenting no credential at
  all, with the key file's trailing newline trimmed end to end; a
  client-sent key header in server-held mode is SERVED with the server's
  key — never rejected, never read, and nothing authenticating with the
  header's value reaches Bugzilla (expect(0) on that key); per-request mode
  still authenticates with the client's header; a missing header in
  per-request mode is a protocol-level invalid_request costing zero
  upstream requests; the key is resolved once at startup (rewriting the key
  file mid-flight changes nothing — the old key keeps serving); and the
  guard's uniform denial text is byte-identical over http (I2 transport
  parity).
- Audit tests (crates/bugwarden/tests/audit_wiremock.rs + #[cfg(test)] in
  server.rs and audit.rs): one record per call for EVERY routed tool,
  refusal paths and protocol errors included; the refusal map is total
  over the full router; responses byte-identical with auditing off, on,
  and failing-open; suppressed ids in the record and never in the
  envelope; content and API-key canaries never reach the file; the
  fail-closed scopes (pre-dispatch gate proven by upstream request
  counts) via the sink's cfg(test) fault injection; the transport-derived
  fail-mode defaults bound to their documented wording; the params
  allowlist (free text to `_len`, 1024-char truncation).
- CI: `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
  `cargo test --workspace --locked`, `cargo deny check`.
