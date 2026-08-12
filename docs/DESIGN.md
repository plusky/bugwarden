# bugwarden — design contract

An MCP server exposing Bugzilla to LLM clients, hardened with
operator-controlled security guards. This document is the binding
contract between modules. If an implementation must deviate, note the deviation
explicitly in your report.

## Architecture

Cargo workspace, two crates:

- `crates/bugwarden-core` — guard policy engine + async Bugzilla REST client.
  MUST NOT depend on rmcp, axum, clap, or any MCP/transport crate.
- `crates/bugwarden` — the binary: clap CLI, rmcp 3.1 MCP server, stdio and
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
  paths apply before CREATING such a link (I8/I11: dependency targets,
  `duplicate_of`, and the local-instance targets of `update_bug_fields`'
  `see_also_add`/`see_also_remove`), since a link read out and a link
  written in disclose the same fact. Candidate ids come from Bugzilla,
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
- **I7** `update_bug_fields.custom_fields` and `create_bug.custom_fields`:
  every key must start with `cf_`; otherwise the tool errors without calling
  Bugzilla (prevents smuggling `groups`/`cc`/`assigned_to` changes through
  the generic updater or the create payload). On `create_bug` the gate runs
  before `may_create` and before any upstream request; unlike the padded,
  uniform create refusal, this early error is safe to distinguish because
  its outcome is a pure function of the client's own key names, not of
  policy or upstream state.
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
- **I16** `bugzilla_products` and `bug_fields` return Bugzilla instance
  metadata (products, components, versions, milestones, bug fields and
  their legal values) exactly as Bugzilla returned it to the caller's own
  key — NEVER filtered against the guard policy. A policy-filtered catalog
  would itself be a policy-enumeration oracle, exactly what `create_bug`'s
  padded uniform refusal exists to deny (cross-reference that row below).
  They return no bug data and no bug ids, so no capability applies and no
  classification runs (I8 does not apply — there is no bug id to assess).
  Both are removed from the tool listing (`ToolRouter::remove_route`,
  I13) unless the operator sets `global.allow_discovery = true`; the
  default is `false`. `components[].default_assigned_to` and
  `default_qa_contact` (account emails) are stripped by the SERVER's own
  projection, never merely omitted from an upstream `include_fields`
  request — the omission is enforced locally, not trusted upstream.

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
    // validate: every rule name is non-blank, unique, and not one the guard
    // decides under itself ("default", "min_bug_age_days", "unavailable",
    // or any name ending in ":unreadable-metadata") — the collision
    // comparisons are exact, so "Default" and " default" stay legal, while
    // the blank check trims; Restrict rules need >=1 capability; Allow/Deny
    // rules must have empty capabilities; default_action must not be
    // Restrict; a written `operations = []` is an error (a rule applying to
    // no operation is dead configuration); a Restrict rule scoped to ONLY
    // `create` must grant exactly the `create` capability (without it the
    // rule could grant nothing reachable, and any other capability it named
    // would be dead — the create gate consults only `create`); a Restrict
    // rule scoped away from `create` must not grant `create` (nothing
    // outside the create gate consults it, so a typoed scope would
    // otherwise silently lose both the intended filing grant and the reads
    // the capability list withholds). Unknown operation names are rejected
    // by serde.
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
    // of results. Returns the classified objects themselves, wrapped in a
    // SearchWindow together with the scan's accounting (issue #29) —
    // server-side only (I3), for the audit record; the client response is
    // built from `bugs` alone.
    pub struct SearchRequest<'a> { query, status, include_fields: &'a str, limit, offset: u32 }
    pub struct SearchWindow { bugs: Vec<serde_json::Value>, scanned: u32, dropped: Vec<u64> }
    pub const MAX_SEARCH_WINDOW: u32;

    // I14 link scrubbing. Candidate ids come from Bugzilla, not the client,
    // so ONE batched classify (bounded, and always issued — an empty set
    // still costs a request, or "no links" and "all links hidden" differ by
    // the clock). Summary bar, the same one the write paths use.
    pub const LINKED_ID_FIELDS: &[&str];
    pub async fn disclosable(&self, bz: &BugzillaClient, key: &str,
        ids: &BTreeSet<u64>, caller: Option<&str>) -> BTreeSet<u64>;
    pub fn linked_bug_ids(bug: &Value, base_url: &str) -> BTreeSet<u64>;
    pub fn see_also_local_id(entry: &str, base_url: &str) -> Option<u64>; // write side reuses the read side's parse
    pub fn scrub_bug_links(bug: &mut Value, base_url: &str, ok: &BTreeSet<u64>);
    pub fn history_bug_ids(history: &Value, base_url: &str) -> BTreeSet<u64>;
    pub fn scrub_history(history: Value, base_url: &str, ok: &BTreeSet<u64>) -> Value;
    pub fn duplicate_marker_id(text: &str) -> Option<u64>;      // both stock templates
    pub fn duplicate_marker_ids(comments: &[Value]) -> BTreeSet<u64>;
    pub fn scrub_duplicate_markers(comments: Vec<Value>, ok: &BTreeSet<u64>) -> Vec<Value>;
    pub async fn quicksearch_window(&self, bz: &BugzillaClient, key: &str,
        req: &SearchRequest<'_>, caller: Option<&str>) -> anyhow::Result<SearchWindow>;

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
    /// summary_view, denied dropped. Returns (kept, dropped_ids) — the ids
    /// are for server-side logging and audit accounting ONLY, never sent to
    /// the client (I3).
    pub fn filter_bug_list(&self, bugs: Vec<serde_json::Value>, caller: Option<&str>) -> (Vec<serde_json::Value>, Vec<u64>);

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

pub struct BugzillaClient { /* base_url, api_url = base_url + "/rest", reqwest::Client (30s timeout + the caller's User-Agent), use_auth_header */ }
impl BugzillaClient {
    pub fn new(base_url: &str, use_auth_header: bool, user_agent: &str) -> anyhow::Result<Self>; // trims trailing '/'; blank or invalid user_agent = error
    pub fn base_url(&self) -> &str;
    pub async fn version(&self, key: &str) -> anyhow::Result<String>;
    pub async fn whoami(&self, key: &str) -> anyhow::Result<String>; // login; missing/non-string/blank "name" = failure
    pub async fn valid_login(&self, key: &str, login: &str) -> anyhow::Result<bool>; // {"result": bool} or bare bool; any other shape = error, never false
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
    pub async fn enterable_product_ids(&self, key: &str) -> anyhow::Result<Vec<u64>>; // .ids, string or number, both accepted
    pub async fn products(&self, key: &str, ids: &[u64], names: &[&str], include_fields: Option<&[&str]>) -> anyhow::Result<serde_json::Value>;
    pub async fn bug_fields(&self, key: &str, name: Option<&str>) -> anyhow::Result<serde_json::Value>; // name is percent-encoded as one path segment
}
```

Endpoint mapping:

| method | request | returns |
|---|---|---|
| version | GET /rest/version | `.version` string |
| whoami | GET /rest/whoami | `.name` string (the account's login); missing/non-string/blank = error |
| valid_login | GET /rest/valid_login?login=\<login\> | boolean: `{"result": bool}` or a bare `bool`; any other shape = error, never read as `false` |
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
| enterable_product_ids | GET /rest/product_enterable | `.ids` as `Vec<u64>`; every element must parse as a numeric string or a JSON number, else error |
| products | GET /rest/product?ids=..&names=..[&include_fields=..] (any of the three may be empty/absent) | whole envelope (`{"products":[..]}`), raw — no local projection at this layer |
| bug_fields | GET /rest/field/bug, or /rest/field/bug/{name} with `name` percent-encoded as one path segment (`Url::path_segments_mut`, never string-interpolated) | whole envelope (`{"fields":[..]}`) |

Auth per request: `use_auth_header` ? header `Authorization: Bearer {key}` :
query param `api_key={key}`. Always `Accept: application/json`.
Errors: non-2xx status or body `{"error": true}` => anyhow error containing the
HTTP status and Bugzilla `message` field; reqwest errors sanitized with
`.without_url()` (I12).

**TLS stack and outbound network behavior.** `reqwest = { version = "0.13",
default-features = false, features = ["json", "query", "rustls",
"system-proxy"] }`. The `rustls` feature (renamed from 0.12's `rustls-tls`)
pulls `rustls-platform-verifier`, so trust anchors come from the **OS trust
store** rather than the bundled Mozilla `webpki-roots` set — deliberate for a
Bugzilla instance behind a corporate or internal CA, and an accepted,
operator-visible change from the previous release. The crypto provider is
`aws-lc-rs`, reqwest 0.13's default (0.12 used `ring`); `aws-lc-sys` needs a C
toolchain at build time, which the release workflow's `ubuntu-latest` and
`macos-latest` runners provide. `system-proxy` keeps `HTTPS_PROXY` /
`HTTP_PROXY` / `NO_PROXY` honored exactly as 0.12 did unconditionally —
without this feature the 0.13 default is to ignore them, which would be a
silent regression for the corporate deployments this server targets. `query`
is likewise required, not cosmetic: `apply_auth`'s `?api_key=` mode and
`quicksearch_syntax_html` both call `.query(...)`, a compile error without
the feature in 0.13.

The operator cost of that switch (issue #65): a deployment with no OS trust
store fails every HTTPS request at first contact with Bugzilla, where the
previous release succeeded from bundled `webpki-roots`, and the symptom is a
TLS handshake error that does not name the missing CA bundle — nothing in
the error points at `ca-certificates`. The fix is the operator's to make:
install `ca-certificates` in the image, or mount the host's bundle into it;
the project ships tarballs, not container images, so containerizing the
binary is a choice made downstream of this repo, without the person making
it necessarily knowing the trust-store dependency exists. The rejected
alternative is keeping the bundled Mozilla roots: rejected because a
distro-packaged tool has to follow the system CA bundle — an admin adding or
revoking a root must take effect without a bugwarden rebuild — and because
bundled roots cannot see the internal CA that the target Bugzilla
deployments sit behind. Re-evaluate only if this project ever ships its own
container image, where the bundle would be under our control instead of the
operator's.

**Caller identity on the wire (issue #55).** Every request carries a
`User-Agent`, set once on the shared `reqwest::Client` so it reaches the
authenticated REST calls and the unauthenticated `page.cgi` fetch alike.
The value is a *parameter*, deliberately: this crate is a library, and a
value built here from its own `CARGO_PKG_*` would name `bugwarden-core` in
the access log of every binary that embeds it — the shape of #53 one layer
down, and just as plausible-looking. The binary supplies
`server::USER_AGENT`, `{name}/{version} (+{repository})` from its own
manifest, and builds its client through `server::bugzilla_client(&cli)` so
the wiring is reachable from a test rather than checkable only by eye.
Consequences that are decisions, not accidents:

- A blank `user_agent` is a construction error, so an embedder cannot get
  an anonymous client back — the state this parameter exists to end —
  from a value that silently resolved to nothing. This binary cannot
  reach it: `USER_AGENT` is a `concat!` of literals and non-empty `env!`s.
- The value is public — it is sent to every configured Bugzilla and lands
  in its access log — so it carries name, version and the project's
  repository and nothing else: no key material, no policy path, no host.
  That is the discipline of **I12** applied to a surface I12 does not
  itself name; the invariant governs logs, error messages and tool
  results, and is not silently widened here.
- **Disclosing the version is accepted, and unlike #53's it is a choice.**
  `serverInfo` had to carry one — it is a required field of
  `InitializeResult` — but a `User-Agent` is optional and nothing was
  disclosed before, so this is a deliberate addition, not a replacement.
  It is accepted because the party learning it is not a passer-by: it is
  the Bugzilla this deployment authenticates to with an API key and sends
  every query. Naming a version tells that operator whether a reported
  misbehaviour is fixed in what is deployed and which builds to allowlist
  — the whole point of #55 — and tells them nothing they could not learn
  by asking the account holder. The exposure is that an operator, or
  anyone reading their access log, can match a fleet against a future
  advisory for this guard; that is the same trade #53 accepted against a
  wider audience.
- It is not operator-configurable. A per-deployment or per-caller identity
  is #32's job (bearer tokens per caller), and a free-text field an
  operator fills in is exactly where deployment detail, or a key, would
  end up.
- With a server-held key (#27) and no per-caller identity yet, one Bugzilla
  account carries a whole fleet's traffic: this header is all that
  distinguishes that traffic from a person with a browser (the value is a
  compile-time constant, identical in every deployment, so it attributes
  the program and never the caller). Hence the binary's wire identity and
  the name it gives in the MCP handshake are asserted to be one build.

## Identity resolution (the `created_by_me` matcher)

`created_by_me` is the one identity-relative matcher criterion: it describes
the bug–caller relationship (did the requesting account author this bug?)
where every other criterion describes bug content. Decisions, all deliberate:

- **Source.** `global.identity_source` (default `"whoami"`) picks how
  `Guard::resolve_caller` gets the caller's login:
  - `"whoami"` — `GET /rest/whoami` (the `name` field; a missing,
    non-string, or blank — empty or all-whitespace — value is a FAILED
    resolution, never an empty login: a blank identity must not compare
    equal to a blank `creator` and grant on no evidence), authenticated
    and error-sanitized exactly like every other client call (I12). "The
    requesting account" is whatever key custody says authenticates:
    per-request http custody gives each caller their own identity, while
    `Server` custody (stdio, or http server-held mode — see "Key custody")
    resolves EVERY caller to the one account that owns the server's key;
    under server-held http custody the collapse is warned about at
    startup.
  - `"declared"` — `global.identity_login` directly, with ZERO HTTP
    requests per call. It is verified once at startup, not per call
    (`BugWarden::preflight`, "Identity preflight" below), against
    `GET /rest/valid_login?login=<login>` — an endpoint Bugzilla Core v1
    DOES define — so it works on a stock deployment `whoami` cannot reach.
    A declared login names the account owning the *server's* key, so it is
    meaningful only under `Server` custody; `BugWarden::new` refuses to
    construct a `declared` + per-request-custody server at all (a hard
    startup error, not a warning — unlike `whoami`, which stays
    per-caller-correct under per-request custody).

  Either source's result is compared case-insensitively (`to_lowercase`,
  the same normalization the glob matcher applies) against the bug's
  `creator` field, which joined `CLASSIFY_FIELDS` for this purpose. A
  non-string `creator` leaves the relationship unknown.
  `Policy::validate` rejects `identity_source = "declared"` without a
  non-blank `identity_login`, and rejects `identity_login` set under
  `identity_source = "whoami"` (a silently-ignored key is exactly the class
  of typo `deny_unknown_fields` exists to catch elsewhere) — both hard
  startup errors. `valid_login` compares logins the way Bugzilla's own
  `Bugzilla->login` does: Perl `eq`, case-sensitively — a declared login
  differing only in case fails closed at startup, not at some later
  `created_by_me` evaluation.
- **Laziness.** `Policy::needs_identity()` = some rule whose `operations`
  cover `Operation::Access` carries a `created_by_me` criterion. When it is
  false, `Guard::resolve_caller` returns `None` without any HTTP request,
  under EITHER source — a policy that never consults identity costs ZERO
  lookups, so pre-identity deployments keep their exact upstream request
  pattern. A create-scoped-only identity rule does not trigger lookups
  either: the create gate forces the answer (below).
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
  forbid. `identity_source = "declared"` has no equivalent per-call failure
  mode: the login was already verified at startup, so `resolve_caller`
  always returns `Some` there — the only way to blackout under `declared`
  is to never start (see "Identity preflight").
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
- **Portability.** `GET /rest/whoami` is not in the current Bugzilla Core v1
  REST reference (`login`, `logout`, `valid_login`, `user`, `version`,
  `extensions`, `timezone`, `time`, `last_audit_time`, `parameters`) — it is
  a fork/BMO extension. On a stock deployment every lookup fails, every
  `created_by_me` criterion is `Unknown`, and I4 denies everything a
  `created_by_me` rule is consulted for: a blackout, not a narrower grant.
  `identity_source = "declared"` is the portable answer: it never calls
  `whoami` at all, verifying the operator's declared login once at startup
  against `valid_login` instead — an endpoint the same reference DOES
  document. The source × custody matrix:

  | `identity_source` | stdio / http server-held key | http per-request key |
  |---|---|---|
  | `whoami` (default) | verified at startup (`BugWarden::preflight`); one `GET /rest/whoami` per tool call | unverifiable at startup (warns instead); one `GET /rest/whoami` per tool call |
  | `declared` | verified once at startup via `GET /rest/valid_login`; **zero** identity requests per tool call | **startup error** (`BugWarden::new`) — no server-held key for the declared login to describe |

  Because of the `whoami` row's stock-deployment gap, `examples/policy.toml`
  ships its `created_by_me` rule ("my-own-reports") commented out —
  documented as an opt-in the operator enables only after either
  confirming their Bugzilla answers `whoami`, or declaring and verifying a
  login instead — rather than active by default. `BugWarden::preflight`
  (see "MCP tool surface") turns an unconfirmed `whoami` deployment into a
  loud startup failure instead of a silent per-call blackout, and verifies
  a declared login the same way.

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
- **A declared login is a hard error under `PerRequest` custody.**
  `identity_source = "declared"` names the account owning the SERVER's
  key (A5); `PerRequest` custody holds no server-side key at all, so
  `BugWarden::new` refuses to construct — `anyhow::bail!`, not a warning —
  when a `needs_identity()` policy pairs `declared` with `PerRequest`. This
  is stricter than the `whoami` row above precisely because `whoami` stays
  per-caller-correct under `PerRequest` (it just cannot be verified at
  startup); a declared login under `PerRequest` describes nobody.
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

### Identity preflight (`BugWarden::preflight`)

`Guard::resolve_caller` maps every `whoami` failure to `None`, and I4 then
denies every classification a `created_by_me` rule reaches (see "Identity
resolution") — correct, but silent: the server starts, looks healthy, and
blacks out every access classification those rules cover while the cause
sits at `tracing::warn!` on the first tool call. `preflight()` probes the
same endpoint once, BEFORE the server serves a tool call, so a deployment
that cannot answer it fails to start with a named reason instead.

Deliberately a separate `async fn`, not folded into the sync
`BugWarden::new`: `new` is the construction path every integration test in
`tools_wiremock.rs`/`http_transport_wiremock.rs` drives, and moving the
probe there would give each of those tests an unaccounted-for `whoami`
call. `main.rs` calls `server.preflight().await?` right after `new`, BEFORE
the audit sink is opened — the same ordering rationale as key custody
resolution: a failed preflight must not create or rotate an audit file.

Behaviour, by `Policy::needs_identity()`, `global.identity_source` and key
custody:

| `needs_identity()` | `identity_source` | custody | preflight does |
|---|---|---|---|
| false | any | any | `Ok(())`, ZERO upstream requests — the laziness contract now covers startup too |
| true | `whoami` | `Server(key)` | one `GET /rest/whoami`; success logs the resolved login at `info!` and returns `Ok(())`; failure `anyhow::bail!`s naming the endpoint, that stock Bugzilla Core v1 does not define it, and that starting anyway would deny every access classification the policy's identity rules reach (I4) |
| true | `whoami` | `PerRequest` | `tracing::warn!` the same compatibility statement and return `Ok(())` — there is no server-held key to probe with (A5); each caller still resolves identity correctly per call, an unreachable endpoint here only surfaces as a denial once a tool is called |
| true | `declared` | `Server(key)` | one `GET /rest/valid_login?login=<identity_login>`; `true` logs the verified login at `info!` and returns `Ok(())` — `resolve_caller` never looks it up again per call; `false` `anyhow::bail!`s naming the login the key does NOT authenticate as (distinct wording from a transport failure — a wrong login is not a broken key); a transport/parse error `anyhow::bail!`s naming the endpoint |
| true | `declared` | `PerRequest` | unreachable: `BugWarden::new` already refuses to construct this combination (A5) — the match arm still exists and fails closed rather than trusting that invariant silently |

The failure path attaches the sanitized client error (I12: `whoami` /
`valid_login` already strip the URL) as the `anyhow` error's source/context
— no key material reaches the bailed-out message either.

Tool descriptions: concise and action-oriented; state the defaults and
constraints the model must know.

| tool | params (schemars struct) | guard capability | notes |
|---|---|---|---|
| bug_info | bug_ids: Vec<u64> | per-id: Read => full, else Summary => redacted, else restricted entry | envelope `{"bugs":[..], "restricted":[{"id":N,"note":denial(N)}]}`; full fetch only for Read-granted ids. Every fetched body is RE-CLASSIFIED before it is served (assemble_bug_info): the verdict came from the classification fetch and the body from a later request, so a bug embargoed in between must not be served on the stale verdict (TOCTOU; same reason download_attachment re-checks). Costs no request — the body is a superset of CLASSIFY_FIELDS — and a body that now earns only summary is served as the summary view, one that earns nothing becomes the uniform restricted entry. A failed body fetch is logged server-side ONLY and leaves those ids restricted: Bugzilla's message names the bug and says whether it exists, so forwarding it would undo I2 |
| bug_history | id, new_since?: DateTime<Utc> | history | |
| bug_comments | id, include_private: bool = false, new_since? | comments | filter_comments applied (I5) |
| bugs_quicksearch | query, status: String = "ALL", include_fields: String = "id,product,component,assigned_to,status,resolution,summary,last_change_time", limit: u32 = 50, offset: u32 = 0 | post-filter | fetch include_fields = requested ∪ CLASSIFY_FIELDS; after filter, project kept bugs to requested fields (keep `_redacted` marker); envelope `{"bugs":[..]}` only (I3), except an advisory `note` when the query is nothing but bug ids (comma/whitespace-separated, optional `#` per id) steering exact id sets to bug_info — the note is a pure function of the CLIENT'S REQUEST (the query and status strings), never of results, verdicts, or anything upstream said (no new oracle), and the `bugs` array is byte-identical with or without it (the query is still searched, never rerouted); its wording tracks the request: a non-empty status is prefixed to the query so upstream content-matches the whole expression, while an empty status sends the query bare and Bugzilla routes a bare all-number query to an exact id lookup (bug_id + anyexact) — on that path the note drops the content-matching claim — and a query naming more distinct ids than MAX_ASSESS_IDS steers to batched bug_info calls (the cap is already public in the too_many_ids refusal text) instead of straight into that refusal | **limit/offset address the bugs the client may SEE, not upstream rows** (Guard::quicksearch_window): filtering an already-paginated page left a hole exactly where a hidden bug sat — a short page the next offset contradicted — and since quicksearch matches summary text that hole was a probe for the hidden title, one word at a time. The guard now scans upstream from row 0 in 200-row chunks, classifies each, and fills the window from the survivors; rows are deduped on the server-reported id (relevance order is not stable between calls) and an id-less row is dropped (I4). A short page is NOT read as end-of-results — Bugzilla is free to cap a page below the requested chunk size (an admin-configured `max_search_results`, for instance), and that cap looks identical to a short page at the genuine end of a result set; only an empty page ends the scan early. Bounds, independent of each other: MAX_SEARCH_WINDOW=1000 addressable, 2000 rows scanned, and 10 sequential requests; hitting any of the three truncates, which looks exactly like the end of results. The objects returned are the ones classified. The scan target is quantised to whole chunks so the stopping point does not track the client's `limit`; without that, `limit` could be binary-searched against the clock to recover each block's exact hidden count. Residual, accepted: filling a window of VISIBLE bugs needs more rows when bugs are hidden, so a stopwatch still learns one bit per scanned block ("not entirely visible"). Removing that would mean scanning the worst case on every search, or letting pages go short again. Search failure returns a bare "Search failed"; the upstream text is logged server-side only (it can name a bug and say whether it exists). The scan's accounting — rows examined, verdict-dropped ids — goes to the audit record only (`guard.scan` plus the suppressed-ids machinery, issue #29); the response is byte-identical with or without drops |
| create_bug | product, component, summary, version, description = "", severity?, priority?, op_sys?, platform?, keywords?: Vec<String>, groups?: Vec<String>, custom_fields?: JsonObject | create (write), judged on the bug AS REQUESTED (Guard::may_create) | there is no bug id to assess, so the request itself is classified BEFORE any upstream call (I8): the rules that hide a product by name refuse filing into it, a field the request omits fails closed (I4), and a client-claimed `groups` list is never trusted — Bugzilla unions the product's mandatory groups in server-side, so may_create forces groups to unknown, which means a group-consulting rule refuses every create request that REACHES it — creation is possible only where an earlier rule covering the create operation grants it (a rule carrying `operations = ["create"]`, placed ahead of the group-consulting rules, is how an operator permits filing without that grant shadowing reads of existing bugs — issue #26), and a policy with no such grant refuses all creation. **Both refusals are one refusal**: a policy refusal and an upstream failure return the same fixed create_denial text after the same single upstream request — the refused path burns one classify call against bug id 0 (never a valid id, creates nothing; download_attachment's padding precedent) instead of the POST. Two texts, or 0 vs 1 requests, would be a free policy-enumeration oracle: send a guaranteed-invalid `version` plus a probe product and read the policy off which refusal (or which latency) comes back, with nothing created. Residual, accepted: a SUCCESSFUL create still confirms the product is allowed — that is the tool doing its job, and it costs a real, attributable bug; and the padding equalizes request count, not the upstream handler's exact latency (GET classify vs rejected POST). Bugzilla's failure message is logged server-side only (it can say whether a product/component exists). `custom_fields` keys must start with `cf_` (I7): the gate runs before `may_create` and errors with ZERO upstream requests on a non-`cf_` key — distinguishable from the padded create refusal on purpose, since it decides nothing about policy or Bugzilla. No Matcher criterion reads `cf_*`, so a custom field cannot move a prospective bug between rules the way `product`/`component` do. `custom_fields` is not in `PARAM_ALLOWLIST`, so the audit stream records it as `_len`, same as the updater |
| add_attachment | bug_id, data (base64), file_name, summary, content_type, comment = "", is_private = false, is_patch = false | attach (write) on bug_id | guard assessment before the upload (I8), uniform denial (I2); then global.max_attachment_bytes caps the DECODED size of `data` (0 = no cap) — the ceiling the operator set on downloads binds uploads through the same server too, measured after base64 expansion is stripped so encoding overhead cannot shrink it. The refusal names neither the payload's size nor the cap value (max_attachment_bytes is not I1-disclosable, exactly as on the download path). Over http that non-disclosure is partial and knowingly so: the transport's POST body cap is derived from this same value (#52), so its 413 boundary is probeable once the cap exceeds ~2.25 MiB decoded — accepted, with the reasoning, under "rmcp 3.1 usage notes" below. Nothing here changes: this refusal still names neither size nor cap. `comment` travels as a PLAIN string — Bug.add_attachment documents it so; the `{"comment": {"body": ..}}` shape belongs to Bug.update only |
| add_comment | bug_id, comment, is_private: bool = false | comment (write) | |
| update_bug_status | bug_id, status, resolution?, comment: String = "" | status (write) | payload always carries `status`; `resolution` only when the caller gives a non-empty one — no local workflow assumption, no synthesised empty resolution. Bugzilla enforces `missing_resolution` on a closing status with none, and auto-clears any resolution when the target status is open |
| assign_bug | bug_id, assignee (email), comment = "" | assign (write) | payload `{"assigned_to": ..}` |
| update_bug_fields | bug_id, priority?, severity?, resolution?, summary?, url?, whiteboard?, version?, target_milestone?, keywords_add?/keywords_remove?: Vec<String>, see_also_add?/see_also_remove?: Vec<String> (bug URLs), custom_fields?: JsonObject, comment = "" | fields (write) on bug_id + summary on every LOCAL see_also target (I8/I14) | at least one field required — the named params all count, so a call touching only the newer fields is valid, and a call carrying nothing but empty strings/lists still errors without contacting Bugzilla; empty strings and empty lists are ignored (clearing a field is unsupported); keywords and see_also travel as `{"add": [..], "remove": [..]}`, NEVER the replace-all `set` variant; a see_also entry that points at THIS instance is a bug-id link, so its target is assessed like a dependency target — at least `summary`, uniform denial (I2), no PUT on refusal — while entries for other trackers carry no local id and pass through unassessed; custom_fields keys must start with `cf_` (I7) — `see_also` and `keywords` are named params now, and as custom_fields keys they still error before Bugzilla is contacted; free-text values (summary/whiteboard/url) never enter the server log — only which fields a call touched (see "Update-field surface") |
| update_bug_dependencies | bug_id, blocks_add?/blocks_remove?/depends_on_add?/depends_on_remove?: Vec<u64>, comment = "" | deps (write) | at least one change required; payload uses `{"blocks": {"add": [..], "remove": [..]}}` shape |
| add_cc_to_bug | bug_id, cc_email | cc (write) | payload `{"cc": {"add": [email]}}` |
| mark_as_duplicate | bug_id, duplicate_of, comment = "" | status on bug_id + summary on duplicate_of (I11) | default comment "Marking as duplicate of bug {duplicate_of}"; payload carries only `dupe_of` (+ comment) — Bugzilla's `set_dup_id` applies the instance's `duplicate_or_move_bug_status` and resolution DUPLICATE itself, so the resulting status is instance-defined, not necessarily CLOSED |
| list_attachments | bug_id | attachments | metadata only (`exclude_fields=data`) |
| download_attachment | attachment_id, include_private: bool = false | attachments (on the owning bug) | metadata fetched FIRST (no blob) for guard assessment + attachment_gate; unknown id, metadata OR blob fetch failure, denied owning bug, missing bug_id, and private-without-opt-in all yield the uniform attachment denial. Constant upstream request count on every path (a metadata miss still runs one classify call against bug id 0) so call latency is not an existence oracle. The gate AND the bug-id check re-run on the blob response (TOCTOU), then the actual base64 size is re-checked against the cap (a lying `size` cannot bypass it). Raster image types from a strict allowlist => ContentBlock::image; everything else (incl. image/svg+xml) => BlobResourceContents whose uri carries only the attachment id (uploader-chosen file_name never enters the uri) |
| bug_url | bug_id | none (I8 exception) | `{base_url}/show_bug.cgi?id={id}` |
| bugzilla_server_info | — | none | client.server_info |
| bugzilla_products | products?: Vec<String> (max 5) | none — present only when `global.allow_discovery = true` (I16) | no `products` named: `enterable_product_ids` then `products(ids, [], [id,name])`, projected to `{id, name}` catalog entries; `products` named: `products([], names, None)`, projected to `{name, description, is_active, default_milestone, has_unconfirmed, components[{name,description,is_active}], versions[{name,is_active}], milestones[{name,is_active}]}` — `default_assigned_to`/`default_qa_contact` are never selected. Over-cap (>5 names) refuses with a fixed text and makes ZERO upstream requests, since the refusal is a pure function of the request's own shape |
| bug_fields | field_names?: Vec<String> (max 5), on_bug_entry_only: bool = false | none — present only when `global.allow_discovery = true` (I16) | no `field_names`: `bug_fields(None)`, projected per field to `{name, display_name, type, is_custom, is_mandatory, is_on_bug_entry, visibility_field, visibility_values, has_values}` — NEVER `values` — optionally filtered to `is_on_bug_entry` fields; `field_names` named: one `bug_fields(Some(name))` call per name (sequential; Bugzilla's field lookup is single-field), same projection plus `values` as `[{name, is_open?, can_change_to?}]` — `is_open` and `can_change_to: [{name, comment_required}]` present exactly when the upstream value carries them (only `bug_status` does today), omitted rather than `null` on every other field, reported exactly as Bugzilla gave it (I16). Over-cap (>5 names) refuses with a fixed text and makes ZERO upstream requests. A named field Bugzilla does not recognise is a call-level failure (the generic `Failed to fetch bug fields` text), not a partial result |
| quicksearch_syntax | — | none | HTML doc page |
| mcp_server_info | — | none | name (CARGO_PKG_NAME) and version (CARGO_PKG_VERSION), the same two the handshake sends; bugzilla server url, transport, and policy summary per I1 |
| summarize_bug | id | comments | fetches comments (private filtered with include_private=false), returns the summarization prompt text (fixed prompt template) |

### Update-field surface (issue #38)

The full audit of Bugzilla's `PUT /rest/bug/<id>` parameter surface against
the guard model. The split is deliberate and permanent record: every REST
update parameter is either exposed through a named tool/param below or
withheld for the stated reason — nothing is exposed by accident, and
nothing may be smuggled through `custom_fields` (I7).

Exposed:

| REST param | tool / param | capability |
|---|---|---|
| `priority`, `severity`, `resolution`, `cf_*` | `update_bug_fields` | `fields` |
| `summary` | `update_bug_fields.summary` | `fields` |
| `url` | `update_bug_fields.url` | `fields` |
| `whiteboard` | `update_bug_fields.whiteboard` | `fields` |
| `version` | `update_bug_fields.version` (product-scoped vocabulary; Bugzilla validates the value) | `fields` |
| `target_milestone` | `update_bug_fields.target_milestone` (product-scoped vocabulary; Bugzilla validates the value) | `fields` |
| `keywords` (add/remove) | `update_bug_fields.keywords_add` / `keywords_remove` — parity with `create_bug`, which can already set them; the replace-all `set` variant stays withheld as a footgun | `fields` |
| `see_also` (add/remove) | `update_bug_fields.see_also_add` / `see_also_remove` (bug URLs) | `fields`, plus at least `summary` on every target the URL resolves to on THIS instance (I8/I14 — the same bar as dependency targets; foreign-tracker entries are unassessed) |
| `status` + `resolution` | `update_bug_status` | `status` |
| `dupe_of` | `mark_as_duplicate` | `status` |
| `assigned_to` | `assign_bug` | `assign` |
| `cc.add` | `add_cc_to_bug` | `cc` |
| `blocks` / `depends_on` (add/remove) | `update_bug_dependencies` | `deps` |
| `comment` | `add_comment`, plus the optional comment on the write tools that take one (update_bug_status, assign_bug, update_bug_fields, update_bug_dependencies, mark_as_duplicate, add_attachment — add_cc_to_bug does not) | `comment` (write tools: their own capability) |

Withheld, deliberately:

| REST param | why |
|---|---|
| `product`, `component` | the reclassification levers: they change which guard rules match *and* which Bugzilla groups apply server-side. If ever exposed, that wants its own design (and probably its own capability) — a follow-up issue, not this surface. |
| `groups` (add/remove) | directly edits the confidentiality boundary the guard exists to respect. |
| `is_cc_accessible`, `is_creator_accessible`, `comment_is_private` | confidentiality toggles, same reasoning. |
| `flags` | instance-specific approval workflows with high blast radius; own design if ever needed. |
| `alias` | global namespace, niche. |
| `deadline`, `estimated_time`, `remaining_time`, `work_time` | time tracking; no agent use case. |
| `qa_contact`, `reset_qa_contact`, `reset_assigned_to` | not requested; assignee handling stays with `assign_bug`. |
| `cc.remove` | not requested; CC handling stays additive via `add_cc_to_bug`. |
| `op_sys`, `platform` | not requested; trivially addable under `fields` later. |
| new-comment privacy (`comment.is_private` inside the `comment` object) | already handled (and pinned by tests) by `add_comment`'s `is_private` param; the privacy of EXISTING comments is the `comment_is_private` confidentiality toggle withheld above. |
| `ids` (batch update) | one bug per call, so the guard verdict stays exactly per-bug. |
| `keywords`/`see_also` `set` variant | replace-all from a possibly stale view silently wipes concurrent additions. |

On policy relevance: `keywords`, `summary` and `whiteboard` are
matcher-visible (rules can match on them), so writing them lets a caller
move a bug along matcher axes. That is not a new property — `severity`,
`priority` and `status` are matcher-visible and writable today. The bound,
stated precisely: it takes a `fields` grant on the bug's *current*
classification to touch it, so a write can never lift a bug out of a
`deny` — a deny grants nothing, and a denied bug cannot be written at
all. A `restrict` rule that grants `fields` is NOT bounded this way: if
its match criteria include a field `fields` can write
(`summary_contains`, `whiteboard_contains`, `keywords`, `severities`,
`priorities` — or `statuses` under a `status` grant), the rule is
self-defeating — one write rewrites the very field the rule matches on,
classification is never cached, and on the next call the bug falls
through to a later, more permissive rule or to `default_action`, opening
the capabilities the rule withheld. Operators must not grant `fields` in
a restrict rule whose match criteria are fields `fields` can write (the
warning is restated at the restrict examples in `examples/policy.toml`).
The opposite direction is reachable too, and one-way: a write CAN move a
bug INTO a rule that denies it (adding an embargo keyword under the
example policy, say), and because a denied bug is unwritable, that change
cannot be reverted through this server — only an operator with direct
Bugzilla access can undo it. Both directions are the price of `fields`
under a policy whose rules key on writable fields; grant it accordingly.

Semantics kept deliberately narrow: add/remove only, never replace-all;
empty strings are ignored, as for the pre-existing params — clearing a
field (e.g. blanking the whiteboard) stays unsupported until someone needs
it; one bug per call. The free-text values (`summary`, `whiteboard`,
`url`) never appear in the server log — only which fields a call touched
(presence/counts in the tool-entry trace; the audit stream's params
allowlist records them, and the see_also URL lists, as `_len`).
`keywords_add`/`keywords_remove` and `target_milestone` are closed
instance vocabulary — the same class as the already-allowlisted
`keywords` and `version` — and are audit-recorded by value, so the
keyword that hid a bug is recoverable from the audit stream no matter
which tool wrote it.

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
- **Trace enrichment (issue #28).** When a tool call's `params._meta`
  carries a `traceparent` (SEP-414), its trace and span ids are copied
  into the record's `trace` field — the pre-dispatch fail-closed gate
  record included. Validation is strict: exactly the W3C version-00
  layout (55 bytes, `00-<32 lowercase hex>-<16 lowercase hex>-<2
  lowercase hex>`) with non-zero trace and span ids; `ff` and every
  future version are rejected (no lenient forward parsing — ids from a
  format revision the parser cannot fully validate are not stored), and
  anything malformed records nothing rather than something wrong. The
  value is client-controlled bytes headed for operator logs, so it is
  never logged anywhere, valid or not, and it never influences a guard
  decision or a response (I15) — enrichment is unconditional when
  auditing is on, with no configuration knob. The stored ids are
  unauthenticated client claims: any client can stamp any call with any
  well-formed ids — its own probes with an innocent service's ids, or
  unrelated calls with an id an operator is pivoting on — so they are
  correlation hints, never evidence; attribution rests on the record's
  session and client anchoring, not on `trace`. `tracestate` and `baggage`
  are deliberately not stored: the schema has no field for either,
  `tracestate` is client free text, and `baggage` is unbounded client
  key/values — revisit under #34.
- **Search-window drop accounting (issue #29).** A `bugs_quicksearch`
  record carries `guard.scan = {scanned, dropped}`: how many upstream rows
  the window scan examined and how many it dropped by verdict — without
  it, a search that silently withheld many denied rows is
  indistinguishable in the stream from one that withheld none. Pinned
  semantics follow what the scan actually classified: overshoot-region
  denials (past the requested window but inside the quantised chunk) are
  counted, deduped repeats and id-less rows are not (they never reach a
  verdict). The field is present on every served `bugs_quicksearch`
  call — a zero-limit call touches no upstream rows and records
  `{scanned: 0, dropped: 0}`, and a failed search records no scan (the
  error discards its partial accounting along with the window) — so on
  a served search, `dropped: 0` is a statement, not an omission;
  records from before the field existed deserialize with no scan
  (optional field, schema still v1). The dropped IDS ride the existing suppressed-ids machinery —
  unioned into `guard.suppressed_ids` under the same `suppressed_ids`
  config switch, no second knob — while the counts in `scan` are recorded
  regardless of that switch. DELIBERATE verdict change: a search whose
  scan dropped rows now records `served_filtered` (through the worst-wins
  merge; previously such a call recorded `served`), because a search that
  withheld rows IS a filtered serve; a clean scan leaves the verdict
  untouched. Client-invisible by construction (I3): the response is built
  from the window's bugs alone, byte-identical with or without drops.
- **The `guard.rule` encoding (issue #67).** `Access` carries
  `rule: String`, never an `Option`, so every assessment names what
  decided it — the policy default included, under the literal `"default"`.
  That is deliberate, and strictly more informative than absence: it
  separates "the default decided this call" from "no single rule decided
  it", which one absent field cannot express. Beside the operator's own
  names the guard emits three further synthetic ones —
  `"min_bug_age_days"` (the age quarantine, before any rule runs),
  `"<rule>:unreadable-metadata"` (a GRANTING rule whose verdict hinged on
  metadata nobody could read, I4; an undecidable deny rule keeps its plain
  name, having denied for its own reason), and `"unavailable"` (the
  classification fetch never reached the bug). For a policy loaded from
  TOML, validation reserves those spellings against an operator choosing
  the same rule name (issue #84, below), so `rule` names what decided AND
  which kind of thing it was. Absence therefore carries exactly one
  meaning — no single rule decided the call: a refusal answered from the
  request alone, the pre-dispatch gate (the guard never ran), a search
  (the verdict is the window's, not one bug's), the create gate on either
  arm (it judges the request as a whole), an id with no matching
  `Access`, the attachment withhold
  together with its constant-cost bug-0 padding assessment, and a SERVE
  the cell later upgraded to `served_filtered` through a rule-less note —
  a suppression, a redaction, a dropping scan — since that note outranks
  the grant and the worst-wins merge clears the rule with it (a
  `list_attachments` call that dropped private metadata is the plain
  case: the default granted the bug, and the record still names no
  rule). A tool the router never carried (I13) is not this case at all:
  it records no `guard` object. Re-encoding a default decision AS
  absence would be a record-schema change and is deferred to #34; schema
  v1 records `"default"`.
- **What `guard.suppressed_count` totals (issue #68).** The cell keeps two
  tallies: a `BTreeSet` of bug ids the guard withheld (`note_suppressed` —
  I14-scrubbed links, scrubbed duplicate markers, verdict-dropped search
  rows) and a plain counter of suppressed content that HAS no bug id
  (`note_suppressed_count` — private comments in `bug_comments` and
  `summarize_bug`, private attachment metadata in `list_attachments`).
  `suppressed_count` is their SUM. It used to be their maximum, which is
  not a count of anything: a `summarize_bug` call that dropped three
  private comments while scrubbing two duplicate-marker ids recorded
  `3` beside a two-element id list, under-reporting by two and still
  validating. Summing is sound because the populations are disjoint by
  construction — both comment sites derive their marker ids from the
  comments that SURVIVED the private filter, so a dropped comment can
  never also contribute an id, and the attachment site names no ids at
  all; within the id set itself a `BTreeSet` dedupes the overlap between
  the search scan's dropped ids and the link ids scrubbed beside them.
  Disjointness is what makes the sum sound, so it is load-bearing rather
  than incidental: both harvest sites in `server.rs` carry a comment
  saying so, and the fixture behind the record tests plants a duplicate
  marker inside a PRIVATE comment — harvesting pre-filter would count
  that one comment in both tallies and over-report, which is strictly
  worse than the under-report being fixed.
  This matters because I3 forbids telling the CLIENT anything was
  withheld, so the audit stream is the only place the fact surfaces, and
  `suppressed_ids` is gated behind the `suppressed_ids` config switch
  while the count always ships — a maximum cannot be the authoritative
  number the field claims to be.
  ACCEPTED COST, deliberate: no field is added or removed and the wire
  shape is unchanged, so this stays schema v1 — but parseable is not
  comparable, and the change of MEANING inside v1 is undetectable from a
  record. There is no discriminator: an event carries `v`, `ts`, `seq`
  and `session` only, `initialize` records the CLIENT's version and never
  bugwarden's build, `policy_hash` is unchanged unless the operator
  edited policy, and `suppressed_count >= len(suppressed_ids)` holds
  under both readings, so there is no structural tell either. A `v: 1`
  corpus spanning the upgrade therefore carries both readings under one
  version stamp, with the deployed BUILD as the boundary:
  `{suppressed_count: 3, suppressed_ids: [666, 667]}` reads as "3
  withheld" after and "at least 5 withheld" before. The safe reading of a
  pre-upgrade record is "at least `max(suppressed_count,
  len(suppressed_ids))`, possibly more"; a consumer that asserted
  equality between the two, or alerted on the inequality, changes
  behaviour on mixed calls — observable only where `suppressed_ids =
  true`, since with ids elided the two readings are indistinguishable. A
  version bump was considered and rejected: it would fork every reader
  over a record whose fields, names and types are identical, for a field
  already documented as authoritative — which a maximum never satisfied,
  making this a correction to the stated contract rather than a new one.
  The rule this relies on is that `v` tracks structure, not meaning; it
  is now stated on `SCHEMA_VERSION` itself. Splitting the tallies into
  two fields (`suppressed_ids_count` and `suppressed_other_count`) is the
  cleaner end state, would have made the change self-announcing, and
  stays with the v2 work in #34.
- **Rule names the operator may not take (issue #84).** `Policy::validate`
  rejects a rule named `"default"`, `"min_bug_age_days"` or
  `"unavailable"`, a rule whose name ends in `":unreadable-metadata"`, a
  blank name, and two rules sharing one name. Those four spellings are
  exactly what the guard decides under on its own behalf — the first two
  and the suffix form from `Policy::classify`, `"unavailable"` from
  `Guard::assess` — and an audit record must identify what decided it.
  Without the reservation a log consumer counting default-decided calls by
  `rule == "default"` over-counted silently, a duplicate name said nothing
  about which of two rules decided, and a blank name identified nothing at
  all; I3 keeps that fact from the client, so the stream is the only place
  it can hold. This is the same startup-error class `validate` already
  applies to dead configuration (`operations = []`, a capability list on an
  allow/deny rule, a create-scoped restrict rule whose capabilities
  disagree with its scope). BOOT-BREAKING and accepted: a policy that
  started before now fails at startup with an error naming the rule — the
  correct direction, because the server refusing to run beats it writing
  ambiguous audit records. The comparison is EXACT, byte equality on the
  string that reaches the record: `"Default"`, `" default"` and
  `"unreadable-metadata"` (no colon) collide with nothing and stay legal,
  and over-rejecting them would break policies that never had the problem.
  Blank is the one check that is not about collision — `trim().is_empty()`,
  the same reading `global.identity_login` gets in the same function —
  because a name that identifies nothing is the one thing the field exists
  to prevent; its error is POSITIONAL (`rule #3 (name = "")`) since the
  name is exactly what cannot identify the rule there. Blankness is still
  judged bytewise, so `"embargo"` and `"embargo\u{200B}"` are two accepted
  names that any log viewer renders identically — the guarantee is
  byte-level, not human-reader-level, and nothing normalizes a name
  anywhere between `Rule::name` and the JSON record. That is deliberate:
  normalizing would break the exactness the collision checks rest on, and
  the policy file is the trust root, so a name only its author can
  distinguish is operator self-harm across no privilege boundary. The
  reservation is SINGLE-SOURCED rather than restated: `RULE_DEFAULT`,
  `RULE_MIN_BUG_AGE_DAYS`, `RULE_UNAVAILABLE` and
  `UNREADABLE_METADATA_SUFFIX` are consumed both by the emit sites
  (`Policy::classify`, and `Guard::assess` across the module boundary) and
  by `RESERVED_RULE_NAMES`, so renaming a decision renames what is
  reserved with it and the reservation cannot drift from what the engine
  writes into a record. The set is also CLOSED: no accepted name may end
  in the suffix and names are unique, so no generated
  `"<rule>:unreadable-metadata"` can ever equal a bare reserved name. The
  alternative, namespacing the synthetics in the record (a `rule_kind`
  field, or a prefix), was rejected here: it is a record-schema change and
  belongs to #34.

## rmcp 3.1 usage notes

Reference source is the rmcp this workspace pins, unpacked in the local
registry: `~/.cargo/registry/src/*/rmcp-3.1.1/` — today's version, and the
directory holding the `rmcp` package's `manifest_path` in `cargo metadata
--format-version 1` on any day, so it follows `Cargo.lock` rather than a copy
of it and is by construction the source this build compiles against. Every rmcp
path cited below is relative to that tree's `src/`. The modules these notes rest
on: `transport/streamable_http_server/tower.rs` (the transport config and both
routing traps), `handler/server/router/tool.rs` (`ToolRouter`, incl.
`remove_route` / `has_route` — I13), `model.rs` and `model/serde_impl.rs`
(`InitializeResult`, the `_meta` strip), `service.rs` (the serve loop); the
`#[tool_router]` / `#[tool_handler]` expansions are in the sibling
`rmcp-macros-3.1.1` tree. The published crate carries no `examples/` — those
live upstream at the `rmcp-v3.1.1` tag — but for how this server is actually
wired, `server.rs` and `main.rs` are the reference.

- `rmcp = { version = "3.1", features = ["server", "macros", "transport-io", "transport-streamable-http-server"] }`
- Protocol revisions: `SUPPORTED_PROTOCOL_VERSIONS` (server.rs) lists what
  this build serves and `supported_protocol_versions()` returns it, narrowing
  the SDK default of every revision it knows. What that override bounds is
  precisely which **declared** revisions `initialize`, per-request `_meta` and
  `server/discover` may agree to; it does not decide which request *lifecycle*
  the transport routes to (see the `_meta`-shape trap below). `2026-07-28` is excluded
  because this build has not adopted it (issue #34, stage 2).
  The hand-written `initialize` tests the same list — the SDK negotiates
  again afterwards using the handler's answer as its fallback, so a handler
  that echoed an unsupported request would make the SDK echo it too — and
  records the negotiated revision, never the requested one. `get_info` pins
  `DEFAULT_PROTOCOL_VERSION` rather than inheriting `ProtocolVersion::default()`,
  which moves with the SDK.
- **rmcp trap — `Implementation::from_build_env()` names the SDK, not this
  crate.** It expands `env!("CARGO_CRATE_NAME")` / `env!("CARGO_PKG_VERSION")`
  *inside rmcp*, so a server built on it introduces itself as `rmcp` at the
  SDK's version. It is not opt-in: `ServerInfo::new()` (i.e.
  `InitializeResult::new`, model.rs) seeds `server_info` with it, and
  `Implementation::default()` is that same constructor — so `get_info`
  starts from the SDK's identity every time and only the explicit
  `.with_server_info(server_identity())` displaces it. Dropping that one
  call silently restores the SDK's answer, which is why a test asserts the
  identity rather than a review. bugwarden builds `server_identity()` from
  its own `CARGO_PKG_*` (`SERVER_NAME` / `SERVER_VERSION`, server.rs) via
  `Implementation::new`; the struct-literal form is unavailable anyway, the
  type being `#[non_exhaustive]`. `mcp_server_info` reports those same two
  constants — the handshake and the tool must never name two different
  servers — and the identity is also read back off a served session, which
  pins that it survives serialization into `ServerPeerInfo.server_info`, a
  field that is `Option` on the client side. Same constructor as the
  placeholder `client_info` in the `_meta`-shape trap below, in the other
  direction: the SDK's build environment is not this build's identity
  (issue #53). `server/discover` is the second place a peer reads it, and
  it is answered with no handshake — so until #32 lands, anything that can
  open the port learns the exact deployed version, unauthenticated and
  unrecorded. Accepted deliberately: `serverInfo` is a required field of
  `InitializeResult`, so withholding it is not protocol-legal, and the
  value being replaced was rmcp's own exact release — a dependency
  fingerprint, which is not the smaller disclosure. The same trap has a
  non-MCP twin, and it is not rmcp's: the `User-Agent` sent to Bugzilla
  must likewise be built in this crate rather than in the library that
  holds the HTTP client (issue #55, "Caller identity on the wire" above).
- **rmcp trap — the handshake-free lifecycle is chosen by `_meta` shape, not
  by revision.** `message_has_per_request_protocol_version`
  (`transport/streamable_http_server/tower.rs`) routes a request to the
  stateless path when `_meta.io.modelcontextprotocol/protocolVersion` is
  merely PRESENT, whatever revision it names, and that path synthesises a
  peer whose `client_info` is `Implementation::default()` — the SDK's own
  crate name and version. Narrowing the revision list therefore does **not**
  keep a request off it: a client naming `2025-11-25`, which this build
  serves, would otherwise reach a tool with no `initialize` behind it and
  land in the audit stream as a client the server never spoke to. So
  `call_tool` and `list_tools` refuse any request carrying that key
  (`skips_the_handshake`), and a refused call is recorded with `client`
  absent rather than with the placeholder. `server/discover` takes the same
  path unconditionally in rmcp; it answers `get_info` only and reaches no
  tool, guard or router. General rule: **no `_meta` key and no `Mcp-*` header
  may carry a security decision** — like `KNOWN_VERSIONS`, they are the SDK's
  vocabulary, not this build's contract.
- `list_tools` names every `ListToolsResult` field: `result_type` is
  `COMPLETE`, and the 2026-07-28 cache hints stay absent while that revision
  is unserved. When it is adopted, `cache_scope` is `Private` — the listing is
  pruned per deployment (I13), so a shared cache must never serve one
  deployment's list to another — and `CacheScope::default()` is `Public`.
- **Every `StreamableHttpServerConfig` field is accounted for below** — set by
  name or inherited for a stated reason. `BugWarden::http_server_config()`
  (server.rs) names two; main.rs adds a third at the call site. The struct is
  `#[non_exhaustive]`, so an SDK bump may grow it: a field this table does not
  list is an unreviewed default, and adding the row is part of the bump, not a
  follow-up. Counting them in prose is what let two fields go unlisted here
  before.

  | field | rmcp 3.1 default | this build |
  |---|---|---|
  | `allowed_hosts` | `localhost`, `127.0.0.1`, `::1` | **set** — `disable_allowed_hosts()`, or the operator's `--allowed-hosts` list when given |
  | `max_request_body_bytes` | 4 MiB | **set** — derived from `global.max_attachment_bytes`, floored at that same 4 MiB (see below) |
  | `cancellation_token` | fresh token | **set** (main.rs) — a child of the process token |
  | `allowed_origins` | `[]`, i.e. validation off | inherited, deliberately |
  | `stateless_protocol_metadata_required` | `false` | inherited; #34 decides it |
  | `legacy_session_mode` | `true` | inherited |
  | `session_store` | `None` | inherited |
  | `json_response` | `false` | inherited |
  | `sse_keep_alive` / `sse_retry` | 15 s / 3 s | inherited |

  `allowed_hosts` is a DNS-rebinding defence for MCP servers a browser can
  reach on localhost, and its default would refuse every deployment not
  addressed as `localhost`, containers included; bugwarden disables it
  deliberately, since its access control is the network boundary and, when it
  lands, per-caller authentication (#32). `max_request_body_bytes` is a POST
  cap with no rmcp 2.2 equivalent: kept as a memory bound, but it also
  ceilings `add_attachment`, so a fixed value silently overrides the
  operator's `global.max_attachment_bytes` — at the SDK's 4 MiB, base64
  expansion alone put every decoded cap above ~3 MiB out of reach (#52). It is
  therefore **derived** from the policy, in `max_request_body_bytes`
  (server.rs), which `BugWarden::http_server_config` calls with its own
  guard's value — one place reads the policy field, so a deployment and its
  tests cannot size the transport from different numbers.
  `ceil(max_attachment_bytes / 3) * 4` for the base64 expansion, plus 1 MiB
  of headroom for the JSON-RPC framing and the call's other arguments,
  **clamped to [4 MiB, 64 MiB]** and saturating at every step (the policy
  value is operator input up to `u64::MAX`, and this runs in the startup
  path). Derived rather than inherited for the original reason: an SDK bump
  still must not move an operator-visible limit. Both clamps exist because
  the transport buffers a body before anything inspects it, so this is a
  memory bound first and an attachment allowance second. The 4 MiB floor is
  what this build served before the derivation, so ordinary traffic is
  unchanged and a small policy cap cannot shrink it; `0` — "no policy cap" —
  returns that floor rather than an unbounded body, since an unbounded body
  is an unbounded-memory lever for anyone who can reach the port. The 64 MiB
  ceiling says the same thing about a huge finite value, which is the same
  operator intent spelled differently (an "unlimited", or a typo): it carries
  every decoded cap up to ~47 MiB, far above any plausible Bugzilla
  attachment limit, and refuses to let a policy number remove the bound.
  Honest consequence, the mirror of the `0` case: a policy cap above ~47 MiB
  decoded is not honored over HTTP. A body over the cap is refused by rmcp's
  tower layer with a bare `413` that reaches neither `call_tool` nor the
  guard, so it is **unrecordable** in the audit stream — the same class as a
  pre-handler auth refusal (#32), and accepted on the same terms; an operator
  diagnosing a 413 compares the body size against the derived cap, because
  nothing server-side recorded the attempt.

  That boundary is also observable to an unauthenticated client, which is
  **ACCEPTED**: whenever the derivation exceeds the floor (a decoded cap above
  ~2.25 MiB) the 413 threshold is a function of `max_attachment_bytes`, so
  binary-searching body sizes recovers it — a value the add_attachment row
  above and the download refusal deliberately do not disclose, neither the
  size nor the cap. It is accepted for three reasons. Below ~2.25 MiB —
  including the 2 MiB default and `0` — the cap is the constant 4 MiB floor
  and discloses nothing about the policy at all. What leaks above it is a
  memory-tuning number, not bug data: no rule name, no match criterion, no
  bug's existence or content, so I1's "the policy file is never readable
  through MCP" and I2/I3 are untouched — this is the one policy-derived
  number a transport-level limit inherently exposes, in exchange for the
  operator's configured limit actually working. And the probing itself needs
  network reach, which is the access control until per-caller authentication
  lands (#32); a caller who can binary-search POST sizes can already call
  tools. If #32 changes that calculus, revisit here and at the add_attachment
  row together. The `cancellation_token` is named so ctrl_c tears the live
  transport down with the process instead of leaving it to outlive the
  shutdown.

  An operator who does know the authorities their deployment answers to names
  them with a repeated `--allowed-hosts`, which turns that validation back on
  for exactly that list. Tighten-only like every other CLI knob (I9), since
  the disabled state serves every `Host`; command line only, and deliberately
  without an environment variable, because it is a per-deployment network fact
  stated where the bind address is stated.

  `allowed_origins` is the browser-facing sibling of `allowed_hosts`, and the
  #32 argument covers it identically. It is inherited rather than named because
  the empty default IS the disabled state — `origin_is_allowed` returns true on
  an empty list, exactly what `disable_allowed_origins()` would produce — so
  naming it would assert nothing the default does not already say. The
  asymmetry with `allowed_hosts` is real and not an oversight: the host default
  refuses ordinary requests from this build's clients, whereas Origin is only
  checked when the header is present and a non-browser MCP client does not send
  one. An rmcp that shipped a non-empty `allowed_origins` still would not lock
  such a client out.

  `stateless_protocol_metadata_required` is the transport-level enforcement of
  the per-request `_meta` that the handshake-free lifecycle needs. It must stay
  `false` while this build serves the legacy revisions: rmcp clients negotiated
  below `2026-07-28` do not attach that metadata, so enabling it refuses their
  ordinary requests, and the field's own rustdoc says a server using it should
  advertise only `2026-07-28` and later. Adopting the revision (#34) therefore
  has to pick one — enforce at the transport and drop `2024-11-05` through
  `2025-11-25`, or keep them and enforce in the handler. **DECIDED 2026-08-05:
  keep the legacy revisions and enforce in the handler**, so this field stays
  `false` and #34 adds `2026-07-28` to the existing list rather than replacing
  it. Flipping it to `true` is not a tuning knob: it silently drops every
  revision this build serves. The rejected alternative is rejected on timing,
  not on cleanliness — transport-level enforcement is the tidier mechanism, but
  `2026-07-28` is not yet even rmcp's own `LATEST` (upstream PR #1105 is open),
  so taking it now would strand every current client to gain validation the
  handler can do itself, in a handler that already polices this exact request
  class. Revisit when the ecosystem has moved and dropping the legacy revisions
  costs little. Moot until then: `skips_the_handshake` refuses the whole
  request class before it reaches a tool. `legacy_session_mode` is inherited
  `true`, so sessions exist for the revisions served; per SEP-2567 rmcp serves
  `2026-07-28` requests statelessly whatever this flag says, which #34 inherits
  rather than configures. `session_store` stays `None`: the client's
  `initialize` parameters remain in-process, and there is one process here and
  no cross-instance recovery to do. `json_response`, `sse_keep_alive` and
  `sse_retry` set response framing and SSE liveness — client-visible timing,
  with no guard or operator-visible limit riding on them.
- axum MUST be 0.8 (rmcp's version — extension extraction breaks otherwise);
  schemars 1.x with feature `chrono04`; tokio 1; tokio-util 0.7.
- Server struct: `#[derive(Clone)] pub struct BugWarden { cfg: Arc<Cli>, guard: Arc<Guard>, bz: Arc<BugzillaClient>, tool_router: ToolRouter<Self>, key_custody: KeyCustody, audit: Option<Arc<AuditState>> }`
- `BugWarden::new` builds `Self::tool_router()` then `remove_route` for write
  tools when read-only and for every `global.disabled_tools` entry (I13).
  Write tool names: add_comment, update_bug_status, assign_bug,
  update_bug_fields, update_bug_dependencies, add_cc_to_bug, mark_as_duplicate,
  create_bug, add_attachment.
- API key resolution: a match on `key_custody` (resolved once at startup, see Key custody — never re-read per request): `Server(key)` => the server's key, without touching the request at all; `PerRequest` => `ctx.extensions.get::<axum::http::request::Parts>()`, then `parts.headers.get(lowercased_header_name)`.
- HTTP serving: `let config = server.http_server_config().with_cancellation_token(ct.child_token());` — built while `server` can still be borrowed, since the body cap comes from its own guard policy — then `StreamableHttpService::new(move || Ok(server.clone()), LocalSessionManager::default().into(), config)`, never a bare `StreamableHttpServerConfig::default()`, see the field table above — then `axum::Router::new().nest_service("/mcp", service)`, `tokio::net::TcpListener::bind`, graceful shutdown on ctrl_c cancelling `ct`.
- Request `_meta` (SEP-414, e.g. `traceparent`): over every serialized
  transport the wire `params._meta` does NOT arrive in the params struct
  (`CallToolRequestParams.meta` stays `None`) — the SDK's custom
  `Deserialize for Request` (model/serde_impl.rs) strips `_meta` out of
  the params into the request's extensions typemap, and the serve loop
  (service.rs) moves that into `RequestContext.meta`. So read
  `context.meta`; the params-struct `meta` field is populated only by
  in-process callers that never serialize (`call_tool` consults it
  first, then falls back to `context.meta`). Reading only the params
  field compiles fine and is silently empty over every real transport —
  pinned by the streamable-http traceparent test. The inverse mutant
  (reading only `context.meta`) is behavior-preserving over every
  serialized transport, so no transport-level test can kill it; the
  params-struct arm is pinned by a direct in-process
  `ServerHandler::call_tool` test with a hand-built `RequestContext`
  (the only caller shape that populates the field).
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
  restrict rule scoped away from `create` that grants `create`; rule names
  — validation rejects a rule named `default`, `min_bug_age_days` or
  `unavailable`, a name ending in `:unreadable-metadata`, a blank
  (empty or whitespace-only) name, and two rules sharing a name even when
  they are not adjacent, while near misses stay LEGAL (`default-allow`,
  `my-default`, `Default`, ` default`, `unreadable-metadata` without the
  colon), and every name `classify` actually emits is checked to be one
  validation rejects — with `Guard::assess`'s `"unavailable"` checked the
  same way in `guard_wiremock.rs`, so the reservation cannot drift from
  what the engine writes into a record; the
  shipped examples/policy.toml is pinned end to end against its own
  header: it parses, accepts filing into the desktop products, refuses an
  embargo-marked title everywhere, refuses filing elsewhere (omitted and
  claimed group lists alike), keeps existing world-readable desktop bugs
  fully readable (the issue-#26 regression surface), keeps group-restricted
  desktop bugs denied, and — since the "my-own-reports" identity rule ships
  commented out (Portability, above) — denies the caller's own
  group-restricted bug exactly like anyone else's, proving the shipped file
  never consults `created_by_me` at all; created_by_me — the TOML spelling
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
  created_by_me = false never matches a create); and the "my-own-reports"
  rule's ENABLED behaviour is pinned separately, against an inline literal
  reproducing the same rule ahead of a group-restricting deny rule (the
  shipped file cannot pin behaviour a commented-out rule never runs): with
  the caller known, a group-restricted bug the caller authored grants
  exactly read/comments/history/attachments and no write, the same bug
  authored by someone else stays Denied, and with identity UNKNOWN that
  bug, the foreign one, and a world-readable bug are all Denied — the
  whoami-failure blackout is pinned so it cannot be "fixed" into fail-open
  later; `global.identity_source`/`identity_login` — the default is
  `whoami` with no login, `declared` with a non-blank login parses,
  `declared` without (or with a blank) `identity_login` is a hard startup
  error, `identity_login` set under `whoami` is a hard startup error (the
  silently-ignored-key class of typo), and an unknown `identity_source`
  value is rejected; `resolve_caller` under `declared` returns the login
  with ZERO HTTP requests (pinned against both `/rest/whoami` and
  `/rest/valid_login` with `expect(0)`).
- Unit tests (#[cfg(test)] in crates/bugwarden/src/server.rs): assemble_bug_info
  re-classification — a body embargoed after the verdict is refused, a body
  that now earns only summary is downgraded, a body granting neither read nor
  summary is refused, and refused/absent/up-front-denied ids yield byte-
  identical restricted entries; the distinct-id bound; read-only delists
  create_bug and add_attachment (I13); the upload size gate measures decoded
  (never base64-encoded) bytes, is disabled at 0, and its refusal names no
  number; stdio without any key source fails at `BugWarden::new`
  construction, never at first request; and `identity_source = "declared"`
  under `KeyCustody::PerRequest` plus a `needs_identity()` policy fails at
  `BugWarden::new` construction naming both "declared" and "per-request",
  while the same policy under a server-held key builds successfully (A5).
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
  requests, the scan target does not track `limit`, a page capped below the
  requested chunk size (Bugzilla's own `max_search_results`, for instance) is
  not read as end-of-results and the scan keeps going to fill the window, a
  1-row page cap still bounds the scan at 10 requests, id-less rows are dropped,
  rows repeated across chunks are served once, exhaustion and scan truncation look alike, zero limit
  touches nothing (and accounts for nothing), the returned objects are the
  classified ones, and the scan accounting (issue #29) — `scanned` counts
  every upstream row examined and `dropped` is exactly the verdict-dropped
  ids, overshoot-region denials included, id-less rows and deduped repeats
  excluded, and both accumulate across chunks (a multi-chunk corpus with a
  drop in each chunk pins the per-chunk `extend`/`+=`);
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
  instead of passing on a fixture that volunteers fields nobody requested;
  valid_login endpoint mapping (GET /rest/valid_login?login=.. accepts
  both `{"result": bool}` and a bare bool for true AND false; any other
  shape — an object without a boolean `result`, a string, a number,
  `null` — is an ERROR, never silently read as `false`), the API key
  absent from a valid_login transport error (I12), and
  resolve_caller under `identity_source = "declared"` costing ZERO HTTP
  requests to either endpoint for one tool call.
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
  API shape), pinned by a wiremock body matcher; the update-field surface
  (issue #38) — see_also travels as the `{"add": [..], "remove": [..]}`
  object with both sides present, keywords travel as add/remove and NEVER
  as the replace-all `set` (a catch-all PUT mock fails the test if any
  other body shape reaches Bugzilla), the five scalar fields
  (summary/url/whiteboard/version/target_milestone) land in one PUT body
  together with the attached comment, empty strings and empty lists are
  ignored (an expect(0) trap mock proves the ignored field never reaches
  the wire), a new-fields-only call against a policy-denied bug takes the
  uniform denial with zero PUTs, a see_also entry naming a policy-denied
  bug on THIS instance draws that bug's uniform denial with zero PUTs
  (I8/I14) while foreign-tracker entries are never assessed (the bug-7-only
  classify mock's expect(1) proves it), `see_also` inside `custom_fields` still
  errors on the `cf_` gate (I7) with zero upstream requests, and an
  all-empty call errors "At least one field must be specified" without
  contacting Bugzilla; and identity end to end —
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
  no API key into any client-visible text (I12); and the declared-login
  counterpart of the issue-#33 scenario — the same my-own-reports carve-out
  resolved via `identity_source = "declared"` grants the caller's own
  group-restricted bug through bug_info and denies a foreign one
  identically, with `expect(0)` whoami hits proving the endpoint is never
  touched.
- Integration tests (crates/bugwarden/tests/preflight_wiremock.rs,
  wiremock): `BugWarden::preflight` — a missing `/rest/whoami` under
  server-held key custody plus an identity-consulting policy fails
  preflight naming `GET /rest/whoami` and `created_by_me`; a working
  `whoami` under the same custody/policy passes it (one request, verified
  by the mock's drop-time expectation); a policy without any identity
  criterion costs ZERO whoami requests at preflight (the laziness contract
  extends to startup); `KeyCustody::PerRequest` under an identity policy
  passes preflight (warn only) while issuing zero whoami requests, since
  there is no server-held key to verify it with (A5); a transport-level
  whoami failure leaks no API key into the preflight error text (I12); and
  the `declared` arm — a correct declared login passes preflight via one
  `valid_login` request and zero whoami requests, a login the key does NOT
  authenticate as fails preflight naming that login, and a transport-level
  `valid_login` failure fails preflight naming the endpoint.
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
  file mid-flight changes nothing — the old key keeps serving); the
  guard's uniform denial text is byte-identical over http (I2 transport
  parity); and a `params._meta` traceparent sent over real streamable
  http lands its ids in the audit record with the response unchanged —
  the end-to-end proof that the wire `_meta` is read from where the SDK
  delivers it (`RequestContext.meta`), not from the params-struct field
  that stays empty over serialized transports; and the derived POST body
  cap (#52) — a ~5 MiB body is ADMITTED by a server whose policy sets
  `max_attachment_bytes = 6 MiB`, refused (413) once past that policy's
  derived cap, and the very same body is refused under the default policy,
  where the 4 MiB floor stands. The unit derivation itself is pinned in
  server.rs: `0` and the 2 MiB default both give the 4 MiB floor; 3 MiB
  gives 5 MiB (expansion plus the 1 MiB headroom); a cap ≡ 1 (mod 3) rounds
  the encoded size UP, which a truncating division would not; 47.25 MiB
  decoded lands exactly on the 64 MiB ceiling, one quantum below it still
  derives and one above clamps; and `u64::MAX` clamps to the ceiling rather
  than panicking, wrapping, or saturating into an unbounded body.
- Audit tests (crates/bugwarden/tests/audit_wiremock.rs + #[cfg(test)] in
  server.rs and audit.rs): one record per call for EVERY routed tool,
  refusal paths and protocol errors included; the refusal map is total
  over the full router; responses byte-identical with auditing off, on,
  and failing-open; suppressed ids in the record and never in the
  envelope; content and API-key canaries never reach the file; the
  fail-closed scopes (pre-dispatch gate proven by upstream request
  counts) via the sink's cfg(test) fault injection; the transport-derived
  fail-mode defaults bound to their documented wording; the params
  allowlist (free text to `_len`, 1024-char truncation); and trace
  enrichment (issue #28) — the strict traceparent parser (the canonical
  W3C value and its flags-00 variant parse into their ids; empty,
  54-byte, 56-byte, and ~1 MiB values, uppercase hex, versions other
  than `00` including `ff` and the W3C forward-format, all-zero trace
  or span ids, non-hex bytes and spaces in every field, misplaced
  separators, surrounding whitespace, and a 55-byte multibyte-unicode
  value are all `None`, without panicking), a well-formed traceparent
  in `_meta` lands its ids in the tool record over the duplex transport
  with the response byte-identical to the meta-less call, a malformed
  one leaves the record without any `trace` bytes (and the rejected
  value never reaches the file), a guard-denied call keeps the uniform
  denial text while its record carries verdict and ids, the
  failing-sink pre-dispatch gate record carries the ids too, and a
  direct in-process `ServerHandler::call_tool` invocation with the
  traceparent in the params-struct meta and an empty `context.meta`
  pins the `CallToolRequestParams.meta` arm that no serialized
  transport can exercise; and search-window drop accounting (issue #29)
  — a search over hidden rows records `guard.scan` with the exact
  scanned/dropped counts, the dropped ids in `suppressed_ids`, and
  verdict `served_filtered`, while the served envelope carries not a
  byte of accounting and is byte-identical to the same window over an
  upstream where the hidden rows do not exist; with `suppressed_ids =
  false` the scan counts and `suppressed_count` survive while the ids
  are elided; a clean search records `scan.dropped == 0` under verdict
  `served`; and a pre-#29 record line without `guard.scan`
  deserializes with the scan absent (plus the cell-level note_scan
  merge tests and the updated schema golden in audit.rs); and the
  `guard.rule` encoding (issue #67) — a call decided by the policy
  default records the literal `"default"`, on the deny side and the
  allow side alike, while a CLEAN search (no drops, so nothing the scan
  merge could have cleared) records no rule at all even though a named
  rule granted every row it served, since absence means "no single rule
  decided" and not "the default decided"; and what `suppressed_count`
  totals (issue #68) — `bug_comments` AND `summarize_bug`, each on a
  call that drops three private comments while scrubbing two
  duplicate-marker ids in the SAME request, record
  `suppressed_count == 5` over a two-element `suppressed_ids`, so the
  count exceeds the id list rather than being the larger tally, and with
  `suppressed_ids = false` the same call still records `5` with no id at
  all — the operator's only signal. One of those three private comments
  is itself a duplicate marker naming a third hidden bug, so the fixture
  DEFENDS the disjointness the sum rests on: harvesting marker ids from
  the pre-filter comment list counts that one comment in both tallies
  and records `6` over three ids, and both tools' tests fail on the
  number (plus the cell-level sum tests in audit.rs); and the counter's
  zero guard (issue #87) — a `bug_comments` call whose private filter
  dropped nothing records verdict `served`, `suppressed_count == 0` and
  the rule that decided it, so deleting `note_suppressed_count`'s
  `n == 0` early return, which would merge `served_filtered` (rule-less,
  clearing the rule) on EVERY call of the three tools that feed the
  counter, fails on the verdict rather than on a count that stays `0`
  either way; and `list_attachments`, the id-less site whose guard fields
  no record assertion had reached (the one-record-per-call test calls the
  tool but reads only its envelope), records a non-zero count over an
  EMPTY `suppressed_ids` when the I5 gate drops private attachment
  metadata, and `served` with a zero count over a listing of PUBLIC
  attachments the gate kept — a real "nothing was withheld" rather than
  an empty list's "nothing to withhold". Between them: deleting that
  counter call, counting the whole list rather than the drop, and adding
  any unconditional note beside it (a `note_redacted`, a rule-less
  `note_verdict`) — which the zero guard, living inside
  `note_suppressed_count`, cannot stop — are all detectable; and the
  empty-set guards at the note call sites themselves (issue #88), where
  the counter's zero guard reaches nothing: `note_suppressed` merges
  `served_filtered` whatever it is handed, so a call site that drops its
  `if !hidden.is_empty()` claims a filtered serve over an EMPTY
  `suppressed_ids` on every call, and `note_redacted` does the same over
  a `redacted_fields` naming a view the client was never put into. A
  `summarize_bug` call whose comments are all public and name one
  DISCLOSABLE bug records verdict `served`, `suppressed_count == 0`, no
  id and the rule that decided it — pinning that tool's id-set guard and
  giving the counter's third call site the clean-call record #87 left it
  without; a `bug_info` call over a bug served whole whose only link the
  guard weighed and allowed records the same clean serve with an empty
  `redacted_fields`, pinning both of that tool's notes on the side no
  assertion had reached — its link suppression had only ever been read
  on a call that DID suppress, its redaction note on no record at all.
  The one shared fixture hands each id-set site a candidate to weigh
  instead of an empty set, and earns bug 7 a FULL grant rather than a
  summary view, so a clean record means "the guard withheld nothing" and
  not "there was nothing to withhold". The remaining note sites —
  `bug_history`'s and `bug_comments`' id sets, `bugs_quicksearch`'s two
  id sets and its redaction note — already fail on a clean-call record
  above, but over fixtures with nothing to weigh.
- Identity tests (#[cfg(test)] in crates/bugwarden/src/server.rs and
  crates/bugwarden-core/src/client.rs; crates/bugwarden/tests/
  http_transport_wiremock.rs, crates/bugwarden/tests/binary_user_agent.rs
  and crates/bugwarden-core/tests/user_agent_wiremock.rs): what this build
  calls itself, in both directions. Inbound (issue #53) — `mcp_server_info`
  and the handshake report the same name and version, asserted as VALUES
  and against `Implementation::from_build_env()`, so an identity inherited
  from the SDK fails; the SDK's own default is pinned separately, so its
  drift reads as upstream news rather than a bug here; the identity is read
  back off a served session, `title` included, since that is the field a
  client displays in preference to the name; and `server/discover`, the
  handshake-free surface, names the same build and reaches nothing else.
  Outbound (issue #55) — the SHIPPED BINARY is spawned against a real
  HTTP server and its request read off the wire, because every assertion
  one call frame in (at `bugzilla_client`) still passes for a `main` that
  builds its own client; that run also pins `--use-auth-header` reaching
  the same constructor, since dropping it would put the key back in the
  URL. The name and repository are spelled out rather than read from the
  manifest the code reads, which would agree with any value the manifest
  took. In the library, the caller's value reaches the authenticated GET,
  the POST and PUT bodies and the unauthenticated `page.cgi` fetch, in
  BOTH auth modes — the header and the credential are chosen by one
  constructor, so a per-mode identity would send nothing at all in the
  other — and a blank or non-header-value identity fails at construction
  rather than going out anonymously.
- CI: `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
  `cargo test --workspace --locked`, `cargo deny check`.
