//! Operator-controlled guard policy for bugwarden.
//!
//! The policy comes ONLY from a TOML file given at startup (`--policy` /
//! `BUGWARDEN_POLICY`) and is immutable at runtime (invariant I1). It decides,
//! per bug, which [`Capability`] set the MCP client is granted. The engine is
//! deliberately fail-closed (I4): whenever a rule asks about a field the bug
//! object did not carry — absent, null, wrongly typed, or a list that could
//! only be read in part — that rule is undecidable and the bug is denied,
//! whatever the rule's action.
//!
//! TOML shape (all keys are strict; unknown keys are rejected so a typo can
//! never silently weaken a policy):
//!
//! ```toml
//! default_action = "allow"   # or "deny"; "restrict" is only valid on rules
//!
//! [global]
//! min_bug_age_days = 0       # 0 = disabled; bugs younger than N days are denied
//! allow_private_comments = false
//! read_only = false
//! disabled_tools = []
//!
//! [[rule]]
//! name = "embargo"
//! description = "hide embargoed security bugs"
//! action = "deny"
//! [rule.match]
//! groups = ["*embargo*", "*security*"]
//!
//! [[rule]]
//! name = "summaries-only"
//! action = "restrict"
//! capabilities = ["summary"]
//! [rule.match]
//! products = ["SUSE*"]
//! ```
//!
//! Rules are evaluated in file order, first match wins; unmatched bugs fall
//! through to `default_action`.

use std::collections::BTreeSet;
use std::path::Path;

use anyhow::Context as _;
use chrono::{DateTime, Duration, Utc};
use serde_json::Value;

/// A capability a policy grant can carry.
///
/// Capabilities are the unit of restriction: an `allow` rule grants all of
/// them, a `restrict` rule grants exactly the listed subset, a `deny` rule
/// grants none. The only implication is `read` ⇒ `summary` (invariant I6),
/// applied in [`Access::allows`] — never stored in the set itself.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    /// Full bug details (implies [`Capability::Summary`], I6).
    Read,
    /// Redacted summary-only view of a bug (see `guard::SUMMARY_FIELDS`).
    Summary,
    /// Read comments.
    Comments,
    /// Read change history.
    History,
    /// List attachment metadata and download attachment content.
    Attachments,
    /// Write: add a comment.
    Comment,
    /// Write: change status/resolution/mark as duplicate.
    Status,
    /// Write: change priority/severity/resolution/custom `cf_*` fields.
    Fields,
    /// Write: change the assignee.
    Assign,
    /// Write: change the CC list.
    Cc,
    /// Write: change blocks/depends_on.
    Deps,
}

impl Capability {
    /// Every capability, in declaration order. Used to expand `allow` grants.
    pub const ALL: [Capability; 11] = [
        Capability::Read,
        Capability::Summary,
        Capability::Comments,
        Capability::History,
        Capability::Attachments,
        Capability::Comment,
        Capability::Status,
        Capability::Fields,
        Capability::Assign,
        Capability::Cc,
        Capability::Deps,
    ];

    /// Whether this capability permits mutating Bugzilla state.
    ///
    /// Write capabilities are stripped from every grant when
    /// `global.read_only` is set (which the CLI `--read-only` flag can only
    /// tighten, never loosen — invariant I9).
    pub fn is_write(self) -> bool {
        matches!(
            self,
            Capability::Comment
                | Capability::Status
                | Capability::Fields
                | Capability::Assign
                | Capability::Cc
                | Capability::Deps
        )
    }
}

/// Case-insensitive glob match; `'*'` matches any (possibly empty) substring.
///
/// The whole `value` must be covered by `pattern` (this is a match, not a
/// substring search). Every character other than `'*'` — including `'?'` —
/// matches only itself. Implemented with iterative backtracking: no regex
/// dependency, no recursion, O(len(pattern) * len(value)) worst case.
pub fn glob_match(pattern: &str, value: &str) -> bool {
    let pat: Vec<char> = pattern.to_lowercase().chars().collect();
    let val: Vec<char> = value.to_lowercase().chars().collect();
    let (mut p, mut s) = (0usize, 0usize);
    // Position of the most recent '*' in `pat`, and the position in `val`
    // where the next backtrack should resume matching.
    let mut star: Option<usize> = None;
    let mut resume = 0usize;
    while s < val.len() {
        if p < pat.len() && pat[p] == '*' {
            star = Some(p);
            p += 1;
            resume = s;
        } else if p < pat.len() && pat[p] == val[s] {
            p += 1;
            s += 1;
        } else if let Some(star_pos) = star {
            // Let the last '*' swallow one more character and retry.
            p = star_pos + 1;
            resume += 1;
            s = resume;
        } else {
            return false;
        }
    }
    // Only trailing '*'s may remain unconsumed in the pattern.
    while p < pat.len() && pat[p] == '*' {
        p += 1;
    }
    p == pat.len()
}

fn any_glob(patterns: &[String], value: &str) -> bool {
    patterns.iter().any(|p| glob_match(p, value))
}

fn any_glob_multi(patterns: &[String], values: &[String]) -> bool {
    patterns
        .iter()
        .any(|p| values.iter().any(|v| glob_match(p, v)))
}

/// Whether `haystack` contains any of `needles`, case-insensitively.
fn contains_any(needles: &[String], haystack: &str) -> bool {
    let hay = haystack.to_lowercase();
    needles.iter().any(|n| hay.contains(&n.to_lowercase()))
}

/// `now - days`, or `None` when the subtraction is not representable.
///
/// Callers must treat `None` as "the cutoff cannot be computed" and fail
/// closed (I4).
fn age_cutoff(now: DateTime<Utc>, days: i64) -> Option<DateTime<Utc>> {
    Duration::try_days(days).and_then(|d| now.checked_sub_signed(d))
}

/// Bug-matching criteria of a rule.
///
/// Semantics: every criterion that is present must hold (AND across
/// criteria); within a single list any element may match (OR within a list).
/// An empty matcher matches every bug, which makes it the catch-all rule.
#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Matcher {
    /// Globs matched against the bug's product.
    #[serde(default)]
    pub products: Vec<String>,
    /// Globs matched against any of the bug's components.
    #[serde(default)]
    pub components: Vec<String>,
    /// Globs matched against any of the bug's group names. This is the
    /// primary tool for hiding embargoed/security bugs.
    #[serde(default)]
    pub groups: Vec<String>,
    /// Globs matched against any of the bug's keywords.
    #[serde(default)]
    pub keywords: Vec<String>,
    /// Globs matched against the bug's status.
    #[serde(default)]
    pub statuses: Vec<String>,
    /// Globs matched against the bug's severity.
    #[serde(default)]
    pub severities: Vec<String>,
    /// Globs matched against the bug's priority.
    #[serde(default)]
    pub priorities: Vec<String>,
    /// Case-insensitive substrings searched in the bug's whiteboard.
    ///
    /// A whiteboard the classification data does not carry is unknown, not
    /// empty, and unknown resolves per `unknown_matches` in
    /// [`Matcher::matches`] (I4). An empty whiteboard is knowledge: it
    /// simply contains no substring.
    #[serde(default)]
    pub whiteboard_contains: Vec<String>,
    /// Case-insensitive substrings searched in the bug's summary.
    ///
    /// Security teams routinely mark an undisclosed issue in the bug title,
    /// and for such a bug the one-line summary is itself the sensitive part,
    /// so this criterion exists to deny on the title alone. An unreadable
    /// summary is handled like an unreadable whiteboard (I4).
    #[serde(default)]
    pub summary_contains: Vec<String>,
    /// Matches on whether the bug carries a group restriction at all:
    /// `true` selects bugs readable only by at least one Bugzilla group,
    /// `false` selects world-readable bugs.
    ///
    /// Group NAMES differ per instance, so a policy that must hold on any
    /// Bugzilla cannot enumerate them; this criterion asks the
    /// instance-independent question instead. A bug whose group list could
    /// not be read answers neither way and resolves per `unknown_matches`
    /// (I4), whichever side the rule asked about.
    #[serde(default)]
    pub group_restricted: Option<bool>,
    /// Matches when `creation_time` is newer than `now - N days`.
    ///
    /// A bug with a missing/unparsable `creation_time` MATCHES this
    /// criterion (fail closed, I4): this matcher exists to deny or restrict
    /// young bugs, so a bug of unknown age must be treated as young.
    #[serde(default)]
    pub younger_than_days: Option<i64>,
}

/// The result of testing a bug against a [`Matcher`].
///
/// The third state is what makes fail-closed classification possible: a rule
/// can hold, not hold, or be undecidable because the classification data did
/// not carry a field the rule asks about. [`Policy::classify`] must never
/// resolve `Unknown` into a grant (I4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchOutcome {
    /// Every criterion held, on data that could be read.
    Yes,
    /// A criterion definitively did not hold; the rule does not apply.
    No,
    /// No criterion ruled the bug out, but at least one could not be
    /// evaluated because its field was absent or unreadable.
    Unknown,
}

impl MatchOutcome {
    /// Whether every criterion held on readable data.
    pub fn is_yes(self) -> bool {
        self == MatchOutcome::Yes
    }
}

impl Matcher {
    /// Test `bug` against every criterion present in this matcher.
    ///
    /// `now` is passed in (rather than read from the clock) so that
    /// classification of a batch is consistent and tests are deterministic.
    ///
    /// A criterion whose field is `None` in [`BugMeta`] — absent from the
    /// bug object, or present in a shape the parser could not read — cannot
    /// be evaluated and yields [`MatchOutcome::Unknown`], unless some other
    /// criterion already ruled the bug out (a definitive `No` wins, because
    /// then the unreadable field cannot change the answer).
    pub fn evaluate(&self, bug: &BugMeta, now: DateTime<Utc>) -> MatchOutcome {
        let mut unknown = false;

        // Globs against a single value.
        for (patterns, value) in [
            (&self.products, &bug.product),
            (&self.statuses, &bug.status),
            (&self.severities, &bug.severity),
            (&self.priorities, &bug.priority),
        ] {
            if patterns.is_empty() {
                continue;
            }
            match value {
                None => unknown = true,
                Some(v) => {
                    if !any_glob(patterns, v) {
                        return MatchOutcome::No;
                    }
                }
            }
        }

        // Globs against any element of a list.
        for (patterns, values) in [
            (&self.components, &bug.components),
            (&self.groups, &bug.groups),
            (&self.keywords, &bug.keywords),
        ] {
            if patterns.is_empty() {
                continue;
            }
            match values {
                None => unknown = true,
                Some(vs) => {
                    if !any_glob_multi(patterns, vs) {
                        return MatchOutcome::No;
                    }
                }
            }
        }

        // Case-insensitive substring searches in free text.
        for (needles, text) in [
            (&self.whiteboard_contains, &bug.whiteboard),
            (&self.summary_contains, &bug.summary),
        ] {
            if needles.is_empty() {
                continue;
            }
            match text {
                None => unknown = true,
                Some(t) => {
                    if !contains_any(needles, t) {
                        return MatchOutcome::No;
                    }
                }
            }
        }

        if let Some(want_restricted) = self.group_restricted {
            match &bug.groups {
                None => unknown = true,
                Some(groups) => {
                    if !groups.is_empty() != want_restricted {
                        return MatchOutcome::No;
                    }
                }
            }
        }

        if let Some(days) = self.younger_than_days {
            match (bug.creation_time, age_cutoff(now, days)) {
                // Age unreadable: undecidable like any other missing field.
                (None, _) => unknown = true,
                // Cutoff not representable: the window covers all of
                // representable time, so every bug counts as young.
                (Some(_), None) => {}
                (Some(ct), Some(cutoff)) => {
                    if ct <= cutoff {
                        // Strictly older than N days => not "younger than".
                        return MatchOutcome::No;
                    }
                }
            }
        }

        if unknown {
            MatchOutcome::Unknown
        } else {
            MatchOutcome::Yes
        }
    }
}

/// What a matching rule (or the policy default) does with a bug.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    /// Grant every capability (subject to `global.read_only` stripping).
    Allow,
    /// Grant nothing. A denied bug is indistinguishable from a nonexistent
    /// one in every response (invariant I2).
    Deny,
    /// Grant exactly the rule's `capabilities` list. Only valid on rules,
    /// never as `default_action`, and requires a non-empty capability list —
    /// both enforced by [`Policy::from_toml_str`] validation.
    Restrict,
}

/// One policy rule: matching criteria plus the action to take.
///
/// Rule names exist for operator-side logging only; they are never exposed
/// through any MCP tool (invariant I1).
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    /// Operator-facing identifier (logged server-side, never sent to clients).
    pub name: String,
    /// Free-form operator documentation.
    #[serde(default)]
    pub description: String,
    /// Matching criteria; an absent/empty `match` table matches every bug.
    #[serde(rename = "match", default)]
    pub matcher: Matcher,
    /// What to do when the matcher matches.
    pub action: Action,
    /// Capabilities granted by `action = "restrict"`; must be empty for
    /// `allow`/`deny` and non-empty for `restrict` (validated).
    #[serde(default)]
    pub capabilities: Vec<Capability>,
}

/// Policy-wide guards applied on top of (and before) the rule list.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GlobalGuards {
    /// Deny every bug younger than this many days; `0` disables the gate.
    /// This runs BEFORE any rule, and a missing `creation_time` while the
    /// gate is active means Denied (fail closed, I4).
    #[serde(default)]
    pub min_bug_age_days: i64,
    /// Whether private comments may ever be returned. Even when `true` a
    /// call must also pass `include_private = true` to see them (I5).
    /// Defaults to `false` — private data is strictly opt-in.
    #[serde(default)]
    pub allow_private_comments: bool,
    /// Strip write capabilities from every grant. The CLI `--read-only` flag
    /// ORs into this — it can only tighten, never loosen (I9). Write tools
    /// are additionally removed from the MCP tool listing entirely (I13).
    #[serde(default)]
    pub read_only: bool,
    /// MCP tool names removed from the tool router at startup (I13).
    /// Enforcement lives in the `bugwarden` binary crate.
    #[serde(default)]
    pub disabled_tools: Vec<String>,
    /// Largest attachment (decoded bytes, as reported by Bugzilla) that
    /// `download_attachment` may return; `0` removes the cap. Defaults to
    /// 2 MiB — attachment blobs are base64-embedded in tool results and land
    /// in the model's context, so unlimited is an explicit operator choice.
    #[serde(default = "default_max_attachment_bytes")]
    pub max_attachment_bytes: u64,
}

fn default_max_attachment_bytes() -> u64 {
    2 * 1024 * 1024
}

// Hand-written so the no-policy-file default carries the 2 MiB attachment
// cap: a derived `Default` would zero it, which means "no cap" (fail open).
impl Default for GlobalGuards {
    fn default() -> Self {
        Self {
            min_bug_age_days: 0,
            allow_private_comments: false,
            read_only: false,
            disabled_tools: Vec::new(),
            max_attachment_bytes: default_max_attachment_bytes(),
        }
    }
}

fn default_default_action() -> Action {
    Action::Allow
}

/// The complete guard policy: default action, global guards, ordered rules.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// Action for bugs no rule matches. Must be `allow` or `deny`
    /// (a `restrict` default would grant an unspecified capability set).
    #[serde(default = "default_default_action")]
    pub default_action: Action,
    /// Policy-wide guards.
    #[serde(default)]
    pub global: GlobalGuards,
    /// Ordered rule list (`[[rule]]` tables); first match wins.
    #[serde(default, rename = "rule")]
    pub rules: Vec<Rule>,
}

impl Default for Policy {
    /// The policy used when no `--policy` file is given: allow-all, no
    /// rules, `min_bug_age_days = 0`, `read_only = false`, and — per I5 —
    /// `allow_private_comments = false`.
    fn default() -> Self {
        Policy {
            default_action: Action::Allow,
            global: GlobalGuards::default(),
            rules: Vec::new(),
        }
    }
}

impl Policy {
    /// Strict parse + validation of a policy document.
    ///
    /// Parsing rejects unknown keys everywhere (`deny_unknown_fields`) so a
    /// typo like `product = [...]` for `products` fails loudly instead of
    /// silently matching nothing. Validation then enforces:
    ///
    /// - `restrict` rules carry at least one capability;
    /// - `allow`/`deny` rules carry no capabilities (a capability list on
    ///   them would be dead configuration masking operator intent);
    /// - `default_action` is not `restrict`.
    pub fn from_toml_str(s: &str) -> anyhow::Result<Policy> {
        let policy: Policy = toml::from_str(s).context("failed to parse guard policy TOML")?;
        policy.validate()?;
        Ok(policy)
    }

    /// Read + [`Policy::from_toml_str`].
    ///
    /// On unix, warns via `tracing::warn` when the file is writable by group
    /// or others: the policy is the security boundary, and a world-writable
    /// policy file means anyone on the host can widen access.
    pub fn load(path: &Path) -> anyhow::Result<Policy> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            if let Ok(meta) = std::fs::metadata(path) {
                let mode = meta.permissions().mode();
                if mode & 0o022 != 0 {
                    tracing::warn!(
                        path = %path.display(),
                        mode = format!("{:o}", mode & 0o777),
                        "guard policy file is writable by group or others; \
                         anyone with write access can change what this server exposes"
                    );
                }
            }
        }
        let s = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read guard policy file {}", path.display()))?;
        Self::from_toml_str(&s)
            .with_context(|| format!("invalid guard policy file {}", path.display()))
    }

    fn validate(&self) -> anyhow::Result<()> {
        if self.default_action == Action::Restrict {
            anyhow::bail!(
                "default_action must be \"allow\" or \"deny\": \"restrict\" is only \
                 meaningful on a rule, where it names the granted capabilities"
            );
        }
        for rule in &self.rules {
            match rule.action {
                Action::Restrict if rule.capabilities.is_empty() => {
                    anyhow::bail!(
                        "rule \"{}\": action = \"restrict\" requires at least one capability",
                        rule.name
                    );
                }
                Action::Allow | Action::Deny if !rule.capabilities.is_empty() => {
                    anyhow::bail!(
                        "rule \"{}\": capabilities may only be set when action = \"restrict\"",
                        rule.name
                    );
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Classify one bug into an [`Access`] decision.
    ///
    /// Evaluation order (normative):
    ///
    /// 1. `global.min_bug_age_days` — a bug younger than the minimum age is
    ///    Denied before any rule runs. A missing/unparsable `creation_time`
    ///    while this gate is active is also Denied (fail closed, I4).
    /// 2. Rules in file order, first match wins.
    /// 3. `default_action`.
    ///
    /// Every grant — from a rule or from the default — has write capabilities
    /// stripped when `global.read_only` is set.
    pub fn classify(&self, bug: &BugMeta, now: DateTime<Utc>) -> Access {
        if self.global.min_bug_age_days > 0 {
            let too_young = match (
                bug.creation_time,
                age_cutoff(now, self.global.min_bug_age_days),
            ) {
                // Unknown age: fail closed (I4).
                (None, _) => true,
                // Cutoff not representable: fail closed.
                (Some(_), None) => true,
                (Some(ct), Some(cutoff)) => ct > cutoff,
            };
            if too_young {
                return Access::Denied {
                    rule: "min_bug_age_days".to_string(),
                };
            }
        }
        for rule in &self.rules {
            match rule.matcher.evaluate(bug, now) {
                // The rule definitively does not apply; try the next one.
                MatchOutcome::No => continue,
                MatchOutcome::Yes => {
                    return match rule.action {
                        Action::Deny => Access::Denied {
                            rule: rule.name.clone(),
                        },
                        Action::Allow => self.grant(Capability::ALL.iter().copied(), &rule.name),
                        Action::Restrict => {
                            self.grant(rule.capabilities.iter().copied(), &rule.name)
                        }
                    };
                }
                // The rule's verdict hinges on metadata that could not be
                // read. A deny rule denies — the bug may well be what the
                // rule looks for. A granting rule (allow, and restrict:
                // under a denying default a restrict rule GRANTS) must not
                // hand out access on data nobody could check, and must not
                // be skipped either, because skipping would pass the bug to
                // a later granting rule or to an allowing default. Both
                // horns lead to the same fail-closed answer (I4).
                MatchOutcome::Unknown => {
                    return match rule.action {
                        Action::Deny => Access::Denied {
                            rule: rule.name.clone(),
                        },
                        Action::Allow | Action::Restrict => Access::Denied {
                            rule: format!("{}:unreadable-metadata", rule.name),
                        },
                    };
                }
            }
        }
        match self.default_action {
            Action::Allow => self.grant(Capability::ALL.iter().copied(), "default"),
            // `Restrict` as default is rejected by validation; if it appears
            // in a hand-constructed Policy, fail closed and deny.
            Action::Deny | Action::Restrict => Access::Denied {
                rule: "default".to_string(),
            },
        }
    }

    /// Build a grant, stripping write capabilities when `global.read_only`.
    fn grant(&self, caps: impl IntoIterator<Item = Capability>, rule: &str) -> Access {
        let mut set: BTreeSet<Capability> = caps.into_iter().collect();
        if self.global.read_only {
            set.retain(|c| !c.is_write());
        }
        Access::Granted {
            caps: set,
            rule: rule.to_string(),
        }
    }
}

/// The subset of bug fields the policy engine classifies on.
///
/// Every field is optional and `None` means UNKNOWN — the bug object did not
/// carry it, or carried it in a shape the parser could not read. Unknown is
/// never silently downgraded to empty: an unreadable field makes the
/// criteria that consult it undecidable, which [`Policy::classify`] resolves
/// on the restrictive side (I4).
#[derive(Debug, Clone, Default)]
pub struct BugMeta {
    /// Bug id (`0` when absent from the JSON — never a valid Bugzilla id).
    pub id: u64,
    /// One-line summary (bug title).
    pub summary: Option<String>,
    /// Product name.
    pub product: Option<String>,
    /// Component names; the REST `component` field may be a string or array.
    pub components: Option<Vec<String>>,
    /// Current status.
    pub status: Option<String>,
    /// Severity.
    pub severity: Option<String>,
    /// Priority.
    pub priority: Option<String>,
    /// Keywords.
    pub keywords: Option<Vec<String>>,
    /// Group names the bug is in. An empty list means world-readable, which
    /// is knowledge; `None` means the group list could not be read, which is
    /// not.
    pub groups: Option<Vec<String>>,
    /// Whiteboard text.
    pub whiteboard: Option<String>,
    /// Creation time; `None` when absent or unparsable.
    pub creation_time: Option<DateTime<Utc>>,
}

/// A string field, or `None` when absent or not a string.
fn str_field(v: &Value, key: &str) -> Option<String> {
    match v.get(key) {
        Some(Value::String(s)) => Some(s.clone()),
        _ => None,
    }
}

/// A list-of-names field, or `None` when it cannot be read IN FULL.
///
/// Bugzilla returns these as a single name, an array of names, or an array
/// of objects carrying a `name` key. An element in none of those shapes
/// makes the WHOLE list unknown rather than being dropped: a partially
/// recovered list looks like a shorter list, and a group list that lost its
/// only element would look exactly like a world-readable bug.
fn list_field(v: &Value, key: &str) -> Option<Vec<String>> {
    match v.get(key) {
        Some(Value::String(s)) => Some(vec![s.clone()]),
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| match item {
                Value::String(s) => Some(s.clone()),
                Value::Object(o) => o.get("name").and_then(Value::as_str).map(str::to_string),
                _ => None,
            })
            .collect(),
        _ => None,
    }
}

/// The whiteboard, which arrives as `whiteboard` or (XML-RPC style)
/// `status_whiteboard`.
///
/// `whiteboard` wins when it carries text; an empty one falls back to the
/// legacy key. A key that is present but unreadable makes the whiteboard
/// unknown — it may have held the very marker a rule looks for.
fn whiteboard_field(v: &Value) -> Option<String> {
    let unreadable = |key: &str| v.get(key).is_some() && str_field(v, key).is_none();
    match (
        str_field(v, "whiteboard"),
        str_field(v, "status_whiteboard"),
    ) {
        (Some(wb), _) if !wb.is_empty() => Some(wb),
        (Some(wb), Some(legacy)) => Some(if legacy.is_empty() { wb } else { legacy }),
        (Some(wb), None) if !unreadable("status_whiteboard") => Some(wb),
        (None, Some(legacy)) if !unreadable("whiteboard") => Some(legacy),
        _ => None,
    }
}

impl BugMeta {
    /// Build classification metadata from a Bugzilla REST bug object.
    ///
    /// Tolerant on shape — the `component` field may be a string or an array
    /// of strings, `groups` elements may be plain names or objects carrying a
    /// `name` key, the whiteboard may arrive under either key — but tolerance
    /// stops short of pretending a field was there. Anything absent, null,
    /// oddly typed, or only partially recoverable becomes `None`, i.e.
    /// unknown, which fails closed during classification (I4).
    pub fn from_json(v: &Value) -> BugMeta {
        BugMeta {
            id: v.get("id").and_then(Value::as_u64).unwrap_or(0),
            summary: str_field(v, "summary"),
            product: str_field(v, "product"),
            components: list_field(v, "component"),
            status: str_field(v, "status"),
            severity: str_field(v, "severity"),
            priority: str_field(v, "priority"),
            keywords: list_field(v, "keywords"),
            groups: list_field(v, "groups"),
            whiteboard: whiteboard_field(v),
            creation_time: v
                .get("creation_time")
                .and_then(Value::as_str)
                .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                .map(|dt| dt.with_timezone(&Utc)),
        }
    }
}

/// The outcome of classifying one bug against the policy.
#[derive(Debug, Clone)]
pub enum Access {
    /// No access at all. `rule` names the deciding rule (or the synthetic
    /// `"min_bug_age_days"` / `"default"` / `"unavailable"`) for server-side
    /// logging only — it is never sent to the MCP client (I1/I2).
    Denied {
        /// Server-side-only name of the deciding rule.
        rule: String,
    },
    /// Access with exactly `caps` capabilities.
    Granted {
        /// The granted capability set (writes already stripped if read-only).
        caps: BTreeSet<Capability>,
        /// Server-side-only name of the deciding rule.
        rule: String,
    },
}

impl Access {
    /// Whether this decision permits `cap`.
    ///
    /// Implements the single capability implication (I6): `read` implies
    /// `summary`, so `allows(Summary)` is true whenever `Read` was granted.
    /// Nothing else is implied — in particular `read` does NOT imply
    /// `comments`, `history` or `attachments`.
    pub fn allows(&self, cap: Capability) -> bool {
        match self {
            Access::Denied { .. } => false,
            Access::Granted { caps, .. } => {
                caps.contains(&cap)
                    || (cap == Capability::Summary && caps.contains(&Capability::Read))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn t(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    /// Fixed "now" so age arithmetic is deterministic.
    fn now() -> DateTime<Utc> {
        t("2026-01-15T12:00:00Z")
    }

    /// A bug whose every classification field is readable.
    fn meta() -> BugMeta {
        BugMeta {
            id: 42,
            summary: Some("kernel panic on boot".into()),
            product: Some("openSUSE Tumbleweed".into()),
            components: Some(vec!["Kernel".into(), "Base".into()]),
            status: Some("NEW".into()),
            severity: Some("Major".into()),
            priority: Some("P2".into()),
            keywords: Some(vec!["regression".into()]),
            groups: Some(vec![]),
            whiteboard: Some("needs-triage [qa:blocked]".into()),
            creation_time: Some(t("2025-06-01T00:00:00Z")),
        }
    }

    // ---------- glob_match ----------

    #[test]
    fn glob_exact_match_whole_value() {
        assert!(glob_match("kernel", "kernel"));
        assert!(!glob_match("kernel", "kerne"));
        assert!(!glob_match("kernel", "kernels"));
        assert!(!glob_match("ernel", "kernel")); // match, not substring search
    }

    #[test]
    fn glob_case_insensitive() {
        assert!(glob_match("KeRnEl", "kERNEL"));
        assert!(glob_match("suse*", "SUSE Linux Enterprise"));
        assert!(glob_match("*SECURITY*", "suse-security-internal"));
    }

    #[test]
    fn glob_star_matches_everything_including_empty() {
        assert!(glob_match("*", ""));
        assert!(glob_match("*", "anything at all"));
        assert!(glob_match("**", "x"));
    }

    #[test]
    fn glob_empty_pattern_matches_only_empty() {
        assert!(glob_match("", ""));
        assert!(!glob_match("", "x"));
    }

    #[test]
    fn glob_prefix_suffix_inner() {
        assert!(glob_match("open*", "openSUSE"));
        assert!(glob_match("*suse", "openSUSE"));
        assert!(glob_match("o*n*e", "opensuse"));
        assert!(!glob_match("open*x", "openSUSE"));
        assert!(!glob_match("*sle*", "openSUSE"));
    }

    #[test]
    fn glob_star_can_match_empty_infix() {
        assert!(glob_match("open*suse", "opensuse"));
        assert!(glob_match("a*", "a"));
        assert!(glob_match("*a", "a"));
    }

    #[test]
    fn glob_backtracking() {
        // The first '*'-anchored attempt at "bc" fails and must backtrack.
        assert!(glob_match("a*bc", "abxbc"));
        assert!(!glob_match("a*bc", "abxbd"));
        assert!(glob_match("*a*b*", "xxaYYb"));
        assert!(glob_match("**a**", "bab"));
        assert!(!glob_match("*a*b*", "ba"));
    }

    #[test]
    fn glob_question_mark_is_literal() {
        assert!(glob_match("what?", "what?"));
        assert!(!glob_match("what?", "whatx"));
    }

    // ---------- Capability ----------

    #[test]
    fn capability_all_lists_eleven_unique() {
        assert_eq!(Capability::ALL.len(), 11);
        let set: BTreeSet<_> = Capability::ALL.iter().copied().collect();
        assert_eq!(set.len(), 11);
    }

    #[test]
    fn capability_write_split() {
        let writes: Vec<_> = Capability::ALL
            .iter()
            .copied()
            .filter(|c| c.is_write())
            .collect();
        assert_eq!(
            writes,
            vec![
                Capability::Comment,
                Capability::Status,
                Capability::Fields,
                Capability::Assign,
                Capability::Cc,
                Capability::Deps,
            ]
        );
        for c in [
            Capability::Read,
            Capability::Summary,
            Capability::Comments,
            Capability::History,
            Capability::Attachments,
        ] {
            assert!(!c.is_write(), "{c:?} must be a read capability");
        }
    }

    // ---------- Matcher ----------

    #[test]
    fn empty_matcher_matches_everything() {
        assert!(Matcher::default().evaluate(&meta(), now()).is_yes());
        assert!(Matcher::default()
            .evaluate(&BugMeta::default(), now())
            .is_yes());
        // A catch-all stays a catch-all in an allow rule: with no criteria
        // there is nothing for unknown metadata to resolve.
        assert!(Matcher::default()
            .evaluate(&BugMeta::default(), now())
            .is_yes());
    }

    #[test]
    fn matcher_product_glob() {
        let m = Matcher {
            products: vec!["opensuse*".into()],
            ..Default::default()
        };
        assert!(m.evaluate(&meta(), now()).is_yes());
        let m = Matcher {
            products: vec!["SLE*".into()],
            ..Default::default()
        };
        assert!(!m.evaluate(&meta(), now()).is_yes());
    }

    #[test]
    fn matcher_or_within_list() {
        let m = Matcher {
            products: vec!["SLE*".into(), "openSUSE*".into()],
            ..Default::default()
        };
        assert!(m.evaluate(&meta(), now()).is_yes());
    }

    #[test]
    fn matcher_and_across_criteria() {
        // Product matches but status does not => no match.
        let m = Matcher {
            products: vec!["openSUSE*".into()],
            statuses: vec!["RESOLVED".into()],
            ..Default::default()
        };
        assert!(!m.evaluate(&meta(), now()).is_yes());
        // Both match => match.
        let m = Matcher {
            products: vec!["openSUSE*".into()],
            statuses: vec!["new".into()],
            ..Default::default()
        };
        assert!(m.evaluate(&meta(), now()).is_yes());
    }

    #[test]
    fn matcher_components_any_of() {
        let m = Matcher {
            components: vec!["base".into()],
            ..Default::default()
        };
        assert!(m.evaluate(&meta(), now()).is_yes()); // second component, case folded
        let m = Matcher {
            components: vec!["YaST*".into()],
            ..Default::default()
        };
        assert!(!m.evaluate(&meta(), now()).is_yes());
    }

    #[test]
    fn matcher_groups_any_of() {
        let mut bug = meta();
        bug.groups = Some(vec!["suse-security".into()]);
        let m = Matcher {
            groups: vec!["*security*".into()],
            ..Default::default()
        };
        assert!(m.evaluate(&bug, now()).is_yes());
        // A bug with no groups cannot satisfy a group criterion.
        assert!(!m.evaluate(&meta(), now()).is_yes());
    }

    #[test]
    fn matcher_keywords_severity_priority() {
        let m = Matcher {
            keywords: vec!["REGRESSION".into()],
            ..Default::default()
        };
        assert!(m.evaluate(&meta(), now()).is_yes());
        let m = Matcher {
            severities: vec!["major".into()],
            priorities: vec!["p2".into()],
            ..Default::default()
        };
        assert!(m.evaluate(&meta(), now()).is_yes());
        let m = Matcher {
            priorities: vec!["P0".into()],
            ..Default::default()
        };
        assert!(!m.evaluate(&meta(), now()).is_yes());
    }

    #[test]
    fn matcher_whiteboard_substring_case_insensitive() {
        let m = Matcher {
            whiteboard_contains: vec!["QA:BLOCKED".into()],
            ..Default::default()
        };
        assert!(m.evaluate(&meta(), now()).is_yes());
        let m = Matcher {
            whiteboard_contains: vec!["embargo".into()],
            ..Default::default()
        };
        assert!(!m.evaluate(&meta(), now()).is_yes());
    }

    #[test]
    fn matcher_unreadable_text_is_unknown_not_empty() {
        // A field the classification data did not carry cannot be searched,
        // so the criterion is undecidable — distinct from a field that is
        // present and simply contains nothing.
        let m = Matcher {
            whiteboard_contains: vec!["embargo".into()],
            ..Default::default()
        };
        let unreadable = BugMeta {
            whiteboard: None,
            ..meta()
        };
        assert_eq!(m.evaluate(&unreadable, now()), MatchOutcome::Unknown);
        let empty = BugMeta {
            whiteboard: Some(String::new()),
            ..meta()
        };
        assert_eq!(m.evaluate(&empty, now()), MatchOutcome::No);

        let m = Matcher {
            summary_contains: vec!["embargo".into()],
            ..Default::default()
        };
        let unreadable = BugMeta {
            summary: None,
            ..meta()
        };
        assert_eq!(m.evaluate(&unreadable, now()), MatchOutcome::Unknown);
    }

    #[test]
    fn matcher_summary_substring_case_insensitive() {
        let m = Matcher {
            summary_contains: vec!["PANIC".into()],
            ..Default::default()
        };
        assert!(m.evaluate(&meta(), now()).is_yes());
        let m = Matcher {
            summary_contains: vec!["embargo".into()],
            ..Default::default()
        };
        assert_eq!(m.evaluate(&meta(), now()), MatchOutcome::No);
        let marked = BugMeta {
            summary: Some("EMBARGOED: CVE-2026-1: openssl: heap overflow".into()),
            ..meta()
        };
        assert!(m.evaluate(&marked, now()).is_yes());
    }

    #[test]
    fn matcher_group_restricted() {
        let restricted = BugMeta {
            groups: Some(vec!["security-internal".into()]),
            ..meta()
        };
        let public = meta(); // groups: Some(vec![]) — readable and empty

        let want_restricted = Matcher {
            group_restricted: Some(true),
            ..Default::default()
        };
        assert!(want_restricted.evaluate(&restricted, now()).is_yes());
        assert_eq!(want_restricted.evaluate(&public, now()), MatchOutcome::No);

        let want_public = Matcher {
            group_restricted: Some(false),
            ..Default::default()
        };
        assert!(want_public.evaluate(&public, now()).is_yes());
        assert_eq!(want_public.evaluate(&restricted, now()), MatchOutcome::No);
    }

    #[test]
    fn matcher_group_restricted_unreadable_is_unknown_either_way() {
        // Whichever side the rule asks about, a group list that could not be
        // read answers neither — the outcome is undecidable, and it is
        // classify() that resolves it on the restrictive side.
        let unreadable = BugMeta {
            groups: None,
            ..meta()
        };
        for asked in [true, false] {
            let m = Matcher {
                group_restricted: Some(asked),
                ..Default::default()
            };
            assert_eq!(
                m.evaluate(&unreadable, now()),
                MatchOutcome::Unknown,
                "asked for group_restricted = {asked}"
            );
        }
    }

    #[test]
    fn matcher_every_criterion_reports_unknown_on_an_unreadable_field() {
        // No criterion may silently treat "could not read" as "empty".
        let cases: Vec<(Matcher, BugMeta)> = vec![
            (
                Matcher {
                    products: vec!["*".into()],
                    ..Default::default()
                },
                BugMeta {
                    product: None,
                    ..meta()
                },
            ),
            (
                Matcher {
                    components: vec!["*".into()],
                    ..Default::default()
                },
                BugMeta {
                    components: None,
                    ..meta()
                },
            ),
            (
                Matcher {
                    groups: vec!["*".into()],
                    ..Default::default()
                },
                BugMeta {
                    groups: None,
                    ..meta()
                },
            ),
            (
                Matcher {
                    keywords: vec!["*".into()],
                    ..Default::default()
                },
                BugMeta {
                    keywords: None,
                    ..meta()
                },
            ),
            (
                Matcher {
                    statuses: vec!["*".into()],
                    ..Default::default()
                },
                BugMeta {
                    status: None,
                    ..meta()
                },
            ),
            (
                Matcher {
                    severities: vec!["*".into()],
                    ..Default::default()
                },
                BugMeta {
                    severity: None,
                    ..meta()
                },
            ),
            (
                Matcher {
                    priorities: vec!["*".into()],
                    ..Default::default()
                },
                BugMeta {
                    priority: None,
                    ..meta()
                },
            ),
            (
                Matcher {
                    summary_contains: vec!["x".into()],
                    ..Default::default()
                },
                BugMeta {
                    summary: None,
                    ..meta()
                },
            ),
            (
                Matcher {
                    whiteboard_contains: vec!["x".into()],
                    ..Default::default()
                },
                BugMeta {
                    whiteboard: None,
                    ..meta()
                },
            ),
            (
                Matcher {
                    younger_than_days: Some(5),
                    ..Default::default()
                },
                BugMeta {
                    creation_time: None,
                    ..meta()
                },
            ),
        ];
        for (i, (m, bug)) in cases.into_iter().enumerate() {
            assert_eq!(m.evaluate(&bug, now()), MatchOutcome::Unknown, "case {i}");
        }
    }

    #[test]
    fn matcher_definitive_no_wins_over_unknown() {
        // An unreadable field cannot rescue a rule that another criterion
        // already ruled out; such a rule genuinely does not apply.
        let m = Matcher {
            products: vec!["SomethingElse".into()],
            summary_contains: vec!["embargo".into()],
            ..Default::default()
        };
        let bug = BugMeta {
            summary: None,
            ..meta()
        };
        assert_eq!(m.evaluate(&bug, now()), MatchOutcome::No);
    }

    #[test]
    fn matcher_criteria_are_anded() {
        // A marker rule scoped by age must need BOTH, not either.
        let m = Matcher {
            summary_contains: vec!["embargo".into()],
            younger_than_days: Some(30),
            ..Default::default()
        };
        let old_marked = BugMeta {
            summary: Some("EMBARGOED: CVE-2026-1".into()),
            creation_time: Some(t("2025-01-01T00:00:00Z")),
            ..meta()
        };
        assert!(!m.evaluate(&old_marked, now()).is_yes());
        let fresh_marked = BugMeta {
            creation_time: Some(t("2026-01-14T00:00:00Z")),
            ..old_marked
        };
        assert!(m.evaluate(&fresh_marked, now()).is_yes());
    }

    #[test]
    fn matcher_younger_than_days() {
        let m = Matcher {
            younger_than_days: Some(30),
            ..Default::default()
        };
        let mut bug = meta();
        bug.creation_time = Some(t("2026-01-10T00:00:00Z")); // 5 days old
        assert!(m.evaluate(&bug, now()).is_yes());
        bug.creation_time = Some(t("2025-06-01T00:00:00Z")); // months old
        assert!(!m.evaluate(&bug, now()).is_yes());
    }

    #[test]
    fn matcher_younger_than_days_boundary() {
        let m = Matcher {
            younger_than_days: Some(7),
            ..Default::default()
        };
        let mut bug = meta();
        // Exactly 7 days old: not strictly newer than the cutoff => no match.
        bug.creation_time = Some(t("2026-01-08T12:00:00Z"));
        assert!(!m.evaluate(&bug, now()).is_yes());
        // One second younger => match.
        bug.creation_time = Some(t("2026-01-08T12:00:01Z"));
        assert!(m.evaluate(&bug, now()).is_yes());
    }

    #[test]
    fn matcher_younger_than_days_missing_creation_time_is_unknown() {
        let m = Matcher {
            younger_than_days: Some(30),
            ..Default::default()
        };
        let mut bug = meta();
        bug.creation_time = None;
        // An age that cannot be established makes the criterion undecidable;
        // classify() is what turns that into a denial (I4).
        assert_eq!(m.evaluate(&bug, now()), MatchOutcome::Unknown);
    }

    #[test]
    fn matcher_younger_than_days_huge_value_fails_closed() {
        // Unrepresentable cutoff => every bug counts as young.
        let m = Matcher {
            younger_than_days: Some(i64::MAX),
            ..Default::default()
        };
        assert!(m.evaluate(&meta(), now()).is_yes());
    }

    // ---------- Policy parsing + validation ----------

    const FULL_POLICY: &str = r#"
default_action = "deny"

[global]
min_bug_age_days = 7
allow_private_comments = true
read_only = false
disabled_tools = ["add_comment"]

[[rule]]
name = "embargo"
description = "hide embargoed security bugs"
action = "deny"
[rule.match]
groups = ["*embargo*", "*security*"]

[[rule]]
name = "public-products"
action = "allow"
[rule.match]
products = ["openSUSE*"]

[[rule]]
name = "summaries"
action = "restrict"
capabilities = ["summary", "comments"]
[rule.match]
products = ["SUSE*"]
"#;

    #[test]
    fn parse_full_policy() {
        let p = Policy::from_toml_str(FULL_POLICY).unwrap();
        assert_eq!(p.default_action, Action::Deny);
        assert_eq!(p.global.min_bug_age_days, 7);
        assert!(p.global.allow_private_comments);
        assert!(!p.global.read_only);
        assert_eq!(p.global.disabled_tools, vec!["add_comment".to_string()]);
        assert_eq!(p.rules.len(), 3);
        assert_eq!(p.rules[0].name, "embargo");
        assert_eq!(p.rules[0].action, Action::Deny);
        assert_eq!(p.rules[0].matcher.groups.len(), 2);
        assert_eq!(p.rules[1].action, Action::Allow);
        assert_eq!(p.rules[2].action, Action::Restrict);
        assert_eq!(
            p.rules[2].capabilities,
            vec![Capability::Summary, Capability::Comments]
        );
    }

    #[test]
    fn empty_policy_string_is_default() {
        let p = Policy::from_toml_str("").unwrap();
        assert_eq!(p.default_action, Action::Allow);
        assert_eq!(p.global.min_bug_age_days, 0);
        assert!(!p.global.allow_private_comments); // I5 default
        assert!(!p.global.read_only);
        assert!(p.global.disabled_tools.is_empty());
        assert!(p.rules.is_empty());
    }

    #[test]
    fn default_policy_is_allow_all_private_comments_off() {
        let d = Policy::default();
        assert_eq!(d.default_action, Action::Allow);
        assert!(d.rules.is_empty());
        assert!(!d.global.allow_private_comments); // I5
        assert!(!d.global.read_only);
        assert_eq!(d.global.min_bug_age_days, 0);
    }

    #[test]
    fn reject_unknown_top_level_key() {
        let err = Policy::from_toml_str("unknown_option = \"deny\"").unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("unknown field"), "unexpected error: {msg}");
    }

    #[test]
    fn reject_unknown_global_key() {
        let err = Policy::from_toml_str("[global]\nmin_age = 3\n").unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("unknown field"), "unexpected error: {msg}");
    }

    #[test]
    fn reject_unknown_rule_key() {
        let s = "[[rule]]\nname = \"r\"\naction = \"deny\"\nseverity = \"high\"\n";
        let err = Policy::from_toml_str(s).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("unknown field"), "unexpected error: {msg}");
    }

    #[test]
    fn reject_unknown_matcher_key() {
        // Singular "product" instead of "products" must fail loudly, not
        // silently match nothing.
        let s = "[[rule]]\nname = \"r\"\naction = \"deny\"\n[rule.match]\nproduct = [\"x\"]\n";
        let err = Policy::from_toml_str(s).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("unknown field"), "unexpected error: {msg}");
    }

    #[test]
    fn reject_unknown_capability_name() {
        let s = "[[rule]]\nname = \"r\"\naction = \"restrict\"\ncapabilities = [\"root\"]\n";
        assert!(Policy::from_toml_str(s).is_err());
    }

    #[test]
    fn reject_unknown_action_name() {
        let s = "[[rule]]\nname = \"r\"\naction = \"permit\"\n";
        assert!(Policy::from_toml_str(s).is_err());
    }

    #[test]
    fn reject_restrict_without_capabilities() {
        let s = "[[rule]]\nname = \"r\"\naction = \"restrict\"\n";
        let err = Policy::from_toml_str(s).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("at least one capability"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn reject_allow_with_capabilities() {
        let s = "[[rule]]\nname = \"r\"\naction = \"allow\"\ncapabilities = [\"read\"]\n";
        let err = Policy::from_toml_str(s).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("restrict"), "unexpected error: {msg}");
    }

    #[test]
    fn reject_deny_with_capabilities() {
        let s = "[[rule]]\nname = \"r\"\naction = \"deny\"\ncapabilities = [\"read\"]\n";
        let err = Policy::from_toml_str(s).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("restrict"), "unexpected error: {msg}");
    }

    #[test]
    fn reject_restrict_default_action() {
        let err = Policy::from_toml_str("default_action = \"restrict\"").unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("default_action"), "unexpected error: {msg}");
    }

    // ---------- Policy::load ----------

    #[test]
    fn load_reads_and_validates_file() {
        let path = std::env::temp_dir().join(format!(
            "bugwarden-policy-load-test-{}.toml",
            std::process::id()
        ));
        std::fs::write(&path, "default_action = \"deny\"\n").unwrap();
        let p = Policy::load(&path).unwrap();
        assert_eq!(p.default_action, Action::Deny);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn load_missing_file_errors() {
        let err = Policy::load(Path::new("/nonexistent/bugwarden-policy.toml")).unwrap_err();
        assert!(format!("{err:#}").contains("failed to read"));
    }

    #[test]
    fn load_invalid_file_errors_with_path_context() {
        let path = std::env::temp_dir().join(format!(
            "bugwarden-policy-invalid-test-{}.toml",
            std::process::id()
        ));
        std::fs::write(&path, "default_action = \"restrict\"\n").unwrap();
        let err = Policy::load(&path).unwrap_err();
        assert!(format!("{err:#}").contains("invalid guard policy file"));
        std::fs::remove_file(&path).ok();
    }

    // ---------- classify ----------

    #[test]
    fn classify_default_allow_grants_everything() {
        let p = Policy::default();
        let access = p.classify(&meta(), now());
        match &access {
            Access::Granted { caps, rule } => {
                assert_eq!(rule, "default");
                assert_eq!(caps.len(), 11);
            }
            other => panic!("expected grant, got {other:?}"),
        }
        for c in Capability::ALL {
            assert!(access.allows(c), "{c:?} must be allowed by default");
        }
    }

    #[test]
    fn classify_default_deny_denies_everything() {
        let p = Policy::from_toml_str("default_action = \"deny\"").unwrap();
        let access = p.classify(&meta(), now());
        match &access {
            Access::Denied { rule } => assert_eq!(rule, "default"),
            other => panic!("expected denial, got {other:?}"),
        }
        for c in Capability::ALL {
            assert!(!access.allows(c), "{c:?} must be denied");
        }
    }

    #[test]
    fn classify_first_match_wins() {
        let s = r#"
[[rule]]
name = "first"
action = "deny"
[rule.match]
products = ["openSUSE*"]

[[rule]]
name = "second"
action = "allow"
[rule.match]
products = ["*"]
"#;
        let p = Policy::from_toml_str(s).unwrap();
        match p.classify(&meta(), now()) {
            Access::Denied { rule } => assert_eq!(rule, "first"),
            other => panic!("first matching rule must win, got {other:?}"),
        }
        // A bug the first rule does not match falls through to the second.
        let mut other_bug = meta();
        other_bug.product = Some("GNOME".into());
        match p.classify(&other_bug, now()) {
            Access::Granted { rule, .. } => assert_eq!(rule, "second"),
            other => panic!("expected grant from catch-all, got {other:?}"),
        }
    }

    #[test]
    fn classify_embargo_group_deny() {
        let s = r#"
default_action = "allow"

[[rule]]
name = "embargo"
action = "deny"
[rule.match]
groups = ["*security*", "*embargo*"]
"#;
        let p = Policy::from_toml_str(s).unwrap();
        let mut bug = meta();
        bug.groups = Some(vec!["suse-security-internal".into()]);
        match p.classify(&bug, now()) {
            Access::Denied { rule } => assert_eq!(rule, "embargo"),
            other => panic!("embargoed bug must be denied, got {other:?}"),
        }
        // Without the group the default allows.
        assert!(p.classify(&meta(), now()).allows(Capability::Read));
    }

    #[test]
    fn classify_min_bug_age_denies_young_bug() {
        let p = Policy::from_toml_str("[global]\nmin_bug_age_days = 30\n").unwrap();
        let mut bug = meta();
        bug.creation_time = Some(t("2026-01-14T00:00:00Z")); // 1 day old
        match p.classify(&bug, now()) {
            Access::Denied { rule } => assert_eq!(rule, "min_bug_age_days"),
            other => panic!("young bug must be denied, got {other:?}"),
        }
        bug.creation_time = Some(t("2025-01-01T00:00:00Z")); // over a year old
        assert!(p.classify(&bug, now()).allows(Capability::Read));
    }

    #[test]
    fn classify_min_bug_age_missing_creation_time_fails_closed() {
        let p = Policy::from_toml_str("[global]\nmin_bug_age_days = 30\n").unwrap();
        let mut bug = meta();
        bug.creation_time = None;
        match p.classify(&bug, now()) {
            Access::Denied { rule } => assert_eq!(rule, "min_bug_age_days"),
            other => panic!("unknown age must be denied under an age gate (I4), got {other:?}"),
        }
        // With the gate disabled a missing creation_time is fine.
        assert!(Policy::default()
            .classify(&bug, now())
            .allows(Capability::Read));
    }

    #[test]
    fn classify_min_bug_age_boundary_exactly_n_days() {
        let p = Policy::from_toml_str("[global]\nmin_bug_age_days = 7\n").unwrap();
        let mut bug = meta();
        // Exactly 7 days old => age requirement met => allowed.
        bug.creation_time = Some(t("2026-01-08T12:00:00Z"));
        assert!(p.classify(&bug, now()).allows(Capability::Read));
        // One second younger => denied.
        bug.creation_time = Some(t("2026-01-08T12:00:01Z"));
        assert!(matches!(p.classify(&bug, now()), Access::Denied { .. }));
    }

    #[test]
    fn classify_min_bug_age_runs_before_allow_rules() {
        let s = r#"
[global]
min_bug_age_days = 30

[[rule]]
name = "allow-everything"
action = "allow"
"#;
        let p = Policy::from_toml_str(s).unwrap();
        let mut bug = meta();
        bug.creation_time = Some(t("2026-01-14T00:00:00Z"));
        match p.classify(&bug, now()) {
            Access::Denied { rule } => assert_eq!(rule, "min_bug_age_days"),
            other => panic!("global age gate must precede rules, got {other:?}"),
        }
    }

    #[test]
    fn classify_restrict_grants_exact_caps() {
        let s = r#"
[[rule]]
name = "limited"
action = "restrict"
capabilities = ["summary", "comments"]
"#;
        let p = Policy::from_toml_str(s).unwrap();
        let access = p.classify(&meta(), now());
        assert!(access.allows(Capability::Summary));
        assert!(access.allows(Capability::Comments));
        assert!(!access.allows(Capability::Read));
        assert!(!access.allows(Capability::History));
        assert!(!access.allows(Capability::Attachments));
        assert!(!access.allows(Capability::Comment));
        assert!(!access.allows(Capability::Status));
    }

    #[test]
    fn classify_younger_than_days_restrict_rule() {
        let s = r#"
[[rule]]
name = "fresh-bugs-summary-only"
action = "restrict"
capabilities = ["summary"]
[rule.match]
younger_than_days = 14
"#;
        let p = Policy::from_toml_str(s).unwrap();
        let mut bug = meta();
        bug.creation_time = Some(t("2026-01-10T00:00:00Z")); // 5 days old
        let access = p.classify(&bug, now());
        assert!(access.allows(Capability::Summary));
        assert!(!access.allows(Capability::Read));
        // Old bug falls through to default allow.
        bug.creation_time = Some(t("2025-06-01T00:00:00Z"));
        assert!(p.classify(&bug, now()).allows(Capability::Read));
        // Unknown age is treated as young (fail closed).
        bug.creation_time = None;
        assert!(!p.classify(&bug, now()).allows(Capability::Read));
    }

    #[test]
    fn read_implies_summary_only() {
        let read_only_cap = Access::Granted {
            caps: [Capability::Read].into_iter().collect(),
            rule: "r".into(),
        };
        assert!(read_only_cap.allows(Capability::Read));
        assert!(read_only_cap.allows(Capability::Summary)); // I6
        assert!(!read_only_cap.allows(Capability::Comments)); // nothing else implied
        assert!(!read_only_cap.allows(Capability::History));
        assert!(!read_only_cap.allows(Capability::Attachments));

        // Summary does NOT imply read.
        let summary_only = Access::Granted {
            caps: [Capability::Summary].into_iter().collect(),
            rule: "r".into(),
        };
        assert!(summary_only.allows(Capability::Summary));
        assert!(!summary_only.allows(Capability::Read));

        // Comments does not imply summary.
        let comments_only = Access::Granted {
            caps: [Capability::Comments].into_iter().collect(),
            rule: "r".into(),
        };
        assert!(!comments_only.allows(Capability::Summary));
    }

    #[test]
    fn access_denied_allows_nothing() {
        let denied = Access::Denied { rule: "x".into() };
        for c in Capability::ALL {
            assert!(!denied.allows(c));
        }
    }

    #[test]
    fn read_only_strips_write_caps_from_default_grant() {
        let p = Policy::from_toml_str("[global]\nread_only = true\n").unwrap();
        let access = p.classify(&meta(), now());
        for c in Capability::ALL {
            if c.is_write() {
                assert!(!access.allows(c), "{c:?} must be stripped in read-only");
            } else {
                assert!(access.allows(c), "{c:?} must survive read-only");
            }
        }
    }

    #[test]
    fn read_only_strips_write_caps_from_allow_rule() {
        let s = r#"
[global]
read_only = true

[[rule]]
name = "allow-all"
action = "allow"
"#;
        let p = Policy::from_toml_str(s).unwrap();
        let access = p.classify(&meta(), now());
        assert!(access.allows(Capability::Read));
        assert!(!access.allows(Capability::Comment));
        assert!(!access.allows(Capability::Status));
        match &access {
            Access::Granted { caps, .. } => {
                assert_eq!(caps.len(), 5, "only the five read caps remain");
                assert!(caps.iter().all(|c| !c.is_write()));
            }
            other => panic!("expected grant, got {other:?}"),
        }
    }

    #[test]
    fn read_only_strips_write_caps_from_restrict_rule() {
        let s = r#"
[global]
read_only = true

[[rule]]
name = "mixed"
action = "restrict"
capabilities = ["summary", "comment", "status"]
"#;
        let p = Policy::from_toml_str(s).unwrap();
        let access = p.classify(&meta(), now());
        assert!(access.allows(Capability::Summary));
        assert!(!access.allows(Capability::Comment));
        assert!(!access.allows(Capability::Status));
        match &access {
            Access::Granted { caps, .. } => assert_eq!(caps.len(), 1),
            other => panic!("expected grant, got {other:?}"),
        }
    }

    #[test]
    fn classify_unreadable_metadata_never_grants() {
        // A granting rule whose verdict hinges on a field nobody could read
        // must not grant, and must not be skipped into a permissive default
        // either. Both an allow rule under an allowing default and a
        // restrict rule under a denying default are grants (I4).
        let unreadable = BugMeta {
            creation_time: None,
            ..meta()
        };
        let known_fresh = BugMeta {
            creation_time: Some(t("2026-01-14T00:00:00Z")),
            ..meta()
        };

        let allow_rule = Policy::from_toml_str(concat!(
            "default_action = \"allow\"\n",
            "[[rule]]\nname = \"fresh\"\naction = \"allow\"\n",
            "[rule.match]\nyounger_than_days = 30\n",
        ))
        .unwrap();
        assert!(matches!(
            allow_rule.classify(&unreadable, now()),
            Access::Denied { .. }
        ));
        assert!(allow_rule
            .classify(&known_fresh, now())
            .allows(Capability::Read));

        // The case a permissive default would hide: under `deny`, a restrict
        // rule is the only thing granting anything at all.
        let restrict_rule = Policy::from_toml_str(concat!(
            "default_action = \"deny\"\n",
            "[[rule]]\nname = \"recent-summaries\"\naction = \"restrict\"\n",
            "capabilities = [\"summary\"]\n",
            "[rule.match]\nyounger_than_days = 30\n",
        ))
        .unwrap();
        assert!(matches!(
            restrict_rule.classify(&unreadable, now()),
            Access::Denied { .. }
        ));
        assert!(restrict_rule
            .classify(&known_fresh, now())
            .allows(Capability::Summary));
    }

    #[test]
    fn classify_unreadable_metadata_does_not_slip_past_a_later_deny_rule() {
        // First-match-wins: a granting rule that matches only because of an
        // unreadable field must not short-circuit the deny rule that would
        // have caught the bug had the field been readable.
        let p = Policy::from_toml_str(concat!(
            "default_action = \"allow\"\n",
            "[[rule]]\nname = \"triage\"\naction = \"restrict\"\n",
            "capabilities = [\"summary\", \"comments\"]\n",
            "[rule.match]\nwhiteboard_contains = [\"needs-triage\"]\n",
            "[[rule]]\nname = \"undisclosed\"\naction = \"deny\"\n",
            "[rule.match]\nsummary_contains = [\"embargo\"]\n",
        ))
        .unwrap();
        // Readable: the deny rule catches it.
        let readable = BugMeta {
            summary: Some("EMBARGOED: CVE-2026-1: openssl".into()),
            whiteboard: Some(String::new()),
            ..meta()
        };
        assert!(matches!(
            p.classify(&readable, now()),
            Access::Denied { .. }
        ));
        // The same bug with neither field readable must not do better.
        let unreadable = BugMeta {
            summary: None,
            whiteboard: None,
            ..meta()
        };
        assert!(matches!(
            p.classify(&unreadable, now()),
            Access::Denied { .. }
        ));
    }

    #[test]
    fn classify_unreadable_field_no_rule_asks_about_is_harmless() {
        // Fail-closed must not degenerate into "deny everything with a gap":
        // only the criteria a rule actually uses can make it undecidable.
        let p = Policy::from_toml_str(concat!(
            "default_action = \"allow\"\n",
            "[[rule]]\nname = \"undisclosed\"\naction = \"deny\"\n",
            "[rule.match]\nsummary_contains = [\"embargo\"]\n",
        ))
        .unwrap();
        let no_whiteboard = BugMeta {
            summary: Some("ordinary bug".into()),
            whiteboard: None,
            ..meta()
        };
        assert!(p.classify(&no_whiteboard, now()).allows(Capability::Read));
    }

    #[test]
    fn classify_hand_built_restrict_default_fails_closed() {
        // Validation forbids default_action = restrict; a hand-constructed
        // Policy carrying it must still deny, never grant.
        let p = Policy {
            default_action: Action::Restrict,
            global: GlobalGuards::default(),
            rules: Vec::new(),
        };
        assert!(matches!(p.classify(&meta(), now()), Access::Denied { .. }));
    }

    // ---------- BugMeta::from_json ----------

    #[test]
    fn bugmeta_from_json_full_object() {
        let m = BugMeta::from_json(&json!({
            "id": 7,
            "summary": "boom",
            "product": "P",
            "component": "C",
            "status": "NEW",
            "severity": "Major",
            "priority": "P1",
            "keywords": ["k1", "k2"],
            "groups": ["g1"],
            "whiteboard": "wb-text",
            "creation_time": "2025-01-02T03:04:05Z"
        }));
        assert_eq!(m.id, 7);
        assert_eq!(m.summary.as_deref(), Some("boom"));
        assert_eq!(m.product.as_deref(), Some("P"));
        assert_eq!(m.components, Some(vec!["C".to_string()]));
        assert_eq!(m.status.as_deref(), Some("NEW"));
        assert_eq!(m.severity.as_deref(), Some("Major"));
        assert_eq!(m.priority.as_deref(), Some("P1"));
        assert_eq!(m.keywords, Some(vec!["k1".to_string(), "k2".to_string()]));
        assert_eq!(m.groups, Some(vec!["g1".to_string()]));
        assert_eq!(m.whiteboard.as_deref(), Some("wb-text"));
        assert!(m.creation_time.is_some());
    }

    #[test]
    fn bugmeta_component_string_or_array() {
        assert_eq!(
            BugMeta::from_json(&json!({"component": "One"})).components,
            Some(vec!["One".to_string()])
        );
        assert_eq!(
            BugMeta::from_json(&json!({"component": ["One", "Two"]})).components,
            Some(vec!["One".to_string(), "Two".to_string()])
        );
    }

    #[test]
    fn bugmeta_group_objects_with_name_key() {
        let m = BugMeta::from_json(&json!({"groups": [{"name": "sec"}, "plain"]}));
        assert_eq!(m.groups, Some(vec!["sec".to_string(), "plain".to_string()]));
    }

    #[test]
    fn bugmeta_partially_readable_list_is_unknown() {
        // A group list whose elements cannot be read must NOT collapse into
        // a shorter list: dropping the only element would make a restricted
        // bug look world-readable, the most permissive answer there is.
        for shape in [
            json!({"groups": [{"id": 12}]}),
            json!({"groups": [12, 13]}),
            json!({"groups": [{"name": "sec"}, {"id": 9}]}),
            json!({"groups": [null]}),
        ] {
            let m = BugMeta::from_json(&shape);
            assert_eq!(m.groups, None, "shape {shape}");
        }
        // An empty list is fully readable: the bug really is world-readable.
        assert_eq!(
            BugMeta::from_json(&json!({"groups": []})).groups,
            Some(vec![])
        );
    }

    #[test]
    fn bugmeta_missing_fields_are_unknown_not_empty() {
        let m = BugMeta::from_json(&json!({}));
        assert_eq!(m.id, 0);
        assert!(m.summary.is_none());
        assert!(m.product.is_none());
        assert!(m.components.is_none());
        assert!(m.groups.is_none());
        assert!(m.keywords.is_none());
        assert!(m.whiteboard.is_none());
        assert!(m.creation_time.is_none());
        // Even a non-object is tolerated.
        let m = BugMeta::from_json(&Value::Null);
        assert_eq!(m.id, 0);
        assert!(m.groups.is_none());
    }

    #[test]
    fn bugmeta_present_but_empty_is_knowledge() {
        let m = BugMeta::from_json(&json!({
            "summary": "", "groups": [], "whiteboard": ""
        }));
        assert_eq!(m.summary.as_deref(), Some(""));
        assert_eq!(m.groups, Some(vec![]));
        assert_eq!(m.whiteboard.as_deref(), Some(""));
    }

    #[test]
    fn bugmeta_wrong_typed_fields_are_unknown() {
        // null or an unexpected type is not "empty" — the policy cannot read
        // it, so it must not be mistaken for a bug that carries nothing.
        let m = BugMeta::from_json(&json!({
            "summary": null, "groups": null, "whiteboard": null, "product": null
        }));
        assert!(m.summary.is_none());
        assert!(m.groups.is_none());
        assert!(m.whiteboard.is_none());
        assert!(m.product.is_none());
        let m = BugMeta::from_json(&json!({
            "summary": 7, "groups": {"name": "sec"}, "whiteboard": ["a"], "status": true
        }));
        assert!(m.summary.is_none());
        assert!(m.groups.is_none());
        assert!(m.whiteboard.is_none());
        assert!(m.status.is_none());
    }

    #[test]
    fn bugmeta_bad_creation_time_is_none() {
        let m = BugMeta::from_json(&json!({"creation_time": "yesterday"}));
        assert!(m.creation_time.is_none());
        let m = BugMeta::from_json(&json!({"creation_time": 1700000000}));
        assert!(m.creation_time.is_none());
    }

    #[test]
    fn bugmeta_status_whiteboard_fallback() {
        let m = BugMeta::from_json(&json!({"status_whiteboard": "legacy"}));
        assert_eq!(m.whiteboard.as_deref(), Some("legacy"));
        // "whiteboard" wins when both are present.
        let m = BugMeta::from_json(&json!({"whiteboard": "new", "status_whiteboard": "old"}));
        assert_eq!(m.whiteboard.as_deref(), Some("new"));
        // An empty primary falls back to the legacy key.
        let m = BugMeta::from_json(&json!({"whiteboard": "", "status_whiteboard": "old"}));
        assert_eq!(m.whiteboard.as_deref(), Some("old"));
        // An unreadable key on either side makes the whiteboard unknown: the
        // text that could not be read may have held the marker.
        let m = BugMeta::from_json(&json!({"whiteboard": 7, "status_whiteboard": ""}));
        assert!(m.whiteboard.is_none());
        let m = BugMeta::from_json(&json!({"whiteboard": "", "status_whiteboard": 7}));
        assert!(m.whiteboard.is_none());
    }
}
