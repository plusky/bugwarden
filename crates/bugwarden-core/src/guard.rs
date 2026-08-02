//! Runtime guard enforcement on top of [`crate::policy`].
//!
//! The [`Guard`] performs the classification fetch against Bugzilla and turns
//! [`crate::policy::Access`] decisions into response shapes, enforcing the
//! normative invariants:
//!
//! - **I2** — uniform denial: [`Guard::denial`] produces the exact same text
//!   for a policy-denied and a nonexistent bug.
//! - **I3** — silent filtering: [`Guard::filter_bug_list`] returns the count
//!   of dropped bugs for server-side logging only; callers must never send
//!   it to the MCP client.
//! - **I4** — fail closed: [`Guard::assess`] maps every id whose
//!   classification data cannot be fetched to `Denied`.
//! - **I5** — private comments require BOTH the policy opt-in and the
//!   per-call opt-in in [`Guard::filter_comments`]; the same double opt-in
//!   gates private attachment metadata in [`Guard::filter_attachments`].

use std::collections::{BTreeMap, BTreeSet};

use chrono::Utc;
use serde_json::{Map, Value};

use crate::client::{BugzillaClient, CLASSIFY_FIELDS};
use crate::policy::{Access, BugMeta, Capability, Operation, Policy};

/// Fields kept by the redacted summary-only projection of a bug
/// ([`Guard::summary_view`]). Everything else — assignee, CC, groups,
/// whiteboard, flags, custom fields, … — is stripped.
pub const SUMMARY_FIELDS: &[&str] = &[
    "id",
    "summary",
    "status",
    "resolution",
    "product",
    "component",
    "severity",
    "priority",
    "creation_time",
    "last_change_time",
];

/// Policy enforcement wrapper used by every MCP tool that touches a bug id
/// (with the single I8 exception of `bug_url`, which contacts nothing).
#[derive(Debug, Clone)]
pub struct Guard {
    /// The immutable operator policy (I1).
    pub policy: Policy,
}

/// A quicksearch as the client asked for it.
///
/// `limit`/`offset` address the bugs the client may SEE — see
/// [`Guard::quicksearch_window`], which is what makes that true.
#[derive(Debug, Clone, Copy)]
pub struct SearchRequest<'a> {
    /// Bugzilla quicksearch expression.
    pub query: &'a str,
    /// Status filter prepended to the expression ("ALL" for none).
    pub status: &'a str,
    /// Comma-separated projection; callers must include the classification
    /// fields or the guard cannot judge what it is filtering.
    pub include_fields: &'a str,
    /// How many visible bugs to return.
    pub limit: u32,
    /// How many visible bugs to skip.
    pub offset: u32,
}

impl Guard {
    /// The uniform denial text (invariant I2).
    ///
    /// A policy-denied bug and a nonexistent bug MUST produce exactly this
    /// string, with no wording or detail difference, so an MCP client can
    /// never learn whether a hidden bug exists.
    pub fn denial(id: u64) -> String {
        format!("Bug {id} is not accessible through this server")
    }

    /// Largest number of distinct ids one [`Guard::assess`] call will fetch.
    ///
    /// Classification costs one upstream request per distinct id, so the id
    /// count multiplies the work a caller can demand of the Bugzilla behind
    /// this server. The bound lives here, in the crate that owns the fan-out,
    /// rather than in whichever binary happens to call it: `assess` is public
    /// API and must not hand an unbounded loop to an out-of-tree caller.
    pub const MAX_ASSESS_IDS: usize = 25;

    /// Classify `ids` against the policy.
    ///
    /// Fetches `CLASSIFY_FIELDS` with exactly ONE request per distinct id,
    /// sequentially, whatever the outcome. The upstream request count is
    /// therefore a function of the requested ids alone and never of what the
    /// answers turn out to be (I2).
    ///
    /// This is why the batch is gone. How a batch answers for an id it will
    /// not serve is deployment-dependent: `/rest/bug?id=..` routes to
    /// Bug.search on stock Bugzilla and simply omits it, while other versions
    /// and proxies fail the whole request. The old code retried per id ONLY
    /// on failure, so wherever a batch does fail, "no such bug" cost a retry
    /// and "hidden bug" did not — a difference a clock can read. Fetching per
    /// id always removes the dependency on which behaviour an instance has,
    /// and removes batch poisoning outright: one bad id can no longer take
    /// the others down with it, which is what the retry existed to repair.
    ///
    /// Any id that fails or is absent from its response maps to
    /// `(Access::Denied { rule: "unavailable" }, Value::Null)` — every
    /// requested id has an entry in the returned map, and unavailability is
    /// indistinguishable from policy denial downstream (fail closed, I4 + I2).
    ///
    /// Cost: one sequential upstream request per distinct id, bounded by
    /// [`Guard::MAX_ASSESS_IDS`]; ids beyond the bound are denied without
    /// being fetched. Sequential rather than concurrent because some Bugzilla
    /// deployments drop parallel connections (see `client::server_info`).
    ///
    /// `caller` is the requesting account's login as resolved ONCE per tool
    /// call by [`Guard::resolve_caller`] — this method performs no identity
    /// lookup of its own. `None` leaves the `created_by_me` criterion
    /// undecidable, which fails closed for every rule consulting it (I4).
    ///
    /// The API key is only forwarded to the client and never logged (I12).
    pub async fn assess(
        &self,
        bz: &BugzillaClient,
        key: &str,
        ids: &[u64],
        caller: Option<&str>,
    ) -> BTreeMap<u64, (Access, Value)> {
        let mut out = BTreeMap::new();
        if ids.is_empty() {
            return out;
        }
        let now = Utc::now();

        // Classification objects fetched from Bugzilla, keyed by the id the
        // SERVER reported. Requested ids are only trusted when the response
        // actually contains a bug with that id (fail closed).
        //
        // One request per DISTINCT id, unconditionally: the work done must not
        // depend on the answers, or the clock becomes an oracle (I2). Repeats
        // in `ids` are collapsed so a caller cannot inflate the cost, or read
        // anything into it, by asking for the same bug twice.
        let mut fetched: BTreeMap<u64, Value> = BTreeMap::new();
        let mut requested: BTreeSet<u64> = BTreeSet::new();
        for &id in ids {
            if !requested.insert(id) {
                continue;
            }
            if requested.len() > Self::MAX_ASSESS_IDS {
                // Past the bound nothing is fetched, so every remaining id
                // falls through to the denial below (I4). Callers are
                // expected to refuse the request outright with a message;
                // this is the backstop that keeps the fan-out finite even
                // when they do not.
                tracing::warn!(
                    ids = ids.len(),
                    max = Self::MAX_ASSESS_IDS,
                    "assess called with more ids than the bound; denying the excess"
                );
                break;
            }
            match bz.get_bugs(key, &[id], Some(CLASSIFY_FIELDS)).await {
                Ok(envelope) => {
                    if let Some(bugs) = envelope.get("bugs").and_then(Value::as_array) {
                        for bug in bugs {
                            // Only the bug the server itself labels with this
                            // id counts — never the position in the response.
                            if bug.get("id").and_then(Value::as_u64) == Some(id) {
                                fetched.insert(id, bug.clone());
                            }
                        }
                    }
                }
                Err(err) => {
                    // Nonexistent, forbidden upstream, or a transport failure:
                    // all indistinguishable from here, and all fail closed
                    // below (I4). Never logged with the key (I12).
                    tracing::debug!(id, error = %err, "classification fetch failed");
                }
            }
        }

        for &id in ids {
            let entry = match fetched.get(&id) {
                Some(bug) => {
                    let meta = BugMeta::from_json(bug, caller);
                    (
                        self.policy.classify(&meta, now, Operation::Access),
                        bug.clone(),
                    )
                }
                // Absent from the response: nonexistent, server-side denied,
                // or fetch failure — all fail closed identically (I4).
                None => (
                    Access::Denied {
                        rule: "unavailable".into(),
                    },
                    Value::Null,
                ),
            };
            out.insert(id, entry);
        }
        out
    }

    /// Largest `offset + limit` a search may address.
    ///
    /// Paging past this truncates rather than scanning forever; the client
    /// sees the same thing it sees at the genuine end of a result set.
    pub const MAX_SEARCH_WINDOW: u32 = 1_000;

    /// Rows requested from Bugzilla per scan step.
    const SEARCH_SCAN_CHUNK: u32 = 200;

    /// Ceiling on upstream rows examined for one search, i.e. at most
    /// `SEARCH_SCAN_MAX / SEARCH_SCAN_CHUNK` sequential requests.
    const SEARCH_SCAN_MAX: u32 = 2_000;

    /// Run a search whose `limit`/`offset` address the bugs the client may
    /// actually SEE, not the rows Bugzilla happens to return.
    ///
    /// Filtering a page after Bugzilla has already applied `limit`/`offset`
    /// leaves a hole exactly where a hidden bug sat: the page comes back
    /// short while the next offset still yields results, which says "a bug
    /// exists here that you may not see". Because quicksearch matches summary
    /// text, that hole is a probe — append a word to the query, see whether
    /// the hole survives, and the hidden bug's title can be reconstructed one
    /// word at a time. Uniform denials (I2) and silent filtering (I3) are
    /// worth nothing while the window itself reports what was removed.
    ///
    /// So pagination is applied AFTER the guard: scan the upstream result
    /// from row 0, classify each chunk, and keep going until enough visible
    /// bugs have accumulated to fill the requested window. A hidden bug now
    /// costs nothing but a row of upstream scanning — it never shortens a
    /// page and never contradicts a later offset.
    ///
    /// Scanning from row 0 every time is not laziness: a visible-space offset
    /// cannot be mapped onto an upstream offset without first classifying
    /// everything before it, and how many bugs that is, is exactly what the
    /// client must not learn.
    ///
    /// The bugs returned are the objects that were classified, so no second
    /// fetch can serve something the verdict never saw.
    ///
    /// Bounds: at most [`Guard::MAX_SEARCH_WINDOW`] addressable, and at most
    /// `SEARCH_SCAN_MAX` upstream rows examined. Hitting either truncates the
    /// page, which is indistinguishable from running out of results — the
    /// safe direction, since it hides more rather than less.
    ///
    /// Residual, and deliberately accepted: filling a window of VISIBLE bugs
    /// takes more upstream rows when bugs are hidden, so the request count
    /// cannot be made independent of hidden-bug density without either
    /// scanning the worst case on every search or letting pages go short
    /// again. What a stopwatch can still learn is one bit per scanned block —
    /// "this block was not entirely visible" — because the scan target is
    /// quantised to whole chunks; without that quantisation the client could
    /// binary-search `limit` and recover the exact hidden count of every
    /// block, which is why it is there. A long way from reconstructing a
    /// title, which is what this replaces.
    pub async fn quicksearch_window(
        &self,
        bz: &BugzillaClient,
        key: &str,
        req: &SearchRequest<'_>,
        caller: Option<&str>,
    ) -> anyhow::Result<Vec<Value>> {
        let SearchRequest {
            query,
            status,
            include_fields,
            limit,
            offset,
        } = *req;
        let needed = offset.saturating_add(limit).min(Self::MAX_SEARCH_WINDOW);
        if limit == 0 || needed == 0 {
            return Ok(Vec::new());
        }

        // Scan for a whole number of chunks' worth of visible bugs rather
        // than for exactly `needed`. Stopping the moment the window is full
        // makes the stopping point a function of the client's `limit` AND of
        // how many bugs were hidden, and a client can binary-search `limit`
        // against the clock to recover the hidden count of each block
        // exactly. Quantising collapses that: every limit inside a block asks
        // for the same work, so the timing says at most "this block was not
        // entirely visible" instead of how many went missing. Costs nothing
        // in the common case — an unfiltered chunk already fills the target.
        let target = needed
            .div_ceil(Self::SEARCH_SCAN_CHUNK)
            .saturating_mul(Self::SEARCH_SCAN_CHUNK);

        let mut visible: Vec<Value> = Vec::new();
        let mut seen: BTreeSet<u64> = BTreeSet::new();
        let mut scanned: u32 = 0;
        let mut dropped_total = 0usize;

        while (visible.len() as u32) < target && scanned < Self::SEARCH_SCAN_MAX {
            let chunk = Self::SEARCH_SCAN_CHUNK.min(Self::SEARCH_SCAN_MAX - scanned);
            let envelope = bz
                .quicksearch(key, query, status, include_fields, chunk, scanned)
                .await?;
            let rows: Vec<Value> = envelope
                .get("bugs")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            let returned = rows.len() as u32;

            // Relevance ordering is not stable between calls, so chunks can
            // overlap; dedupe on the id the server reported. A row without a
            // readable id cannot be classified and is dropped (I4).
            let fresh: Vec<Value> = rows
                .into_iter()
                .filter(|b| {
                    b.get("id")
                        .and_then(Value::as_u64)
                        .is_some_and(|id| seen.insert(id))
                })
                .collect();
            let (kept, dropped) = self.filter_bug_list(fresh, caller);
            dropped_total += dropped;
            visible.extend(kept);
            scanned += returned;

            if returned < chunk {
                break; // upstream has no more rows
            }
        }

        if dropped_total > 0 {
            // Server-side only, never a count to the client (I3).
            tracing::debug!(
                dropped = dropped_total,
                scanned,
                "quicksearch: withheld policy-denied bugs"
            );
        }

        // `start` is clamped to `end`, not merely to the length. The window
        // stops at MAX_SEARCH_WINDOW but the scan overshoots it whenever a
        // chunk yields fewer visible bugs than it holds — which happens only
        // when bugs WERE hidden. An unclamped start would therefore panic
        // exactly when something was hidden past the window, answering the
        // one question this whole function exists to refuse (and taking the
        // session down with it).
        let end = (needed as usize).min(visible.len());
        let start = (offset as usize).min(end);
        Ok(visible[start..end].to_vec())
    }

    /// Bug fields that carry references to OTHER bugs, as id lists.
    ///
    /// `dupe_of` is a scalar rather than a list and is handled separately.
    /// Legacy and instance-specific spellings are included: an unknown
    /// id-bearing field is a leak, so the list errs towards over-matching.
    pub const LINKED_ID_FIELDS: &[&str] = &[
        "blocks",
        "depends_on",
        "dependson",
        "duplicates",
        "regressed_by",
        "regressions",
        "blocked",
    ];

    /// Which of `ids` may be NAMED inside something the client is being
    /// shown.
    ///
    /// The bar is [`Capability::Summary`] — the same one the write paths
    /// already apply to link targets (I8/I11), because a link and a written
    /// link disclose the same fact: that this bug exists.
    ///
    /// One batched request whatever the ids, unlike [`Guard::assess`]: these
    /// ids come from Bugzilla's own answer, not from the client, so their
    /// number is not something a client can choose to probe with. A failed
    /// fetch yields the empty set — everything is scrubbed (I4).
    pub async fn disclosable(
        &self,
        bz: &BugzillaClient,
        key: &str,
        ids: &BTreeSet<u64>,
        caller: Option<&str>,
    ) -> BTreeSet<u64> {
        let now = Utc::now();
        // Bug id 0 never exists, so an empty candidate set still costs one
        // request: otherwise "this bug has no links" and "every link is
        // hidden" would be told apart by the clock (I2).
        let wanted: Vec<u64> = if ids.is_empty() {
            vec![0]
        } else {
            // Bounded like assess(): a tracker bug can name hundreds of
            // others, and the excess is simply not disclosable (I4).
            ids.iter().copied().take(Self::MAX_ASSESS_IDS * 8).collect()
        };
        let envelope = match bz.get_bugs(key, &wanted, Some(CLASSIFY_FIELDS)).await {
            Ok(v) => v,
            Err(err) => {
                tracing::debug!(error = %err, "link disclosure fetch failed; scrubbing all");
                return BTreeSet::new();
            }
        };
        let mut out = BTreeSet::new();
        if let Some(bugs) = envelope.get("bugs").and_then(Value::as_array) {
            for bug in bugs {
                let Some(id) = bug.get("id").and_then(Value::as_u64) else {
                    continue;
                };
                if !ids.contains(&id) {
                    continue;
                }
                let meta = BugMeta::from_json(bug, caller);
                if self
                    .policy
                    .classify(&meta, now, Operation::Access)
                    .allows(Capability::Summary)
                {
                    out.insert(id);
                }
            }
        }
        out
    }

    /// Bug ids this bug object points at, from every field that can carry one.
    pub fn linked_bug_ids(bug: &Value, base_url: &str) -> BTreeSet<u64> {
        let mut out = BTreeSet::new();
        for field in Self::LINKED_ID_FIELDS {
            match bug.get(*field) {
                Some(Value::Array(items)) => {
                    out.extend(items.iter().filter_map(Value::as_u64));
                }
                Some(v) => out.extend(v.as_u64()),
                None => {}
            }
        }
        out.extend(bug.get("dupe_of").and_then(Value::as_u64));
        out.extend(bug.get("dup_id").and_then(Value::as_u64));
        // bug_file_loc: a plain URL field that routinely points at a bug.
        out.extend(
            bug.get("url")
                .and_then(Value::as_str)
                .and_then(|u| Self::see_also_local_id(u, base_url)),
        );
        if let Some(Value::Array(entries)) = bug.get("see_also") {
            out.extend(
                entries
                    .iter()
                    .filter_map(Value::as_str)
                    .filter_map(|e| Self::see_also_local_id(e, base_url)),
            );
        }
        out
    }

    /// The bug id a `see_also` entry points at, when it points at THIS
    /// Bugzilla. Entries for other trackers are somebody else's to disclose.
    ///
    /// Public because the write side needs the same parse the read side
    /// uses: `update_bug_fields` must assess the local targets of
    /// `see_also_add`/`see_also_remove` before writing the link (I8/I14),
    /// exactly as the read paths scrub such links out of served bugs.
    pub fn see_also_local_id(entry: &str, base_url: &str) -> Option<u64> {
        // Compare host-and-path only, case-insensitively: Bugzilla stores
        // see_also with the host as the user typed it, so scheme and case
        // vary freely for the same instance. An instance reachable under a
        // second hostname is still missed — recorded in I14, not fixed here.
        let strip_scheme = |u: &str| {
            u.trim()
                .trim_start_matches("https://")
                .trim_start_matches("http://")
                .to_ascii_lowercase()
        };
        let base = strip_scheme(base_url);
        let base = base.trim_end_matches('/');
        let entry_l = strip_scheme(entry);
        let rest = entry_l.strip_prefix(base)?.to_string();
        let rest = rest.as_str();
        let digits = rest
            .strip_prefix("/show_bug.cgi?id=")
            .or_else(|| rest.strip_prefix("/rest/bug/"))?;
        digits
            .split(|c: char| !c.is_ascii_digit())
            .next()
            .filter(|d| !d.is_empty())
            .and_then(|d| d.parse().ok())
    }

    /// Remove references to bugs outside `disclosable` from a bug object.
    ///
    /// A link naming a bug the policy hides tells the client that bug exists,
    /// which is the whole of what I2 withholds — and the write paths already
    /// refuse to CREATE such a link, so reading one back out must not be the
    /// way around that.
    pub fn scrub_bug_links(bug: &mut Value, base_url: &str, disclosable: &BTreeSet<u64>) {
        let Some(obj) = bug.as_object_mut() else {
            return;
        };
        for field in Self::LINKED_ID_FIELDS {
            match obj.get_mut(*field) {
                Some(Value::Array(items)) => {
                    items.retain(|v| v.as_u64().is_some_and(|id| disclosable.contains(&id)));
                }
                // A scalar in an id-bearing field: blank it unless allowed.
                Some(slot) if !slot.as_u64().is_some_and(|id| disclosable.contains(&id)) => {
                    *slot = Value::Null;
                }
                _ => {}
            }
        }
        if let Some(slot) = obj.get_mut("url") {
            let hidden = slot
                .as_str()
                .and_then(|u| Self::see_also_local_id(u, base_url))
                .is_some_and(|id| !disclosable.contains(&id));
            if hidden {
                *slot = Value::Null;
            }
        }
        for field in ["dupe_of", "dup_id"] {
            let Some(slot) = obj.get_mut(field) else {
                continue;
            };
            if !slot.as_u64().is_some_and(|id| disclosable.contains(&id)) {
                *slot = Value::Null;
            }
        }
        if let Some(Value::Array(entries)) = obj.get_mut("see_also") {
            entries.retain(|e| {
                e.as_str().is_none_or(|entry| {
                    Self::see_also_local_id(entry, base_url)
                        .is_none_or(|id| disclosable.contains(&id))
                })
            });
        }
    }

    /// Bug ids named by a history response.
    pub fn history_bug_ids(history: &Value, base_url: &str) -> BTreeSet<u64> {
        let mut out = BTreeSet::new();
        Self::walk_history(history, |field, value| {
            out.extend(Self::history_ids_in(field, value, base_url));
        });
        out
    }

    /// Remove history changes that name bugs outside `disclosable`.
    ///
    /// A change is edited down to the ids that may be named; one left with
    /// nothing to say is dropped entirely, rather than shown as an empty
    /// change that still marks the moment something happened.
    pub fn scrub_history(mut history: Value, base_url: &str, disclosable: &BTreeSet<u64>) -> Value {
        let Some(entries) = history.as_array_mut() else {
            return history;
        };
        for entry in entries.iter_mut() {
            let Some(changes) = entry.get_mut("changes").and_then(Value::as_array_mut) else {
                continue;
            };
            changes.retain_mut(|change| {
                let field = change
                    .get("field_name")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string();
                if !Self::is_id_bearing_history_field(&field) {
                    return true;
                }
                let mut anything_left = false;
                for slot in ["added", "removed"] {
                    let Some(v) = change.get_mut(slot) else {
                        continue;
                    };
                    let kept = Self::keep_disclosable_ids(
                        v.as_str().unwrap_or_default(),
                        base_url,
                        disclosable,
                    );
                    anything_left |= !kept.is_empty();
                    *v = Value::String(kept);
                }
                anything_left
            });
        }
        entries.retain(|entry| {
            entry
                .get("changes")
                .and_then(Value::as_array)
                .is_none_or(|c| !c.is_empty())
        });
        history
    }

    fn is_id_bearing_history_field(field: &str) -> bool {
        Self::LINKED_ID_FIELDS.contains(&field)
            || matches!(field, "dupe_of" | "dup_id" | "see_also" | "url")
    }

    /// Keep only the disclosable ids in a comma-separated history value.
    fn keep_disclosable_ids(value: &str, base_url: &str, disclosable: &BTreeSet<u64>) -> String {
        value
            .split(',')
            .map(str::trim)
            .filter(|piece| !piece.is_empty())
            .filter(|piece| match piece.parse::<u64>() {
                Ok(id) => disclosable.contains(&id),
                // A see_also URL, or something unrecognised: keep it only if
                // it does not name a local bug that must stay hidden.
                Err(_) => Self::see_also_local_id(piece, base_url)
                    .is_none_or(|id| disclosable.contains(&id)),
            })
            .collect::<Vec<_>>()
            .join(", ")
    }

    fn walk_history(history: &Value, mut visit: impl FnMut(&str, &str)) {
        let Some(entries) = history.as_array() else {
            return;
        };
        for entry in entries {
            let Some(changes) = entry.get("changes").and_then(Value::as_array) else {
                continue;
            };
            for change in changes {
                let field = change
                    .get("field_name")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                if !Self::is_id_bearing_history_field(field) {
                    continue;
                }
                for slot in ["added", "removed"] {
                    if let Some(v) = change.get(slot).and_then(Value::as_str) {
                        visit(field, v);
                    }
                }
            }
        }
    }

    fn history_ids_in(_field: &str, value: &str, base_url: &str) -> BTreeSet<u64> {
        value
            .split(',')
            .map(str::trim)
            .filter(|p| !p.is_empty())
            .filter_map(|p| {
                p.parse::<u64>()
                    .ok()
                    .or_else(|| Self::see_also_local_id(p, base_url))
            })
            .collect()
    }

    /// The bug id in Bugzilla's auto-generated duplicate marker, if this
    /// comment is one.
    ///
    /// Bugzilla writes these itself when a bug is closed as a duplicate, so
    /// the text is templated rather than typed by a person:
    /// `*** Bug 12345 has been marked as a duplicate of this bug ***`.
    /// Matching a template is inherently brittle — a localised or customised
    /// instance writes something else and this will not recognise it — so it
    /// is a mitigation for the common case, not a guarantee. Free text where
    /// a person simply mentions a bug number is out of reach entirely without
    /// destroying the usefulness of comments.
    pub fn duplicate_marker_id(text: &str) -> Option<u64> {
        // Bugzilla writes BOTH directions, from two templates, and the
        // "*** This bug ***" form is preceded by whatever the closer typed —
        // so neither can be found by looking at the start of the comment.
        //   on the duplicate: *** This bug has been marked as a duplicate of bug N ***
        //   on the target:    *** Bug N has been marked as a duplicate of this bug ***
        if let Some(at) = text.find("*** This bug has been marked as a duplicate of bug ") {
            let rest = &text[at + "*** This bug has been marked as a duplicate of bug ".len()..];
            let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
            return digits.parse().ok();
        }
        let at = text.find("*** Bug ")?;
        let rest = &text[at + "*** Bug ".len()..];
        let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
        if digits.is_empty() {
            return None;
        }
        let tail = &rest[digits.len()..];
        tail.starts_with(" has been marked as a duplicate")
            .then(|| digits.parse().ok())
            .flatten()
    }

    /// Bug ids named by duplicate markers among these comments.
    pub fn duplicate_marker_ids(comments: &[Value]) -> BTreeSet<u64> {
        comments
            .iter()
            .filter_map(|c| c.get("text").and_then(Value::as_str))
            .filter_map(Self::duplicate_marker_id)
            .collect()
    }

    /// Drop duplicate-marker comments naming bugs outside `disclosable`.
    pub fn scrub_duplicate_markers(
        comments: Vec<Value>,
        disclosable: &BTreeSet<u64>,
    ) -> Vec<Value> {
        comments
            .into_iter()
            .filter(|c| {
                c.get("text")
                    .and_then(Value::as_str)
                    .and_then(Self::duplicate_marker_id)
                    .is_none_or(|id| disclosable.contains(&id))
            })
            .collect()
    }

    /// Whether a bug MAY BE FILED as described.
    ///
    /// There is no bug to classify yet, so the bug as requested is
    /// classified instead: the same rules that decide whether an existing bug
    /// may be seen decide whether one may be created looking like that. A
    /// policy that hides a product by NAME therefore also refuses to let
    /// bugs be filed into it, without needing a second vocabulary.
    ///
    /// The request is only evidence for fields Bugzilla will take verbatim.
    /// For product, component, summary, version, severity, priority,
    /// keywords and the rest, the created bug either carries exactly the
    /// requested value or creation fails upstream — so the claim is sound to
    /// classify on. `groups` is different in kind: Bugzilla UNIONS the
    /// product's mandatory groups into whatever the request named, so the
    /// created bug can belong to groups the request never mentioned (the
    /// canonical `security-*` embargo setup works exactly this way). A
    /// client-claimed group list must therefore never decide the verdict —
    /// claiming `groups: []` would otherwise defeat a group deny rule that
    /// omitting `groups` correctly trips. The group list of a prospective
    /// bug is forced to UNKNOWN, whatever the payload said, and unknown
    /// fails closed (I4). Consequence, deliberate: a rule consulting
    /// `groups` or `group_restricted` refuses every create request that
    /// REACHES it, because the answer cannot be known before the bug
    /// exists — so creation is possible only where an earlier rule covering
    /// the create operation grants `create` first, and a policy with no
    /// such earlier grant refuses all creation.
    ///
    /// The request is classified for [`Operation::Create`]: a rule scoped to
    /// `operations = ["access"]` is not consulted here, and a rule scoped to
    /// `operations = ["create"]` exists ONLY here — which is what lets an
    /// operator grant filing into a product ahead of the group-consulting
    /// rules without that grant shadowing reads of the product's existing
    /// bugs (issue #26).
    ///
    /// The prospective bug is dated NOW, so an age rule (`younger_than_days`,
    /// `min_bug_age_days`) refuses creation wherever it would immediately
    /// hide the result. Filing a bug nobody may then read is not a service.
    ///
    /// `created_by_me` is forced to `Some(true)` unconditionally: the
    /// creator of a bug being filed is definitionally the caller — Bugzilla
    /// assigns `creator` server-side from the authenticating account, and
    /// the typed `create_bug` parameters cannot claim it. No `whoami`
    /// lookup is ever performed for the create gate (which is also why a
    /// create-scoped identity rule never triggers one — see
    /// `Policy::needs_identity`). Consequence: a create-covering rule with
    /// `created_by_me = true` matches every create request that reaches it,
    /// and one with `created_by_me = false` can never match a create.
    pub fn may_create(&self, requested: &Value) -> bool {
        let mut meta = BugMeta::from_json(requested, None);
        meta.creation_time = Some(Utc::now());
        // Bugzilla augments the group list server-side on creation; the
        // request's claim about it is not knowledge (see above).
        meta.groups = None;
        // The filer IS the creator — a fact, not a claim (see above).
        meta.created_by_me = Some(true);
        // Every other field the request does not mention is unknown, not
        // empty, and classification fails closed on it (I4).
        self.policy
            .classify(&meta, Utc::now(), Operation::Create)
            .allows(Capability::Create)
    }

    /// Resolve the caller's login for this tool call, lazily.
    ///
    /// Contract (see DESIGN.md, "Identity resolution"):
    /// - when the policy consults no identity for access classification
    ///   ([`Policy::needs_identity`] is false), returns `None` WITHOUT any
    ///   HTTP request — a policy without `created_by_me` never costs a
    ///   `whoami` lookup;
    /// - otherwise performs exactly one `GET /rest/whoami` and returns the
    ///   account's login, mapping every failure to `None` (the sanitized
    ///   error is debug-logged only — never the key, I12). `None` makes
    ///   every `created_by_me` criterion undecidable, which denies every
    ///   classification consulting it (I4): a whoami outage blacks out
    ///   what the identity rules cover, it never fails open.
    ///
    /// Callers (the MCP tools) invoke this at most once per tool call and
    /// thread the result to every classification within that call. The
    /// result is never cached across tool calls.
    pub async fn resolve_caller(&self, bz: &BugzillaClient, key: &str) -> Option<String> {
        if !self.policy.needs_identity() {
            return None;
        }
        match bz.whoami(key).await {
            Ok(login) => Some(login),
            Err(err) => {
                // Sanitized by the client (I12); identity stays unknown and
                // every consulted identity rule fails closed (I4).
                tracing::debug!(error = %err, "whoami failed; caller identity unresolved");
                None
            }
        }
    }

    /// The refusal for a bug that was not filed.
    ///
    /// Says only that the server did not do it: which rule tripped — or
    /// whether it was Bugzilla, not the policy, that refused — stays
    /// server-side (I1/I2). Callers must return this SAME text for a policy
    /// refusal and for an upstream failure: two texts would let a client
    /// send an always-invalid request (a bogus `version`, say) and read the
    /// policy off which refusal came back, creating nothing and paying
    /// nothing.
    pub fn create_denial() -> String {
        "Filing this bug is not permitted through this server".to_string()
    }

    /// Project a bug object down to [`SUMMARY_FIELDS`] and add a
    /// `"_redacted": true` marker so clients (and tests) can tell a summary
    /// view from a full bug. Fields absent from the input are simply omitted.
    pub fn summary_view(bug: &Value) -> Value {
        let mut out = Map::new();
        if let Some(obj) = bug.as_object() {
            for &field in SUMMARY_FIELDS {
                if let Some(v) = obj.get(field) {
                    out.insert(field.to_string(), v.clone());
                }
            }
        }
        out.insert("_redacted".to_string(), Value::Bool(true));
        Value::Object(out)
    }

    /// Filter a list of bug objects (e.g. quicksearch results) by policy.
    ///
    /// Per bug: a `read` grant keeps the object as-is, a `summary`-only
    /// grant replaces it with [`Guard::summary_view`], anything else drops
    /// it. Returns `(kept, dropped_count)`; the count exists for server-side
    /// logging ONLY and must never be sent to the MCP client (I3) — from the
    /// client's perspective filtered results simply never existed.
    ///
    /// The input objects must include the classification fields (callers
    /// fetch `requested ∪ CLASSIFY_FIELDS`), otherwise bugs may be
    /// misclassified against empty metadata.
    ///
    /// `caller` is the login resolved once for the surrounding tool call
    /// ([`Guard::resolve_caller`]); under an identity-consulting policy a
    /// caller of `None` denies every bug the identity rules are consulted
    /// for (I4).
    pub fn filter_bug_list(&self, bugs: Vec<Value>, caller: Option<&str>) -> (Vec<Value>, usize) {
        let now = Utc::now();
        let mut kept = Vec::new();
        let mut dropped = 0usize;
        for bug in bugs {
            let meta = BugMeta::from_json(&bug, caller);
            let access = self.policy.classify(&meta, now, Operation::Access);
            if access.allows(Capability::Read) {
                kept.push(bug);
            } else if access.allows(Capability::Summary) {
                kept.push(Self::summary_view(&bug));
            } else {
                dropped += 1;
            }
        }
        (kept, dropped)
    }

    /// Drop private comments unless BOTH the policy allows them AND the call
    /// asked for them (invariant I5).
    ///
    /// A comment is private when it carries `"is_private": true`; a missing
    /// flag means public. Neither `global.allow_private_comments = true` on
    /// its own nor `include_private = true` on its own is sufficient.
    pub fn filter_comments(&self, comments: Vec<Value>, include_private: bool) -> Vec<Value> {
        self.filter_private(comments, include_private)
    }

    /// Drop private attachment metadata (`"is_private": true`) unless BOTH
    /// the policy allows private content AND the call asked for it — the
    /// same double opt-in invariant I5 mandates for comments.
    ///
    /// Without this, the filename, description, and creator of restricted
    /// attachments would reach clients whose policy redacts the very same
    /// content in comments and bug bodies.
    pub fn filter_attachments(&self, attachments: Vec<Value>, include_private: bool) -> Vec<Value> {
        self.filter_private(attachments, include_private)
    }

    /// The uniform attachment denial text.
    ///
    /// Mirrors `denial` (I2): a policy-blocked attachment and a nonexistent
    /// attachment id MUST be indistinguishable, so an MCP client can never
    /// probe attachment ids to learn whether hidden attachments exist.
    pub fn attachment_denial(id: u64) -> String {
        format!("Attachment {id} is not accessible through this server")
    }

    /// Gate for downloading a single attachment's content, evaluated on its
    /// metadata BEFORE the blob is fetched. Returns the refusal text when
    /// the download must be blocked, `None` when it may proceed.
    ///
    /// Two checks:
    /// - private attachments need the I5 double opt-in — stricter than the
    ///   metadata listing: a MISSING `is_private` flag on a full-content
    ///   download is treated as private (fail closed, I4), because the blob
    ///   is the payload the guard exists to protect;
    /// - the upstream-reported `size` must fit
    ///   `global.max_attachment_bytes` (`0` = no cap); a missing size while
    ///   a cap is active fails closed.
    pub fn attachment_gate(&self, attachment: &Value, include_private: bool) -> Option<String> {
        let id = attachment.get("id").and_then(Value::as_u64).unwrap_or(0);
        let is_private = attachment
            .get("is_private")
            .and_then(Value::as_bool)
            .unwrap_or(true);
        if is_private && !(include_private && self.policy.global.allow_private_comments) {
            return Some(Self::attachment_denial(id));
        }
        // The refusal names neither the attachment's size nor the configured
        // cap: `max_attachment_bytes` is not among the policy fields I1
        // permits a client to learn, and one oversized download must not
        // disclose the operator's configuration.
        let cap = self.policy.global.max_attachment_bytes;
        if cap > 0 {
            match attachment.get("size").and_then(Value::as_u64) {
                Some(size) if size <= cap => {}
                Some(_) => {
                    return Some(format!(
                        "Attachment {id} exceeds the size limit of this server"
                    ));
                }
                None => {
                    return Some(format!(
                        "Attachment {id} has no reported size and cannot be \
                         checked against the size limit of this server"
                    ));
                }
            }
        }
        None
    }

    /// Shared I5 double-opt-in filter for objects carrying an `is_private`
    /// flag. A missing flag means public.
    fn filter_private(&self, items: Vec<Value>, include_private: bool) -> Vec<Value> {
        let private_allowed = include_private && self.policy.global.allow_private_comments;
        items
            .into_iter()
            .filter(|c| {
                let is_private = c
                    .get("is_private")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                !is_private || private_allowed
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {

    // ---------- link / history / duplicate-marker scrubbing (I2) ----------

    const BASE: &str = "https://bugzilla.example.com";

    #[test]
    fn linked_ids_are_collected_from_every_id_bearing_field() {
        let bug = json!({
            "id": 1,
            "blocks": [10, 11],
            "depends_on": [12],
            "dupe_of": 13,
            "regressed_by": [14],
            "see_also": [
                "https://bugzilla.example.com/show_bug.cgi?id=15",
                "https://bugzilla.example.com/rest/bug/16",
                "https://bugs.other.example/show_bug.cgi?id=999",
                "not a url at all"
            ],
        });
        let ids = Guard::linked_bug_ids(&bug, BASE);
        assert_eq!(
            ids.into_iter().collect::<Vec<_>>(),
            vec![10, 11, 12, 13, 14, 15, 16],
            "another tracker's ids are not ours to disclose or scrub"
        );
    }

    #[test]
    fn scrubbing_removes_only_the_ids_that_may_not_be_named() {
        let mut bug = json!({
            "id": 1,
            "blocks": [10, 11],
            "depends_on": [12],
            "dupe_of": 13,
            "see_also": [
                "https://bugzilla.example.com/show_bug.cgi?id=15",
                "https://bugs.other.example/show_bug.cgi?id=999"
            ],
        });
        let allowed: BTreeSet<u64> = [10, 12].into_iter().collect();
        Guard::scrub_bug_links(&mut bug, BASE, &allowed);

        assert_eq!(bug["blocks"], json!([10]));
        assert_eq!(bug["depends_on"], json!([12]));
        assert_eq!(bug["dupe_of"], Value::Null, "a hidden duplicate is blanked");
        assert_eq!(
            bug["see_also"],
            json!(["https://bugs.other.example/show_bug.cgi?id=999"]),
            "local hidden bug dropped, foreign tracker kept"
        );
        assert_eq!(bug["id"], json!(1), "the bug's own id is untouched");
    }

    #[test]
    fn history_changes_are_edited_down_and_emptied_ones_dropped() {
        let history = json!([
            {
                "when": "2026-01-01T00:00:00Z",
                "who": "a@b",
                "changes": [
                    { "field_name": "depends_on", "added": "10, 11", "removed": "" },
                    { "field_name": "status", "added": "RESOLVED", "removed": "NEW" }
                ]
            },
            {
                "when": "2026-01-02T00:00:00Z",
                "who": "a@b",
                "changes": [
                    { "field_name": "blocks", "added": "11", "removed": "" }
                ]
            }
        ]);
        let allowed: BTreeSet<u64> = [10].into_iter().collect();
        let out = Guard::scrub_history(history, BASE, &allowed);

        let first = &out[0]["changes"];
        assert_eq!(first[0]["added"], json!("10"), "hidden id 11 removed");
        assert_eq!(first[1]["added"], json!("RESOLVED"), "other fields intact");
        assert_eq!(
            out.as_array().unwrap().len(),
            1,
            "an entry whose only change named a hidden bug is dropped, not              served empty — an empty change still marks that something happened"
        );
    }

    #[test]
    fn history_ids_are_found_in_both_directions_and_in_see_also_urls() {
        let history = json!([{
            "changes": [
                { "field_name": "blocks", "added": "1", "removed": "2, 3" },
                { "field_name": "see_also",
                  "added": "https://bugzilla.example.com/show_bug.cgi?id=4",
                  "removed": "" },
                { "field_name": "cc", "added": "someone@example.com", "removed": "" }
            ]
        }]);
        let ids = Guard::history_bug_ids(&history, BASE);
        assert_eq!(ids.into_iter().collect::<Vec<_>>(), vec![1, 2, 3, 4]);
    }

    #[test]
    fn duplicate_marker_is_recognised_and_scrubbed() {
        let marker = "*** Bug 4242 has been marked as a duplicate of this bug ***";
        assert_eq!(Guard::duplicate_marker_id(marker), Some(4242));
        // A human writing about a bug number is not a marker, and is out of
        // reach anyway.
        assert_eq!(Guard::duplicate_marker_id("see bug 4242 for context"), None);
        assert_eq!(
            Guard::duplicate_marker_id("*** Bug 4242 was closed ***"),
            None
        );

        let comments = vec![
            json!({ "id": 1, "text": marker }),
            json!({ "id": 2, "text": "a normal comment" }),
            json!({ "id": 3, "text": "*** Bug 7 has been marked as a duplicate of this bug ***" }),
        ];
        let allowed: BTreeSet<u64> = [7].into_iter().collect();
        let kept = Guard::scrub_duplicate_markers(comments, &allowed);
        assert_eq!(kept.len(), 2);
        assert_eq!(kept[0]["id"], json!(2));
        assert_eq!(kept[1]["id"], json!(3), "a disclosable duplicate stays");
    }

    #[test]
    fn both_stock_duplicate_marker_templates_are_recognised() {
        // Bugzilla writes one on the duplicate and one on the target, from
        // two different templates, and the first is preceded by whatever the
        // closer typed — so neither can be found at the start of the text.
        assert_eq!(
            Guard::duplicate_marker_id(
                "*** Bug 2058193 has been marked as a duplicate of this bug. ***"
            ),
            Some(2058193)
        );
        assert_eq!(
            Guard::duplicate_marker_id(
                "closing this, wrong component\n\n*** This bug has been marked as a \
                 duplicate of bug 2057935 ***"
            ),
            Some(2057935)
        );
        assert_eq!(Guard::duplicate_marker_id("*** Bug 5 was closed ***"), None);
        assert_eq!(Guard::duplicate_marker_id("see bug 5 for context"), None);
    }

    #[test]
    fn see_also_matching_survives_scheme_and_case_differences() {
        // Bugzilla stores see_also with the host as the user typed it, so the
        // same instance appears with either scheme and in any case.
        for entry in [
            "http://bugzilla.example.com/show_bug.cgi?id=7",
            "https://BUGZILLA.EXAMPLE.COM/show_bug.cgi?id=7",
            "https://bugzilla.example.com/show_bug.cgi?id=7",
        ] {
            assert_eq!(
                Guard::see_also_local_id(entry, BASE),
                Some(7),
                "must recognise {entry} as local"
            );
        }
    }

    #[test]
    fn url_and_legacy_id_fields_are_scrubbed_too() {
        // bug_file_loc ("url") routinely points at another bug, and the
        // legacy dup_id/blocked spellings are still emitted by some
        // instances.
        let mut bug = json!({
            "id": 1,
            "url": "https://bugzilla.example.com/show_bug.cgi?id=7",
            "dup_id": 8,
            "blocked": [9, 10],
        });
        let allowed: BTreeSet<u64> = [10].into_iter().collect();
        Guard::scrub_bug_links(&mut bug, BASE, &allowed);
        assert_eq!(bug["url"], Value::Null);
        assert_eq!(bug["dup_id"], Value::Null);
        assert_eq!(bug["blocked"], json!([10]));
    }

    #[test]
    fn every_link_field_is_scrubbed_including_the_rarer_ones() {
        let mut bug = json!({
            "id": 1,
            "duplicates": [2, 3],
            "regressed_by": [4],
            "regressions": [5],
            "dependson": [6],
        });
        let allowed: BTreeSet<u64> = [3].into_iter().collect();
        Guard::scrub_bug_links(&mut bug, BASE, &allowed);
        assert_eq!(bug["duplicates"], json!([3]));
        assert_eq!(bug["regressed_by"], json!([]));
        assert_eq!(bug["regressions"], json!([]));
        assert_eq!(bug["dependson"], json!([]));
    }

    #[test]
    fn see_also_matching_is_anchored_to_this_instance() {
        // A host that merely starts with ours, or a path that merely contains
        // an id, must not be mistaken for a local bug link.
        assert_eq!(
            Guard::see_also_local_id("https://bugzilla.example.com/show_bug.cgi?id=5", BASE),
            Some(5)
        );
        assert_eq!(
            Guard::see_also_local_id("https://bugzilla.example.com/rest/bug/5", BASE),
            Some(5)
        );
        assert_eq!(
            Guard::see_also_local_id("https://bugzilla.example.com/other.cgi?id=5", BASE),
            None
        );
        assert_eq!(
            Guard::see_also_local_id("https://evil.example/show_bug.cgi?id=5", BASE),
            None
        );
    }
    use super::*;
    use serde_json::json;

    fn policy(s: &str) -> Policy {
        Policy::from_toml_str(s).unwrap()
    }

    // ---------- denial (I2) ----------

    #[test]
    fn denial_text_is_uniform_i2() {
        assert_eq!(
            Guard::denial(123),
            "Bug 123 is not accessible through this server"
        );
        assert_eq!(
            Guard::denial(0),
            "Bug 0 is not accessible through this server"
        );
        assert_eq!(
            Guard::denial(u64::MAX),
            format!("Bug {} is not accessible through this server", u64::MAX)
        );
    }

    // ---------- summary_view ----------

    #[test]
    fn summary_view_projects_and_marks_redacted() {
        let bug = json!({
            "id": 7,
            "summary": "boom",
            "status": "NEW",
            "resolution": "",
            "product": "openSUSE",
            "component": "Kernel",
            "severity": "major",
            "priority": "P1",
            "creation_time": "2026-01-01T00:00:00Z",
            "last_change_time": "2026-01-02T00:00:00Z",
            // must all be stripped:
            "assigned_to": "dev@example.com",
            "cc": ["watcher@example.com"],
            "groups": ["security"],
            "whiteboard": "secret embargo notes",
            "cf_secret_field": "hidden",
        });
        let s = Guard::summary_view(&bug);
        let obj = s.as_object().unwrap();
        assert_eq!(s["_redacted"], json!(true));
        assert_eq!(s["id"], json!(7));
        assert_eq!(s["summary"], json!("boom"));
        assert_eq!(s["component"], json!("Kernel"));
        assert_eq!(s["creation_time"], json!("2026-01-01T00:00:00Z"));
        assert!(!obj.contains_key("assigned_to"));
        assert!(!obj.contains_key("cc"));
        assert!(!obj.contains_key("groups"));
        assert!(!obj.contains_key("whiteboard"));
        assert!(!obj.contains_key("cf_secret_field"));
        // Exactly the summary fields plus the marker.
        assert_eq!(obj.len(), SUMMARY_FIELDS.len() + 1);
    }

    #[test]
    fn summary_view_tolerates_missing_fields() {
        let s = Guard::summary_view(&json!({"id": 1}));
        let obj = s.as_object().unwrap();
        assert_eq!(obj.len(), 2); // id + _redacted
        assert_eq!(s["_redacted"], json!(true));
    }

    #[test]
    fn summary_view_tolerates_non_object() {
        let s = Guard::summary_view(&Value::Null);
        let obj = s.as_object().unwrap();
        assert_eq!(obj.len(), 1);
        assert_eq!(s["_redacted"], json!(true));
    }

    // ---------- filter_comments (I5) ----------

    fn comments() -> Vec<Value> {
        vec![
            json!({"id": 1, "text": "public", "is_private": false}),
            json!({"id": 2, "text": "private", "is_private": true}),
            json!({"id": 3, "text": "no flag at all"}),
        ]
    }

    #[test]
    fn filter_comments_drops_private_by_default() {
        let g = Guard {
            policy: Policy::default(),
        };
        let out = g.filter_comments(comments(), false);
        assert_eq!(out.len(), 2);
        assert!(out.iter().all(|c| c["id"] != json!(2)));
    }

    #[test]
    fn filter_comments_request_alone_is_not_enough_i5() {
        // Default policy has allow_private_comments = false: asking for
        // private comments must not surface them.
        let g = Guard {
            policy: Policy::default(),
        };
        let out = g.filter_comments(comments(), true);
        assert_eq!(out.len(), 2);
        assert!(out.iter().all(|c| c["id"] != json!(2)));
    }

    #[test]
    fn filter_comments_policy_alone_is_not_enough_i5() {
        // Policy opt-in without the per-call opt-in also hides them.
        let g = Guard {
            policy: policy("[global]\nallow_private_comments = true\n"),
        };
        let out = g.filter_comments(comments(), false);
        assert_eq!(out.len(), 2);
        assert!(out.iter().all(|c| c["id"] != json!(2)));
    }

    #[test]
    fn filter_comments_policy_and_request_surface_private() {
        let g = Guard {
            policy: policy("[global]\nallow_private_comments = true\n"),
        };
        let out = g.filter_comments(comments(), true);
        assert_eq!(out.len(), 3);
    }

    #[test]
    fn filter_comments_missing_flag_is_public() {
        let g = Guard {
            policy: Policy::default(),
        };
        let out = g.filter_comments(vec![json!({"id": 9})], false);
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn filter_comments_empty_input() {
        let g = Guard {
            policy: Policy::default(),
        };
        assert!(g.filter_comments(Vec::new(), true).is_empty());
    }

    // ---------- filter_attachments (I5 for attachment metadata) ----------

    fn attachments() -> Vec<Value> {
        vec![
            json!({"id": 1, "file_name": "log.txt", "is_private": false}),
            json!({"id": 2, "file_name": "customer-dump.sql", "summary": "prod credentials", "is_private": true}),
            json!({"id": 3, "file_name": "no-flag.png"}),
        ]
    }

    #[test]
    fn filter_attachments_drops_private_by_default() {
        let g = Guard {
            policy: Policy::default(),
        };
        let out = g.filter_attachments(attachments(), false);
        assert_eq!(out.len(), 2);
        assert!(out.iter().all(|a| a["id"] != json!(2)));
    }

    #[test]
    fn filter_attachments_request_alone_is_not_enough_i5() {
        let g = Guard {
            policy: Policy::default(),
        };
        let out = g.filter_attachments(attachments(), true);
        assert_eq!(out.len(), 2);
        assert!(out.iter().all(|a| a["id"] != json!(2)));
    }

    #[test]
    fn filter_attachments_policy_alone_is_not_enough_i5() {
        let g = Guard {
            policy: policy("[global]\nallow_private_comments = true\n"),
        };
        let out = g.filter_attachments(attachments(), false);
        assert_eq!(out.len(), 2);
        assert!(out.iter().all(|a| a["id"] != json!(2)));
    }

    #[test]
    fn filter_attachments_policy_and_request_surface_private() {
        let g = Guard {
            policy: policy("[global]\nallow_private_comments = true\n"),
        };
        let out = g.filter_attachments(attachments(), true);
        assert_eq!(out.len(), 3);
    }

    #[test]
    fn filter_attachments_missing_flag_is_public() {
        let g = Guard {
            policy: Policy::default(),
        };
        let out = g.filter_attachments(vec![json!({"id": 9})], false);
        assert_eq!(out.len(), 1);
    }

    // ---------- filter_bug_list (I3) ----------

    const LIST_POLICY: &str = r#"
default_action = "allow"

[[rule]]
name = "deny-secret"
action = "deny"
[rule.match]
products = ["Secret*"]

[[rule]]
name = "summary-only"
action = "restrict"
capabilities = ["summary"]
[rule.match]
products = ["Partial*"]

[[rule]]
name = "comments-only"
action = "restrict"
capabilities = ["comments"]
[rule.match]
products = ["NoView*"]
"#;

    #[test]
    fn filter_bug_list_keeps_redacts_and_drops() {
        let g = Guard {
            policy: policy(LIST_POLICY),
        };
        let bugs = vec![
            json!({"id": 1, "product": "Public", "summary": "ok", "assigned_to": "a@b"}),
            json!({"id": 2, "product": "SecretSauce", "summary": "hidden"}),
            json!({"id": 3, "product": "PartialThing", "summary": "partial", "assigned_to": "c@d"}),
            // comments-only grants neither read nor summary => dropped.
            json!({"id": 4, "product": "NoViewer", "summary": "also hidden"}),
        ];
        let (kept, dropped) = g.filter_bug_list(bugs, None);
        assert_eq!(dropped, 2, "denied and view-less bugs are dropped");
        assert_eq!(kept.len(), 2);
        // Full-read bug passes through unmodified — extra fields intact, no
        // redaction marker.
        assert_eq!(kept[0]["id"], json!(1));
        assert_eq!(kept[0]["assigned_to"], json!("a@b"));
        assert!(kept[0].get("_redacted").is_none());
        // Summary-only bug is replaced by the redacted projection.
        assert_eq!(kept[1]["id"], json!(3));
        assert_eq!(kept[1]["_redacted"], json!(true));
        assert!(kept[1].get("assigned_to").is_none());
    }

    #[test]
    fn filter_bug_list_drops_undisclosed_bugs() {
        // The two signals an undisclosed issue carries — a marker in the
        // title and a group restriction — each suffice on their own, and a
        // list entry that cannot answer either question is dropped too.
        let g = Guard {
            policy: policy(concat!(
                "default_action = \"allow\"\n",
                "[[rule]]\nname = \"restricted\"\naction = \"deny\"\n",
                "[rule.match]\ngroup_restricted = true\n",
                "[[rule]]\nname = \"marked\"\naction = \"deny\"\n",
                "[rule.match]\nsummary_contains = [\"embargo\"]\n",
            )),
        };
        let bugs = vec![
            json!({"id": 1, "summary": "plain bug", "groups": []}),
            json!({"id": 2, "summary": "plain bug", "groups": ["security-internal"]}),
            json!({"id": 3, "summary": "EMBARGOED: CVE-2026-1: pkg", "groups": []}),
            // Group list in a shape the parser cannot read: the restriction
            // is unknown, which must not read as "world-readable" (I4).
            json!({"id": 4, "summary": "plain bug", "groups": [{"id": 12}]}),
            // Projection carrying neither classification field.
            json!({"id": 5, "assigned_to": "a@b"}),
            // Readable groups, unreadable title: the marker rule cannot be
            // evaluated, so this one goes too.
            json!({"id": 6, "groups": []}),
        ];
        let (kept, dropped) = g.filter_bug_list(bugs, None);
        assert_eq!(dropped, 5, "only the plain, world-readable bug survives");
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0]["id"], json!(1));
    }

    #[test]
    fn filter_bug_list_read_restrict_keeps_full_object() {
        let g = Guard {
            policy: policy(
                "[[rule]]\nname = \"r\"\naction = \"restrict\"\ncapabilities = [\"read\"]\n",
            ),
        };
        let (kept, dropped) =
            g.filter_bug_list(vec![json!({"id": 9, "product": "x", "cc": ["a@b"]})], None);
        assert_eq!(dropped, 0);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0]["cc"], json!(["a@b"]));
        assert!(kept[0].get("_redacted").is_none());
    }

    #[test]
    fn filter_bug_list_default_policy_keeps_everything() {
        let g = Guard {
            policy: Policy::default(),
        };
        let (kept, dropped) = g.filter_bug_list(vec![json!({"id": 1}), json!({"id": 2})], None);
        assert_eq!(kept.len(), 2);
        assert_eq!(dropped, 0);
    }

    #[test]
    fn filter_bug_list_default_deny_drops_all_silently() {
        let g = Guard {
            policy: policy("default_action = \"deny\""),
        };
        let (kept, dropped) = g.filter_bug_list(vec![json!({"id": 1}), json!({"id": 2})], None);
        assert!(kept.is_empty());
        assert_eq!(dropped, 2);
    }

    #[test]
    fn filter_bug_list_empty_input() {
        let g = Guard {
            policy: Policy::default(),
        };
        let (kept, dropped) = g.filter_bug_list(Vec::new(), None);
        assert!(kept.is_empty());
        assert_eq!(dropped, 0);
    }

    #[test]
    fn filter_bug_list_embargo_group_dropped() {
        let g = Guard {
            policy: policy(
                "[[rule]]\nname = \"embargo\"\naction = \"deny\"\n[rule.match]\ngroups = [\"*security*\"]\n",
            ),
        };
        let bugs = vec![
            json!({"id": 1, "product": "P", "groups": ["suse-security"]}),
            json!({"id": 2, "product": "P", "groups": []}),
        ];
        let (kept, dropped) = g.filter_bug_list(bugs, None);
        assert_eq!(dropped, 1);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0]["id"], json!(2));
    }

    // ---------- attachment_gate ----------

    fn public_attachment(size: u64) -> Value {
        json!({ "id": 7, "is_private": false, "size": size })
    }

    #[test]
    fn attachment_denial_matches_bug_denial_shape_i2() {
        assert_eq!(
            Guard::attachment_denial(7),
            "Attachment 7 is not accessible through this server"
        );
    }

    #[test]
    fn attachment_gate_allows_public_within_cap() {
        let g = Guard {
            policy: Policy::default(),
        };
        assert_eq!(g.attachment_gate(&public_attachment(1024), false), None);
    }

    #[test]
    fn attachment_gate_denies_private_without_double_opt_in_i5() {
        let allowing = Guard {
            policy: policy("[global]\nallow_private_comments = true"),
        };
        let strict = Guard {
            policy: Policy::default(),
        };
        let private = json!({ "id": 7, "is_private": true, "size": 10 });
        // Policy alone is not enough...
        assert!(allowing.attachment_gate(&private, false).is_some());
        // ...the flag alone is not enough...
        assert!(strict.attachment_gate(&private, true).is_some());
        // ...both together are.
        assert_eq!(allowing.attachment_gate(&private, true), None);
        // The private denial is the uniform text (I2).
        assert_eq!(
            strict.attachment_gate(&private, true),
            Some(Guard::attachment_denial(7))
        );
    }

    #[test]
    fn attachment_gate_missing_is_private_fails_closed_i4() {
        let g = Guard {
            policy: Policy::default(),
        };
        assert!(g
            .attachment_gate(&json!({ "id": 7, "size": 10 }), false)
            .is_some());
    }

    #[test]
    fn attachment_gate_enforces_size_cap() {
        let g = Guard {
            policy: policy("[global]\nmax_attachment_bytes = 100"),
        };
        assert_eq!(g.attachment_gate(&public_attachment(100), false), None);
        let refusal = g.attachment_gate(&public_attachment(101), false);
        assert!(refusal.is_some_and(|r| r.contains("size limit")));
    }

    #[test]
    fn attachment_gate_missing_size_fails_closed_under_cap_i4() {
        let g = Guard {
            policy: Policy::default(),
        };
        let no_size = json!({ "id": 7, "is_private": false });
        assert!(g.attachment_gate(&no_size, false).is_some());
        // Without a cap there is nothing to check against.
        let uncapped = Guard {
            policy: policy("[global]\nmax_attachment_bytes = 0"),
        };
        assert_eq!(uncapped.attachment_gate(&no_size, false), None);
    }

    #[test]
    fn default_policy_caps_attachments_at_two_mib() {
        assert_eq!(
            Policy::default().global.max_attachment_bytes,
            2 * 1024 * 1024
        );
        // TOML without the key gets the same non-zero default (fail closed).
        assert_eq!(
            policy("default_action = \"allow\"")
                .global
                .max_attachment_bytes,
            2 * 1024 * 1024
        );
    }

    // ---------- may_create ----------

    /// A minimal well-formed create request, as `create_bug` builds one.
    fn create_request(product: &str) -> Value {
        json!({
            "product": product,
            "component": "core",
            "summary": "crash on start",
            "version": "1.0",
        })
    }

    #[test]
    fn may_create_refuses_the_products_the_policy_hides() {
        // The same rule that hides a product refuses filing into it.
        let g = Guard {
            policy: policy(concat!(
                "[[rule]]\nname = \"hide-security\"\naction = \"deny\"\n",
                "[rule.match]\nproducts = [\"Security*\"]\n",
            )),
        };
        assert!(!g.may_create(&create_request("Security Response")));
        assert!(g.may_create(&create_request("openSUSE")));
    }

    #[test]
    fn may_create_never_lets_the_claimed_group_list_decide() {
        // Bugzilla UNIONS the product's mandatory groups into whatever the
        // request named, so the created bug can be in groups the request
        // never mentioned. A group deny rule therefore refuses creation
        // whatever the payload claims: omitting `groups`, claiming `[]`, and
        // claiming a non-matching list must all be refused alike — if
        // `groups: []` were taken as fact it would be strictly MORE
        // permissive than omitting the field, and the canonical security-*
        // embargo pattern would be filed straight through.
        let g = Guard {
            policy: policy(concat!(
                "[[rule]]\nname = \"embargo\"\naction = \"deny\"\n",
                "[rule.match]\ngroups = [\"embargo*\"]\n",
            )),
        };
        let mut req = create_request("openSUSE");
        assert!(!g.may_create(&req), "absent groups must fail closed");
        req["groups"] = json!([]);
        assert!(
            !g.may_create(&req),
            "a claimed empty group list is not knowledge: Bugzilla adds \
             mandatory groups the request cannot disclaim"
        );
        req["groups"] = json!(["harmless"]);
        assert!(!g.may_create(&req), "a non-matching claim decides nothing");
        req["groups"] = json!(["embargo-security"]);
        assert!(!g.may_create(&req));
    }

    #[test]
    fn may_create_group_restricted_policies_refuse_all_creation() {
        // The example policy's first rule: deny anything group-restricted.
        // Whether the created bug will be group-restricted cannot be known
        // in advance, so every create request is refused (I4) — including
        // one that claims to be world-readable.
        let g = Guard {
            policy: policy(concat!(
                "[[rule]]\nname = \"group-restricted\"\naction = \"deny\"\n",
                "[rule.match]\ngroup_restricted = true\n",
            )),
        };
        let mut req = create_request("openSUSE");
        assert!(!g.may_create(&req));
        req["groups"] = json!([]);
        assert!(!g.may_create(&req));
    }

    #[test]
    fn may_create_forces_created_by_me_true_without_whoami() {
        // The account filing a bug is definitionally its creator: Bugzilla
        // assigns `creator` server-side, and the typed create params cannot
        // claim it. may_create takes no client and performs no whoami — the
        // forcing is a fact about the operation, not a lookup. A
        // create-covering deny rule on created_by_me = true therefore
        // refuses every create request that reaches it...
        let deny_own = Guard {
            policy: policy(concat!(
                "[[rule]]\nname = \"no-self-filing\"\naction = \"deny\"\n",
                "operations = [\"create\"]\n",
                "[rule.match]\ncreated_by_me = true\n",
            )),
        };
        assert!(!deny_own.may_create(&create_request("openSUSE")));

        // ...and one on created_by_me = false can never match a create: the
        // rule is a definitive No and the allowing default decides.
        let deny_foreign = Guard {
            policy: policy(concat!(
                "[[rule]]\nname = \"no-foreign\"\naction = \"deny\"\n",
                "[rule.match]\ncreated_by_me = false\n",
            )),
        };
        assert!(deny_foreign.may_create(&create_request("openSUSE")));

        // The unscoped deny-own variant refuses creation too: forcing does
        // not depend on the rule's scoping, only on the operation.
        let deny_own_unscoped = Guard {
            policy: policy(concat!(
                "[[rule]]\nname = \"no-self-filing\"\naction = \"deny\"\n",
                "[rule.match]\ncreated_by_me = true\n",
            )),
        };
        assert!(!deny_own_unscoped.may_create(&create_request("openSUSE")));
    }

    #[test]
    fn shipped_example_policy_files_into_desktop_products_only_and_keeps_reads() {
        // examples/policy.toml promises, in its header: new bug reports are
        // accepted into the desktop products ONLY (the create-scoped
        // "reporters" rule), except that an embargo-marked title may not be
        // filed anywhere; everywhere else filing is refused because the
        // first deny rule the create gate reaches consults the unknowable
        // group list. Pin the whole shipped contract — the accept half, the
        // refuse half, and that the create grant stays invisible to reads
        // of existing desktop bugs (the silent-vanishing regression of
        // issue #26). Read at runtime (not include_str!) so the core crate
        // stays packageable without the file.
        let path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/policy.toml");
        let toml = std::fs::read_to_string(path).expect("example policy must exist in-repo");
        let g = Guard {
            policy: policy(&toml),
        };

        // Accept half: the desktop products take new bug reports.
        assert!(
            g.may_create(&create_request("GNOME Shell")),
            "the example's headline: desktop products accept filings"
        );
        assert!(g.may_create(&create_request("KDE Frameworks")));

        // ...but never with the embargo marker in the title: the
        // create-scoped screen refuses what "undisclosed-marker" would
        // instantly hide (no create-then-vanish).
        let mut marked = create_request("GNOME Shell");
        marked["summary"] = json!("EMBARGO: heap overflow in the shell");
        assert!(
            !g.may_create(&marked),
            "an embargo-marked title must not be filed anywhere"
        );

        // Refuse half: everywhere else the group-consulting deny rule fails
        // closed on the unknowable group list, whatever the request claims.
        let mut req = create_request("openSUSE");
        assert!(!g.may_create(&req), "omitted groups: refused");
        req["groups"] = json!([]);
        assert!(!g.may_create(&req), "claimed empty groups: refused");
        req["groups"] = json!(["security-team"]);
        assert!(!g.may_create(&req), "claimed groups: refused");

        // Every read below runs with the caller's identity KNOWN, as
        // resolve_caller provides it in production: the "my-own-reports"
        // rule consults created_by_me, so identity-unknown classification
        // is a different (pinned further down) regime.
        let caller = Some("reporter@example.com");

        // Issue #26: the create grant is scoped away from access, so an
        // existing world-readable desktop bug someone ELSE filed keeps its
        // FULL read — under the pre-fix policy shape the same rule was
        // first match for reads and silently revoked everything but
        // `create`.
        let public = BugMeta::from_json(
            &json!({
                "id": 500,
                "summary": "totem crashes when seeking in a webm file",
                "product": "GNOME Multimedia",
                "component": "totem",
                "groups": [],
                "keywords": [],
                "whiteboard": "",
                "status": "NEW",
                "creator": "other.person@example.com",
                "creation_time": "2020-01-01T00:00:00Z",
            }),
            caller,
        );
        assert!(
            g.policy
                .classify(&public, Utc::now(), Operation::Access)
                .allows(Capability::Read),
            "existing desktop bugs must stay fully readable"
        );

        // ...while a group-restricted desktop bug someone else filed stays
        // denied: the grant does not shadow the deny rules for reads either.
        let restricted_foreign = json!({
            "id": 501,
            "summary": "totem crashes when seeking in a webm file",
            "product": "GNOME Multimedia",
            "component": "totem",
            "groups": ["secteam"],
            "keywords": [],
            "whiteboard": "",
            "status": "NEW",
            "creator": "other.person@example.com",
            "creation_time": "2020-01-01T00:00:00Z",
        });
        let restricted = BugMeta::from_json(&restricted_foreign, caller);
        assert!(
            matches!(
                g.policy
                    .classify(&restricted, Utc::now(), Operation::Access),
                Access::Denied { .. }
            ),
            "group-restricted desktop bugs must stay denied"
        );

        // The identity carve-out ("my-own-reports"): the SAME
        // group-restricted bug, authored by the caller, is readable —
        // reads, comments, history and attachment listing, and nothing
        // that writes.
        let mut own_restricted_json = restricted_foreign.clone();
        own_restricted_json["creator"] = json!("reporter@example.com");
        let own_restricted = BugMeta::from_json(&own_restricted_json, caller);
        let own_access = g
            .policy
            .classify(&own_restricted, Utc::now(), Operation::Access);
        for cap in [
            Capability::Read,
            Capability::Comments,
            Capability::History,
            Capability::Attachments,
        ] {
            assert!(
                own_access.allows(cap),
                "the caller's own group-restricted bug must grant {cap:?}"
            );
        }
        for cap in Capability::ALL.iter().filter(|c| c.is_write()) {
            assert!(
                !own_access.allows(*cap),
                "the my-own-reports carve-out must not grant the write {cap:?}"
            );
        }

        // Identity unknown (whoami failed): the my-own-reports rule cannot
        // be decided for ANY bug it is consulted for, and an undecidable
        // consulted rule denies (I4) — the caller's own restricted bug AND
        // the world-readable public bug alike. This blackout is the
        // deliberate fail-closed reading; do not "fix" it into fail-open.
        for bug_json in [&own_restricted_json, &restricted_foreign] {
            let unknown = BugMeta::from_json(bug_json, None);
            assert!(
                matches!(
                    g.policy.classify(&unknown, Utc::now(), Operation::Access),
                    Access::Denied { .. }
                ),
                "identity-unknown must deny (blackout), bug {}",
                bug_json["id"]
            );
        }
        let public_unknown = BugMeta::from_json(
            &json!({
                "id": 500,
                "summary": "totem crashes when seeking in a webm file",
                "product": "GNOME Multimedia",
                "component": "totem",
                "groups": [],
                "keywords": [],
                "whiteboard": "",
                "status": "NEW",
                "creator": "other.person@example.com",
                "creation_time": "2020-01-01T00:00:00Z",
            }),
            None,
        );
        assert!(
            matches!(
                g.policy
                    .classify(&public_unknown, Utc::now(), Operation::Access),
                Access::Denied { .. }
            ),
            "even a world-readable desktop bug is denied while identity is unknown"
        );
    }

    #[test]
    fn shipped_example_policy_denies_security_named_groups_on_their_own() {
        // The example stacks two rules over security-group bugs: the broad
        // "group-restricted" (any group at all) and "security-groups" (the
        // names, by glob). The second is the backstop the file promises: an
        // operator who narrows or removes the broad rule — as its own
        // comment invites — must not thereby expose security-group bugs.
        // Pin both layers on a bug carrying NO other deniable signal: no
        // marker in the summary, no keywords, empty whiteboard, years past
        // every freshness window — and somebody ELSE'S bug under a resolved
        // caller identity, so the "my-own-reports" carve-out (a definitive
        // No here) neither grants nor fails closed in the way.
        let caller = Some("reporter@example.com");
        let path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/policy.toml");
        let toml = std::fs::read_to_string(path).expect("example policy must exist in-repo");
        let bug = BugMeta::from_json(
            &json!({
                "id": 42,
                "summary": "kernel oops when unplugging a USB dock",
                "groups": ["team-security"],
                "keywords": [],
                "whiteboard": "",
                "product": "Base System",
                "component": "Kernel",
                "status": "NEW",
                "severity": "major",
                "priority": "P2",
                "creator": "other.person@example.com",
                "creation_time": "2020-01-01T00:00:00Z",
            }),
            caller,
        );

        // The shipped file as-is: denied (the broad rule reaches it first).
        let full = policy(&toml);
        assert!(
            matches!(
                full.classify(&bug, Utc::now(), Operation::Access),
                Access::Denied { .. }
            ),
            "shipped policy must deny a security-group bug"
        );

        // Excise the whole group-restricted rule (everything up to the next
        // [[rule]] header) and classify again: still denied, and by the
        // named-group rule itself — proof the backstop carries its weight.
        let start = toml
            .find("[[rule]]\nname = \"group-restricted\"")
            .expect("the broad rule must exist in the example");
        let after = start + "[[rule]]".len();
        let end = after
            + toml[after..]
                .find("[[rule]]")
                .expect("a rule must follow the broad rule");
        let narrowed = policy(&format!("{}{}", &toml[..start], &toml[end..]));
        match narrowed.classify(&bug, Utc::now(), Operation::Access) {
            Access::Denied { rule } => assert_eq!(
                rule, "security-groups",
                "the named-group rule itself must be the one denying"
            ),
            Access::Granted { .. } => {
                panic!("removing the broad rule must not expose security-group bugs")
            }
        }

        // A restricted-but-not-security bug is exactly what an operator
        // removes the broad rule FOR: under the narrowed policy it falls
        // through to default_action and becomes visible.
        let partner = BugMeta::from_json(
            &json!({
                "id": 43,
                "summary": "invoice import fails for partner deployments",
                "groups": ["partnerconfidential"],
                "keywords": [],
                "whiteboard": "",
                "product": "Base System",
                "component": "Billing",
                "status": "NEW",
                "severity": "major",
                "priority": "P2",
                "creator": "other.person@example.com",
                "creation_time": "2020-01-01T00:00:00Z",
            }),
            caller,
        );
        assert!(
            matches!(
                full.classify(&partner, Utc::now(), Operation::Access),
                Access::Denied { .. }
            ),
            "shipped policy hides every restricted bug"
        );
        assert!(
            matches!(
                narrowed.classify(&partner, Utc::now(), Operation::Access),
                Access::Granted { .. }
            ),
            "narrowing is meant to expose non-security restricted bugs"
        );

        // Creation stays refused under the narrowed file too: the backstop
        // still consults the group list, which is unknowable pre-creation.
        let g = Guard { policy: narrowed };
        assert!(
            !g.may_create(&create_request("openSUSE")),
            "narrowed policy must still refuse all creation"
        );
    }

    #[test]
    fn may_create_group_rules_ruled_out_by_other_criteria_do_not_block() {
        // Forcing groups to unknown must not turn every group-consulting
        // rule into a blanket refusal: a rule some OTHER criterion already
        // ruled out (definitive No) cannot apply either way, and evaluation
        // moves on.
        let g = Guard {
            policy: policy(concat!(
                "[[rule]]\nname = \"secret-embargo\"\naction = \"deny\"\n",
                "[rule.match]\nproducts = [\"Secret*\"]\ngroups = [\"embargo*\"]\n",
            )),
        };
        assert!(g.may_create(&create_request("openSUSE")));
        assert!(!g.may_create(&create_request("SecretSauce")));
    }

    #[test]
    fn may_create_dates_the_request_now() {
        // An age gate that would immediately hide the new bug refuses its
        // creation — and a creation_time CLAIMED by the payload must not
        // defeat that: the prospective bug is dated NOW, whatever the
        // request says.
        let g = Guard {
            policy: policy("[global]\nmin_bug_age_days = 1\n"),
        };
        let mut req = create_request("openSUSE");
        assert!(!g.may_create(&req));
        req["creation_time"] = json!("2000-01-01T00:00:00Z");
        assert!(!g.may_create(&req));
    }

    #[test]
    fn may_create_restrict_grants_only_the_named_products() {
        // Pins the operator-facing TOML spelling "create" along the way.
        let g = Guard {
            policy: policy(concat!(
                "default_action = \"deny\"\n",
                "[[rule]]\nname = \"filers\"\naction = \"restrict\"\n",
                "capabilities = [\"create\"]\n",
                "[rule.match]\nproducts = [\"openSUSE*\"]\n",
            )),
        };
        assert!(g.may_create(&create_request("openSUSE Tumbleweed")));
        assert!(!g.may_create(&create_request("Internal Tools")));
    }

    #[test]
    fn may_create_refuses_everything_in_read_only() {
        let g = Guard {
            policy: policy("[global]\nread_only = true\n"),
        };
        assert!(!g.may_create(&create_request("openSUSE")));
    }

    // ---------- operation-scoped rules (issue #26) ----------

    /// The policy shape from the issue #26 reproduction, fixed: a
    /// create-scoped grant placed ahead of the group-consulting deny rule.
    const ISSUE_26_POLICY: &str = r#"
default_action = "allow"

[[rule]]
name = "file-new-bugs"
action = "restrict"
capabilities = ["create"]
operations = ["create"]
[rule.match]
products = ["SUSE Linux Enterprise*"]

[[rule]]
name = "group-restricted"
action = "deny"
[rule.match]
group_restricted = true
"#;

    #[test]
    fn create_scoped_rule_no_longer_shadows_reads_issue_26() {
        let g = Guard {
            policy: policy(ISSUE_26_POLICY),
        };

        // An existing, world-readable bug in a matched product: the
        // create-scoped rule is invisible to access classification, so the
        // bug falls through the deny rule to the allowing default — this is
        // the read the pre-fix policy shape silently revoked.
        let public = BugMeta::from_json(
            &json!({
                "id": 100,
                "summary": "boot hangs after update",
                "product": "SUSE Linux Enterprise Server 15",
                "component": "Kernel",
                "groups": [],
                "creation_time": "2020-01-01T00:00:00Z",
            }),
            None,
        );
        match g.policy.classify(&public, Utc::now(), Operation::Access) {
            Access::Granted { rule, .. } => assert_eq!(rule, "default"),
            other => panic!("non-restricted bug must stay readable, got {other:?}"),
        }

        // A group-restricted bug in the same product stays denied: the
        // create grant does not shadow the deny rule for reads.
        let restricted = BugMeta::from_json(
            &json!({
                "id": 101,
                "summary": "boot hangs after update",
                "product": "SUSE Linux Enterprise Server 15",
                "component": "Kernel",
                "groups": ["secteam"],
                "creation_time": "2020-01-01T00:00:00Z",
            }),
            None,
        );
        match g
            .policy
            .classify(&restricted, Utc::now(), Operation::Access)
        {
            Access::Denied { rule } => assert_eq!(rule, "group-restricted"),
            other => panic!("group-restricted bug must stay denied, got {other:?}"),
        }

        // Filing into the matched product works: for the create operation
        // the scoped rule is first match and grants `create` before the
        // group-consulting rule can fail closed on the unknowable groups.
        assert!(g.may_create(&create_request("SUSE Linux Enterprise Server 15")));
        // Elsewhere creation still fails closed on the group rule.
        assert!(!g.may_create(&create_request("openSUSE")));
    }

    #[test]
    fn create_scoped_grant_does_not_defeat_a_preceding_name_deny() {
        // A deny rule placed ABOVE the create-scoped grant still wins for
        // creation: scoping changes which rules are consulted, never the
        // first-match order among those that are.
        let g = Guard {
            policy: policy(concat!(
                "[[rule]]\nname = \"hide-sle\"\naction = \"deny\"\n",
                "[rule.match]\nproducts = [\"SUSE Linux Enterprise*\"]\n",
                "[[rule]]\nname = \"file-new-bugs\"\naction = \"restrict\"\n",
                "capabilities = [\"create\"]\noperations = [\"create\"]\n",
                "[rule.match]\nproducts = [\"SUSE Linux Enterprise*\"]\n",
            )),
        };
        assert!(!g.may_create(&create_request("SUSE Linux Enterprise Server 15")));
    }

    #[test]
    fn access_scoped_rule_is_invisible_to_may_create() {
        // A rule scoped to `operations = ["access"]` decides nothing for the
        // create gate: creation falls through to the denying default.
        let g = Guard {
            policy: policy(concat!(
                "default_action = \"deny\"\n",
                "[[rule]]\nname = \"readers\"\naction = \"restrict\"\n",
                "capabilities = [\"read\"]\noperations = [\"access\"]\n",
                "[rule.match]\nproducts = [\"openSUSE*\"]\n",
            )),
        };
        assert!(!g.may_create(&create_request("openSUSE")));
    }

    #[test]
    fn may_create_read_only_strips_a_create_scoped_grant() {
        // I9: read_only strips write capabilities from EVERY grant, a
        // create-scoped one included — the scoping must not open a side door
        // around read-only mode.
        let g = Guard {
            policy: policy(concat!(
                "[global]\nread_only = true\n",
                "[[rule]]\nname = \"file-new-bugs\"\naction = \"restrict\"\n",
                "capabilities = [\"create\"]\noperations = [\"create\"]\n",
                "[rule.match]\nproducts = [\"openSUSE*\"]\n",
            )),
        };
        assert!(!g.may_create(&create_request("openSUSE")));
    }

    #[test]
    fn create_denial_is_uniform_and_names_nothing() {
        // One fixed text whatever tripped the refusal: no rule name, no
        // criterion, no product (I1).
        assert_eq!(
            Guard::create_denial(),
            "Filing this bug is not permitted through this server"
        );
    }
}
