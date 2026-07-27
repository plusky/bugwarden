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
use crate::policy::{Access, BugMeta, Capability, Policy};

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
    /// This is why the batch is gone. Bugzilla reports a nonexistent id by
    /// failing the WHOLE request, while a bug the caller may not see is
    /// silently omitted from a successful one — so any scheme that reacts to
    /// a batch failure spends different work on "no such bug" than on "hidden
    /// bug", and a client with a clock can tell the two apart. Per-id also
    /// removes batch poisoning outright: one bad id can no longer take the
    /// others down with it, which is what the old retry existed to repair.
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
    /// The API key is only forwarded to the client and never logged (I12).
    pub async fn assess(
        &self,
        bz: &BugzillaClient,
        key: &str,
        ids: &[u64],
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
                    let meta = BugMeta::from_json(bug);
                    (self.policy.classify(&meta, now), bug.clone())
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
            let (kept, dropped) = self.filter_bug_list(fresh);
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
    pub fn filter_bug_list(&self, bugs: Vec<Value>) -> (Vec<Value>, usize) {
        let now = Utc::now();
        let mut kept = Vec::new();
        let mut dropped = 0usize;
        for bug in bugs {
            let meta = BugMeta::from_json(&bug);
            let access = self.policy.classify(&meta, now);
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
        let (kept, dropped) = g.filter_bug_list(bugs);
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
        let (kept, dropped) = g.filter_bug_list(bugs);
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
            g.filter_bug_list(vec![json!({"id": 9, "product": "x", "cc": ["a@b"]})]);
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
        let (kept, dropped) = g.filter_bug_list(vec![json!({"id": 1}), json!({"id": 2})]);
        assert_eq!(kept.len(), 2);
        assert_eq!(dropped, 0);
    }

    #[test]
    fn filter_bug_list_default_deny_drops_all_silently() {
        let g = Guard {
            policy: policy("default_action = \"deny\""),
        };
        let (kept, dropped) = g.filter_bug_list(vec![json!({"id": 1}), json!({"id": 2})]);
        assert!(kept.is_empty());
        assert_eq!(dropped, 2);
    }

    #[test]
    fn filter_bug_list_empty_input() {
        let g = Guard {
            policy: Policy::default(),
        };
        let (kept, dropped) = g.filter_bug_list(Vec::new());
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
        let (kept, dropped) = g.filter_bug_list(bugs);
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
}
