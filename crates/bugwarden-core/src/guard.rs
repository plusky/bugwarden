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

use std::collections::BTreeMap;

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

impl Guard {
    /// The uniform denial text (invariant I2).
    ///
    /// A policy-denied bug and a nonexistent bug MUST produce exactly this
    /// string, with no wording or detail difference, so an MCP client can
    /// never learn whether a hidden bug exists.
    pub fn denial(id: u64) -> String {
        format!("Bug {id} is not accessible through this server")
    }

    /// Classify `ids` against the policy.
    ///
    /// Fetches `CLASSIFY_FIELDS` for all ids in one batched request; if the
    /// batch call fails, retries each id individually so one bad id cannot
    /// take down the whole batch. Any id that still fails or is absent from
    /// the response maps to `(Access::Denied { rule: "unavailable" },
    /// Value::Null)` — every requested id has an entry in the returned map,
    /// and unavailability is indistinguishable from policy denial downstream
    /// (fail closed, I4 + I2).
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
        let mut fetched: BTreeMap<u64, Value> = BTreeMap::new();
        match bz.get_bugs(key, ids, Some(CLASSIFY_FIELDS)).await {
            Ok(envelope) => {
                if let Some(bugs) = envelope.get("bugs").and_then(Value::as_array) {
                    for bug in bugs {
                        if let Some(id) = bug.get("id").and_then(Value::as_u64) {
                            fetched.insert(id, bug.clone());
                        }
                    }
                }
            }
            Err(err) if ids.len() > 1 => {
                // Batch failed (e.g. one denied id poisoning the whole
                // request on some Bugzilla versions): retry per id.
                tracing::debug!(error = %err, "batch classification fetch failed; retrying per id");
                for &id in ids {
                    match bz.get_bugs(key, &[id], Some(CLASSIFY_FIELDS)).await {
                        Ok(envelope) => {
                            if let Some(bugs) = envelope.get("bugs").and_then(Value::as_array) {
                                for bug in bugs {
                                    if bug.get("id").and_then(Value::as_u64) == Some(id) {
                                        fetched.insert(id, bug.clone());
                                    }
                                }
                            }
                        }
                        Err(err) => {
                            tracing::debug!(id, error = %err, "per-id classification fetch failed");
                        }
                    }
                }
            }
            Err(err) => {
                // Single-id batch: a per-id retry would repeat the identical
                // request and could never recover anything. Skipping it also
                // keeps the upstream request count (and thus latency)
                // identical for a nonexistent id and a policy-denied one, so
                // a client timing its calls gets no existence oracle (I2).
                tracing::debug!(error = %err, "single-id classification fetch failed");
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
}
