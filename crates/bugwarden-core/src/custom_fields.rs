//! Bugzilla custom field types, learned by name and cached for the process.
//!
//! A "Bug ID" custom field (`cf_*`, Bugzilla field type 6) links to another
//! bug exactly as `depends_on` does, so a history change to one, or a write
//! naming one, needs the treatment the named link fields get (I14, I8).
//! Which `cf_` names are of that type is instance schema, learned through
//! `GET /rest/field/bug?names=..&include_fields=name,type` — by name, never
//! as the whole field list: Bugzilla computes the legal values of every
//! select and product-specific field server-side and `include_fields`
//! filters only the output, so a large instance answers the full list
//! slower than the client's timeout allows.
//!
//! A lookup that fails, or a name Bugzilla does not answer for, is
//! [`CustomFieldKind::Unknown`]: never cached, and treated by every caller
//! as a possible bug link (I4).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Mutex, MutexGuard, PoisonError};

use serde_json::Value;

use crate::client::{BugzillaClient, BugzillaError};
use crate::quoted::QuotedError;

/// Bugzilla's `FIELD_TYPE_BUG_ID`.
const FIELD_TYPE_BUG_ID: u64 = 6;
/// Bugzilla's `FIELD_TYPE_BUG_URLS`, the type of `see_also`. A custom
/// field cannot work with it (`Field::create` makes no `bugs` column for
/// it, though BMO's dropdown offers it), so it is read as a bug list only
/// in case one exists.
const FIELD_TYPE_BUG_URLS: u64 = 7;
/// BMO's `FIELD_TYPE_BUG_LIST`, which backs its core list fields; a custom
/// field cannot work with it either, for the same reason.
const FIELD_TYPE_BUG_LIST: u64 = 22;

/// Names per lookup request, which bounds the URL.
const LOOKUP_CHUNK: usize = 50;

/// What a custom field can hold, as far as bug links are concerned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CustomFieldKind {
    /// Type 6: one bug id.
    BugId,
    /// Type 22 (BMO) or 7: a list of bug ids.
    BugList,
    /// Any other type Bugzilla reported: never a bug link.
    Other,
    /// Not known — the lookup failed, or Bugzilla did not name the field —
    /// and therefore a possible bug link (I4).
    Unknown,
}

impl CustomFieldKind {
    /// Whether a value of this kind may name another bug. `Unknown` may:
    /// an unknown field fails closed.
    pub fn may_link(self) -> bool {
        !matches!(self, Self::Other)
    }
}

/// The kind a `Bug.fields` `type` value denotes, `None` when unreadable.
fn kind_of_type(t: &Value) -> Option<CustomFieldKind> {
    let code = match t {
        Value::Number(n) => n.as_u64()?,
        Value::String(s) => s.parse().ok()?,
        _ => return None,
    };
    Some(match code {
        FIELD_TYPE_BUG_ID => CustomFieldKind::BugId,
        FIELD_TYPE_BUG_LIST | FIELD_TYPE_BUG_URLS => CustomFieldKind::BugList,
        _ => CustomFieldKind::Other,
    })
}

/// The kinds of `names` read off one `Bug.fields` envelope: every requested
/// name the envelope carries with a readable type. Entries the caller did
/// not ask for are ignored, and a name listed twice reads as a link if any
/// of its entries does.
fn kinds_in(envelope: &Value, names: &[String]) -> BTreeMap<String, CustomFieldKind> {
    let mut out = BTreeMap::new();
    let Some(fields) = envelope.get("fields").and_then(Value::as_array) else {
        return out;
    };
    for field in fields {
        let Some(name) = field.get("name").and_then(Value::as_str) else {
            continue;
        };
        if !names.iter().any(|n| n == name) {
            continue;
        }
        let Some(kind) = field.get("type").and_then(kind_of_type) else {
            continue;
        };
        out.entry(name.to_string())
            .and_modify(|known| {
                if kind.may_link() {
                    *known = kind;
                }
            })
            .or_insert(kind);
    }
    out
}

/// Custom field kinds learned from Bugzilla, kept for the life of the
/// process. `Default` is an empty cache that has made no request.
///
/// The lock is a plain `std::sync::Mutex` guarding a map: it is never held
/// across an `.await`, so concurrent lookups of the same name simply both
/// ask, which is harmless.
#[derive(Debug, Default)]
pub struct FieldTypeCache {
    known: Mutex<BTreeMap<String, CustomFieldKind>>,
}

impl FieldTypeCache {
    /// The kind of every name in `names`, cached names answered locally and
    /// the rest looked up with the caller's `key`, in batches of at most
    /// `LOOKUP_CHUNK` names per request. Every name has an entry: a name
    /// the lookup could not settle is [`CustomFieldKind::Unknown`] and stays
    /// uncached, so a later call asks again. No request when every name is
    /// cached.
    pub async fn kinds(
        &self,
        bz: &BugzillaClient,
        key: &str,
        names: &BTreeSet<String>,
    ) -> BTreeMap<String, CustomFieldKind> {
        let mut out = BTreeMap::new();
        let mut missing = Vec::new();
        {
            let known = self.lock();
            for name in names {
                match known.get(name) {
                    Some(kind) => {
                        out.insert(name.clone(), *kind);
                    }
                    None => missing.push(name.clone()),
                }
            }
        }
        if !missing.is_empty() {
            out.extend(self.look_up(bz, key, &missing).await);
        }
        out
    }

    /// Like [`FieldTypeCache::kinds`], but every name is looked up afresh
    /// and the cache refreshed with what came back: a write must judge the
    /// field as it is now, not as it was at some earlier read.
    pub async fn kinds_fresh(
        &self,
        bz: &BugzillaClient,
        key: &str,
        names: &BTreeSet<String>,
    ) -> BTreeMap<String, CustomFieldKind> {
        let names: Vec<String> = names.iter().cloned().collect();
        self.look_up(bz, key, &names).await
    }

    /// Ask Bugzilla for `names` in chunks and cache what it answered. Every
    /// name gets an entry, `Unknown` where nothing readable came back.
    async fn look_up(
        &self,
        bz: &BugzillaClient,
        key: &str,
        names: &[String],
    ) -> BTreeMap<String, CustomFieldKind> {
        let mut out: BTreeMap<String, CustomFieldKind> = names
            .iter()
            .map(|n| (n.clone(), CustomFieldKind::Unknown))
            .collect();
        for chunk in names.chunks(LOOKUP_CHUNK) {
            let wanted: Vec<&str> = chunk.iter().map(String::as_str).collect();
            match bz.bug_field_types(key, &wanted).await {
                Ok(envelope) => {
                    let found = kinds_in(&envelope, chunk);
                    {
                        let mut known = self.lock();
                        known.extend(found.iter().map(|(n, k)| (n.clone(), *k)));
                    }
                    out.extend(found);
                }
                Err(e) => {
                    // A 404/51 message echoes a name the client chose, so the
                    // warn line carries status and code only; debug has the text.
                    let refusal = e.downcast_ref::<BugzillaError>();
                    tracing::warn!(
                        http_status = refusal.map(BugzillaError::http_status),
                        bugzilla_code = refusal.and_then(BugzillaError::code),
                        names = chunk.len(),
                        "custom field type lookup failed; treating those fields as possible bug links"
                    );
                    tracing::debug!(error = ?QuotedError(&e), "custom field type lookup error");
                }
            }
        }
        out
    }

    /// The critical section only reads or inserts verified kinds, so a lock
    /// poisoned by a panic elsewhere still guards a map worth keeping.
    fn lock(&self) -> MutexGuard<'_, BTreeMap<String, CustomFieldKind>> {
        self.known.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn names(list: &[&str]) -> Vec<String> {
        list.iter().map(|n| (*n).to_string()).collect()
    }

    #[test]
    fn field_types_map_to_kinds() {
        // 6 is the one Bug ID type; 22 (BMO) and 7 are lists; every other
        // readable code is Other; a digit string reads like a number; a
        // missing or unreadable type leaves the name out, as does an entry
        // the caller never asked for.
        let envelope = json!({ "fields": [
            { "name": "cf_regression_of", "type": 6 },
            { "name": "cf_related", "type": 22 },
            { "name": "cf_links", "type": 7 },
            { "name": "cf_build", "type": 1 },
            { "name": "cf_foundby", "type": 2 },
            { "name": "cf_quoted", "type": "6" },
            { "name": "cf_untyped" },
            { "name": "cf_odd", "type": "six" },
            { "name": "blocks", "type": 22 },
        ]});
        let asked = names(&[
            "cf_regression_of",
            "cf_related",
            "cf_links",
            "cf_build",
            "cf_foundby",
            "cf_quoted",
            "cf_untyped",
            "cf_odd",
            "cf_absent",
        ]);
        let kinds = kinds_in(&envelope, &asked);
        let kind = |n: &str| kinds.get(n).copied();
        assert_eq!(kind("cf_regression_of"), Some(CustomFieldKind::BugId));
        assert_eq!(kind("cf_related"), Some(CustomFieldKind::BugList));
        assert_eq!(kind("cf_links"), Some(CustomFieldKind::BugList));
        assert_eq!(kind("cf_build"), Some(CustomFieldKind::Other));
        assert_eq!(kind("cf_foundby"), Some(CustomFieldKind::Other));
        assert_eq!(kind("cf_quoted"), Some(CustomFieldKind::BugId));
        assert_eq!(kind("cf_untyped"), None, "a missing type settles nothing");
        assert_eq!(kind("cf_odd"), None, "an unreadable type settles nothing");
        assert_eq!(
            kind("cf_absent"),
            None,
            "a name not answered settles nothing"
        );
        assert_eq!(kind("blocks"), None, "an entry nobody asked for is ignored");
        assert_eq!(kinds.len(), 6);
    }

    #[test]
    fn a_name_listed_twice_links_if_any_entry_does() {
        let envelope = json!({ "fields": [
            { "name": "cf_x", "type": 1 },
            { "name": "cf_x", "type": 6 },
            { "name": "cf_y", "type": 6 },
            { "name": "cf_y", "type": 1 },
        ]});
        let kinds = kinds_in(&envelope, &names(&["cf_x", "cf_y"]));
        assert_eq!(kinds.get("cf_x"), Some(&CustomFieldKind::BugId));
        assert_eq!(kinds.get("cf_y"), Some(&CustomFieldKind::BugId));
    }

    #[test]
    fn an_envelope_without_fields_settles_nothing() {
        assert!(kinds_in(&json!({ "error": true }), &names(&["cf_x"])).is_empty());
        assert!(kinds_in(&json!({ "fields": "none" }), &names(&["cf_x"])).is_empty());
    }

    #[test]
    fn only_other_cannot_link() {
        assert!(CustomFieldKind::BugId.may_link());
        assert!(CustomFieldKind::BugList.may_link());
        assert!(CustomFieldKind::Unknown.may_link(), "unknown fails closed");
        assert!(!CustomFieldKind::Other.may_link());
    }
}
