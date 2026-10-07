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

use serde_json::{Map, Value};

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

/// Names per lookup request, which bounds the URL. A write caps its custom
/// fields at this many, so it costs one lookup however many a client sends.
pub const LOOKUP_CHUNK: usize = 50;

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

/// What a custom field value a client wants to WRITE says about bug links,
/// read the way Bugzilla's `_check_bugid_field` will read it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CustomLinkValue {
    /// Names no bug: null, an empty string or `0`, which Bugzilla clears
    /// the field on (`return undef if !$value`), and spellings such as
    /// `00`, `#0` or blanks, which it rejects as bug 0 or an invalid id —
    /// nothing to assess either way.
    Clear,
    /// One bug id, as Bugzilla will resolve it: a number, or ASCII digits
    /// after a trim and at most one leading `#`, which is what
    /// `Bug->check` and `Bug->new` accept as an id.
    Target(u64),
    /// Anything Bugzilla would resolve some other way — an alias, an
    /// `{"id": N}` object, a float, a bool, a list, non-ASCII digits or
    /// edges — which the guard cannot judge and therefore refuses.
    Unassessable,
}

impl CustomLinkValue {
    /// Read one JSON value.
    pub fn parse(value: &Value) -> Self {
        match value {
            Value::Null => Self::Clear,
            Value::Number(n) => match n.as_u64() {
                Some(0) => Self::Clear,
                Some(id) => Self::Target(id),
                None => Self::Unassessable,
            },
            Value::String(s) => Self::parse_str(s),
            Value::Bool(_) | Value::Array(_) | Value::Object(_) => Self::Unassessable,
        }
    }

    /// Read one string as `Bug->check` does — a trim, one optional `#`,
    /// then digits that fit an id — but narrower: Bugzilla's trim strips
    /// Perl `\s` (Unicode White_Space), this one ASCII whitespace only, so
    /// a Unicode-space edge stays unassessable and is refused.
    fn parse_str(s: &str) -> Self {
        let s = s.trim_matches(|c: char| c.is_ascii_whitespace());
        if s.is_empty() {
            return Self::Clear;
        }
        let digits = s.strip_prefix('#').unwrap_or(s);
        if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return Self::Unassessable;
        }
        match digits.parse::<u64>() {
            Ok(0) => Self::Clear,
            Ok(id) => Self::Target(id),
            Err(_) => Self::Unassessable,
        }
    }
}

/// Every link a list-shaped value could carry: the items of an array, the
/// comma pieces of a string, or the one scalar.
fn link_values(value: &Value) -> Vec<CustomLinkValue> {
    match value {
        Value::Array(items) => items.iter().map(CustomLinkValue::parse).collect(),
        Value::String(s) if s.contains(',') => {
            s.split(',').map(CustomLinkValue::parse_str).collect()
        }
        other => vec![CustomLinkValue::parse(other)],
    }
}

/// Every bug id the values of `fields` could name, whatever the fields'
/// kinds: an upper bound on [`custom_links`]' targets that is a function of
/// the request alone, for a cap that must refuse before any request.
pub fn candidate_ids(fields: &Map<String, Value>) -> BTreeSet<u64> {
    fields
        .values()
        .flat_map(link_values)
        .filter_map(|v| match v {
            CustomLinkValue::Target(id) => Some(id),
            CustomLinkValue::Clear | CustomLinkValue::Unassessable => None,
        })
        .collect()
}

/// The bug links a write's custom fields carry, judged by kind.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct CustomLinks<'a> {
    /// Every bug id the write would link to.
    pub targets: BTreeSet<u64>,
    /// The first field (in key order) holding a value the guard cannot
    /// judge, which the write must refuse.
    pub unassessable: Option<&'a str>,
}

/// Judge the custom field values a client wants to write. A Bug ID field
/// and a field of unknown kind hold one scalar; a Bug List field holds
/// array items or comma pieces, each judged the same way; a field of any
/// other kind is never a link and is skipped.
pub fn custom_links<'a>(
    fields: &'a Map<String, Value>,
    kinds: &BTreeMap<String, CustomFieldKind>,
) -> CustomLinks<'a> {
    let mut out = CustomLinks::default();
    for (name, value) in fields {
        let kind = kinds.get(name).copied().unwrap_or(CustomFieldKind::Unknown);
        let pieces = match kind {
            CustomFieldKind::Other => continue,
            CustomFieldKind::BugList => link_values(value),
            CustomFieldKind::BugId | CustomFieldKind::Unknown => {
                vec![CustomLinkValue::parse(value)]
            }
        };
        for piece in pieces {
            match piece {
                CustomLinkValue::Clear => {}
                CustomLinkValue::Target(id) => {
                    out.targets.insert(id);
                }
                CustomLinkValue::Unassessable => {
                    out.unassessable.get_or_insert(name.as_str());
                }
            }
        }
    }
    out
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

    #[test]
    fn write_values_are_read_as_bugzilla_resolves_them() {
        use CustomLinkValue::{Clear, Target, Unassessable};
        // Bugzilla clears on null, "" and 0, rejects `00`, `#0` and blanks
        // as no bug, trims, strips one `#`, and looks anything else up as an
        // alias — which the guard cannot judge.
        let table = [
            (json!(null), Clear),
            (json!(""), Clear),
            (json!("0"), Clear),
            (json!(0), Clear),
            (json!("00"), Clear),
            (json!(7), Target(7)),
            (json!("7"), Target(7)),
            (json!(" #7\n"), Target(7)),
            (json!("007"), Target(7)),
            (json!("##7"), Unassessable),
            (json!("#"), Unassessable),
            (json!("+7"), Unassessable),
            (json!("abc"), Unassessable),
            (json!(-7), Unassessable),
            (json!(7.0), Unassessable),
            (json!(1e3), Unassessable),
            (json!(true), Unassessable),
            (json!([7]), Unassessable),
            (json!({ "id": 7 }), Unassessable),
            (json!("18446744073709551616"), Unassessable),
            (json!("٧"), Unassessable),
            (json!("\u{a0}7"), Unassessable),
            (json!("7, 8"), Unassessable),
        ];
        for (value, expected) in table {
            assert_eq!(CustomLinkValue::parse(&value), expected, "{value}");
        }
    }

    #[test]
    fn custom_links_are_judged_by_kind() {
        let kinds: BTreeMap<String, CustomFieldKind> = [
            ("cf_id".to_string(), CustomFieldKind::BugId),
            ("cf_list".to_string(), CustomFieldKind::BugList),
            ("cf_text".to_string(), CustomFieldKind::Other),
        ]
        .into_iter()
        .collect();
        let fields = |v: Value| v.as_object().cloned().expect("object");

        // A Bug ID field and an unknown field hold one id; a Bug List field
        // holds a list; an Other field is skipped whatever it holds.
        let ok = fields(json!({
            "cf_id": "#7",
            "cf_list": "8, 9",
            "cf_text": "10",
            "cf_new": 11,
            "cf_cleared": "",
        }));
        assert_eq!(
            custom_links(&ok, &kinds),
            CustomLinks {
                targets: [7, 8, 9, 11].into_iter().collect(),
                unassessable: None,
            }
        );

        // Array items of a list are judged one by one; one bad item taints
        // the field, and the first offending key is named.
        let bad_item = fields(json!({ "cf_list": [12, "x"], "cf_id": "CVE-x" }));
        let links = custom_links(&bad_item, &kinds);
        assert_eq!(links.unassessable, Some("cf_id"), "first in key order");
        assert_eq!(links.targets, [12].into_iter().collect());

        // A Bug ID or unknown field never splits: a comma list and an array
        // are unassessable there; and text in an unknown field is refused.
        for value in [json!("1, 2"), json!([1, 2]), json!("fixed in 1.2")] {
            let one = fields(json!({ "cf_id": value }));
            assert_eq!(
                custom_links(&one, &kinds).unassessable,
                Some("cf_id"),
                "{value}"
            );
            let unknown = fields(json!({ "cf_new": value }));
            assert_eq!(
                custom_links(&unknown, &kinds).unassessable,
                Some("cf_new"),
                "{value}"
            );
        }
        let other = fields(json!({ "cf_text": "fixed in 1.2", "cf_text2": null }));
        let kinds_other: BTreeMap<String, CustomFieldKind> = [
            ("cf_text".to_string(), CustomFieldKind::Other),
            ("cf_text2".to_string(), CustomFieldKind::Other),
        ]
        .into_iter()
        .collect();
        assert_eq!(custom_links(&other, &kinds_other), CustomLinks::default());
    }

    #[test]
    fn candidate_ids_bound_the_targets_whatever_the_kinds() {
        // The cap runs before any lookup, so it counts every id a value
        // could name under any kind: scalars, array items and comma pieces.
        let fields = json!({
            "cf_a": 7,
            "cf_b": "#8",
            "cf_c": "9, 10",
            "cf_d": [11, "12", "x"],
            "cf_e": "fixed in 13",
            "cf_f": null,
            "cf_g": 0,
        })
        .as_object()
        .cloned()
        .expect("object");
        assert_eq!(
            candidate_ids(&fields),
            [7, 8, 9, 10, 11, 12].into_iter().collect()
        );
    }
}
