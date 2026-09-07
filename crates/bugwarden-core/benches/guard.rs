//! Instruction-count benches for the CPU we own: policy classify and I14
//! link scrub. No network. Wall-clock is Bugzilla wait; these pin the
//! in-process work a 25-id assess or a fat bug_info actually does.
//!
//! Linux + valgrind only (`iai-callgrind`). Behind `--features iai` so
//! `cargo test --all-targets` does not run the harness.

use std::collections::BTreeSet;
use std::hint::black_box;

use bugwarden_core::guard::Guard;
use bugwarden_core::policy::{BugMeta, Operation, Policy};
use chrono::{DateTime, Utc};
use iai_callgrind::{
    library_benchmark, library_benchmark_group, main, Callgrind, EventKind, LibraryBenchmarkConfig,
};
use serde_json::{json, Value};

const POLICY: &str = r#"
default_action = "allow"

[[rule]]
name = "embargo"
action = "deny"
[rule.match]
groups = ["*embargo*"]

[[rule]]
name = "suse-summary"
action = "restrict"
capabilities = ["summary"]
[rule.match]
products = ["SUSE*"]
"#;

fn now() -> DateTime<Utc> {
    DateTime::parse_from_rfc3339("2026-01-15T00:00:00Z")
        .expect("fixed instant")
        .with_timezone(&Utc)
}

fn meta(product: Option<&str>, groups: Option<&[&str]>, creation: Option<&str>) -> BugMeta {
    BugMeta {
        id: 7,
        summary: Some("a bug".into()),
        product: product.map(str::to_owned),
        components: Some(vec!["Kernel".into()]),
        status: Some("NEW".into()),
        severity: Some("Normal".into()),
        priority: Some("P3".into()),
        keywords: Some(vec![]),
        groups: groups.map(|g| g.iter().map(|s| (*s).to_owned()).collect()),
        whiteboard: Some(String::new()),
        creation_time: creation.map(|s| {
            DateTime::parse_from_rfc3339(s)
                .expect("fixture time")
                .with_timezone(&Utc)
        }),
        created_by_me: Some(false),
    }
}

struct ClassifyFix {
    policy: Policy,
    bug: BugMeta,
    now: DateTime<Utc>,
}

fn classify_allow() -> ClassifyFix {
    ClassifyFix {
        policy: Policy::from_toml_str(POLICY).expect("fixture policy"),
        bug: meta(Some("Firefox"), Some(&[]), Some("2020-01-01T00:00:00Z")),
        now: now(),
    }
}

fn classify_deny() -> ClassifyFix {
    ClassifyFix {
        policy: Policy::from_toml_str(POLICY).expect("fixture policy"),
        bug: meta(
            Some("Kernel"),
            Some(&["embargo-2026"]),
            Some("2020-01-01T00:00:00Z"),
        ),
        now: now(),
    }
}

fn classify_restrict() -> ClassifyFix {
    ClassifyFix {
        policy: Policy::from_toml_str(POLICY).expect("fixture policy"),
        bug: meta(
            Some("SUSE Linux Enterprise"),
            Some(&[]),
            Some("2020-01-01T00:00:00Z"),
        ),
        now: now(),
    }
}

fn classify_unreadable() -> ClassifyFix {
    ClassifyFix {
        policy: Policy::from_toml_str(POLICY).expect("fixture policy"),
        // groups None: embargo rule is undecidable → deny (I4)
        bug: meta(Some("Kernel"), None, Some("2020-01-01T00:00:00Z")),
        now: now(),
    }
}

#[library_benchmark]
#[bench::allow(classify_allow())]
#[bench::deny(classify_deny())]
#[bench::restrict(classify_restrict())]
#[bench::unreadable(classify_unreadable())]
fn classify(fix: ClassifyFix) {
    black_box(fix.policy.classify(&fix.bug, fix.now, Operation::Access));
}

fn linked_bug() -> Value {
    json!({
        "id": 1,
        "blocks": [2, 3, 99],
        "depends_on": [4, 99],
        "duplicates": [5],
        "dupe_of": 99,
        "see_also": [
            "https://bugzilla.example/show_bug.cgi?id=2",
            "https://bugzilla.example/show_bug.cgi?id=99"
        ],
        "url": "https://bugzilla.example/show_bug.cgi?id=99"
    })
}

fn disclosable() -> BTreeSet<u64> {
    [1, 2, 3, 4, 5].into_iter().collect()
}

#[library_benchmark]
#[bench::mixed(args = (linked_bug(), disclosable()))]
fn scrub_links(mut bug: Value, allowed: BTreeSet<u64>) {
    Guard::scrub_bug_links(&mut bug, "https://bugzilla.example", &allowed);
    black_box(bug);
}

library_benchmark_group!(
    name = classify_group;
    benchmarks = classify
);

library_benchmark_group!(
    name = scrub_group;
    benchmarks = scrub_links
);

// 20% Ir over last run: LLVM noise, not a wall-clock gate. Job is never required.
main!(
    config = LibraryBenchmarkConfig::default()
        .tool(Callgrind::default().soft_limits([(EventKind::Ir, 20f64)]));
    library_benchmark_groups = classify_group, scrub_group
);
