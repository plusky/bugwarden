//! What the SHIPPED BINARY's tracing lines carry of a client's own strings
//! and id arrays (issues #240, #258).
//!
//! The audit record caps every client string at 1024 chars before it
//! reaches the JSONL file or the OTLP audit stream; the `info!` line the
//! handler opens with used to carry the same text raw, to the same
//! operator and the same collector. That is a whole-channel defect, so
//! this drives the real executable: only a process proves the line clears
//! the DEFAULT filter `main` installs (`RUST_LOG` scrubbed, never set
//! back) and reaches the stderr writer; `testlog` runs at TRACE under its
//! own writer and proves neither.
//!
//! Coverage contract (each of these mutations must fail a test here):
//! - any `Capped` field formatted from its parameter instead of the
//!   wrapper — one [`Site`] row per field, the handshake `warn!` that is
//!   not a tool parameter included;
//! - a wrapper cutting at cap-1, cap+1, or on a byte boundary, which is
//!   why every probe is multi-byte;
//! - `bug_info` or `update_bug_dependencies` logging an id array whole, or
//!   a head without the count that says how long the array really was.

use std::path::Path;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use bugwarden_core::guard::Guard;
use serde_json::json;
use tokio::io::AsyncWriteExt as _;
use tokio::process::Command;

#[path = "common/scrub_env.rs"]
mod scrub_env;

#[path = "common/startup_line.rs"]
mod startup_line;

/// Bounded so a binary that never logs the line fails this test rather than
/// hanging the suite until CI's own timeout kills it.
const LOG_TIMEOUT: Duration = Duration::from_secs(20);

/// The cap, spelled out: `server::PARAM_VALUE_MAX_CHARS` is private, and a
/// test that reads the constant it is testing agrees with any value.
const CAP: usize = 1024;

/// A revision the server serves, so the handshake is unremarkable
/// everywhere except the row testing an unsupported one.
const SUPPORTED_VERSION: &str = "2025-11-25";

/// Each binary runs the walker itself, so a single-binary
/// `cargo test --test binary_tracing_caps` still proves what its scrub claims.
#[test]
fn the_scrub_list_covers_every_environment_fallback() {
    scrub_env::assert_the_scrub_list_covers_every_environment_fallback(
        scrub_env::AMBIENT_VARS,
        scrub_env::HTTP_TOKEN_VARS,
    );
}

/// Drive one client message sequence through the real executable over
/// stdio and return the first stderr line containing `needle`.
///
/// Bugzilla is deliberately unreachable: the lines under test are logged
/// before any upstream call, or — the create denial — after one that can
/// only fail, so the handshake, the call and the line happen in order
/// without a mock. stdout goes to /dev/null: the replies are not the
/// subject.
async fn log_line(
    protocol_version: &str,
    policy: Option<&Path>,
    call: Option<(&str, serde_json::Value)>,
    needle: &str,
) -> String {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_bugwarden"));
    cmd.args(["--transport", "stdio"])
        .args(["--bugzilla-server", "https://bugzilla.example.invalid"])
        .args(["--api-key", "test-key"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    if let Some(path) = policy {
        cmd.arg("--policy").arg(path);
    }
    // Scrubbed and NOT set back: `RUST_LOG` included, so these lines are
    // read at the level `main` falls back to. A line that only appears
    // under a raised level is not what this issue is about.
    for var in scrub_env::AMBIENT_VARS {
        cmd.env_remove(var);
    }
    let mut child = cmd.spawn().expect("the built binary must start");
    let mut stderr = startup_line::stderr_lines(&mut child);
    let mut stdin = child.stdin.take().expect("stdin is piped");
    let mut messages = vec![json!({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {
            "protocolVersion": protocol_version,
            "capabilities": {},
            "clientInfo": { "name": "binary-tracing-caps-test", "version": "0" }
        }
    })];
    if let Some((tool, arguments)) = call {
        messages.push(json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }));
        messages.push(json!({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": { "name": tool, "arguments": arguments }
        }));
    }
    for message in messages {
        stdin
            .write_all(format!("{message}\n").as_bytes())
            .await
            .expect("the child must accept input");
    }
    // Holds `stdin` open until the line arrives: EOF ends the child's serve
    // loop and `kill_on_drop` finishes it off on return, which together can
    // retire the child before the reader has what it came for.
    let mut log = String::new();
    let line = startup_line::wait_for_line(&mut stderr, &mut log, needle, LOG_TIMEOUT).await;
    drop(stdin);
    line
}

/// [`log_line`] for the ordinary case: a served handshake, one tool call,
/// the default allow-all policy.
async fn tool_call_log_line(tool: &str, arguments: serde_json::Value, needle: &str) -> String {
    log_line(SUPPORTED_VERSION, None, Some((tool, arguments)), needle).await
}

/// The value the tracing line gives `field`; `ends_with` is `None` when the
/// field is the last one on its line.
fn logged_field<'a>(line: &'a str, field: &str, ends_with: Option<&str>) -> &'a str {
    let after = line
        .split_once(field)
        .unwrap_or_else(|| panic!("the line must carry a {field} field: {line}"))
        .1;
    match ends_with {
        None => after,
        Some(end) => match after.split_once(end) {
            Some((value, _)) => value,
            None => panic!("the {field} field must be followed by {end}: {line}"),
        },
    }
}

/// The ids an array field logged, `field` being everything up to its first
/// id.
fn logged_ids(line: &str, field: &str) -> Vec<u64> {
    logged_field(line, field, Some("]"))
        .split(", ")
        .map(|id| id.parse().unwrap_or_else(|e| panic!("{id:?}: {e}: {line}")))
        .collect()
}

/// One tracing field that formats a client string, and the call that puts
/// it on stderr. `field` and `ends_with` bracket the value: a `%Capped`
/// field prints bare, an `?Option<Capped>` one prints `Some("…")`.
struct Site {
    /// `None` for the handshake `warn!`, whose probe is the declared
    /// protocol version rather than a tool argument.
    tool: Option<&'static str>,
    arguments: serde_json::Value,
    /// A policy the guard refuses, for the line only a refusal reaches.
    policy: Option<&'static str>,
    needle: &'static str,
    field: &'static str,
    ends_with: Option<&'static str>,
}

/// Denies every product, so `create_bug` reaches its refusal line. No other
/// row needs a policy: the guard is consulted after the field under test is
/// already formatted.
const DENY_ALL: &str = "[[rule]]\nname = \"deny-all\"\naction = \"deny\"\n\
                        [rule.match]\nproducts = [\"*\"]\n";

/// Every field in `server.rs` that formats a client string, with the
/// smallest call that logs it and the probe in that field alone.
fn sites(probe: &str) -> Vec<Site> {
    vec![
        Site {
            tool: Some("bugs_quicksearch"),
            arguments: json!({ "query": probe }),
            policy: None,
            needle: "tool: bugs_quicksearch",
            field: "query=",
            ends_with: Some(" status="),
        },
        Site {
            tool: Some("bugs_quicksearch"),
            arguments: json!({ "query": "kernel", "status": probe }),
            policy: None,
            needle: "tool: bugs_quicksearch",
            field: "status=",
            ends_with: Some(" include_fields="),
        },
        Site {
            tool: Some("bugs_quicksearch"),
            arguments: json!({ "query": "kernel", "include_fields": probe }),
            policy: None,
            needle: "tool: bugs_quicksearch",
            field: "include_fields=",
            ends_with: Some(" limit="),
        },
        Site {
            tool: Some("bugs_quicksearch"),
            arguments: json!({ "query": "kernel", "group_by": probe }),
            policy: None,
            needle: "tool: bugs_quicksearch",
            // Debug-formatted, so it stays quoted like the bare `&str`
            // field it replaced.
            field: "group_by=\"",
            ends_with: Some("\""),
        },
        Site {
            tool: Some("create_bug"),
            arguments: json!({
                "product": probe, "component": "kernel",
                "summary": "s", "version": "v"
            }),
            policy: None,
            needle: "tool: create_bug",
            field: "product=",
            ends_with: Some(" component="),
        },
        Site {
            tool: Some("create_bug"),
            arguments: json!({
                "product": "openSUSE", "component": probe,
                "summary": "s", "version": "v"
            }),
            policy: None,
            needle: "tool: create_bug",
            field: "component=",
            ends_with: Some(" custom_field_count="),
        },
        Site {
            tool: Some("create_bug"),
            arguments: json!({
                "product": probe, "component": "kernel",
                "summary": "s", "version": "v"
            }),
            policy: Some(DENY_ALL),
            needle: "guard denied bug creation",
            field: "product=",
            ends_with: None,
        },
        Site {
            tool: Some("add_attachment"),
            arguments: json!({
                "bug_id": 1, "data": "", "file_name": probe,
                "summary": "s", "content_type": "text/plain"
            }),
            policy: None,
            needle: "tool: add_attachment",
            field: "file_name=",
            ends_with: Some(" is_private="),
        },
        Site {
            tool: Some("update_bug_status"),
            arguments: json!({ "bug_id": 1, "status": probe }),
            policy: None,
            needle: "tool: update_bug_status",
            field: "status=",
            ends_with: Some(" resolution="),
        },
        Site {
            tool: Some("update_bug_status"),
            arguments: json!({ "bug_id": 1, "status": "RESOLVED", "resolution": probe }),
            policy: None,
            needle: "tool: update_bug_status",
            field: "resolution=Some(\"",
            ends_with: Some("\")"),
        },
        Site {
            tool: Some("assign_bug"),
            arguments: json!({ "bug_id": 1, "assignee": probe }),
            policy: None,
            needle: "tool: assign_bug",
            field: "assignee=",
            ends_with: None,
        },
        Site {
            tool: Some("update_bug_fields"),
            arguments: json!({ "bug_id": 1, "priority": probe }),
            policy: None,
            needle: "tool: update_bug_fields",
            field: "priority=Some(\"",
            ends_with: Some("\")"),
        },
        Site {
            tool: Some("update_bug_fields"),
            arguments: json!({ "bug_id": 1, "severity": probe }),
            policy: None,
            needle: "tool: update_bug_fields",
            field: "severity=Some(\"",
            ends_with: Some("\")"),
        },
        Site {
            tool: Some("update_bug_fields"),
            arguments: json!({ "bug_id": 1, "resolution": probe }),
            policy: None,
            needle: "tool: update_bug_fields",
            field: "resolution=Some(\"",
            ends_with: Some("\")"),
        },
        Site {
            tool: Some("add_cc_to_bug"),
            arguments: json!({ "bug_id": 1, "cc_email": probe }),
            policy: None,
            needle: "tool: add_cc_to_bug",
            field: "cc_email=",
            ends_with: None,
        },
        Site {
            // rmcp logs the same message text with the version raw (#260),
            // so this row selects on the target.
            tool: None,
            arguments: json!({}),
            policy: None,
            needle: "bugwarden::server: client requested unsupported",
            field: "client_requested=",
            ends_with: Some(" server_fallback="),
        },
    ]
}

/// `toml` where the spawned child can read it.
fn policy_file(toml: &str) -> PathBuf {
    let path = Path::new(env!("CARGO_TARGET_TMPDIR")).join("tracing_caps_policy.toml");
    std::fs::write(&path, toml).expect("the policy file must be writable");
    path
}

#[tokio::test]
async fn every_tracing_field_that_formats_a_client_string_is_cut_to_the_cap() {
    // Multi-byte: an ASCII probe cannot tell a char cap from a byte one,
    // and a byte cut is one of the two ways the shared wrapper can drift.
    let probe = "é".repeat(CAP * 4);
    for site in sites(&probe) {
        let policy = site.policy.map(policy_file);
        let version = if site.tool.is_some() {
            SUPPORTED_VERSION
        } else {
            probe.as_str()
        };
        let call = site.tool.map(|tool| (tool, site.arguments));
        let line = log_line(version, policy.as_deref(), call, site.needle).await;
        let value = logged_field(&line, site.field, site.ends_with);
        // EXACTLY the cap, not "at most": an off-by-one cut is a second
        // rule that has to be remembered next to the audit record's, which
        // is the thing #191 and this share a definition to prevent.
        assert_eq!(
            value.chars().count(),
            CAP,
            "{} on {:?} must reach stderr as exactly {CAP} chars: {line}",
            site.field,
            site.needle
        );
        assert!(
            value.chars().all(|c| c == 'é'),
            "and as a prefix of what the client actually sent: {line}"
        );
    }
}

#[tokio::test]
async fn bug_ids_reach_stderr_as_a_raw_count_and_a_distinct_head() {
    // The head stops where `too_many_ids` refuses; the count says how long
    // the array really was.
    let mut repeated: Vec<u64> = vec![7; Guard::MAX_ASSESS_IDS];
    repeated.push(8);
    for (sent, head) in [
        (
            (1..=Guard::MAX_ASSESS_IDS as u64 + 5).collect::<Vec<u64>>(),
            (1..=Guard::MAX_ASSESS_IDS as u64).collect::<Vec<u64>>(),
        ),
        // Positional over the raw array, this head would be 25 sevens and
        // would omit the served id 8.
        (repeated, vec![7, 8]),
    ] {
        let line =
            tool_call_log_line("bug_info", json!({ "bug_ids": sent }), "tool: bug_info").await;
        assert!(
            line.contains(&format!("bug_ids_len={}", sent.len())),
            "the count is what the whole array used to say: {line}"
        );
        assert_eq!(
            logged_ids(&line, "bug_ids=["),
            head,
            "and the head is exactly the distinct ids the call may serve: {line}"
        );
    }
}

#[tokio::test]
async fn every_dependency_array_reaches_stderr_as_a_count_and_a_head() {
    // Four client-sized arrays on one line, each refused only further down
    // (#258).
    let sent = Guard::MAX_ASSESS_IDS + 5;
    let list = |base: u64| (base..base + sent as u64).collect::<Vec<u64>>();
    let line = tool_call_log_line(
        "update_bug_dependencies",
        json!({
            "bug_id": 1,
            "blocks_add": list(1000),
            "blocks_remove": list(2000),
            "depends_on_add": list(3000),
            "depends_on_remove": list(4000),
        }),
        "tool: update_bug_dependencies",
    )
    .await;
    for (field, base) in [
        ("blocks_add", 1000),
        ("blocks_remove", 2000),
        ("depends_on_add", 3000),
        ("depends_on_remove", 4000),
    ] {
        assert!(
            line.contains(&format!("{field}_len={sent}")),
            "{field} must carry the count of the whole array: {line}"
        );
        assert_eq!(
            logged_ids(&line, &format!("{field}=Some([")),
            (base..base + Guard::MAX_ASSESS_IDS as u64).collect::<Vec<u64>>(),
            "and no more of it than the guard's own bound: {line}"
        );
    }
}
