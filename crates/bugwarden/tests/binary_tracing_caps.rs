//! What the SHIPPED BINARY's tracing lines carry of a client's own strings
//! and id arrays (issues #240, #258, #260, #266).
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
//! The second half is not ours to spell at all: rmcp's own lines print
//! the handshake, the notifications and the request ids of a client this
//! process never gave a `Capped` to. Those are bounded at the SINK, by
//! the field formatter `main` installs (#260), and sanitized there too
//! (#266) — and only a process can show it, because the formatter is
//! part of the subscriber `main` builds and of nothing else.
//!
//! Coverage contract (each of these mutations must fail a test here):
//! - the stderr layer built without `fmt_fields`, or with a formatter
//!   that caps only the fields and not `message`, or only the values
//!   bugwarden itself formats — the [`Site`] rows whose field is
//!   `Debug`-shaped are the sharp ones there, because the sink's budget
//!   covers the RENDERED value: without it a `resolution=Some("` row
//!   measures 1024 client characters where [`decoration`] expects 1018;
//! - a cut at cap-1, cap+1, or on a byte boundary, which is why every
//!   probe is multi-byte;
//! - `bug_info` or `update_bug_dependencies` logging an id array whole, or
//!   a head without the count that says how long the array really was;
//! - ESC or BEL reaching stderr unescaped. BS, FF, DEL and the C1 range
//!   are in the same match arm but are not probed here; the module's own
//!   `the_escaping_matches_what_default_fields_does_to_a_message` walks
//!   the whole byte set, and a process is the wrong instrument for that.
//!
//! What this file NO LONGER proves, since #260, is anything about the
//! call SITES. `%Capped(&p.query)` and `%p.query` render identically once
//! the sink cuts at the same constant, so removing a wrapper leaves every
//! row here green — measured. The wrappers stay all the same: `capped()`
//! shares their cut and IS the audit record's, `bug_ids` needs a
//! count-plus-head shape no sink can synthesise (and the row below still
//! observes that one), and a second bound costs nothing. The record is
//! measured by `audit_wiremock`, not here.
//!
//! Untestable at any level and so not claimed: making the escaping
//! conditional on `Writer::sanitizes_ansi_escapes`. That flag is `true`
//! in every configuration this workspace builds — its default, and
//! `with_ansi_sanitization` is called nowhere — so such a mutant changes
//! no byte anywhere.

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

/// The character every over-cap probe is made of. Multi-byte on purpose:
/// an ASCII probe cannot tell a character cap from a byte one, and a byte
/// cut is one of the two ways a cap drifts.
const PROBE: char = 'é';

/// The byte a terminal reads as the start of a control sequence, and the
/// one it rings the bell for (#266).
const ESC: char = '\u{1b}';
const BEL: char = '\u{7}';

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

/// Drive `messages` through the real executable over stdio and return
/// EVERYTHING it wrote to stderr, first line to EOF.
///
/// [`log_line`] answers "what did that one line say". The sink's cap is
/// not a line's property but the stream's, and it covers lines this
/// workspace does not spell — rmcp's — so these rows have to see all of
/// them. `needle` is a barrier rather than the subject: stdin stays open
/// until the line carrying it has been logged, because EOF ends the serve
/// loop and a spawned handler's line can lose that race; the drain past
/// it is what makes "no line over the cap" evidence.
///
/// `rust_log` is `Some` only where a row is proving that the cap does not
/// depend on the filter; every other row runs at the level `main` falls
/// back to, with the variable scrubbed like everywhere else here.
///
/// The writes go in a task of their own because these rows send hundreds
/// of kilobytes: filling the child's stdin pipe while nobody is draining
/// its stderr deadlocks the pair, and the defect under test is precisely
/// a child that answers a large frame with a larger log line.
async fn stderr_through(messages: &[String], rust_log: Option<&str>, needle: &str) -> String {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_bugwarden"));
    cmd.args(["--transport", "stdio"])
        .args(["--bugzilla-server", "https://bugzilla.example.invalid"])
        .args(["--api-key", "test-key"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    for var in scrub_env::AMBIENT_VARS {
        cmd.env_remove(var);
    }
    if let Some(filter) = rust_log {
        cmd.env("RUST_LOG", filter);
    }
    let mut child = cmd.spawn().expect("the built binary must start");
    let mut stderr = startup_line::stderr_lines(&mut child);
    let mut stdin = child.stdin.take().expect("stdin is piped");
    let payload: Vec<u8> = messages
        .iter()
        .flat_map(|line| format!("{line}\n").into_bytes())
        .collect();
    // Holds stdin open until the barrier is reached: EOF ends the serve
    // loop, and a handler's line can lose that race.
    let (release, released) = tokio::sync::oneshot::channel::<()>();
    let writes = tokio::spawn(async move {
        stdin
            .write_all(&payload)
            .await
            .expect("the child must accept input");
        let _ = released.await;
    });
    let mut log = String::new();
    startup_line::wait_for_line(&mut stderr, &mut log, needle, LOG_TIMEOUT).await;
    let _ = release.send(());
    writes.await.expect("the writer task must not panic");
    tokio::time::timeout(LOG_TIMEOUT, async {
        while startup_line::next_logged_line(&mut stderr, &mut log)
            .await
            .is_some()
        {}
    })
    .await
    .unwrap_or_else(|_| panic!("the child's stderr must reach EOF: {}", excerpt(&log)));
    log
}

/// The `initialize` request, with `name` as the client's declared name.
///
/// A LINE rather than a `Value`, because one row sends a line that is not
/// JSON at all and every message goes down the same pipe.
fn initialize(name: &str) -> String {
    json!({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {
            "protocolVersion": SUPPORTED_VERSION,
            "capabilities": {},
            "clientInfo": { "name": name, "version": "0" }
        }
    })
    .to_string()
}

/// The notification that ends the handshake.
fn initialized() -> String {
    json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }).to_string()
}

/// A `tools/call` under `id`, so a row can choose an id the client wrote.
fn tools_call(id: serde_json::Value, tool: &str, arguments: serde_json::Value) -> String {
    json!({
        "jsonrpc": "2.0", "id": id, "method": "tools/call",
        "params": { "name": tool, "arguments": arguments }
    })
    .to_string()
}

/// As much of a log as a panic message should carry: a failing row here
/// can be holding a hundred kilobytes of one client string.
fn excerpt(log: &str) -> String {
    log.chars().take(2_000).collect()
}

/// The first line of `log` carrying `needle`.
fn find_line<'a>(log: &'a str, needle: &str) -> &'a str {
    log.lines()
        .find(|line| line.contains(needle))
        .unwrap_or_else(|| panic!("stderr must carry a {needle:?} line: {}", excerpt(log)))
}

/// The lines the subscriber wrote, told apart by the RFC 3339 UTC
/// timestamp it puts first — 27 characters ending in `Z`.
///
/// The child's own `Error:` exit line is `anyhow`'s Debug of the failure
/// `main` returned rather than a tracing event, carries no such prefix,
/// and is #261's subject rather than this file's.
fn tracing_lines(log: &str) -> impl Iterator<Item = &str> {
    log.lines().filter(|line| line.chars().nth(26) == Some('Z'))
}

/// `line` with the `TIMESTAMP LEVEL [span: ]<target>: ` prefix removed,
/// so what an assertion bounds is the message and the fields alone.
///
/// Split off the line rather than assumed: the prefix's width is the
/// event formatter's business and no part of what #260 decided.
fn after_target<'a>(line: &'a str, target: &str) -> &'a str {
    line.split_once(&format!("{target}: "))
        .unwrap_or_else(|| panic!("the line must be {target}'s: {}", excerpt(line)))
        .1
}

/// The longest run of `probe` in `text`: the client's own characters,
/// which is what the cap is a cap on.
fn longest_run(text: &str, probe: char) -> usize {
    let mut longest = 0;
    let mut run = 0;
    for ch in text.chars() {
        run = if ch == probe { run + 1 } else { 0 };
        longest = longest.max(run);
    }
    longest
}

/// No raw ESC and no raw BEL anywhere on stderr, and both present in
/// their escaped spellings so the absence is evidence rather than an
/// empty haystack.
fn assert_control_bytes_escaped(log: &str) {
    for (byte, name, escaped) in [(ESC, "ESC", "\\x1b"), (BEL, "BEL", "\\x07")] {
        assert!(
            !log.contains(byte),
            "a raw {name} reached stderr: {}",
            excerpt(log)
        );
        assert!(
            log.contains(escaped),
            "and its escaped form must be there, or this proves nothing: {}",
            excerpt(log)
        );
    }
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
/// it on stderr.
struct Site {
    /// `None` for the handshake `warn!`, whose probe is the declared
    /// protocol version rather than a tool argument.
    tool: Option<&'static str>,
    arguments: serde_json::Value,
    /// A policy the guard refuses, for the line only a refusal reaches.
    policy: Option<&'static str>,
    needle: &'static str,
    /// The field as it reaches the line, up to where the client's own
    /// text begins: `query=` for a `%Capped` field, `resolution=Some("`
    /// for an `?Option<Capped>` one. Everything it carries past the `=`
    /// is [`decoration`].
    field: &'static str,
}

/// The characters a field's own rendering spends out of the sink's
/// per-field budget before the client's text starts: none for a bare
/// `%Capped` field, one for a `Debug`-quoted one, six for `Some("`.
///
/// Since #260 the budget covers the RENDERED value (the sink sees a
/// stream of characters and cannot know which of them the client wrote),
/// so a decorated field carries exactly that much less of the probe —
/// and loses its closing delimiter to the cut, which is why no row
/// brackets its value on one.
fn decoration(field: &str) -> usize {
    field
        .split_once('=')
        .unwrap_or_else(|| panic!("a field needle carries its `=`: {field}"))
        .1
        .chars()
        .count()
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
        },
        Site {
            tool: Some("bugs_quicksearch"),
            arguments: json!({ "query": "kernel", "status": probe }),
            policy: None,
            needle: "tool: bugs_quicksearch",
            field: "status=",
        },
        Site {
            tool: Some("bugs_quicksearch"),
            arguments: json!({ "query": "kernel", "include_fields": probe }),
            policy: None,
            needle: "tool: bugs_quicksearch",
            field: "include_fields=",
        },
        Site {
            tool: Some("bugs_quicksearch"),
            arguments: json!({ "query": "kernel", "group_by": probe }),
            policy: None,
            needle: "tool: bugs_quicksearch",
            // Debug-formatted, so it stays quoted like the bare `&str`
            // field it replaced — and the opening quote is one character
            // of the sink's budget.
            field: "group_by=\"",
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
        },
        Site {
            tool: Some("update_bug_status"),
            arguments: json!({ "bug_id": 1, "status": probe }),
            policy: None,
            needle: "tool: update_bug_status",
            field: "status=",
        },
        Site {
            tool: Some("update_bug_status"),
            arguments: json!({ "bug_id": 1, "status": "RESOLVED", "resolution": probe }),
            policy: None,
            needle: "tool: update_bug_status",
            field: "resolution=Some(\"",
        },
        Site {
            tool: Some("assign_bug"),
            arguments: json!({ "bug_id": 1, "assignee": probe }),
            policy: None,
            needle: "tool: assign_bug",
            field: "assignee=",
        },
        Site {
            tool: Some("update_bug_fields"),
            arguments: json!({ "bug_id": 1, "priority": probe }),
            policy: None,
            needle: "tool: update_bug_fields",
            field: "priority=Some(\"",
        },
        Site {
            tool: Some("update_bug_fields"),
            arguments: json!({ "bug_id": 1, "severity": probe }),
            policy: None,
            needle: "tool: update_bug_fields",
            field: "severity=Some(\"",
        },
        Site {
            tool: Some("update_bug_fields"),
            arguments: json!({ "bug_id": 1, "resolution": probe }),
            policy: None,
            needle: "tool: update_bug_fields",
            field: "resolution=Some(\"",
        },
        Site {
            tool: Some("add_cc_to_bug"),
            arguments: json!({ "bug_id": 1, "cc_email": probe }),
            policy: None,
            needle: "tool: add_cc_to_bug",
            field: "cc_email=",
        },
        Site {
            // rmcp logs the same message text with the version raw (#260),
            // so this row selects on the target.
            tool: None,
            arguments: json!({}),
            policy: None,
            needle: "bugwarden::server: client requested unsupported",
            field: "client_requested=",
        },
        Site {
            // And rmcp's own copy of it, one line later: the fourth row
            // of #260's table, and a field no `Capped` of ours can
            // reach — 100 179 characters on this branch's parent for a
            // 100 000-character `protocolVersion`.
            tool: None,
            arguments: json!({}),
            policy: None,
            needle: "rmcp::service::server: client requested unsupported",
            field: "client_requested=",
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
    let probe = PROBE.to_string().repeat(CAP * 4);
    for site in sites(&probe) {
        let policy = site.policy.map(policy_file);
        let version = if site.tool.is_some() {
            SUPPORTED_VERSION
        } else {
            probe.as_str()
        };
        let call = site.tool.map(|tool| (tool, site.arguments));
        let line = log_line(version, policy.as_deref(), call, site.needle).await;
        let value = line
            .split_once(site.field)
            .unwrap_or_else(|| panic!("the line must carry {}: {line}", site.field))
            .1;
        // EXACTLY the cap, not "at most": an off-by-one cut is a second
        // rule that has to be remembered next to the audit record's, which
        // is the thing #191 and this share a definition to prevent. The
        // run stops where the sink's budget ran out, so counting it also
        // proves the field ended there rather than running on.
        let run = value.chars().take_while(|c| *c == PROBE).count();
        assert_eq!(
            run + decoration(site.field),
            CAP,
            "{} on {:?} must reach stderr as exactly {CAP} rendered chars, \
             {} of them its own decoration: {line}",
            site.field,
            site.needle,
            decoration(site.field)
        );
    }
}

/// rmcp's own lines print the client's handshake and its notifications
/// whole (#260). Measured there and again on this branch's parent, with
/// an ASCII probe: a 50 000-character `clientInfo.name` made
/// `Service initialized as server` 50 438 characters, and a
/// 100 000-character `notifications/progress` message made
/// `received notification` 100 335. Neither is a field this workspace
/// spells, so no call-site cap can reach either.
///
/// Both are `info!`, so the DEFAULT filter is what this row runs at:
/// dropping to `warn` would have hidden these two and left the two
/// `warn!` lines of the same table untouched, which is the argument the
/// sink won. The lines a raised filter adds are the next row's.
#[tokio::test]
async fn rmcps_handshake_and_notification_lines_are_cut_at_the_sink() {
    let name = PROBE.to_string().repeat(50_000);
    let message = PROBE.to_string().repeat(100_000);
    let log = stderr_through(
        &[
            initialize(&name),
            initialized(),
            json!({
                "jsonrpc": "2.0", "method": "notifications/progress",
                "params": { "progressToken": "t", "progress": 1, "message": message }
            })
            .to_string(),
        ],
        None,
        "notification=ProgressNotification",
    )
    .await;

    // The overhead is stated rather than guessed: the prefix comes off
    // the line, and what is left is rmcp's own static message plus its
    // one field name plus that field's value.
    for (needle, message_text, field) in [
        (
            "Service initialized as server",
            "Service initialized as server",
            " peer_info=",
        ),
        (
            "notification=ProgressNotification",
            "received notification",
            " notification=",
        ),
    ] {
        let line = find_line(&log, needle);
        let body = after_target(line, "rmcp::service").chars().count();
        assert!(
            body <= message_text.chars().count() + field.chars().count() + CAP,
            "{needle:?} must fit its message, its field name and one \
             capped value: {body} chars in {}",
            excerpt(line)
        );
        assert!(
            longest_run(line, PROBE) >= CAP / 2,
            "and must still carry the client's text, or it bounds \
             nothing: {}",
            excerpt(line)
        );
    }

    for line in tracing_lines(&log) {
        assert!(
            longest_run(line, PROBE) <= CAP,
            "no line may carry more than {CAP} of the client's own \
             characters: {}",
            excerpt(line)
        );
    }
}

/// rmcp answers every failed request with `warn!(%id, ..)`, so a
/// client-chosen STRING request id reaches stderr through a field this
/// workspace never spells — and, being `%`, without even `Debug`'s
/// escaping. A 4096-character ASCII id measured 4259 characters on the
/// unpatched tree, at the DEFAULT filter.
#[tokio::test]
async fn an_over_long_request_id_is_cut_at_the_sink() {
    let id = PROBE.to_string().repeat(CAP * 4);
    let log = stderr_through(
        &[
            initialize("binary-tracing-caps-test"),
            initialized(),
            tools_call(json!(id), "no_such_tool", json!({})),
        ],
        None,
        "response error",
    )
    .await;
    let line = find_line(&log, "response error");
    let value = logged_field(line, "id=", Some(" error="));
    assert_eq!(
        value.chars().count(),
        CAP,
        "a string request id must reach stderr as exactly {CAP} chars: {}",
        excerpt(line)
    );
    assert!(
        value.chars().all(|c| c == PROBE),
        "and as a prefix of what the client actually sent: {}",
        excerpt(line)
    );
}

/// Two rmcp lines that only a raised filter opens, both carrying client
/// bytes this workspace never formats — which is where a level filter
/// would have been the wrong fix and the sink is the right one.
///
/// `service.rs:1535` logs the whole request at debug, `params` and every
/// argument included. `transport/async_rw.rs:336` logs the whole
/// UNPARSABLE line at debug, once per malformed line — and it is the
/// `message` field, so only a sink that budgets `message` bounds it.
/// Measured on this branch's parent at `RUST_LOG=debug`: 100 330
/// characters for a 100 000-character argument and 100 150 for a
/// 100 000-character garbage line.
///
/// A malformed line does not end the session — rmcp skips it and serves
/// the next message — so one child produces both.
#[tokio::test]
async fn a_raised_filter_opens_no_line_the_sink_does_not_cut() {
    let probe = PROBE.to_string().repeat(100_000);
    let log = stderr_through(
        &[
            initialize("binary-tracing-caps-test"),
            initialized(),
            // Not JSON, and not a prefix of any: rmcp echoes it whole.
            probe.clone(),
            tools_call(json!(2), "bugs_quicksearch", json!({ "query": probe })),
        ],
        Some("debug"),
        "tool: bugs_quicksearch",
    )
    .await;

    // The unparsable line is all `message`, so its whole body is one
    // budgeted field and lands on the cap exactly.
    let parse_failure = find_line(&log, "Failed to parse message");
    assert_eq!(
        after_target(parse_failure, "rmcp::transport::async_rw")
            .chars()
            .count(),
        CAP,
        "an unparsable line reaches stderr as one capped message: {}",
        excerpt(parse_failure)
    );

    // The request line is a message plus two fields; the overhead is its
    // own static text, and the id is the `2` this row sent.
    const REQUEST: &str = "received request";
    let request = find_line(&log, REQUEST);
    let body = after_target(request, "rmcp::service").chars().count();
    assert!(
        body <= REQUEST.chars().count() + " id=2".len() + " request=".len() + CAP,
        "a whole request at debug must fit its two field names and one \
         capped value: {body} chars in {}",
        excerpt(request)
    );
    assert!(
        longest_run(request, PROBE) >= CAP / 2,
        "and must still carry the client's text, or it bounds nothing: {}",
        excerpt(request)
    );

    for line in tracing_lines(&log) {
        assert!(
            longest_run(line, PROBE) <= CAP,
            "no line may carry more than {CAP} of the client's own \
             characters, whatever the filter: {}",
            excerpt(line)
        );
    }
}

/// A `%` field is written verbatim (#266): tracing-subscriber sanitizes
/// `message` and `record_error` and nothing else, and most of the client
/// strings this workspace logs are `%`, `query` among them. A `query` of
/// ESC `[2J` clears the operator's terminal and BEL rings it; exactly one
/// raw ESC and one raw BEL reached stderr on the unpatched tree.
#[tokio::test]
async fn a_tool_argument_never_reaches_stderr_as_a_raw_control_byte() {
    let log = stderr_through(
        &[
            initialize("binary-tracing-caps-test"),
            initialized(),
            tools_call(
                json!(2),
                "bugs_quicksearch",
                json!({ "query": format!("a{ESC}[2Jb{BEL}c") }),
            ),
        ],
        None,
        "tool: bugs_quicksearch",
    )
    .await;
    assert_control_bytes_escaped(&log);
    assert!(
        log.contains("query=a\\x1b[2Jb\\x07c"),
        "and the field must read as the escape, not as a hole: {}",
        excerpt(&log)
    );
}

/// The same for the fields no code of this workspace spells: rmcp's
/// `warn!(%id, ..)` prints a client-chosen string request id raw, and its
/// `?peer_info` prints the declared client name — the latter already
/// escaped by `str`'s own `Debug`, pinned here so it stays that way.
#[tokio::test]
async fn rmcps_own_fields_never_reach_stderr_as_raw_control_bytes() {
    let log = stderr_through(
        &[
            initialize(&format!("client{ESC}[2Jname")),
            initialized(),
            tools_call(json!(format!("id{ESC}[2J{BEL}")), "no_such_tool", json!({})),
        ],
        None,
        "response error",
    )
    .await;
    assert_control_bytes_escaped(&log);
    let line = find_line(&log, "response error");
    assert!(
        line.contains("id=id\\x1b[2J\\x07"),
        "rmcp's `%id` is the field with no `Debug` to fall back on: {}",
        excerpt(line)
    );
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
