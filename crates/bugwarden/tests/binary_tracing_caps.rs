//! What the SHIPPED BINARY's tracing lines carry of a client's own strings
//! and id arrays (issues #240, #258, #260, #266, #275, #278).
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
//! (#266, #275) — and only a process can show it, because the formatter
//! is part of the subscriber `main` builds and of nothing else.
//!
//! Coverage contract (each of these mutations must fail a test here):
//! - the stderr layer built without `fmt_fields`, or with a formatter
//!   that caps only the fields and not `message`, or only the values
//!   bugwarden itself formats — the sharp rows are rmcp's now, since
//!   #278 bounds our own fields at the site and a sink with no budget
//!   leaves them unchanged. The two handshake-fallback rows drive the
//!   same initialize and differ only in whose line they read, so such a
//!   mutant shows up as the rmcp one running past [`CAP`] while ours
//!   stays at [`QUOTED_CAP`];
//! - a cut at cap-1, cap+1, or on a byte boundary, which is why every
//!   probe is multi-byte;
//! - `bug_info` or `update_bug_dependencies` logging an id array whole, or
//!   a head without the count that says how long the array really was;
//! - ESC or BEL reaching stderr unescaped (#266), probed on a `query`
//!   of ours and on the two fields rmcp writes that no code here fronts,
//!   its `%id` and its `?peer_info`;
//! - CR or TAB reaching stderr unescaped (#275), probed on a `query` of
//!   ours and on rmcp's `message` — the one field for which a child
//!   process is the only instrument;
//! - a client string reaching a line through a `%` field, where nothing
//!   marks the end of its value and a ` status=HACKED` inside it becomes
//!   a field of the line (#278):
//!   `a_client_field_cannot_forge_a_later_field_on_its_own_line` reads
//!   the value with [`quoted_field`], which finds the boundary the
//!   WRITER marked, and then reads the real `status` past it;
//! - an upstream error reaching a line through a `%` field, the #278
//!   residual: Bugzilla echoes the client's `version` into `error=`
//!   (#288). `an_upstream_error_cannot_forge_a_later_field_on_its_own_line`
//!   drives `create_bug` against a mock that returns the fixture
//!   message with `status=HACKED` inside; a `%e` site fails here;
//! - a quoted value whose closing quote the SINK cuts off, which a
//!   reader then runs out of into the next client field (#278):
//!   `a_cut_client_field_still_closes_its_own_quote` drives the two
//!   narrowest shapes — 1023 plain characters, 128 U+2028 — and reads
//!   the line's keys back with [`logfmt_keys`]. A `Capped::Debug` that
//!   spent the sink's whole 1024 instead of [`QUOTED_CAP`], or wrote a
//!   half escape at the boundary, fails there and nowhere else;
//! - LF or U+2028 ending a line the client did not open. No absence
//!   assertion can see those: LF is what separates the lines being read,
//!   and U+2028 is not. So
//!   `a_client_field_can_neither_end_a_stderr_line_nor_open_one` counts
//!   tracing lines against a SECOND child given the same session with
//!   those characters replaced by spaces, and pins the forged text to
//!   the tool's own line.
//!   `an_unparsable_line_reaches_the_message_field_escaped` is the
//!   `message` half and spawns ONE child, counting the forged text's
//!   occurrences: rmcp's reader is line-delimited, so an LF ends
//!   the frame before rmcp sees it and that row smuggles CR and TAB
//!   inside one instead;
//! - the rest of C0, DEL, the C1 range and U+2029 are in the same match
//!   arms but are not probed here. `tracing_fields`' own
//!   `every_escaped_character_leaves_the_sink_as_its_escape` walks every
//!   character in the set against a spelled-out table, and a child
//!   process is the wrong instrument for 67 rows;
//!
//! Between #260 and #278 this file proved nothing about the call SITES:
//! the sink cut every field at the same constant, so `%Capped(&p.query)`
//! and `%p.query` rendered alike and removing a wrapper left every row
//! green — measured then. #278 gives the wrapper work only it can do.
//! `Capped` writes its own quotes inside a budget of its own, eight
//! characters under the sink's, so a long value closes at 1018 where the
//! bare `?p.query` beside it would be cut open at 1024 — and a field cut
//! open is one a quote-honouring reader runs straight out of. So the
//! rows below measure the site and the sink both: [`QUOTED_CAP`] and the
//! closing delimiter are the site's, the 1024 on rmcp's own fields is
//! the sink's. `capped()` still shares [`CAP`] and IS the audit record's
//! cut, measured by `audit_wiremock` rather than here, and `bug_ids`
//! still needs a count-plus-head shape no sink can synthesise from a
//! rendered value.
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
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

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

/// The rendered characters a client string of OURS carries between the
/// quotes `server::Capped` writes round it (#278), spelled out for the
/// reason [`CAP`] is.
///
/// Eight less than the cap, which is what the widest shape a site wraps
/// a `Capped` in costs: `Some("` and `")` are six characters and the
/// quotes are two, so `Some("` + 1016 + `")` is 1024 exactly and the
/// sink has nothing left to cut. A field cut open is a field whose
/// closing quote is gone, and that is what this number exists to stop.
const QUOTED_CAP: usize = 1016;

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

/// The characters that end a line, or a column, for whatever reads
/// stderr next (#275). LF is the line separator itself; CR is one to a
/// terminal and to a good many log shippers; TAB ends a column in the
/// field-separated formats they parse into; and U+2028 ends a line for
/// every consumer that splits the way Python, Java and JavaScript do,
/// which is why the sink escapes it even though stderr itself does not
/// break on it.
const LF: char = '\u{a}';
const CR: char = '\u{d}';
const TAB: char = '\u{9}';
const LS: char = '\u{2028}';

/// A tracing line as `main`'s formatter writes one, made of nothing but
/// characters a client may put in a `query`.
///
/// The forgery this exists to stop: a value carrying LF ends the line
/// the server was writing and this text begins another, with a
/// timestamp, a level and a bugwarden target of the client's choosing.
/// Nothing reads the date; `FORGED LINE` is what tells this text from a
/// real line, and the midnight timestamp is a shape no line this server
/// writes will ever have.
const FORGED_LINE: &str = "2026-09-05T00:00:00.000000Z  INFO bugwarden::server: FORGED LINE";

/// A `query` shaped like the tail of the very line it lands on: a value,
/// then a space, then two `key=value` pairs of the client's own (#278).
/// `status` is a field the same line really carries, so a reader fooled
/// by this one reads `HACKED` where the server wrote `ALL`.
const FORGING_PAIR: &str = "evil status=HACKED limit=999";

/// The same forgery carrying the two characters `Debug` escapes, the
/// backslash placed LAST so the rendered value ends `\\` immediately
/// before its closing quote.
///
/// That is the shape a reader gets wrong when it decides a `"` is
/// escaped by looking only at the character before it: here the
/// backslash before the closing quote is itself escaped, the quote is
/// real, and a reader fooled by it runs on into the next field — the
/// same outcome the bare `%` field had.
const FORGING_ESCAPES: &str = "evil\" status=HACKED \\";

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
/// subject. The #288 row needs a real upstream body; it uses
/// [`log_line_at`] against a mock.
async fn log_line(
    protocol_version: &str,
    policy: Option<&Path>,
    call: Option<(&str, serde_json::Value)>,
    needle: &str,
) -> String {
    log_line_at(
        "https://bugzilla.example.invalid",
        protocol_version,
        policy,
        call,
        needle,
    )
    .await
}

/// [`log_line`] pointed at `bugzilla_server` instead of the unreachable
/// default.
async fn log_line_at(
    bugzilla_server: &str,
    protocol_version: &str,
    policy: Option<&Path>,
    call: Option<(&str, serde_json::Value)>,
    needle: &str,
) -> String {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_bugwarden"));
    cmd.args(["--transport", "stdio"])
        .args(["--bugzilla-server", bugzilla_server])
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

/// None of `bytes` raw in any line's TEXT, and each present in its
/// escaped spelling so the absence is evidence rather than an empty
/// haystack.
///
/// "In any line's text" is the honest scope. `log` was assembled from
/// tokio's `Lines`, which pops a trailing `\n` and then a trailing `\r`
/// (tokio 1.53 `io/util/lines.rs:126-129`), so a CR sitting immediately
/// before a line end is gone before this function ever sees it. Both
/// #275 rows put their CR in the middle of a value, where that blind
/// spot does not reach.
fn assert_escaped_never_raw(log: &str, bytes: &[(char, &str, &str)]) {
    for (byte, name, escaped) in bytes {
        assert!(
            !log.contains(*byte),
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

/// No raw ESC and no raw BEL anywhere on stderr (#266), each present in
/// the spelling the field carrying it uses.
///
/// The two differ, and the caller says which it expects. The spelling
/// follows the SIGIL and not the owner: a `?` field is escaped by
/// `Debug` long before the sink sees it and reads `\u{1b}`, a `%` field
/// arrives raw and takes the sink's `\x1b`. Both families appear on
/// bugwarden's own lines — every client string of ours is `?` since
/// #278, and `error=` since #288, while `path`, `location` and `thread`
/// are still `%` — and on rmcp's, whose `?peer_info` is quoted where
/// its `%id` is not.
fn assert_control_bytes_escaped(log: &str, esc: &str, bel: &str) {
    assert_escaped_never_raw(log, &[(ESC, "ESC", esc), (BEL, "BEL", bel)]);
}

/// No raw CR and no raw TAB in stderr's line texts (#275).
///
/// LF is not in this list and cannot be: it is the separator between the
/// lines being read. That the client's LF opened no line of its own is
/// what the line COUNT in the rows below proves instead, and U+2028 is
/// held to the same count for the same reason.
fn assert_cr_and_tab_escaped(log: &str) {
    assert_escaped_never_raw(log, &[(CR, "CR", "\\r"), (TAB, "TAB", "\\t")]);
}

/// The value the tracing line gives `field`; `ends_with` is `None` when the
/// field is the last one on its line.
///
/// For a value written BARE — rmcp's `%id`, an id array of ours — where
/// there is no closing delimiter to find. A client string of ours is
/// quoted and read with [`quoted_field`] instead, because a caller-named
/// `ends_with` is a boundary the VALUE can move (#278).
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

/// The value of a `Debug`-quoted field, and the rest of the line after
/// its closing quote.
///
/// [`logged_field`] ends a value where the CALLER says the next field
/// begins, which is exactly what a `%` field let a client move: a
/// `query` of `evil status=HACKED limit=999` handed it `evil`, because
/// the client's own ` status=` came first (#278). A quoted value ends at
/// its own closing quote — the first `"` OUTSIDE an escape, which is not
/// the same as the first `"` no backslash precedes: a value ending in a
/// backslash renders `…\\"` and closes there — so this reads the
/// boundary the WRITER marked, and returns the tail so the field after
/// it is found past that boundary rather than inside it.
fn quoted_field<'a>(line: &'a str, field: &str) -> (&'a str, &'a str) {
    let after = line
        .split_once(field)
        .unwrap_or_else(|| panic!("the line must carry a {field} field: {line}"))
        .1;
    let inner = after
        .strip_prefix('"')
        .unwrap_or_else(|| panic!("the {field} field must open with a quote: {line}"));
    let mut escaped = false;
    for (at, ch) in inner.char_indices() {
        match ch {
            _ if escaped => escaped = false,
            '\\' => escaped = true,
            '"' => return (&inner[..at], &inner[at + 1..]),
            _ => {}
        }
    }
    panic!("the {field} field must close its quote: {line}")
}

/// The ids an array field logged, `field` being everything up to its first
/// id.
fn logged_ids(line: &str, field: &str) -> Vec<u64> {
    logged_field(line, field, Some("]"))
        .split(", ")
        .map(|id| id.parse().unwrap_or_else(|e| panic!("{id:?}: {e}: {line}")))
        .collect()
}

/// The field KEYS a quote-honouring reader finds in `text`, in order.
///
/// This is the reader #278 is about, written out: a field is a `key=` at
/// a token boundary; its value is either a `Debug`-quoted string, ended
/// by the first `"` outside an escape, or a bare run up to the next
/// space. A client value that keeps its own quotes contributes no key
/// here. One that LOSES its closing quote runs on to the opening quote
/// of the next client field, swallows the server's key in between and
/// hands back a key the client wrote — which is the whole defect, and
/// what a run-length assertion alone cannot see.
///
/// Fed the text after the target, so the timestamp and level are gone;
/// a token carrying no `=` (the message's own words) is skipped.
fn logfmt_keys(text: &str) -> Vec<&str> {
    let mut keys = Vec::new();
    let mut rest = text;
    loop {
        rest = rest.trim_start_matches(' ');
        if rest.is_empty() {
            return keys;
        }
        let token_end = rest.find(['=', ' ']).unwrap_or(rest.len());
        if rest.as_bytes().get(token_end) != Some(&b'=') {
            rest = &rest[token_end..];
            continue;
        }
        keys.push(&rest[..token_end]);
        let value = &rest[token_end + 1..];
        rest = match value.strip_prefix('"') {
            Some(inner) => {
                let mut escaped = false;
                let mut closed = None;
                for (at, ch) in inner.char_indices() {
                    match ch {
                        _ if escaped => escaped = false,
                        '\\' => escaped = true,
                        '"' => {
                            closed = Some(at);
                            break;
                        }
                        _ => {}
                    }
                }
                // An unclosed value swallows the rest of the line, which
                // is exactly what the reader would do.
                closed.map_or("", |at| &inner[at + 1..])
            }
            None => &value[value.find(' ').unwrap_or(value.len())..],
        };
    }
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
    /// text begins: `query="` for a `?Capped` field (#278),
    /// `resolution=Some("` for an `?Option<Capped>` one, and a bare
    /// `client_requested=` for the one row rmcp writes itself. Everything
    /// it carries past the `=` is [`decoration`], and the trailing quote
    /// is also what tells the two REGIMES apart: a needle that opens a
    /// quote is a field `Capped` bounds and closes, one that does not is
    /// a field only the sink bounds.
    field: &'static str,
}

/// The characters a field's own rendering spends before the client's
/// text starts: one for the opening quote every client string of ours
/// carries (#278), six for `Some("`, none for the field rmcp writes raw.
///
/// Since #260 the sink's budget covers the RENDERED value — it sees a
/// stream of characters and cannot know which of them the client wrote —
/// so decoration and value are spent out of one 1024. What changed with
/// #278 is who spends first: `Capped` bounds its own value at
/// [`QUOTED_CAP`] and writes both quotes, so decoration plus value plus
/// the closing delimiter comes to at most the cap and the sink cuts
/// nothing. This count is what the row checks that arithmetic with.
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
            field: "query=\"",
        },
        Site {
            tool: Some("bugs_quicksearch"),
            arguments: json!({ "query": "kernel", "status": probe }),
            policy: None,
            needle: "tool: bugs_quicksearch",
            field: "status=\"",
        },
        Site {
            tool: Some("bugs_quicksearch"),
            arguments: json!({ "query": "kernel", "include_fields": probe }),
            policy: None,
            needle: "tool: bugs_quicksearch",
            field: "include_fields=\"",
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
            field: "product=\"",
        },
        Site {
            tool: Some("create_bug"),
            arguments: json!({
                "product": "openSUSE", "component": probe,
                "summary": "s", "version": "v"
            }),
            policy: None,
            needle: "tool: create_bug",
            field: "component=\"",
        },
        Site {
            tool: Some("create_bug"),
            arguments: json!({
                "product": probe, "component": "kernel",
                "summary": "s", "version": "v"
            }),
            policy: Some(DENY_ALL),
            needle: "guard denied bug creation",
            field: "product=\"",
        },
        Site {
            tool: Some("add_attachment"),
            arguments: json!({
                "bug_id": 1, "data": "", "file_name": probe,
                "summary": "s", "content_type": "text/plain"
            }),
            policy: None,
            needle: "tool: add_attachment",
            field: "file_name=\"",
        },
        Site {
            tool: Some("update_bug_status"),
            arguments: json!({ "bug_id": 1, "status": probe }),
            policy: None,
            needle: "tool: update_bug_status",
            field: "status=\"",
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
            field: "assignee=\"",
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
            field: "cc_email=\"",
        },
        Site {
            // rmcp logs the same message text with the version raw (#260),
            // so this row selects on the target.
            tool: None,
            arguments: json!({}),
            policy: None,
            needle: "bugwarden::server: client requested unsupported",
            field: "client_requested=\"",
        },
        Site {
            // And rmcp's own copy of it, one line later: the fourth row
            // of #260's table, and a field no `Capped` of ours can
            // reach — 100 179 characters on this branch's parent for a
            // 100 000-character `protocolVersion`.
            tool: None,
            arguments: json!({}),
            policy: None,
            needle: "rmcp::service::server: client requested a protocol version unavailable over initialize",
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
        // EXACTLY the bound, not "at most": an off-by-one cut is a second
        // rule that has to be remembered next to the audit record's, which
        // is the thing #191 and this share a definition to prevent. The
        // run stops where the budget ran out, so counting it also proves
        // the field ended there rather than running on.
        let run = value.chars().take_while(|c| *c == PROBE).count();
        let tail = value
            .char_indices()
            .nth(run)
            .map_or("", |(at, _)| &value[at..]);
        let Some(opened) = site.field.strip_suffix('"') else {
            // rmcp's own field: bare, and the sink is its only bound.
            assert_eq!(
                run + decoration(site.field),
                CAP,
                "{} on {:?} must reach stderr as exactly {CAP} rendered chars: {line}",
                site.field,
                site.needle
            );
            continue;
        };
        // Ours (#278). `Capped` bounds the value itself and writes both
        // quotes, so the run is ITS budget, the closing delimiter is on
        // the line, and the whole field still fits the sink's cap — which
        // is what keeps a cut from opening the value.
        assert_eq!(
            run, QUOTED_CAP,
            "{} on {:?} must carry exactly {QUOTED_CAP} of the client's \
             own characters: {line}",
            site.field, site.needle
        );
        let closer = if opened.ends_with("Some(") {
            "\")"
        } else {
            "\""
        };
        assert!(
            tail.starts_with(closer),
            "and must close with {closer:?}, or a reader runs on into the \
             next field: {line}"
        );
        assert!(
            decoration(site.field) + run + closer.chars().count() <= CAP,
            "and the whole field must fit the sink's {CAP}, or the sink \
             cuts the closing delimiter off again: {line}"
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
/// argument included. `transport/async_rw.rs:335` logs the whole
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
/// strings this workspace logged were `%`, `query` among them. A `query` of
/// ESC `[2J` clears the operator's terminal and BEL rings it; exactly one
/// raw ESC and one raw BEL reached stderr on the unpatched tree.
///
/// The SPELLING moved with #278 and the guarantee did not: `query` is
/// `Debug`-formatted now, so `str`'s own `Debug` writes `\u{1b}` and
/// `\u{7}` before the sink is reached, where the sink would have written
/// `\x1b` and `\x07`. Neither byte reaches stderr raw either way, which
/// is the whole of what this row claims.
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
    assert_control_bytes_escaped(&log, "\\u{1b}", "\\u{7}");
    assert!(
        log.contains(r#"query="a\u{1b}[2Jb\u{7}c""#),
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
    assert_control_bytes_escaped(&log, "\\x1b", "\\x07");
    let line = find_line(&log, "response error");
    assert!(
        line.contains("id=id\\x1b[2J\\x07"),
        "rmcp's `%id` is the field with no `Debug` to fall back on: {}",
        excerpt(line)
    );
}

/// A LINE is the unit an operator greps and a log shipper ships, so a
/// client field carrying LF used to end the server's line and open one
/// of its own (#275): the escape set copied from `EscapeGuard` in #266
/// left LF, CR and TAB raw. Measured on this branch's parent, a `query`
/// of `a`CR`b`TAB`c`LF plus a hand-written timestamp put a second,
/// well-formed `INFO bugwarden::server:` line on stderr.
///
/// U+2028 rides along in the same value. It ends no line HERE — stderr
/// and this test both split on LF alone — so the count below is blind
/// to it and only the field assertion binds; that is enough to keep the
/// arm honest end to end, and the unit table is where the character is
/// really pinned.
///
/// Two assertions on the forgery, because either alone can be met by
/// accident: the forged text must sit ON the tool line and on no other,
/// and the count of tracing lines must equal the count the SAME session
/// produces with those characters replaced by spaces. The second is the
/// one the issue asks for by name, and the pair costs one extra child.
///
/// The escaped spellings below are `str`'s own `Debug` since #278, and
/// are the same four characters for character as the sink's — LF, CR and
/// TAB are where the two sets agree by construction, and U+2028 is
/// `\u{2028}` either way. Only the surrounding quotes are new, which is
/// why the value is read with [`quoted_field`].
#[tokio::test]
async fn a_client_field_can_neither_end_a_stderr_line_nor_open_one() {
    let forging = format!("a{CR}b{TAB}c{LS}d{LF}{FORGED_LINE}");
    // Same session, same query length, same needle: only the characters
    // under test differ, so a difference in the line count is theirs.
    let plain = forging.replace([CR, TAB, LF, LS], " ");

    let mut runs = Vec::new();
    for query in [plain, forging] {
        runs.push(
            stderr_through(
                &[
                    initialize("binary-tracing-caps-test"),
                    initialized(),
                    tools_call(json!(2), "bugs_quicksearch", json!({ "query": query })),
                ],
                None,
                "tool: bugs_quicksearch",
            )
            .await,
        );
    }
    let (plain_log, forged_log) = (&runs[0], &runs[1]);

    // The forgery first, because it is what the issue is: the text after
    // the client's LF must not stand as a line of its own.
    let forged_lines: Vec<&str> = forged_log
        .lines()
        .filter(|line| line.contains("FORGED LINE"))
        .collect();
    assert_eq!(
        forged_lines.len(),
        1,
        "the forged text may appear on exactly one line: {}",
        excerpt(forged_log)
    );
    assert!(
        forged_lines[0].contains("query="),
        "and that line must be the tool's own, not a line of the \
         client's making: {}",
        excerpt(forged_log)
    );
    assert_eq!(
        tracing_lines(forged_log).count(),
        tracing_lines(plain_log).count(),
        "a client's LF may not add a line to stderr:\nforged: {}\nplain: {}",
        excerpt(forged_log),
        excerpt(plain_log)
    );

    assert_eq!(
        quoted_field(find_line(forged_log, "tool: bugs_quicksearch"), "query=").0,
        format!("a\\rb\\tc\\u{{2028}}d\\n{FORGED_LINE}"),
        "and the whole of it stays inside one field, escaped: {}",
        excerpt(forged_log)
    );
    assert_cr_and_tab_escaped(forged_log);
}

/// A field's VALUE could be shaped like a later ` key=value` pair, and a
/// `%` field gave no sign of where it stopped (#278): a `query` of
/// `evil status=HACKED limit=999` rendered as
/// `query=evil status=HACKED limit=999 status=ALL …`, and every reader
/// that splits a line into fields — a shipper's extractor, a
/// `grep 'status=HACKED'`, [`logged_field`] itself — read a `status` the
/// client chose. The cap bounds a value's LENGTH and #275 keeps it on one
/// line; neither says where it ends.
///
/// Every client string is `Debug`-formatted now, so the value is quoted
/// and its boundary is the writer's. Three assertions, because each
/// alone can be met by accident: the whole of the client's text reads
/// back as ONE field, the `status` past that field's closing quote is
/// the server's own `ALL`, and the line's KEYS are the six the server
/// named. The second probe carries a `"` and a trailing `\` so the
/// rendered value ends in an escaped backslash immediately before its
/// closing quote — the case a reader that only looks at the preceding
/// character gets wrong, and the one no other row here reaches.
#[tokio::test]
async fn a_client_field_cannot_forge_a_later_field_on_its_own_line() {
    for (query, expected) in [
        (FORGING_PAIR, FORGING_PAIR.to_string()),
        // Rendered, the escapes are the client's characters doubled;
        // reading them back is how the closing quote is shown to be the
        // writer's rather than one the value could move.
        (FORGING_ESCAPES, r#"evil\" status=HACKED \\"#.to_string()),
    ] {
        let line = tool_call_log_line(
            "bugs_quicksearch",
            json!({ "query": query }),
            "tool: bugs_quicksearch",
        )
        .await;
        let (logged, rest) = quoted_field(&line, "query=");
        assert_eq!(
            logged, expected,
            "the whole of the client's text must stay inside one field: {line}"
        );
        assert_eq!(
            quoted_field(rest, " status=").0,
            "ALL",
            "and the `status` past its closing quote must be the server's own: {line}"
        );
        assert_eq!(
            logfmt_keys(after_target(&line, "bugwarden::server")),
            [
                "query",
                "status",
                "include_fields",
                "limit",
                "offset",
                "group_by"
            ],
            "and the line's fields are the server's own, in its own order: {line}"
        );
    }
}

/// Bugzilla's error `message` is client-influenced and was logged bare
/// (`error=%e`), so a version of `1.0 status=HACKED limit=999` forged
/// logfmt keys on the `create_bug: upstream refused` line (#288).
///
/// A `%e` site fails here: the sink caps and escapes the text but cannot
/// mark where a `%` value ends, so [`quoted_field`] would not find an
/// opening quote and [`logfmt_keys`] would see `status` and `limit`.
#[tokio::test]
async fn an_upstream_error_cannot_forge_a_later_field_on_its_own_line() {
    let mock = MockServer::start().await;
    let message = concat!(
        "There is no version named '1.0 status=HACKED limit=999' ",
        "in the 'openSUSE' product."
    );
    Mock::given(method("POST"))
        .and(path("/rest/bug"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": true,
            "message": message,
        })))
        .expect(1)
        .mount(&mock)
        .await;

    let line = log_line_at(
        &mock.uri(),
        SUPPORTED_VERSION,
        None,
        Some((
            "create_bug",
            json!({
                "product": "openSUSE",
                "component": "core",
                "summary": "crash on start",
                "version": "1.0 status=HACKED limit=999",
            }),
        )),
        "create_bug: upstream refused",
    )
    .await;

    let display = format!("bugzilla error (HTTP 400): {message}");
    let (logged, _rest) = quoted_field(&line, "error=");
    assert_eq!(
        logged, display,
        "the whole Display including the forged pair must stay inside one field: {line}"
    );
    let keys = logfmt_keys(after_target(&line, "bugwarden::server"));
    assert!(
        !keys.contains(&"status") && !keys.contains(&"limit"),
        "status/limit must not be keys of this line: {keys:?} in {line}"
    );
    assert!(
        logged.contains("status=HACKED"),
        "the HACKED text lives inside the quoted value: {logged:?}"
    );
}

/// A quote marks a boundary only if it SURVIVES, and until `Capped`
/// budgeted its own rendering the sink cut it off (#278). The sink
/// bounds a field at 1024 RENDERED characters and cannot see that a
/// value is open, so a `query` just over that bound reached stderr as
/// `query="` plus its text and no terminator; a quote-honouring reader
/// then ran on to the next unescaped `"` — the OPENING quote of the next
/// client field — swallowed the server's own field between the two, and
/// came back out reading the client's text as unquoted line content.
///
/// Two probes, because the budget is spent in rendered characters and a
/// client picks how many each of its own costs. Plain text spends one
/// apiece, so 1023 characters used to overflow by exactly the closing
/// quote while staying inside `Capped`'s own 1024-character slice — the
/// narrowest window there is, and the one a value-length bound alone
/// misses. U+2028 spends eight, so 128 of them overflowed where 127 did
/// not, and the row also shows the last escape dropped whole rather than
/// half-written.
///
/// The `status` beside the first probe is the client's, and carries a
/// `key=value` of its own: with the `query` cut open, the server's
/// `status` key vanished from a [`logfmt_keys`] scan and an `admin` key
/// the client wrote took its place. That substitution is what the run
/// length cannot see and this row is for.
#[tokio::test]
async fn a_cut_client_field_still_closes_its_own_quote() {
    let line = tool_call_log_line(
        "bugs_quicksearch",
        json!({ "query": "a".repeat(QUOTED_CAP + 7), "status": "x admin=true" }),
        "tool: bugs_quicksearch",
    )
    .await;
    let body = after_target(&line, "bugwarden::server");
    let (query, rest) = quoted_field(body, "query=");
    assert_eq!(
        query,
        "a".repeat(QUOTED_CAP),
        "a cut value keeps its closing quote and loses characters instead: {line}"
    );
    assert_eq!(
        quoted_field(rest, " status=").0,
        "x admin=true",
        "the next client field is still its own field: {line}"
    );
    let keys = logfmt_keys(body);
    assert!(
        keys.contains(&"status") && !keys.contains(&"admin"),
        "and the line's keys are the server's, not the client's: {keys:?} in {line}"
    );

    // Eight rendered characters apiece: 127 fill the budget exactly, and
    // the 128th is dropped whole rather than written as a half escape.
    let line = tool_call_log_line(
        "bugs_quicksearch",
        json!({ "query": LS.to_string().repeat(QUOTED_CAP / 8 + 1) }),
        "tool: bugs_quicksearch",
    )
    .await;
    assert_eq!(
        quoted_field(after_target(&line, "bugwarden::server"), "query=").0,
        "\\u{2028}".repeat(QUOTED_CAP / 8),
        "an escaping value is bounded by what it RENDERS, and no escape is \
         cut in half: {line}"
    );
}

/// The same forgery through rmcp's `message`, which no field name of this
/// workspace fronts: `transport/async_rw.rs:335` echoes an unparsable
/// line whole at debug, and only a sink that escapes `message` bounds it.
///
/// CR and not LF, because rmcp's reader is line-delimited: an LF ends the
/// frame before rmcp sees it, so CR is the byte a client can smuggle
/// INSIDE one. It reached stderr raw on this branch's parent, where a
/// terminal reads it as a return to column zero and a good many log
/// shippers read it as a line of its own.
#[tokio::test]
async fn an_unparsable_line_reaches_the_message_field_escaped() {
    let garbage = format!("garbage{CR}{TAB}{FORGED_LINE}");
    let log = stderr_through(
        &[
            initialize("binary-tracing-caps-test"),
            initialized(),
            // Not JSON, and not a prefix of any: rmcp echoes it whole.
            garbage,
            tools_call(json!(2), "bugs_quicksearch", json!({ "query": "kernel" })),
        ],
        Some("debug"),
        "tool: bugs_quicksearch",
    )
    .await;

    let parse_failure = find_line(&log, "Failed to parse message");
    assert!(
        parse_failure.contains(&format!("garbage\\r\\t{FORGED_LINE}")),
        "rmcp's whole unparsable line rides `message`, and its control \
         bytes must be escaped there too: {}",
        excerpt(parse_failure)
    );
    assert_eq!(
        log.lines()
            .filter(|line| line.contains("FORGED LINE"))
            .count(),
        1,
        "and the forgery stays on that one line: {}",
        excerpt(&log)
    );
    assert_cr_and_tab_escaped(&log);
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
