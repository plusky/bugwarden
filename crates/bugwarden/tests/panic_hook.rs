//! What the process's panic hook puts on a real fd 2, and what it never
//! puts there (#270).
//!
//! The claim under test is about a FILE DESCRIPTOR: over stdio, fd 2 is the
//! pipe the MCP host handed the server, so "the payload does not reach the
//! peer" is only proven by reading the descriptor a panic would have been
//! written to. An in-process capture cannot prove it — a hook that chained
//! std's previous hook instead of replacing it would put both markers on
//! the real stderr and leave an in-memory buffer looking spotless.
//!
//! So this file re-executes itself: the ONE test function is the parent
//! when [`CHILD_VAR`] is unset and the child when it is set. The child
//! builds `main`'s subscriber shape, installs the hook, panics two threads
//! and exits; the parent spawns it with its stdout and stderr on pipes and
//! asserts over the bytes that actually arrived. That also keeps the hook
//! out of this binary's own process, so the parent's assertions still fail
//! the way libtest reports every other failure — under std's own hook, with
//! a file, a line and a message.
//!
//! Three child runs, because panic reporting now follows the operator's
//! `RUST_LOG` like every other diagnostic: with no filter set (main's
//! `info` fallback) both panics are reported, at `error` only the first,
//! and `error,bugwarden::panic_hook=warn` is the directive that keeps every
//! panic visible under an otherwise quiet global level.

use std::process::{ExitStatus, Stdio};
use std::time::Duration;

use bugwarden::tracing_fields::CappedFields;
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;
use tracing_subscriber::EnvFilter;

/// Set by the parent on the child it spawns; its presence is the whole of
/// what tells the two roles apart. Named for this file so an ambient value
/// is implausible rather than merely unlikely.
const CHILD_VAR: &str = "BUGWARDEN_PANIC_HOOK_CHILD";

/// The test the parent asks the child to run, spelled out because
/// `--exact` needs it as a string. A rename that missed this line makes
/// the child run zero tests, which [`run_child`] refuses.
const CHILD_TEST: &str = "the_hook_reports_every_panic_on_fd_2_and_never_the_payload";

/// The hook's fixed text, spelled out here rather than imported so that
/// rewording the production constant has to be a deliberate edit on both
/// sides: this string is what an operator's alerting greps for.
const PANIC_LINE: &str = "a thread panicked; the payload is not logged";

/// The event target, which is the hook's own module path. Pinned because
/// it is what makes the directive in [`VISIBLE_FILTER`] possible: an
/// operator running at `error` globally can raise this one target back to
/// `warn` only while the target keeps this name.
const HOOK_TARGET: &str = "bugwarden::panic_hook";

/// The name given to the first probe thread, to pin that `thread` carries
/// the spawner's choice and not something derived from the panic.
const NAMED_THREAD: &str = "bw-panic-probe";

/// What the hook writes for a thread nobody named.
const UNNAMED_THREAD: &str = "<unnamed>";

/// The payloads. Distinct, so the second assertion cannot pass on the
/// first panic's residue, and shaped like the secret the hook exists to
/// keep out of the peer's pipe.
const FIRST_MARKER: &str = "SECRET-4f21ab-first-payload";
const SECOND_MARKER: &str = "SECRET-9c07de-second-payload";

/// A filter that hides the second panic: the hook logs it at WARN.
const QUIET_FILTER: &str = "error";

/// The directive an operator uses to keep every panic reported while the
/// rest of the log stays at ERROR. The reason the hook has a target of its
/// own.
const VISIBLE_FILTER: &str = "error,bugwarden::panic_hook=warn";

/// A child that has not exited by now is a defect in the child, not a slow
/// machine: it starts a subscriber, panics twice and returns.
const CHILD_BUDGET: Duration = Duration::from_secs(20);

/// What one child run produced.
struct Run {
    stdout: String,
    stderr: String,
    status: ExitStatus,
}

impl Run {
    /// The child's own panic lines, in the order it wrote them.
    fn panic_lines(&self) -> Vec<&str> {
        self.stderr
            .lines()
            .filter(|line| line.contains(PANIC_LINE))
            .collect()
    }

    /// Neither payload anywhere the child wrote, on EITHER descriptor.
    /// stdout as well as stderr, because "the payload is not logged" is a
    /// claim about the process and not about one pipe.
    fn assert_no_payload(&self) {
        for marker in [FIRST_MARKER, SECOND_MARKER] {
            assert!(
                !self.stderr.contains(marker),
                "a payload reached the child's stderr: {}",
                excerpt(&self.stderr)
            );
            assert!(
                !self.stdout.contains(marker),
                "a payload reached the child's stdout: {}",
                excerpt(&self.stdout)
            );
        }
    }
}

/// As much of a stream as a failure message should carry: a child that
/// went wrong can be holding a great deal of it.
fn excerpt(stream: &str) -> String {
    stream.chars().take(2_000).collect()
}

/// The value of `name=` on `line`, up to the next space or the line's end.
///
/// Panics rather than returning an `Option`: a missing field is the defect
/// this file exists to catch, and it must fail with the line that lacks it.
#[track_caller]
fn field<'a>(line: &'a str, name: &str) -> &'a str {
    let value = line
        .split_once(&format!("{name}="))
        .unwrap_or_else(|| panic!("the line must carry a {name} field: {line}"))
        .1;
    value.split_whitespace().next().unwrap_or(value)
}

/// Everything the hook promises about one line that does not depend on
/// which panic produced it.
///
/// `level` is matched with the spaces the `Full` format puts around it, so
/// `WARN` cannot be satisfied by a `WARNING` inside someone's message and
/// the level of the line is read rather than its text.
#[track_caller]
fn assert_hook_line(line: &str, level: &str, thread: &str) {
    assert!(
        line.contains(&format!(" {level} ")),
        "the line must be at {level}: {line}"
    );
    assert!(
        line.contains(&format!("{HOOK_TARGET}:")),
        "the line must carry the hook's own target, which is what a \
         per-target directive addresses: {line}"
    );
    assert!(
        field(line, "location").contains("tests/panic_hook.rs:"),
        "location must name the PANIC's site, not the hook's: {line}"
    );
    assert_eq!(
        field(line, "thread"),
        thread,
        "thread must carry the spawner's choice: {line}"
    );
}

/// Re-run this file's one test in a fresh process, with `rust_log` as its
/// `RUST_LOG` — or with none at all, to exercise main's `info` fallback.
///
/// `--nocapture` so the child's libtest does not stand between the
/// subscriber and the descriptor whose contents are the claim.
async fn run_child(rust_log: Option<&str>) -> Run {
    let exe = std::env::current_exe().expect("a test binary knows its own path");
    let mut cmd = tokio::process::Command::new(exe);
    cmd.args(["--exact", CHILD_TEST, "--nocapture"])
        .env(CHILD_VAR, "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    match rust_log {
        Some(filter) => cmd.env("RUST_LOG", filter),
        None => cmd.env_remove("RUST_LOG"),
    };
    let output = tokio::time::timeout(CHILD_BUDGET, cmd.output())
        .await
        .expect("the child must exit within its budget")
        .expect("the child must start");
    let run = Run {
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        status: output.status,
    };
    assert!(
        run.stdout.contains("1 passed"),
        "the child must have run exactly {CHILD_TEST}: {} {}",
        excerpt(&run.stdout),
        excerpt(&run.stderr)
    );
    run
}

/// The child half: `main`'s subscriber, the hook, two panics, and no
/// assertion until the hook is off again.
fn child() {
    // main.rs's stack minus the OTLP layer: the same filter source and
    // fallback, the same field formatter (so the cap and the escaping this
    // line passes through are the production ones), the same ANSI setting
    // — and the same writer, the process's real stderr, which is the whole
    // point of running in a process of our own.
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(
            tracing_subscriber::fmt::layer()
                .fmt_fields(CappedFields)
                .with_writer(std::io::stderr)
                .with_ansi(false),
        )
        .init();
    // Kept so the assertions below run under a hook that PRINTS: the
    // production hook routes a panic into tracing, which would swallow the
    // file, line and message libtest reports a failing assertion with.
    let previous = std::panic::take_hook();
    bugwarden::panic_hook::install();

    // First panic of the process: on a thread whose name the spawner chose.
    let payload = FIRST_MARKER.to_string();
    let first = std::thread::Builder::new()
        .name(NAMED_THREAD.to_owned())
        .spawn(move || panic!("{payload}"))
        .expect("the probe thread must spawn")
        .join();
    // Second: `thread::spawn` names nothing, so the fallback is pinned too.
    let payload = SECOND_MARKER.to_string();
    let second = std::thread::spawn(move || panic!("{payload}")).join();

    std::panic::set_hook(previous);
    assert!(first.is_err(), "the first probe thread must have panicked");
    assert!(
        second.is_err(),
        "the second probe thread must have panicked"
    );
}

#[tokio::test]
async fn the_hook_reports_every_panic_on_fd_2_and_never_the_payload() {
    if std::env::var_os(CHILD_VAR).is_some() {
        return child();
    }

    // No filter set: main falls back to `info`, so both panics are
    // reported — the first at ERROR, every later one at WARN.
    let run = run_child(None).await;
    let lines = run.panic_lines();
    assert_eq!(
        lines.len(),
        2,
        "two panics, two lines — one event each: {}",
        excerpt(&run.stderr)
    );
    assert_hook_line(lines[0], "ERROR", NAMED_THREAD);
    assert_hook_line(lines[1], "WARN", UNNAMED_THREAD);
    assert!(
        !lines[1].contains("ERROR"),
        "every panic after the first is a WARN: {}",
        lines[1]
    );
    assert_ne!(
        field(lines[0], "location"),
        field(lines[1], "location"),
        "each line carries its OWN panic's site: {}",
        excerpt(&run.stderr)
    );
    run.assert_no_payload();
    assert!(
        run.status.success(),
        "the child must exit cleanly once both panics are recovered: {:?}",
        run.status
    );

    // At `error` the WARN line is filtered out, so an operator sees the
    // process's first panic and nothing after it. Stated in the rustdoc
    // and in DESIGN.md, and pinned here: panic reporting obeys the filter,
    // which is what stops fd 2 from being an unconditional channel.
    let quiet = run_child(Some(QUIET_FILTER)).await;
    let lines = quiet.panic_lines();
    assert_eq!(
        lines.len(),
        1,
        "at {QUIET_FILTER} only the first panic is reported: {}",
        excerpt(&quiet.stderr)
    );
    assert_hook_line(lines[0], "ERROR", NAMED_THREAD);
    quiet.assert_no_payload();

    // The directive that buys both: a quiet global level and every panic
    // still reported. It works only because the hook's target is its own
    // module path.
    let visible = run_child(Some(VISIBLE_FILTER)).await;
    let lines = visible.panic_lines();
    assert_eq!(
        lines.len(),
        2,
        "{VISIBLE_FILTER} must restore the WARN line: {}",
        excerpt(&visible.stderr)
    );
    assert_hook_line(lines[0], "ERROR", NAMED_THREAD);
    assert_hook_line(lines[1], "WARN", UNNAMED_THREAD);
    visible.assert_no_payload();
}
