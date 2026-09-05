//! The process's panic hook: one tracing event per panic, and never the
//! payload (issue #270).
//!
//! std's default hook writes `thread 'name' (tid) panicked at
//! file:line:col:` followed by THE PAYLOAD to fd 2, at panic time, before
//! any unwinding. Over the stdio transport fd 2 is the pipe the MCP host
//! handed this process, so that payload goes to the PEER rather than to an
//! operator — whatever the panicking code happened to format into it. No
//! production panic site formats client text or the API key into a payload
//! today (the #253 security review audited every `expect`, `unwrap`,
//! `panic!` and index site in both crates, and every std payload one of
//! them could produce is integers-only), so this hook closes the channel
//! before the first `expect(&format!(..))` opens it silently, not to
//! repair a leak that already exists.
//!
//! What it emits is one fixed text plus two server-authored fields:
//! `location`, the compile-time `file:line:col` std records at the panic
//! site, and `thread`, the name the code that spawned the thread chose.
//! What it never touches is the payload — not its text, not its type
//! name, not its length, the same rule `server::handler_panicked` follows
//! for the reply (I12). The backtrace goes with it: `RUST_BACKTRACE` is
//! read by the DEFAULT hook, which no longer runs, so `location` is the
//! whole of what makes a line actionable. It can name a dependency's
//! registry path (`…/registry/src/…/rmcp-*/src/…`) as readily as one of
//! this workspace's files, which is exactly what an operator forwarding
//! the line needs to see.
//!
//! **Visibility is now the operator's to set.** The event carries this
//! module as its target and goes through the same `EnvFilter` as every
//! other diagnostic, so a panic is reported when the filter admits it and
//! not otherwise: at the default `info` and at `warn` every panic is on
//! stderr, at `error` only the process's first, at `off` none. That is the
//! design and not a regression — an unconditional write to fd 2 was the
//! defect, because over stdio that descriptor is the peer's. An operator
//! who wants a quiet log and every panic anyway raises this one target:
//! `RUST_LOG=error,bugwarden::panic_hook=warn`. `tests/panic_hook.rs`
//! pins all three behaviours on a real child process's stderr.
//!
//! **The level rule**, stated for the whole server in DESIGN.md's
//! panicking-handler bullet: ERROR is for what an operator must act on and
//! a client cannot repeat at will; a per-request failure a client can
//! cause on demand is WARN — the level six of `server.rs`'s eight
//! upstream-failure lines already use (`download_attachment`'s two are
//! `debug!`), and the level `dispatch`'s recovery line became. A panic is
//! a server bug an operator must learn about — once. So the first panic of
//! the process's life is ERROR and every later one is WARN, same text and
//! same fields either way: the second and every later panic is the same
//! bug or a repeat by the same client. A deployment that pages on ERROR is
//! therefore paged once for a panic a client can trigger at will, instead
//! of once per request; what it trades away is that under a filter at
//! `error` the later panics are not reported at all, which is what the
//! per-target directive above is for.
//!
//! **Bounds.** A panic raised while a panic hook runs is
//! `panic_count::MustAbort::PanicInHook` in std's `panic_with_hook`, and
//! std aborts the process there without unwinding, so no `catch_unwind`
//! anywhere can contain it. This module's own body is written so that it
//! cannot be the one that panics — no `expect`, no indexing and no
//! `Capped` (nothing this line carries is client text anyway) — but that
//! is a statement about the body, NOT a guarantee about the event:
//! emitting it runs the whole subscriber stack (`EnvFilter`, the registry,
//! the fmt layer with `CappedFields`, and the OTLP diagnostics layer when
//! export is on). Four outcomes are worth stating precisely rather than
//! assuming:
//!
//! - **The ordinary case: the event is delivered.** It goes back into the
//!   same subscriber that was running when the panic was raised, with
//!   nothing between them: `main` installs its subscriber as the GLOBAL
//!   default, and tracing-core 0.1's `Event::dispatch` →
//!   `dispatcher::get_default` takes its `SCOPED_COUNT == 0` fast path
//!   straight to that dispatch. The `State::enter`/`can_enter` guard that
//!   would hand a re-entrant event to `Dispatch::none()` only arms once a
//!   SCOPED default exists (`State::set_default` is what increments
//!   `SCOPED_COUNT`), which `set_global_default` never does. What makes
//!   that survivable is tracing-subscriber 0.3's fmt layer: `on_event`
//!   takes its thread-local buffer with `try_borrow_mut` and falls back to
//!   a fresh `String` when it is already borrowed, and it discards writer
//!   errors (its `log_internal_errors` defaults to false). So a panic
//!   raised inside the subscriber's own EVENT path — formatting some other
//!   line's field, say — re-enters it with THIS event, whose fields are a
//!   `&Location` and a `&str` and cannot fail the way a client value can.
//! - **A panic on the hook's own event path aborts.** Whatever raises it —
//!   the fmt layer, `CappedFields`, the OTLP layer, the writer — is
//!   `PanicInHook`, and what std prints before aborting is the NESTED
//!   panic's location and payload, not the original's. Remote today,
//!   because the two production formatters on that path have no panic site
//!   and this event's own fields are infallible `Display`s; a bound, not a
//!   promise.
//! - **A panic raised while a span's extensions are write-locked blocks.**
//!   The fmt layer holds `span.extensions_mut()` across `format_fields` in
//!   `on_new_span` and `on_record`; the hook's event then reads
//!   `span.extensions()` for every span in scope, and those are the two
//!   halves of one `std::sync::RwLock` (tracing-subscriber's `sync` module
//!   selects std's, `parking_lot` being absent from this lock file) taken
//!   twice on one thread, before the unwind that would release the write
//!   guard. Measured: the thread hangs — neither a line nor an abort.
//!   Remote today because neither crate here creates a span or calls
//!   `Span::record`, and rmcp calls neither either; the span that IS in
//!   scope for a handler's lines is rmcp's `serve_inner`, whose extensions
//!   are write-held only while it is being created.
//! - **`std::thread::current`.** It panics after the calling thread's
//!   local data has been destroyed; std's own default hook dodges that
//!   with a crate-private `with_current_name` that has no stable
//!   equivalent. The residual case is a panic in a `thread_local!`
//!   destructor that happens to run after std's own thread handle was
//!   dropped, and it aborts. Even then the payload does not reach fd 2:
//!   the nested panic is std's own, and its message is a fixed string.
//!
//! Panics before `install()` — CLI parsing, OTLP environment resolution —
//! still go to the default hook, which prints them.

use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};

/// The one text the hook writes, whatever panicked and at whichever
/// level. It names nothing about the panic beyond that there was one; the
/// fields carry the rest.
const PANIC_LINE: &str = "a thread panicked; the payload is not logged";

/// What `thread` carries for a thread nobody named. std's default hook
/// spells the same case the same way.
const UNNAMED: &str = "<unnamed>";

/// What `location` carries when std supplied none. Unreachable as std is
/// written today — `PanicHookInfo::location` is documented as always
/// `Some` in the current implementation — and an `Option` in the API, so
/// the hook answers it rather than unwrapping it.
const UNKNOWN_LOCATION: &str = "<unknown>";

/// Whether this process has already logged a panic; see the level rule in
/// the module docs. `Relaxed` because nothing is published alongside it:
/// the flag orders no other memory, and two panics racing for the first
/// ERROR both produce a line either way.
static PANICKED: AtomicBool = AtomicBool::new(false);

/// The `location` field's value: `file:line:col`, or [`UNKNOWN_LOCATION`].
///
/// A `Display` newtype rather than a `String` so the hook allocates
/// nothing for it — and because `Option<&Location>` has no `Display` of
/// its own to hand `%` in the macro.
struct Site<'a>(Option<&'a std::panic::Location<'a>>);

impl fmt::Display for Site<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            // `Location`'s own `Display` is exactly `file:line:col`.
            Some(site) => fmt::Display::fmt(site, f),
            None => f.write_str(UNKNOWN_LOCATION),
        }
    }
}

/// Replace std's default panic hook with the one this module documents.
///
/// Call it once, early, and before anything is served: `main` does so
/// immediately after `registry.init()`, on both the OTLP and the plain
/// branch. The dispatcher is resolved at PANIC time and not at
/// installation time, so this order is not what makes the event reach a
/// subscriber — installing first would route every later panic just as
/// well. What the order decides is the window between the two calls: with
/// the subscriber first, a panic in that window still reaches an operator
/// through std's default hook, whereas a hook installed first would route
/// it into a subscriber that does not exist yet and it would be reported
/// nowhere.
///
/// `main` and the child process `tests/panic_hook.rs` spawns are the only
/// callers. The hook is process-wide, so a test binary that installed it
/// would silence the panic message of every OTHER test in that binary,
/// which has no subscriber to route it to.
///
/// Replacing the default hook is the point, not a side effect: what closes
/// the peer-visible channel is that std no longer writes the payload to
/// fd 2 at panic time. Calling it twice replaces the hook with an
/// equivalent one and keeps the process's first-panic flag, so the
/// ERROR-then-WARN rule is about the PROCESS's panics, not about the
/// installations.
pub fn install() {
    std::panic::set_hook(Box::new(|info| {
        let site = Site(info.location());
        // Held so `name()` can borrow from it; `current()` is the only
        // stable way to reach the name at all.
        let current = std::thread::current();
        let thread = current.name().unwrap_or(UNNAMED);
        if PANICKED.swap(true, Ordering::Relaxed) {
            tracing::warn!(location = %site, thread = %thread, "{PANIC_LINE}");
        } else {
            tracing::error!(location = %site, thread = %thread, "{PANIC_LINE}");
        }
    }));
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `location` renders what std's own `Location` renders, so an
    /// operator's grep for a `file:line:col` matches the field.
    #[test]
    fn a_site_renders_file_line_and_column() {
        let location = std::panic::Location::caller();
        let rendered = Site(Some(location)).to_string();
        assert_eq!(rendered, location.to_string());
        assert!(
            rendered.contains("panic_hook.rs:"),
            "a caller location names its own file: {rendered}"
        );
        assert_eq!(
            rendered.split(':').count(),
            3,
            "file, line and column: {rendered}"
        );
    }

    /// The absent-location arm is defensive, and its text must still be a
    /// value rather than an empty field.
    #[test]
    fn a_missing_site_renders_a_placeholder() {
        assert_eq!(Site(None).to_string(), UNKNOWN_LOCATION);
    }
}
