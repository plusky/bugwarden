//! Test-only capture of tracing output, for pinning what startup log lines
//! say — and, per I12, what they must never say.

use std::cell::RefCell;
use std::io::Write;
use std::sync::Once;

thread_local! {
    /// Where the calling thread's capture accumulates. `None` means this
    /// thread is not capturing, and its events are dropped on the floor.
    static CAPTURE: RefCell<Option<Vec<u8>>> = const { RefCell::new(None) };
}

/// Writer handed to the process-wide subscriber. Appends to the calling
/// thread's capture, so parallel tests cannot splice events into each other's.
struct ThreadCapture;

impl Write for ThreadCapture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        // `try_with`, not `with`: a thread may still log while its
        // thread-locals are being torn down, and that must not panic.
        let _ = CAPTURE.try_with(|slot| {
            if let Some(capture) = slot.borrow_mut().as_mut() {
                capture.extend_from_slice(buf);
            }
        });
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Install the capturing subscriber as the process-wide default, once.
///
/// It has to be a permanent global default rather than a `with_default` scoped
/// to each capture. `tracing` caches a callsite's `Interest` the first time the
/// callsite is hit, computed from the *registering* thread's default subscriber
/// — as of tracing-core 0.1.36 the std `Dispatchers::rebuilder` takes its
/// `has_just_one` fast path and simply asks `dispatcher::get_default`. Under
/// parallel tests a thread running some other test — with no subscriber of its
/// own — can win that race and cache `Interest::never()`, after which the
/// `info!` macro short-circuits without ever consulting a dispatcher and every
/// later capture of that callsite comes back empty (issue #92). Once this
/// global default is visible, every such registration resolves to it instead.
///
/// The explicit rebuild closes the gap installation itself opens: setting the
/// global default raises the global max level to TRACE while building the
/// `Dispatch`, but only publishes the subscriber afterwards, and it never
/// rebuilds. A callsite first hit in between passes `level_enabled!` and still
/// resolves to no subscriber, so it caches `never` with nothing left to correct
/// it; the rebuild recomputes everything registered while the default was
/// invisible.
///
/// Consequence worth knowing: from the first capture onwards the process-wide
/// max level stays TRACE, so every tracing macro in every later test evaluates
/// its fields and is formatted before `ThreadCapture` discards it, where before
/// it short-circuited. Field side effects are live across the whole binary.
fn install() {
    static INSTALLED: Once = Once::new();
    INSTALLED.call_once(|| {
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .with_writer(|| ThreadCapture)
            .finish();
        tracing::subscriber::set_global_default(subscriber)
            .expect("the capturing subscriber must be this test process's only global default");
        tracing::callsite::rebuild_interest_cache();
    });
}

/// Run `f` with everything it logs *on this thread* captured, and return its
/// result together with the captured output. Events emitted meanwhile by other
/// threads go to their own (absent) capture and are discarded.
///
/// Captures do not nest: an inner call would hand the outer one an empty
/// string, so a nested capture is a debug assertion rather than a silent loss.
pub(crate) fn capture_logs<T>(f: impl FnOnce() -> T) -> (T, String) {
    install();
    CAPTURE.with(|slot| {
        let mut slot = slot.borrow_mut();
        debug_assert!(
            slot.is_none(),
            "capture_logs does not nest: the inner capture would swallow the outer one"
        );
        *slot = Some(Vec::new());
    });
    let value = f();
    let captured = CAPTURE
        .with(|slot| slot.borrow_mut().take())
        .unwrap_or_default();
    let logs = String::from_utf8(captured).expect("captured logs are UTF-8");
    (value, logs)
}

/// Assert that the capture is not empty.
///
/// Nothing captured is a different defect from a message that came out wrong —
/// it means the subscriber saw no events at all — and it must be reported as
/// such instead of surfacing as a bare "expected text missing" against an
/// empty haystack. It is also what makes the negative I12 assertions evidence:
/// "the log must never carry the key" holds vacuously over an empty capture.
#[track_caller]
pub(crate) fn assert_captured(logs: &str) {
    assert!(
        !logs.is_empty(),
        "captured nothing: the subscriber saw no events"
    );
}

/// Assert that the capture carries `needle`, distinguishing an empty capture
/// from one that merely lacks the text.
#[track_caller]
pub(crate) fn assert_logged(logs: &str, needle: &str) {
    assert_captured(logs);
    assert!(
        logs.contains(needle),
        "captured logs lack {needle:?}: {logs}"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROBE: &str = "testlog-interest-probe";

    /// Both hits below must be the *same* callsite, so the emit lives in one
    /// function rather than being written out twice.
    fn probe() {
        tracing::info!("{PROBE}");
    }

    #[test]
    fn a_subscriberless_thread_cannot_silence_a_later_capture() {
        // Registering the callsite from a subscriber-less thread *inside* the
        // capture is the deterministic form of the race a parallel test run
        // used to lose: with a scoped `with_default` the interest cached there
        // was `never` and the emit below vanished (issue #92).
        let (_, logs) = capture_logs(|| {
            std::thread::spawn(probe).join().expect("probe thread");
            probe();
        });
        assert_logged(&logs, PROBE);
        // Exactly one hit: the other thread's emit belongs to its own capture,
        // not to this one.
        assert_eq!(
            logs.matches(PROBE).count(),
            1,
            "only this thread's events belong in the capture: {logs}"
        );
    }

    /// An empty capture must be reported as one, not as a missing needle.
    #[test]
    #[should_panic(expected = "captured nothing")]
    fn an_empty_capture_fails_as_an_empty_capture() {
        assert_logged("", "anything");
    }

    #[test]
    #[should_panic(expected = "captured logs lack")]
    fn a_non_empty_capture_without_the_needle_fails_as_a_missing_needle() {
        assert_logged("something else entirely", "anything");
    }
}
