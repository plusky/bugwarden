//! Test-only capture of tracing output, for pinning what startup log lines
//! say — and, per I12, what they must never say.

use std::io::Write;
use std::sync::{Arc, Mutex};

/// Cloneable in-memory writer handed to the fmt subscriber.
#[derive(Clone, Default)]
struct Buffer(Arc<Mutex<Vec<u8>>>);

impl Write for Buffer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .expect("log buffer lock")
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Run `f` with a fresh fmt subscriber as the thread-default and return its
/// result together with everything it logged.
pub(crate) fn capture_logs<T>(f: impl FnOnce() -> T) -> (T, String) {
    let buffer = Buffer::default();
    let writer = buffer.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .finish();
    let value = tracing::subscriber::with_default(subscriber, f);
    let logs = String::from_utf8(buffer.0.lock().expect("log buffer lock").clone())
        .expect("captured logs are UTF-8");
    (value, logs)
}
