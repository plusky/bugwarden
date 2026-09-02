//! Frame bound for the stdio transport.
//!
//! rmcp's `AsyncRwTransport` reads a newline-delimited frame with
//! `read_until(b'\n', &mut self.line_buf)` into a `Vec<u8>` it never
//! bounds, so a peer that writes bytes and no `\n` grows that buffer until
//! the allocator gives up (#234). HTTP has the derived POST cap and a
//! `413`; stdio had nothing.
//!
//! [`BoundedLines`] is that missing half: an [`AsyncRead`] wrapper that
//! counts the bytes since the last `\n` and fails the read past the cap.
//! The obvious alternatives do not work — `JsonRpcMessageCodec`'s
//! `new_with_max_length` bounds only the `FramedWrite` half, which is
//! bugwarden's own output, and `AsyncReadExt::take` truncates the whole
//! stream rather than one frame.
//!
//! An over-cap frame is fatal, not skippable: the request id lives inside
//! the unparsed frame, so no response can name it, and rmcp clients set no
//! default request timeout — a peer that resumed would hang forever, which
//! is worse than a closed transport. rmcp maps the read error to
//! `receive() -> None`, i.e. a silent close indistinguishable from a clean
//! peer hangup, so the trip is also published through [`BoundedLines::over_cap`]
//! for `main` to turn into a non-zero exit.

use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{ready, Context, Poll};

use tokio::io::{AsyncRead, ReadBuf};

/// An [`AsyncRead`] that fails once a newline-delimited frame exceeds
/// `cap` bytes.
///
/// Wraps stdin under rmcp's own `BufReader`, so the counter sees the
/// delivered chunks and not the frames: the cap is enforced as soon as the
/// running frame passes it, without waiting for the `\n` that may never
/// come. A frame of exactly `cap` bytes is accepted, mirroring the http
/// side's `<= max_bytes`.
///
/// The count lives here rather than in a per-`receive` future because rmcp
/// keeps partial bytes across cancelled polls: `receive` is polled inside a
/// `select!` and an in-progress line read is dropped whenever an outgoing
/// response wins, so a per-call counter would restart mid-frame and the cap
/// would bound nothing.
#[derive(Debug)]
pub struct BoundedLines<R> {
    inner: R,
    /// Largest frame accepted, in bytes before the delimiter.
    cap: usize,
    /// Bytes delivered since the last `\n` — the length of the frame in
    /// progress.
    since_newline: usize,
    /// Set once, never cleared: the read stays failed, and `main` reads it
    /// after `waiting()` to tell an over-cap close from a clean one.
    over_cap: Arc<AtomicBool>,
}

impl<R> BoundedLines<R> {
    /// Bound `inner` to frames of at most `cap` bytes before the `\n`.
    pub fn new(inner: R, cap: usize) -> Self {
        Self {
            inner,
            cap,
            since_newline: 0,
            over_cap: Arc::new(AtomicBool::new(false)),
        }
    }

    /// The frame cap this reader enforces, in bytes before the delimiter.
    ///
    /// Exposed so a test can assert that the stdio and http transports were
    /// sized from the same derivation rather than from two numbers that
    /// happen to agree today.
    pub fn cap(&self) -> usize {
        self.cap
    }

    /// The trip flag, shared with whoever outlives the transport.
    ///
    /// rmcp turns the read error into `receive() -> None`, which the
    /// service reports as an ordinary close (`QuitReason::Closed`) — so
    /// without this flag a refused frame and a peer hangup are the same
    /// `Ok` exit. `main` bails on it after `waiting()` so both stages exit
    /// non-zero.
    pub fn over_cap(&self) -> Arc<AtomicBool> {
        self.over_cap.clone()
    }

    /// The error a tripped reader returns, on the trip and on every read
    /// after it. `InvalidData` matches rmcp's own mapping of its codec's
    /// `MaxLineLengthExceeded`.
    fn refusal(&self) -> io::Error {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("stdio frame exceeds the {}-byte request cap", self.cap),
        )
    }

    /// Trip the flag, log once from bugwarden's side, and return the error.
    ///
    /// The log matters: rmcp's own `Error reading from stream` is the only
    /// other trace of this, and it names neither the cap nor the transport.
    fn trip(&mut self) -> io::Error {
        self.over_cap.store(true, Ordering::Release);
        tracing::error!(
            "stdio frame exceeds the {}-byte request cap; closing the transport",
            self.cap
        );
        self.refusal()
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for BoundedLines<R> {
    /// Delegates the read, then measures what arrived.
    ///
    /// Every frame in the chunk is checked at its delimiter, not only the
    /// bytes after the chunk's last newline: a frame that both passes the
    /// cap and *ends* inside the tripping chunk would otherwise be seen as a
    /// short tail and let through. (Chunk length is not the measure either —
    /// many short frames may share one chunk.) Overshoot is bounded by one chunk
    /// (8 KiB under rmcp's `BufReader`), since the cap can only be observed
    /// on bytes already delivered.
    ///
    /// Bytes the tripping read delivered stay in `buf`; the caller drops
    /// them with the error, and the transport is closed either way.
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.over_cap.load(Ordering::Acquire) {
            return Poll::Ready(Err(this.refusal()));
        }
        let before = buf.filled().len();
        ready!(Pin::new(&mut this.inner).poll_read(cx, buf))?;
        let mut rest = &buf.filled()[before..];
        while let Some(newline) = rest.iter().position(|&byte| byte == b'\n') {
            if this.since_newline.saturating_add(newline) > this.cap {
                return Poll::Ready(Err(this.trip()));
            }
            this.since_newline = 0;
            rest = &rest[newline + 1..];
        }
        this.since_newline = this.since_newline.saturating_add(rest.len());
        if this.since_newline > this.cap {
            return Poll::Ready(Err(this.trip()));
        }
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use rmcp::transport::async_rw::AsyncRwTransport;
    use rmcp::transport::Transport as _;
    use rmcp::RoleServer;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _, DuplexStream};

    use super::BoundedLines;

    /// Read everything `bytes` yields through a reader capped at `cap`,
    /// returning the first error if there was one.
    async fn drain(bytes: &[u8], cap: usize) -> std::io::Result<()> {
        let mut reader = BoundedLines::new(bytes, cap);
        let mut sink = [0u8; 512];
        while reader.read(&mut sink).await? != 0 {}
        Ok(())
    }

    fn duplex(cap: usize) -> (DuplexStream, BoundedLines<DuplexStream>) {
        let (peer, ours) = tokio::io::duplex(64 * 1024);
        (peer, BoundedLines::new(ours, cap))
    }

    #[tokio::test]
    async fn a_frame_of_exactly_the_cap_is_accepted() {
        // `<= cap`, mirroring http's `<= max_bytes`. A `>=` here would
        // refuse the largest frame the cap names.
        drain(b"0123456789abcdef\n", 16)
            .await
            .expect("16 bytes is the cap, not past it");
    }

    #[tokio::test]
    async fn a_frame_of_exactly_the_cap_waits_for_its_delimiter() {
        // The chunked half of the same `<=`: a 4 MiB frame arrives in 8 KiB
        // pieces, so the cap is reached with the `\n` still in flight. A
        // `>=` in the no-delimiter-yet branch refuses the largest legal
        // frame on every real stream while the whole-chunk test above still
        // passes.
        let (mut peer, mut reader) = duplex(16);
        let mut buf = [0u8; 512];
        peer.write_all(b"0123456789abcdef")
            .await
            .expect("duplex write");
        assert_eq!(reader.read(&mut buf).await.expect("exactly the cap"), 16);
        peer.write_all(b"\n").await.expect("duplex write");
        assert_eq!(reader.read(&mut buf).await.expect("the delimiter"), 1);
    }

    #[tokio::test]
    async fn one_byte_past_the_cap_is_refused() {
        let err = drain(b"0123456789abcdefg\n", 16)
            .await
            .expect_err("17 bytes is past a 16-byte cap");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(
            err.to_string().contains("16-byte request cap"),
            "the refusal must name the cap: {err}"
        );
    }

    #[tokio::test]
    async fn the_count_is_per_frame_and_not_a_running_total() {
        // Chunked on purpose: within a single chunk the loop starts from
        // zero whether or not it resets, so a whole-frames-in-one-read test
        // passes even with the reset deleted. Only a frame that STRADDLES a
        // chunk boundary leaves a stale count for the next one to inherit —
        // and then an ordinary session is refused after a few requests.
        let (mut peer, mut reader) = duplex(16);
        let mut buf = [0u8; 512];
        peer.write_all(b"0123456789").await.expect("duplex write");
        assert_eq!(reader.read(&mut buf).await.expect("10 bytes"), 10);
        // Closes that frame at 12 bytes and opens the next one.
        peer.write_all(b"ab\ncdef").await.expect("duplex write");
        assert_eq!(reader.read(&mut buf).await.expect("12 then 4"), 7);
        // 10 bytes into the second frame, but 20 into the session.
        peer.write_all(b"ghijkl\n").await.expect("duplex write");
        assert_eq!(reader.read(&mut buf).await.expect("10 bytes, not 20"), 7);
    }

    #[tokio::test]
    async fn a_frame_that_ends_inside_the_tripping_chunk_is_still_refused() {
        // One chunk carrying an over-cap frame AND its delimiter. Checking
        // only the bytes after the chunk's last newline lets this through
        // as a short tail.
        let err = drain(b"0123456789abcdefg\nshort\n", 16)
            .await
            .expect_err("the delimiter does not excuse the frame before it");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn an_over_cap_second_frame_inside_one_chunk_is_refused() {
        // The under-cap first frame must not reset the scan so far that the
        // second one, entirely inside the same chunk, escapes its check.
        let err = drain(b"short\n0123456789abcdefg\n", 16)
            .await
            .expect_err("the second frame of the chunk is over the cap");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn several_under_cap_frames_in_one_chunk_are_accepted() {
        // Four 8-byte frames in a 32-byte chunk at cap 16: a check that
        // measured the chunk, or forgot to reset at each delimiter, would
        // refuse a stream of frames that individually fit.
        drain(b"aaaaaaa\nbbbbbbb\nccccccc\nddddddd\n", 16)
            .await
            .expect("every frame is half the cap");
    }

    #[tokio::test]
    async fn the_count_survives_a_cancelled_read() {
        // rmcp polls `receive` inside a `select!` and keeps the partial
        // bytes when another branch wins, so the counter has to live in the
        // reader. A per-future count would restart here and accept 20 bytes
        // under a 16-byte cap.
        let (mut peer, mut reader) = duplex(16);
        let mut buf = [0u8; 512];
        peer.write_all(b"0123456789").await.expect("duplex write");
        assert_eq!(reader.read(&mut buf).await.expect("first chunk"), 10);
        // A read with nothing to deliver, dropped mid-flight.
        assert!(
            tokio::time::timeout(Duration::from_millis(50), reader.read(&mut buf))
                .await
                .is_err(),
            "an empty duplex must leave the read pending"
        );
        peer.write_all(b"0123456789").await.expect("duplex write");
        let err = reader
            .read(&mut buf)
            .await
            .expect_err("20 bytes of one frame is past a 16-byte cap");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn the_refusal_is_sticky() {
        // rmcp stops reading after the first error, but nothing in the
        // `AsyncRead` contract makes it: a reader that recovered would hand
        // the tail of a refused frame to the parser as a fresh one.
        //
        // The refused frame carries its own delimiter, so the count is back
        // at zero and the next frame is legal on its face — without the
        // sticky check the second read succeeds. A refusal with no
        // delimiter would leave the count over the cap and trip again
        // whether or not the reader remembered anything.
        let (mut peer, mut reader) = duplex(16);
        let mut buf = [0u8; 512];
        peer.write_all(b"0123456789abcdefg\n")
            .await
            .expect("duplex write");
        reader.read(&mut buf).await.expect_err("over the cap");
        peer.write_all(b"{}\n").await.expect("duplex write");
        let err = reader
            .read(&mut buf)
            .await
            .expect_err("a tripped reader stays failed");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn an_under_cap_stream_reaches_the_reader_unchanged() {
        // The wrapper is transparent below the cap: a `\r\n` frame, an
        // empty frame and a trailing fragment all pass through byte for
        // byte, so nothing it does can corrupt the framing rmcp parses.
        let payload = b"{\"a\":1}\r\n\n{\"b\":2}\ntrailing";
        let mut reader = BoundedLines::new(&payload[..], 16);
        let mut read = Vec::new();
        reader.read_to_end(&mut read).await.expect("under the cap");
        assert_eq!(read, payload);
    }

    #[tokio::test]
    async fn rmcp_turns_the_refusal_into_a_closed_transport() {
        // The contract this whole design rests on, and the one thing an
        // rmcp bump can silently change: `receive` maps a read error to
        // `None`, so the service quits instead of retrying. If a future
        // rmcp propagated the error or resumed the read, this fails and the
        // exit-code path in `main` needs rethinking.
        //
        // Bounded: a reader that does not refuse leaves rmcp blocked in
        // `read_until` on a duplex nothing else will write to, and this
        // would hang the suite instead of failing.
        let (mut peer, reader) = duplex(16);
        let mut transport =
            AsyncRwTransport::<RoleServer, _, _>::new_server(reader, tokio::io::sink());
        peer.write_all(b"0123456789abcdefghij\n")
            .await
            .expect("duplex write");
        let received = tokio::time::timeout(Duration::from_secs(5), transport.receive())
            .await
            .expect("the transport must not block on a frame it will never accept");
        assert!(
            received.is_none(),
            "an over-cap frame must close the transport, not yield a message"
        );
    }
}
