//! Display-through-Debug quoting for tracing `error=` fields.
//!
//! A `%` field writes its value bare, so Bugzilla's error `message` —
//! which echoes client input — could put a `key=value` pair of the
//! client's choosing on the line. [`QuotedError`] prints the error's
//! Display through the same quoting budget the binary's `Capped`
//! wrapper uses for client strings. No `Display` impl:
//! `%QuotedError(..)` is how the defect is written, and it does not
//! compile.

use std::fmt;

/// Rendered characters [`write_quoted`] puts between its quotes.
///
/// Eight less than the sink's 1024, which is what the widest shape a
/// site wraps a quoted value in costs: `Some("` and `")` are six, the
/// quotes two. A field cut open at the sink is a field whose closing
/// quote is gone.
pub(crate) const QUOTED_DEBUG_MAX_CHARS: usize = 1024 - 8;

/// `str`'s own `Debug` rendering of `s`, stopped at
/// [`QUOTED_DEBUG_MAX_CHARS`] rendered characters so the closing quote
/// always fits.
///
/// Transcribed from `impl Debug for str` rather than delegated to it
/// because that impl offers no seam to stop at, and the transcription is
/// exact: for every Unicode scalar value, `char::escape_debug` is what
/// `str` writes, save the apostrophe — `str` escapes the double quote
/// and not the single one, where a bare `char` escapes both.
///
/// A character is written whole or not at all. Stopping mid-escape would
/// put `\u{20` on the line, which is neither the source text nor a legal
/// escape, and stopping AFTER a too-wide character while carrying on
/// with the next one would reorder the value; both misreport what was
/// sent, and the cut is silent, so it has to be a prefix.
pub(crate) fn write_quoted(f: &mut fmt::Formatter<'_>, s: &str) -> fmt::Result {
    use fmt::Write as _;
    f.write_char('"')?;
    let mut remaining = QUOTED_DEBUG_MAX_CHARS;
    for ch in s.chars() {
        // The apostrophe is the one character `str` leaves raw where
        // a bare `char` escapes it, so it is the one width not read
        // off `escape_debug`.
        let raw_quote = ch == '\'';
        let width = if raw_quote {
            1
        } else {
            ch.escape_debug().count()
        };
        if width > remaining {
            break;
        }
        remaining -= width;
        if raw_quote {
            f.write_char('\'')?;
        } else {
            write!(f, "{}", ch.escape_debug())?;
        }
    }
    f.write_char('"')
}

/// An error as a tracing field: Display, quoted, never the type's Debug.
///
/// `error = ?e` on `anyhow::Error` is the chain. This wrapper is the
/// operator-readable text with a writer-marked end, so a Bugzilla
/// message that echoes `status=HACKED` cannot become a later field for
/// a reader that honours quotes. Hence no `Display` impl:
/// `%QuotedError(..)` does not compile.
pub struct QuotedError<'a, E: ?Sized>(pub &'a E);

impl<E: fmt::Display + ?Sized> fmt::Debug for QuotedError<'_, E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_quoted(f, &self.0.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Display of an error carrying `"` and `status=HACKED` renders as
    /// a closed quoted Debug value — the #288 pin. `%QuotedError` does
    /// not compile; restoring `error = %e` fails the binary row.
    #[test]
    fn quoted_error_renders_display_as_closed_debug() {
        let err = concat!(
            "bugzilla error (HTTP 400): There is no version named ",
            "'1.0 \"status=HACKED\" limit=999' in the 'openSUSE' product."
        );
        let rendered = format!("{:?}", QuotedError(&err));
        assert!(
            rendered.starts_with('"') && rendered.ends_with('"'),
            "the value must open and close: {rendered}"
        );
        assert_eq!(
            rendered,
            format!("{err:?}"),
            "under the budget this is `str`'s own Debug of Display"
        );
        assert!(
            rendered.contains(r#"\"status=HACKED\""#),
            "the forged pair lives inside the quotes, escaped: {rendered}"
        );
    }

    /// A mutant `write_quoted(f, &format!("{:?}", self.0))` agrees with
    /// Display on a bare `&str` and on a single-layer `bail!`. anyhow's
    /// Debug is the chain; this wrapper must not print it.
    #[test]
    fn quoted_error_prints_anyhow_display_not_the_chain() {
        let err = anyhow::anyhow!("inner").context("outer");
        assert_eq!(
            format!("{:?}", QuotedError(&err)),
            format!("{:?}", "outer"),
            "Display of the outer message, quoted, not Debug of the chain"
        );
        let chain = format!("{err:?}");
        assert!(
            chain.contains("inner") && chain.contains("Caused by"),
            "sanity: anyhow Debug is the chain this wrapper must not print: {chain}"
        );
    }

    #[test]
    fn quoted_error_closes_inside_the_sink_budget() {
        let over = "a".repeat(QUOTED_DEBUG_MAX_CHARS + 8);
        let rendered = format!("{:?}", QuotedError(&over));
        assert_eq!(
            rendered,
            format!("\"{}\"", "a".repeat(QUOTED_DEBUG_MAX_CHARS)),
            "the character goes, never the quote: {rendered}"
        );
        assert!(
            rendered.starts_with('"') && rendered.ends_with('"'),
            "and it closes: {rendered}"
        );
        assert!(
            rendered.chars().count() < 1024,
            "a bare one is inside the sink's 1024"
        );
    }
}
