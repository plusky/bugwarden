//! The diagnostic stream's bound, applied at the SINK: every field of
//! every tracing line is cut at [`PARAM_VALUE_MAX_CHARS`] characters and
//! rewritten wherever it carries one of the control bytes
//! tracing-subscriber escapes in `message` (#260, #266). That set is ESC,
//! BEL, BS, FF, DEL and the C1 range, and no more: LF, CR and TAB pass
//! through, which is #275's subject rather than this module's.
//!
//! bugwarden caps the client strings it logs at the CALL SITE
//! (`server::Capped`), which bounds its own lines and nothing else. rmcp
//! writes to the same stderr and into the same OTLP diagnostics stream,
//! and bounds nothing: `service.rs:1342` logs the whole `initialize`
//! parameters (`?peer_info`), `:1597` every client notification whole,
//! `:1585` a JSON-RPC request id raw on every error reply (`%id`), and
//! `service/server.rs:477` the declared protocol version raw. Raise the
//! level and `service.rs:1535` adds the whole of every request at debug
//! and `:1438` the whole of every loop event at trace. A cap that lives
//! at a call site reaches none of them, and a
//! level filter that hides them is undone by the next `RUST_LOG` an
//! operator sets — so the bound goes where every line passes instead:
//! the field formatter `main` gives the stderr layer, and the visitor
//! `otel` builds the exported body with.
//!
//! Escaping is the other half (#266). tracing-subscriber 0.3's
//! `DefaultVisitor` sanitizes `message` and `record_error` only, and a
//! `%`-formatted value is a tracing-core `DisplayValue` recorded through
//! `record_debug`, whose `Debug` hands straight to its `Display` — so it
//! reaches the terminal verbatim, and a `query` of ESC `[2J` clears the
//! operator's screen while ESC `]0;` … BEL retitles it. [`CappedWriter`]
//! escapes the bytes `EscapeGuard` does, for every field.
//!
//! Parity with `DefaultFields` is a requirement, not a courtesy: a value
//! under the cap carrying no control bytes must render byte for byte as
//! it does today, because the operator's own greps and this workspace's
//! `binary_tracing_caps` needles read those lines. The unit tests below
//! render the same events through both and compare.

use std::fmt;
use std::fmt::Write as _;

use tracing::field::{Field, Visit};
use tracing_subscriber::field::RecordFields;
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::FormatFields;

/// The one bound every client-chosen string in this process answers to:
/// 1024 characters.
///
/// It is the audit record's cap — on an allowlisted parameter value, on a
/// recorded object key, on the tool name and on the JSON-RPC request id,
/// where `server.rs` reads it — and, since #260, the per-field cap of
/// every diagnostic line as well. One constant because a bound the record
/// enforces and the log undoes is not a bound, and because a second
/// number would have to be remembered next to this one.
pub const PARAM_VALUE_MAX_CHARS: usize = 1024;

/// A [`fmt::Write`] that bounds and sanitizes one field's value.
///
/// It passes characters through until [`PARAM_VALUE_MAX_CHARS`] of them
/// have been written and then swallows the rest, silently and with no
/// marker — the same cut `server::Capped` and the audit record make, so a
/// field written through `%Capped(..)` and the same text written raw stop
/// at the same character. The budget counts the characters handed TO the
/// adapter, across however many `write_str` calls a `fmt::Arguments`
/// arrives in, so a value assembled in pieces is cut at the total. It
/// allocates nothing.
///
/// The budget covers the RENDERED value, decoration included: the adapter
/// sees a stream of characters and cannot know which of them the client
/// wrote. So a `Debug`-shaped field spends part of its budget on its own
/// `Some("` and loses the closing `")` to the cut, and an `?Capped` field
/// carries that much less of the client's text than the `%Capped` one
/// beside it. For the same reason an OPERATOR's own value — a config
/// path, say — is cut like anyone else's; 1018 characters is legible for
/// any real path, and a bound with an exception for trusted values is a
/// bound with a hole. A strict tightening either way, and the price of a
/// cut that does not depend on the site knowing it exists.
///
/// Control bytes are escaped on the way through, in the rendering
/// tracing-subscriber 0.3's own `EscapeGuard` uses for `message`: ESC,
/// BEL, BS, FF and DEL become `\x1b`-style text and the C1 range
/// `\u{80}`–`\u{9f}` becomes `\u{..}`. `EscapeGuard` is private to
/// tracing-subscriber, so this is a copy of its byte set rather than a
/// reuse, and a unit test below pins the rendering byte-equal to what
/// `DefaultFields` produces for the same bytes in `message`. The escaping
/// is UNCONDITIONAL — it does not consult
/// `Writer::sanitizes_ansi_escapes`, whose `false` setting exists so that
/// TRUSTED sequences in logged values pass through unchanged, which is
/// exactly the channel a client must never inherit.
pub struct CappedWriter<'a, W: fmt::Write> {
    inner: &'a mut W,
    remaining: usize,
}

impl<'a, W: fmt::Write> CappedWriter<'a, W> {
    /// A budget of [`PARAM_VALUE_MAX_CHARS`] characters into `inner`.
    pub fn new(inner: &'a mut W) -> Self {
        Self {
            inner,
            remaining: PARAM_VALUE_MAX_CHARS,
        }
    }
}

impl<W: fmt::Write> fmt::Write for CappedWriter<'_, W> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for ch in s.chars() {
            if self.remaining == 0 {
                return Ok(());
            }
            self.remaining -= 1;
            match ch {
                // The C0 bytes a terminal reads as the start of, or part
                // of, a control sequence.
                '\x1b' => self.inner.write_str("\\x1b")?,
                '\x07' => self.inner.write_str("\\x07")?,
                '\x08' => self.inner.write_str("\\x08")?,
                '\x0c' => self.inner.write_str("\\x0c")?,
                '\x7f' => self.inner.write_str("\\x7f")?,
                // C1: the 8-bit forms of the same sequences.
                '\u{80}'..='\u{9f}' => write!(self.inner, "\\u{{{:x}}}", ch as u32)?,
                _ => self.inner.write_char(ch)?,
            }
        }
        Ok(())
    }
}

/// The stderr layer's field formatter: `DefaultFields`' rendering with
/// every value written through a [`CappedWriter`].
///
/// Installed by `main` with `fmt::layer().fmt_fields(..)`, so it formats
/// the fields of every event and of every span, whatever the target,
/// level or `RUST_LOG` — which is the whole point, since the lines this
/// exists for are rmcp's rather than ours.
#[derive(Debug, Clone, Copy, Default)]
pub struct CappedFields;

impl<'writer> FormatFields<'writer> for CappedFields {
    fn format_fields<R: RecordFields>(&self, writer: Writer<'writer>, fields: R) -> fmt::Result {
        let mut visitor = CappedVisitor {
            writer,
            is_empty: true,
            result: Ok(()),
        };
        fields.record(&mut visitor);
        visitor.result
    }
}

/// [`CappedFields`]' visitor, a transcription of tracing-subscriber
/// 0.3's `DefaultVisitor` whose one intended change is that the value
/// goes through a [`CappedWriter`] and the field NAME does not — a name
/// is static text of ours or of a dependency's, never the client's.
///
/// Transcribed rather than wrapped because `DefaultVisitor` writes
/// straight to its own `Writer` and exposes no seam. That transcription
/// carries one limit: `Writer`'s `italic()`/`dimmed()` are private to
/// tracing-subscriber, so names and separators are written unstyled.
/// bugwarden installs this layer with `with_ansi(false)`, where
/// `DefaultVisitor` writes them unstyled too, so the two agree byte for
/// byte in the only configuration this binary builds.
struct CappedVisitor<'a> {
    writer: Writer<'a>,
    is_empty: bool,
    result: fmt::Result,
}

impl CappedVisitor<'_> {
    /// The single space that separates two fields.
    fn maybe_pad(&mut self) {
        if self.is_empty {
            self.is_empty = false;
        } else {
            self.result = self.writer.write_char(' ');
        }
    }

    /// One field's value, bounded and sanitized.
    fn write_value(&mut self, value: &dyn fmt::Debug) -> fmt::Result {
        write!(CappedWriter::new(&mut self.writer), "{value:?}")
    }
}

impl Visit for CappedVisitor<'_> {
    fn record_str(&mut self, field: &Field, value: &str) {
        if self.result.is_err() {
            return;
        }
        // `message` prints bare and every other string prints quoted, so
        // the two reach `record_debug` as different kinds of value.
        if field.name() == "message" {
            self.record_debug(field, &format_args!("{value}"));
        } else {
            self.record_debug(field, &value);
        }
    }

    fn record_error(&mut self, field: &Field, value: &(dyn std::error::Error + 'static)) {
        // The error's own text, then its chain under a `<name>.sources`
        // pseudo-field — `DefaultVisitor`'s shape, and the raw field name
        // in the label as it uses it, `r#` prefix and all.
        match value.source() {
            Some(source) => self.record_debug(
                field,
                &format_args!("{value} {}.sources={}", field.name(), ErrorSources(source)),
            ),
            None => self.record_debug(field, &format_args!("{value}")),
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        if self.result.is_err() {
            return;
        }
        let name = field.name();
        // `tracing-log`'s bridge hangs a `log` record's real target,
        // module path, file and line on the event as `log.*` fields, and
        // `DefaultVisitor` drops them behind the same feature that
        // installs the bridge — so where they exist, the skip does too.
        // `otel::BodyVisitor` still reads `log.target`, because the
        // export has to know the target the metadata no longer carries.
        if name.starts_with("log.") {
            return;
        }
        self.maybe_pad();
        self.result = match name {
            "message" => self.write_value(value),
            // A raw identifier's field name keeps its `r#` in the
            // metadata and loses it on the line.
            name => {
                let key = name.strip_prefix("r#").unwrap_or(name);
                self.writer
                    .write_str(key)
                    .and_then(|()| self.writer.write_char('='))
                    .and_then(|()| self.write_value(value))
            }
        };
    }
}

/// An error's SOURCE chain as `DefaultVisitor` renders one: `[its
/// source, that source's own source, …]`, each entry a `Display` text
/// unquoted. The error itself is printed before the list, not in it.
struct ErrorSources<'a>(&'a (dyn std::error::Error + 'static));

impl fmt::Display for ErrorSources<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut list = f.debug_list();
        let mut current = Some(self.0);
        while let Some(error) = current {
            list.entry(&Unquoted(error));
            current = error.source();
        }
        list.finish()
    }
}

/// One entry of an [`ErrorSources`] list: `Debug` that prints `Display`,
/// so `debug_list` does not quote what is already prose.
struct Unquoted<'a>(&'a (dyn std::error::Error + 'static));

impl fmt::Debug for Unquoted<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self.0, f)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use tracing_subscriber::fmt::format::DefaultFields;
    use tracing_subscriber::layer::{Context, SubscriberExt as _};
    use tracing_subscriber::Layer;

    use super::*;

    /// ESC, the byte a terminal reads as the start of a control sequence.
    const ESC: char = '\x1b';

    /// One event's fields rendered by both formatters.
    #[derive(Clone, Debug, Default)]
    struct Rendered {
        default: String,
        capped: String,
    }

    /// A layer that renders every event through `DefaultFields` and
    /// through [`CappedFields`], into one `Writer` configuration.
    ///
    /// The differential runs inside one `on_event` on purpose: both
    /// formatters see the SAME `ValueSet`, so a difference cannot come
    /// from the two runs having recorded different values, and no
    /// timestamp or level prefix has to be normalized away.
    ///
    /// `Writer::new` builds the configuration this binary installs — no
    /// ANSI, sanitization on — so the comparison is the one that matters
    /// rather than a convenient one.
    struct Differential(Arc<Mutex<Vec<Rendered>>>);

    impl<S: tracing::Subscriber> Layer<S> for Differential {
        fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
            let mut rendered = Rendered::default();
            DefaultFields::new()
                .format_fields(Writer::new(&mut rendered.default), event)
                .expect("a String never fails to be written");
            CappedFields
                .format_fields(Writer::new(&mut rendered.capped), event)
                .expect("a String never fails to be written");
            self.0.lock().expect("the render lock").push(rendered);
        }
    }

    /// Render everything `emit` logs through both formatters.
    ///
    /// `with_default` and not a global subscriber: these tests share a
    /// process with `testlog`, which installs one of its own.
    fn render(emit: impl FnOnce()) -> Vec<Rendered> {
        let out: Arc<Mutex<Vec<Rendered>>> = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::registry().with(Differential(out.clone()));
        tracing::subscriber::with_default(subscriber, emit);
        let rendered = out.lock().expect("the render lock").clone();
        assert!(!rendered.is_empty(), "the differential saw no events");
        rendered
    }

    /// The one event `emit` logs, rendered through both formatters.
    fn render_one(emit: impl FnOnce()) -> Rendered {
        let mut rendered = render(emit);
        assert_eq!(rendered.len(), 1, "exactly one event: {rendered:?}");
        rendered.remove(0)
    }

    /// The adapter's budget is the whole point: over-cap text stops at
    /// exactly the cap, on a character boundary, and short text is
    /// untouched.
    #[test]
    fn the_budget_cuts_at_exactly_the_cap_on_a_char_boundary() {
        for chars in [0, 1, PARAM_VALUE_MAX_CHARS - 1, PARAM_VALUE_MAX_CHARS] {
            let mut out = String::new();
            // Multi-byte: an ASCII probe cannot tell a char budget from a
            // byte one.
            write!(CappedWriter::new(&mut out), "{}", "é".repeat(chars))
                .expect("a String never fails to be written");
            assert_eq!(out, "é".repeat(chars), "under the cap nothing moves");
        }
        let mut out = String::new();
        write!(
            CappedWriter::new(&mut out),
            "{}",
            "é".repeat(PARAM_VALUE_MAX_CHARS * 4)
        )
        .expect("a String never fails to be written");
        assert_eq!(
            out,
            "é".repeat(PARAM_VALUE_MAX_CHARS),
            "over the cap the cut is exact and lands between characters"
        );
    }

    /// A `fmt::Arguments` reaches the adapter in as many `write_str`
    /// calls as it has pieces, and the budget is the total across them.
    #[test]
    fn a_value_written_in_pieces_is_cut_at_the_char_total() {
        let piece = "é".repeat(PARAM_VALUE_MAX_CHARS / 2);
        let mut out = String::new();
        write!(CappedWriter::new(&mut out), "{piece}{piece}{piece}{piece}")
            .expect("a String never fails to be written");
        assert_eq!(out, "é".repeat(PARAM_VALUE_MAX_CHARS));

        // And the writes past the budget are swallowed rather than
        // failing, so the fields after this one still render.
        let mut writer = CappedWriter::new(&mut out);
        writer
            .write_str(&"z".repeat(PARAM_VALUE_MAX_CHARS * 2))
            .expect("an exhausted budget swallows, it does not error");
        writer
            .write_str("z")
            .expect("an exhausted budget swallows, it does not error");
        assert_eq!(
            out.chars().filter(|c| *c == 'z').count(),
            PARAM_VALUE_MAX_CHARS,
            "a second value gets its own budget and no more"
        );
    }

    /// Every control byte `EscapeGuard` rewrites, rendered exactly as
    /// tracing-subscriber renders it in `message` — the property that
    /// makes this a copy of that byte set rather than an approximation.
    #[test]
    fn the_escaping_matches_what_default_fields_does_to_a_message() {
        let probe: String = ['\x1b', '\x07', '\x08', '\x0c', '\x7f']
            .into_iter()
            .chain(('\u{80}'..='\u{9f}').chain(['a', 'é', '\n', '\t', '"', '\\']))
            .collect();
        // `DefaultFields` escapes `message` and `record_error` and
        // nothing else, so `message` is where the two renderings can be
        // compared directly.
        let rendered = render_one(|| tracing::info!("{probe}"));
        assert_eq!(rendered.capped, rendered.default);
        assert!(
            rendered.capped.contains("\\x1b") && rendered.capped.contains("\\u{9b}"),
            "and it really escaped something: {:?}",
            rendered.capped
        );

        // The same bytes in a `%` field, which `DefaultFields` leaves
        // raw: ours is the escaped rendering of the message, prefixed by
        // the field's name.
        let escaped = rendered.capped.clone();
        let field = render_one(|| tracing::info!(probe = %probe));
        assert_eq!(field.capped, format!("probe={escaped}"));
        assert!(
            field.default.contains(ESC),
            "the raw ESC this exists to stop must still be in what \
             `DefaultFields` writes: {:?}",
            field.default
        );
    }

    /// Parity: a value under the cap with no control bytes renders byte
    /// for byte as it does today, for every shape a field arrives in.
    #[test]
    fn every_field_shape_renders_exactly_as_default_fields_renders_it() {
        #[derive(Debug)]
        struct Inner;

        impl std::fmt::Display for Inner {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("the inner cause")
            }
        }

        impl std::error::Error for Inner {}

        #[derive(Debug)]
        struct Outer(Inner);

        impl std::fmt::Display for Outer {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("the outer failure")
            }
        }

        impl std::error::Error for Outer {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                Some(&self.0)
            }
        }

        let text = "a plain value";
        let owned = String::from("owned text");
        let lone: &(dyn std::error::Error + 'static) = &Inner;
        let chained: &(dyn std::error::Error + 'static) = &Outer(Inner);
        let rendered = render(|| {
            tracing::info!("a message alone");
            tracing::info!(display = %text, "message and fields");
            tracing::info!(debug = ?text, quoted = text, owned = owned.as_str());
            tracing::info!(count = 7u64, signed = -7i64, ratio = 0.5, flag = true);
            tracing::info!(r#type = "raw identifier", nested = ?vec![1, 2, 3]);
            // A field whose NAME really carries the `r#`: the raw
            // identifier above does not — the macro stringifies it to
            // `type` — and only a literal name reaches the visitor with
            // the prefix `DefaultVisitor` strips.
            tracing::info!("r#type" = "a literal raw name");
            tracing::error!(error = lone, "an error without a source");
            tracing::error!(error = chained, "an error with a source");
            // The bridge's own fields, which neither formatter renders.
            tracing::info!(
                log.target = "reqwest::connect",
                log.module_path = "reqwest",
                log.file = "connect.rs",
                log.line = 1,
                "a bridged record"
            );
        });
        for one in &rendered {
            assert_eq!(one.capped, one.default, "rendering must not drift");
        }
        // Named shapes the loop above would pass over silently if the
        // events stopped carrying them.
        let all = rendered
            .iter()
            .map(|one| one.capped.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        for needle in [
            "display=a plain value",
            "debug=\"a plain value\"",
            "quoted=\"a plain value\"",
            "count=7 signed=-7 ratio=0.5 flag=true",
            "type=\"raw identifier\"",
            "type=\"a literal raw name\"",
            "nested=[1, 2, 3]",
            "error=the outer failure error.sources=[the inner cause]",
        ] {
            assert!(all.contains(needle), "{needle:?} missing from:\n{all}");
        }
    }

    /// The bridge's `log.*` fields are dropped, and dropping them does
    /// not eat the separator of the fields that stay.
    #[test]
    fn the_log_bridge_fields_never_reach_the_line() {
        let rendered = render_one(|| {
            tracing::info!(
                log.target = "hyper_util::client::legacy::pool",
                kept = "yes",
                log.line = 12,
                also_kept = "yes",
                "bridged"
            );
        });
        assert_eq!(rendered.capped, "bridged kept=\"yes\" also_kept=\"yes\"");
        assert_eq!(rendered.capped, rendered.default);
    }

    /// `message` is a field like any other here. That is what bounds
    /// the #261 `serving error: {:?}` line, whose whole payload is the
    /// message; rmcp's `?notification` payload rides a field instead and
    /// is bounded by the same budget one field over.
    #[test]
    fn the_message_is_capped_too() {
        let long = "é".repeat(PARAM_VALUE_MAX_CHARS * 4);
        let rendered = render_one(|| tracing::info!("{long}"));
        assert_eq!(rendered.capped, "é".repeat(PARAM_VALUE_MAX_CHARS));
        assert!(
            rendered.default.chars().count() > PARAM_VALUE_MAX_CHARS,
            "and `DefaultFields` is what it is being capped against: {}",
            rendered.default.chars().count()
        );
    }

    /// The budget charges the characters handed IN, not the ones written
    /// OUT.
    ///
    /// The two orders agree on ordinary text and differ by a factor of
    /// four or six on escapable input, and it is the in-order one that
    /// the rustdoc above and DESIGN.md's "at most six bytes per budgeted
    /// character" rest on. Nothing on the stderr path tells them apart,
    /// because a real line's escapable characters are a handful among
    /// thousands.
    #[test]
    fn the_budget_charges_the_characters_handed_in_not_the_ones_written_out() {
        let mut out = String::new();
        write!(
            CappedWriter::new(&mut out),
            "{}",
            ESC.to_string().repeat(PARAM_VALUE_MAX_CHARS + 1)
        )
        .expect("a String never fails to be written");
        assert_eq!(
            out,
            "\\x1b".repeat(PARAM_VALUE_MAX_CHARS),
            "1024 escapes in, four characters out apiece"
        );

        // And through the visitor, on both the `%` path and `message`:
        // the leading ESC costs one character of the field's budget, so
        // 1023 of the client's own characters follow it.
        let long = format!("{ESC}{}", "é".repeat(PARAM_VALUE_MAX_CHARS * 4));
        let expected = format!("\\x1b{}", "é".repeat(PARAM_VALUE_MAX_CHARS - 1));
        assert_eq!(
            render_one(|| tracing::info!(probe = %long)).capped,
            format!("probe={expected}")
        );
        assert_eq!(render_one(|| tracing::info!("{long}")).capped, expected);
    }

    /// Each field gets its own budget, and the cut leaves the fields
    /// after it intact — a shared budget would silently drop them.
    #[test]
    fn every_field_is_capped_on_its_own_budget() {
        let long = "é".repeat(PARAM_VALUE_MAX_CHARS * 2);
        let rendered = render_one(|| tracing::info!(first = %long, second = %long, "m"));
        assert_eq!(
            rendered.capped,
            format!(
                "m first={cap} second={cap}",
                cap = "é".repeat(PARAM_VALUE_MAX_CHARS)
            )
        );
    }
}
