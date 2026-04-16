//! Tracing subscriber initialization with a target-first event format.
//!
//! The default `tracing_subscriber::fmt` renders events as
//! `TIME LEVEL [SPAN_CTX:] TARGET: FIELDS`. When a span is active the span
//! prefix pushes the module target (`p9n_exporter::session_store`) into the
//! 4th whitespace-separated column; without a span it sits in column 3.
//! Column-based log parsers break.
//!
//! This formatter swaps the order so the target always occupies column 3:
//!
//! ```text
//! TIME LEVEL TARGET: [SPAN_CTX:] FIELDS message
//! ```
//!
//! Span context (when present) moves to column 4. Rest of the layout, colour
//! handling, and env filtering match `tracing_subscriber::fmt::init()`.

use std::fmt;

use tracing::{Event, Subscriber};
use tracing_subscriber::fmt::{
    format::{FormatEvent, FormatFields, Writer},
    time::{FormatTime, SystemTime},
    FmtContext, FormattedFields,
};
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::EnvFilter;

/// Event format: `TIME LEVEL TARGET: [SPAN_CTX:] FIELDS`.
pub struct TargetFirst {
    timer: SystemTime,
}

impl TargetFirst {
    pub fn new() -> Self {
        Self { timer: SystemTime }
    }
}

impl Default for TargetFirst {
    fn default() -> Self {
        Self::new()
    }
}

impl<S, N> FormatEvent<S, N> for TargetFirst
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> fmt::Result {
        let meta = event.metadata();

        // Column 1: timestamp (RFC 3339, UTC).
        self.timer.format_time(&mut writer)?;
        write!(writer, " ")?;

        // Column 2: level (5-char right-aligned, matching fmt::Full).
        write!(writer, "{:>5} ", meta.level())?;

        // Column 3: target, always present, span-independent.
        write!(writer, "{}: ", meta.target())?;

        // Column 4 (optional): span context as `name{fields}>name{fields}:`.
        if let Some(scope) = ctx.event_scope() {
            let mut wrote_any = false;
            for span in scope.from_root() {
                if wrote_any {
                    write!(writer, ">")?;
                }
                wrote_any = true;
                write!(writer, "{}", span.name())?;
                let ext = span.extensions();
                if let Some(fields) = ext.get::<FormattedFields<N>>() {
                    if !fields.is_empty() {
                        write!(writer, "{{{}}}", fields)?;
                    }
                }
            }
            if wrote_any {
                write!(writer, ": ")?;
            }
        }

        // Remaining columns: event fields + message.
        ctx.field_format().format_fields(writer.by_ref(), event)?;
        writeln!(writer)
    }
}

/// Install the global tracing subscriber with `TargetFirst` formatting and
/// `RUST_LOG`-driven filtering.
///
/// Drop-in replacement for `tracing_subscriber::fmt::init()`.
pub fn init() {
    tracing_subscriber::fmt()
        .event_format(TargetFirst::new())
        .with_env_filter(EnvFilter::from_default_env())
        .init();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tracing_subscriber::fmt::MakeWriter;

    #[derive(Clone)]
    struct BufferMakeWriter(Arc<Mutex<Vec<u8>>>);

    impl<'a> MakeWriter<'a> for BufferMakeWriter {
        type Writer = BufferWriter;
        fn make_writer(&'a self) -> Self::Writer {
            BufferWriter(self.0.clone())
        }
    }

    struct BufferWriter(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for BufferWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn capture<F: FnOnce()>(f: F) -> String {
        let buf = Arc::new(Mutex::new(Vec::<u8>::new()));
        let subscriber = tracing_subscriber::fmt()
            .event_format(TargetFirst::new())
            .with_writer(BufferMakeWriter(buf.clone()))
            .finish();
        tracing::subscriber::with_default(subscriber, f);
        let bytes = buf.lock().unwrap().clone();
        strip_ansi(&String::from_utf8(bytes).unwrap())
    }

    /// Strip CSI escape sequences so assertions don't depend on the
    /// field formatter's colour decisions.
    fn strip_ansi(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        let mut chars = s.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '\x1b' && chars.peek() == Some(&'[') {
                chars.next();
                for nc in chars.by_ref() {
                    if nc.is_ascii_alphabetic() {
                        break;
                    }
                }
            } else {
                out.push(c);
            }
        }
        out
    }

    #[test]
    fn target_is_third_column_without_span() {
        let out = capture(|| {
            tracing::info!(target: "my_target", foo = 42, "hello");
        });
        let cols: Vec<&str> = out.split_whitespace().collect();
        assert_eq!(cols[2], "my_target:", "column 3 should be target; got: {out}");
    }

    #[test]
    fn target_is_third_column_with_span() {
        let out = capture(|| {
            let span = tracing::info_span!(target: "span_target", "my_span", conn_id = 1u64);
            let _g = span.enter();
            tracing::info!(target: "event_target", foo = 42, "hello");
        });
        let cols: Vec<&str> = out.split_whitespace().collect();
        assert_eq!(
            cols[2], "event_target:",
            "column 3 should be event target even when a span is active; got: {out}",
        );
        // Column 4 should be the span context, not fields.
        assert!(
            cols[3].starts_with("my_span"),
            "column 4 should be span context starting with span name; got: {}",
            cols[3],
        );
    }

    #[test]
    fn span_context_renders_fields() {
        let out = capture(|| {
            let span = tracing::info_span!("outer", conn_id = 7u64);
            let _g = span.enter();
            tracing::info!(foo = "bar", "msg");
        });
        assert!(
            out.contains("outer{conn_id=7}:"),
            "span with fields should render as name{{fields}}:; got: {out}",
        );
    }
}
