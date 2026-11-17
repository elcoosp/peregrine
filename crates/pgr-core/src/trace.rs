//! M61 — the Chrome-trace timeline: the roadmap's §9.4 profiling toolbox
//! ("`--trace` — Chrome-trace-format timeline per thread, so stragglers
//! and idle gaps are visible") names a measurement surface the M54
//! observation seam already serves the raw material for — the typed
//! [`crate::observe::PhaseEvent`]s carry each Pass 1–3 phase's completion
//! and wall time. This module is the consumer that turns those events
//! *as data* into the timeline: [`TraceCollector`] subscribes to the seam
//! (an [`crate::observe::LinkObserver`] impl), and [`TraceReport::render`]
//! writes the Chrome Trace Event Format's *object form* — the
//! `{"traceEvents":[…]}` envelope Chrome's `chrome://tracing` and the
//! Perfetto UI read — as a deterministic one-line interchange (fixed key
//! order, the report-JSON escape rules, integer-microsecond bounds).
//!
//! The timeline is a measurement, not a layout product: the lane set and
//! the columns are deterministic, the bounds are what the clock said.
//! Each event arrives on the thread the pipeline runs the seam on; the
//! collector keeps one lane per distinct arrival thread (first-arrival
//! order — the lane ids are the collector's own registry, never
//! `std::thread` internals), and the registry names its lanes (M64):
//! the pipeline's thread rides `pgr link`, the pool's workers `pgr
//! parse pool N` — the labels the `thread_name` metadata carries and
//! the §9.4 viewer reads. The one-shot pipeline renders the pipeline's
//! own lane plus the M63 worker lanes: the parse pool's per-input parses
//! ride the seam as [`crate::observe::TaskEvent`]s, each carrying the
//! thread that ran it and its own arrival clock, and the collector keeps
//! them as [`TraceTask`] spans on the workers' lanes — the per-thread
//! face the §9.4 toolbox reads stragglers and idle gaps from. A span's
//! start is the arrival clock minus the event's own wall (the seam
//! delivers the completion; the reconstruction is one emit-call behind
//! the clock — documented, and saturating rather than negative). The gaps
//! between the spans are the surface's point: the idle stretch the §9.4
//! toolbox reads.
//!
//! The reader is strict like the other interchange faces
//! (`parse_trace_json`): it restores the writer's data exactly (the
//! round-trip convention, gated) and refuses the broken shapes — an
//! unknown `ph`, an unknown phase or detail token, a non-integer
//! timestamp, a missing or duplicate key, a lane a span names but no
//! `thread_name` declared — with the byte position named. The schema is
//! the writer's own; keys ride in any order, whitespace between tokens.

use std::thread::ThreadId;
use std::time::Instant;

use crate::observe::{LinkNote, LinkObserver, Phase, PhaseDetail, PhaseEvent, TaskEvent};
use crate::time_report::detail_json;

/// The trace's `cat` — every timeline row the collector writes carries
/// it (the reader requires it on the non-metadata rows).
const TRACE_CAT: &str = "pgr";

/// The lane name the `thread_name` metadata carries for the pipeline's
/// own thread (the seam's phase/note events arrive on it; M64 names the
/// worker lanes beside it — `LANE_WORKER_PREFIX` + the registration
/// ordinal).
const LANE_NAME: &str = "pgr link";

/// The worker lane names' prefix (M64): the parse pool's lanes carry
/// `pgr parse pool 1`, `pgr parse pool 2`, … — the §9.4 viewer reads the
/// workers beside the pipeline's `pgr link` lane.
const LANE_WORKER_PREFIX: &str = "pgr parse pool ";

/// The note's stable token — the `name` the instant event carries and
/// the reader restores. The acceptance set mirrors the collector's
/// destructure (one entry per `LinkNote` variant): a later rung joining
/// [`LinkNote`] adds its own token here and its own collector arm.
const RESOLVE_REUSE_FALLBACK: &str = "resolve_reuse_fallback";

/// The relink ladder's fallback token (M65): the instant the timeline
/// writes when the §7.3 in-place ladder handed the link over to the full
/// link (the reason rides `args.reason`, the resolve-reuse fallback's
/// shape).
const RELINK_FALLBACK: &str = "relink_fallback";

/// The note kinds the reader accepts (the mirror of the collector's
/// destructure — one entry per `LinkNote` variant).
const NOTE_KINDS: [&str; 2] = [RESOLVE_REUSE_FALLBACK, RELINK_FALLBACK];

/// The phase tokens the reader accepts, in link order (the mirror of
/// [`Phase::as_str`] — the writer's name set; the M65 rung tokens ride
/// beside the pipeline's passes, in the seam's declaration order).
const PHASES: [Phase; 12] = [
    Phase::Parse,
    Phase::ArchivePull,
    Phase::Intern,
    Phase::Resolve,
    Phase::Liveness,
    Phase::Fold,
    Phase::Layout,
    Phase::Reloc,
    Phase::RelinkGate,
    Phase::RelinkPlan,
    Phase::RelinkPatch,
    Phase::RelinkAudit,
];

/// The phase a timeline row's name restores (the token → phase lookup).
fn phase_from_token(token: &str) -> Option<Phase> {
    PHASES.iter().copied().find(|p| p.as_str() == token)
}

/// One phase span on the timeline: the phase, its shape (the event's own
/// detail, verbatim), the lane it ran on, and the µs bounds (the
/// collector's own measurement — the start is the arrival clock minus
/// the event's wall).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceSpan {
    /// The phase that completed.
    pub phase: Phase,
    /// The phase's own shape.
    pub detail: PhaseDetail,
    /// The lane (the collector's 1-based arrival-thread registry).
    pub lane: u64,
    /// The span's start, in µs from the collector's epoch.
    pub start_us: u64,
    /// The span's wall, in µs (the event's own `elapsed`).
    pub dur_us: u64,
}

/// One intra-phase task span on the timeline (M63): a parse the pool's
/// worker thread carried, on the worker's own lane — the worker lanes
/// the §9.4 toolbox reads stragglers and idle gaps from. The span's
/// start is the task event's own arrival clock minus its wall (the
/// event carries the clock the thread that ran it stamped — the drain
/// never re-stamps).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceTask {
    /// The phase the task rode in (today the parse pool's `Parse`).
    pub phase: Phase,
    /// The task's own label (the input's command-line name for a parse).
    pub label: String,
    /// The lane the task's thread registered (the collector's 1-based
    /// arrival-thread registry).
    pub lane: u64,
    /// The span's start, in µs from the collector's epoch.
    pub start_us: u64,
    /// The span's wall, in µs (the event's own `elapsed`).
    pub dur_us: u64,
}

/// One lane on the timeline (M64): the registry id the spans and notes
/// carry, and the lane's own label — the `thread_name` metadata the
/// viewer reads. The collector names the pipeline's thread `pgr link`
/// and the pool's worker lanes `pgr parse pool N` (1-based, registration
/// order among the workers); the reader restores whatever label the
/// document carries (the round-trip convention — a foreign writer names
/// its lanes its own way).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceLane {
    /// The registry id (1-based, first-arrival order).
    pub id: u64,
    /// The lane's own label (the `thread_name` metadata's `name`).
    pub name: String,
}

/// One pipeline note on the timeline: an instant at its arrival (the
/// ladder's silent-correct rungs, made visible between the spans).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceNote {
    /// The note's stable token (the `name` the instant carries).
    pub kind: &'static str,
    /// The note's own wording (the `ResolveReuseFallback` reason).
    pub reason: String,
    /// The lane the note arrived on.
    pub lane: u64,
    /// The instant's µs from the collector's epoch.
    pub at_us: u64,
}

/// The Chrome-trace timeline: the spans and instants the collector kept,
/// plus the lane registry (the `thread_name` metadata's source). The
/// data-only shape the strict reader restores (the round-trip gate).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TraceReport {
    /// The phase spans, in arrival order (the seam's own).
    pub spans: Vec<TraceSpan>,
    /// The task spans, in the timeline's canonical `ts` order (the
    /// pool's drain interleaves the workers' records; [`TraceCollector::finish`]
    /// sorts so the render's document and the reader's restore agree —
    /// the round-trip convention, gated).
    pub tasks: Vec<TraceTask>,
    /// The notes, in arrival order.
    pub notes: Vec<TraceNote>,
    /// The lanes (M64: the named registry — the ids the spans and notes
    /// carry, ascending, each with its own `thread_name` label).
    pub lanes: Vec<TraceLane>,
}

/// The M61 trace collector: subscribes to the observation seam and keeps
/// every phase event as a timeline span (arrival order) and every note
/// as an instant. The epoch is the collector's construction — the driver
/// and the session build it right before the pipeline starts, so the
/// render's `ts` axis spans the whole run (the pre-parse gap included).
/// Feed it to [`crate::link_observed`] / [`crate::link_reloc_observed`]
/// (the observed pipelines), then [`TraceCollector::finish`] into a
/// [`TraceReport`].
#[derive(Debug)]
pub struct TraceCollector {
    /// The epoch (µs zero on the render's axis).
    base: Instant,
    /// The spans, in arrival order.
    spans: Vec<TraceSpan>,
    /// The task spans, in arrival order.
    tasks: Vec<TraceTask>,
    /// The notes, in arrival order.
    notes: Vec<TraceNote>,
    /// The arrival threads, in first-arrival order (the lane registry).
    lanes: Vec<ThreadId>,
    /// The pipeline's own thread (the first phase/note arrival — the
    /// lane the `pgr link` label names; M64). A feed with no phase or
    /// note events has none, and every lane is a worker lane.
    pipeline: Option<ThreadId>,
}

impl Default for TraceCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl TraceCollector {
    /// Opens the collection: the epoch rides the construction instant.
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: Instant::now(),
            spans: Vec::new(),
            tasks: Vec::new(),
            notes: Vec::new(),
            lanes: Vec::new(),
            pipeline: None,
        }
    }

    /// The lane for an arrival thread: the registry's 1-based
    /// first-arrival position (a linear walk — the lane count is the
    /// distinct arrival threads, one for today's pipelines).
    fn lane_of(&mut self, id: ThreadId) -> u64 {
        if let Some(i) = self.lanes.iter().position(|&l| l == id) {
            u64::try_from(i).unwrap_or(u64::MAX) + 1
        } else {
            self.lanes.push(id);
            u64::try_from(self.lanes.len()).unwrap_or(u64::MAX)
        }
    }

    /// µs since the epoch (the saturating shape — a clock that says the
    /// event predates the collector renders at the axis's zero, never a
    /// negative timestamp).
    fn us_since_base(&self, at: Instant) -> u64 {
        u64::try_from(at.saturating_duration_since(self.base).as_micros()).unwrap_or(u64::MAX)
    }

    /// Consumes the collection into the report. The spans and notes stay
    /// in arrival order (the seam's own — the phases run sequentially on
    /// the pipeline's lane, so their arrival order *is* the timeline's
    /// ts order); the tasks ride the timeline's canonical order — the
    /// pool's drain interleaves the workers' records, the render sorts
    /// by `ts`, and the reader restores the document exactly, so the
    /// tasks land ts-ordered here (stable on the ties) and the round
    /// trip holds (gated in `tests/m63_task_spans.rs`). The lanes are
    /// the named registry (M64): the pipeline's thread rides `pgr link`,
    /// the pool's workers `pgr parse pool N` (1-based, registration
    /// order among the workers); a feed with no phase or note events
    /// names every lane a worker lane.
    #[must_use]
    pub fn finish(mut self) -> TraceReport {
        let mut lanes = Vec::with_capacity(self.lanes.len());
        let mut worker = 0usize;
        for (i, thread) in self.lanes.iter().enumerate() {
            if self.pipeline == Some(*thread) {
                lanes.push(TraceLane {
                    id: u64::try_from(i + 1).unwrap_or(u64::MAX),
                    name: LANE_NAME.to_string(),
                });
            } else {
                worker += 1;
                lanes.push(TraceLane {
                    id: u64::try_from(i + 1).unwrap_or(u64::MAX),
                    name: format!("{LANE_WORKER_PREFIX}{worker}"),
                });
            }
        }
        self.tasks.sort_by_key(|t| t.start_us);
        TraceReport {
            spans: self.spans,
            tasks: self.tasks,
            notes: self.notes,
            lanes,
        }
    }
}

impl LinkObserver for TraceCollector {
    fn on_phase(&mut self, event: PhaseEvent) {
        let thread = std::thread::current().id();
        if self.pipeline.is_none() {
            self.pipeline = Some(thread);
        }
        let lane = self.lane_of(thread);
        // The seam delivers the completion; the span's start is the
        // arrival clock minus the event's own wall (one emit-call behind
        // the clock — the module doc names the reconstruction).
        let arrival = Instant::now();
        let start = arrival.checked_sub(event.elapsed).unwrap_or(self.base);
        let start_us = self.us_since_base(start);
        let dur_us = u64::try_from(event.elapsed.as_micros()).unwrap_or(u64::MAX);
        self.spans.push(TraceSpan {
            phase: event.phase,
            detail: event.detail,
            lane,
            start_us,
            dur_us,
        });
    }

    fn on_task(&mut self, task: TaskEvent) {
        // The lane keys on the thread the task ran on (the event's own
        // fact — a task forwarded from the parse pool's drain lands on
        // the worker's lane, never the caller's), and the span's start
        // reconstructs from the event's own arrival clock (the drain
        // must not re-stamp: every worker's span would end at the
        // drain). Saturating at the axis's floor, like the phase spans.
        let lane = self.lane_of(task.thread);
        let start = task.at.checked_sub(task.elapsed).unwrap_or(self.base);
        let start_us = self.us_since_base(start);
        let dur_us = u64::try_from(task.elapsed.as_micros()).unwrap_or(u64::MAX);
        self.tasks.push(TraceTask {
            phase: task.phase,
            label: task.label,
            lane,
            start_us,
            dur_us,
        });
    }

    fn on_note(&mut self, note: LinkNote) {
        let thread = std::thread::current().id();
        if self.pipeline.is_none() {
            self.pipeline = Some(thread);
        }
        let lane = self.lane_of(thread);
        let at_us = self.us_since_base(Instant::now());
        // Each variant names its own token (an arm, not a skip): a new
        // `LinkNote` rung stops compiling here until the timeline speaks
        // it — and its token joins `NOTE_KINDS` for the reader.
        let (kind, reason) = match note {
            LinkNote::ResolveReuseFallback { reason } => (RESOLVE_REUSE_FALLBACK, reason),
            LinkNote::RelinkFallback { reason } => (RELINK_FALLBACK, reason),
        };
        self.notes.push(TraceNote {
            kind,
            reason,
            lane,
            at_us,
        });
    }
}

impl TraceReport {
    /// Renders the timeline as deterministic, compact JSON — the Chrome
    /// Trace Event Format's object form (`{"traceEvents":[…]}`, one
    /// line): the metadata rows first (one `process_name`, one
    /// `thread_name` per lane ascending), then the spans and instants in
    /// `ts` order (a stable sort — the arrival order rides the ties),
    /// integer-microsecond bounds, the report-JSON escape rules (the
    /// M55/M56/M57/M58 convention — the shape is rigid:
    /// [`parse_trace_json`] restores the exact data).
    ///
    /// The `pid` is the trace's own constant (`1`): one link is one
    /// process, and the format's process identity is the viewer's key,
    /// not the host's.
    #[must_use]
    pub fn render(&self) -> String {
        let mut rows: Vec<String> = Vec::with_capacity(2 + self.spans.len() + self.notes.len());
        rows.push(
            "{\"name\":\"process_name\",\"ph\":\"M\",\"pid\":1,\"args\":{\"name\":\"pgr\"}}"
                .to_string(),
        );
        for lane in &self.lanes {
            rows.push(format!(
                "{{\"name\":\"thread_name\",\"ph\":\"M\",\"pid\":1,\"tid\":{},\"args\":{{\"name\":{}}}}}",
                lane.id,
                crate::map::escape_json(&lane.name),
            ));
        }
        // The timeline rows in `ts` order — the phase tokens are unique
        // per link, so the rows carry their own identity (the sort is
        // the stable `ts` pass below).
        let mut events: Vec<(u64, u8, String)> =
            Vec::with_capacity(self.spans.len() + self.tasks.len() + self.notes.len());
        for span in &self.spans {
            let row = format!(
                "{{\"name\":\"{}\",\"cat\":\"{TRACE_CAT}\",\"ph\":\"X\",\"ts\":{},\"dur\":{},\"pid\":1,\"tid\":{},\"args\":{}}}",
                span.phase.as_str(),
                span.start_us,
                span.dur_us,
                span.lane,
                detail_json(&span.detail),
            );
            events.push((span.start_us, 0, row));
        }
        for task in &self.tasks {
            let row = format!(
                "{{\"name\":\"{}\",\"cat\":\"{TRACE_CAT}\",\"ph\":\"X\",\"ts\":{},\"dur\":{},\"pid\":1,\"tid\":{},\"args\":{{\"kind\":\"task\",\"name\":{}}}}}",
                task.phase.as_str(),
                task.start_us,
                task.dur_us,
                task.lane,
                crate::map::escape_json(&task.label),
            );
            events.push((task.start_us, 0, row));
        }
        for note in &self.notes {
            let row = format!(
                "{{\"name\":\"{}\",\"cat\":\"{TRACE_CAT}\",\"ph\":\"i\",\"ts\":{},\"pid\":1,\"tid\":{},\"args\":{{\"reason\":{}}}}}",
                note.kind,
                note.at_us,
                note.lane,
                crate::map::escape_json(&note.reason),
            );
            events.push((note.at_us, 1, row));
        }
        // The timeline rows sort by `ts` alone — a stable sort, so the
        // writer's arrival order rides the ties (a saturating start
        // never re-orders the rows; the array is the arrival order the
        // seam delivered, and the round trip restores it).
        events.sort_by_key(|(ts, _, _)| *ts);
        rows.extend(events.into_iter().map(|(_, _, row)| row));
        let mut s =
            String::with_capacity(24 + rows.iter().map(String::len).sum::<usize>() + rows.len());
        s.push_str("{\"traceEvents\":[");
        s.push_str(&rows.join(","));
        s.push_str("]}");
        s
    }
}

/// The trace JSON reader's refusals: the shape named, the byte positioned
/// (the `MapJsonError` convention — typed, the fix in the message).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TraceJsonError {
    /// The document is not the trace's shape at `at`.
    #[error("invalid trace JSON at byte {at}: {detail}")]
    Invalid {
        /// The byte the parser refused.
        at: usize,
        /// What the parser expected there.
        detail: String,
    },
    /// A field carries a value or a key the trace's schema refuses.
    #[error("trace JSON field `{name}`: {detail}")]
    Field {
        /// The refused field (or the unknown key, verbatim).
        name: String,
        /// Why the value refused.
        detail: String,
    },
}

/// Parses the trace JSON the interchange writer emits — and the same
/// rigid schema any conforming writer produces (keys in any order,
/// whitespace between tokens, integer-microsecond bounds, no floats, no
/// trailing commas). The reader restores the writer's data exactly: the
/// round-trip is gated in `tests/m61_trace.rs`.
///
/// # Errors
/// [`TraceJsonError::Invalid`] on a malformed document (byte-positioned),
/// [`TraceJsonError::Field`] on a key or value the trace's schema refuses
/// (unknown or duplicate keys, a missing field, a non-integer timestamp,
/// an unknown phase or detail token, an event naming a lane no
/// `thread_name` declared).
pub fn parse_trace_json(raw: &str) -> Result<TraceReport, TraceJsonError> {
    let mut rd = TraceJsonReader {
        s: raw.as_bytes(),
        pos: 0,
    };
    let report = rd.parse_document()?;
    rd.skip_ws();
    if rd.pos != rd.s.len() {
        return rd.invalid("trailing bytes after the trace object");
    }
    Ok(report)
}

/// The strict trace-JSON reader: a recursive descent over the schema the
/// writer emits (byte-positioned [`TraceJsonError`]s; integer-only
/// numbers; unknown, duplicate and missing keys refuse).
struct TraceJsonReader<'a> {
    /// The document bytes.
    s: &'a [u8],
    /// The cursor.
    pos: usize,
}

impl TraceJsonReader<'_> {
    /// A shape refusal at the current byte.
    fn invalid<T>(&self, detail: impl Into<String>) -> Result<T, TraceJsonError> {
        Err(TraceJsonError::Invalid {
            at: self.pos,
            detail: detail.into(),
        })
    }

    /// A field refusal (a key or value the schema refuses).
    fn field<T>(name: impl Into<String>, detail: impl Into<String>) -> Result<T, TraceJsonError> {
        Err(TraceJsonError::Field {
            name: name.into(),
            detail: detail.into(),
        })
    }

    /// Skips the JSON whitespace the compact writer never emits but a
    /// hand-edited document may carry.
    fn skip_ws(&mut self) {
        while matches!(self.s.get(self.pos), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.pos += 1;
        }
    }

    /// The next non-whitespace byte, or an end-of-document refusal.
    fn peek(&mut self) -> Result<u8, TraceJsonError> {
        self.skip_ws();
        match self.s.get(self.pos) {
            Some(&b) => Ok(b),
            None => self.invalid("unexpected end of document"),
        }
    }

    /// Consumes the exact byte `c` (post-whitespace).
    fn expect(&mut self, c: u8) -> Result<(), TraceJsonError> {
        let got = self.peek()?;
        if got != c {
            return self.invalid(format!("expected {:?}, found {:?}", c as char, got as char));
        }
        self.pos += 1;
        Ok(())
    }

    /// The next `"`key`":` pair inside an object: `Ok(None)` on the
    /// object's closing brace, the decoded key otherwise (the `:` is
    /// consumed). `first` marks the object's opening field (no comma
    /// precedes it — a leading or trailing comma is the malformed shape).
    fn next_key(&mut self, first: bool) -> Result<Option<String>, TraceJsonError> {
        if self.peek()? == b'}' {
            self.pos += 1;
            return Ok(None);
        }
        if !first {
            self.expect(b',')?;
            if self.peek()? == b'}' {
                return self.invalid("trailing comma in object");
            }
        }
        let key = self.parse_string()?;
        self.expect(b':')?;
        Ok(Some(key))
    }

    /// Fills one object's slot, refusing a duplicate key by name.
    fn set<T>(
        slot: &mut Option<T>,
        name: impl Into<String>,
        value: T,
    ) -> Result<(), TraceJsonError> {
        if slot.is_some() {
            return Err(TraceJsonError::Field {
                name: name.into(),
                detail: "duplicate key".into(),
            });
        }
        *slot = Some(value);
        Ok(())
    }

    /// Requires one object's slot to be filled (the missing-field refusal
    /// names the key).
    fn require<T>(slot: Option<T>, name: &str) -> Result<T, TraceJsonError> {
        slot.ok_or_else(|| TraceJsonError::Field {
            name: name.to_string(),
            detail: "missing field".into(),
        })
    }

    /// A JSON string: the writer's escapes decoded, multibyte UTF-8 kept
    /// verbatim, raw control bytes refused.
    fn parse_string(&mut self) -> Result<String, TraceJsonError> {
        self.expect(b'"')?;
        let start = self.pos;
        let mut out: Vec<u8> = Vec::new();
        loop {
            let Some(&b) = self.s.get(self.pos) else {
                self.pos = self.s.len();
                return self.invalid("unterminated string");
            };
            self.pos += 1;
            match b {
                b'"' => {
                    return String::from_utf8(out).map_err(|_| TraceJsonError::Invalid {
                        at: start,
                        detail: "the trace JSON must be UTF-8".into(),
                    });
                }
                b'\\' => {
                    let Some(&esc) = self.s.get(self.pos) else {
                        self.pos = self.s.len();
                        return self.invalid("unterminated escape");
                    };
                    self.pos += 1;
                    match esc {
                        b'"' => out.push(b'"'),
                        b'\\' => out.push(b'\\'),
                        b'/' => out.push(b'/'),
                        b'b' => out.push(0x08),
                        b'f' => out.push(0x0C),
                        b'n' => out.push(b'\n'),
                        b'r' => out.push(b'\r'),
                        b't' => out.push(b'\t'),
                        b'u' => out.extend(self.parse_unicode_escape()?),
                        _ => {
                            return self.invalid(format!("unknown escape \\{}", esc as char));
                        }
                    }
                }
                b if b < 0x20 => return self.invalid("raw control byte in string"),
                _ => out.push(b),
            }
        }
    }

    /// One `\uXXXX` escape (a surrogate pair decoded when the high half
    /// leads — a foreign writer may pair them; the house writer's escapes
    /// are always single control characters).
    fn parse_unicode_escape(&mut self) -> Result<Vec<u8>, TraceJsonError> {
        let hi = self.hex4()?;
        let cp = if (0xD800..=0xDBFF).contains(&hi) {
            if self.peek()? != b'\\' {
                return self.invalid("unpaired high surrogate");
            }
            self.pos += 1;
            if self.peek()? != b'u' {
                return self.invalid("unpaired high surrogate");
            }
            self.pos += 1;
            let lo = self.hex4()?;
            if !(0xDC00..=0xDFFF).contains(&lo) {
                return self.invalid("unpaired low surrogate");
            }
            0x1_0000 + ((u32::from(hi) - 0xD800) << 10) + (u32::from(lo) - 0xDC00)
        } else if (0xDC00..=0xDFFF).contains(&hi) {
            return self.invalid("unpaired low surrogate");
        } else {
            u32::from(hi)
        };
        let mut buf = [0u8; 4];
        let enc = char::from_u32(cp)
            .ok_or_else(|| TraceJsonError::Invalid {
                at: self.pos,
                detail: "the escape names no Unicode scalar".into(),
            })?
            .encode_utf8(&mut buf);
        Ok(enc.as_bytes().to_vec())
    }

    /// Four hex digits (the `\u` payload).
    fn hex4(&mut self) -> Result<u16, TraceJsonError> {
        let mut v: u16 = 0;
        for _ in 0..4 {
            let b = self.peek()?;
            let d = match b {
                b'0'..=b'9' => u16::from(b - b'0'),
                b'a'..=b'f' => u16::from(b - b'a') + 10,
                b'A'..=b'F' => u16::from(b - b'A') + 10,
                _ => return self.invalid("expected a hex digit in \\u escape"),
            };
            self.pos += 1;
            v = (v << 4) | d;
        }
        Ok(v)
    }

    /// A non-negative integer: digits only — the trace schema carries no
    /// floats or exponents, and every number is u64.
    fn parse_u64(&mut self) -> Result<u64, TraceJsonError> {
        let b = self.peek()?;
        if !b.is_ascii_digit() {
            return self.invalid(format!(
                "expected a non-negative integer, found {:?}",
                b as char
            ));
        }
        let start = self.pos;
        while matches!(self.s.get(self.pos), Some(d) if d.is_ascii_digit()) {
            self.pos += 1;
        }
        // The trace schema carries integers alone: a fraction or an
        // exponent after the digits is a refusal of its own (a drifted
        // reader would silently floor it).
        if matches!(self.s.get(self.pos), Some(b'.' | b'e' | b'E')) {
            return Self::field("number", "the trace carries integers (a float rode here)");
        }
        let digits =
            std::str::from_utf8(&self.s[start..self.pos]).map_err(|_| TraceJsonError::Invalid {
                at: start,
                detail: "the trace JSON must be UTF-8".into(),
            })?;
        digits.parse::<u64>().map_err(|_| TraceJsonError::Field {
            name: "number".into(),
            detail: format!("{digits} exceeds u64"),
        })
    }

    /// One u64 field's value (the `:` consumed by [`Self::next_key`]).
    fn u64_field(&mut self, name: &str) -> Result<u64, TraceJsonError> {
        match self.parse_u64() {
            Ok(v) => Ok(v),
            Err(TraceJsonError::Field { detail, .. }) => Self::field(name.to_string(), detail),
            Err(e @ TraceJsonError::Invalid { .. }) => Err(e),
        }
    }

    /// One boolean field's value.
    fn bool_field(&mut self, name: &str) -> Result<bool, TraceJsonError> {
        match self.peek()? {
            b't' if self.s[self.pos..].starts_with(b"true") => {
                self.pos += 4;
                Ok(true)
            }
            b'f' if self.s[self.pos..].starts_with(b"false") => {
                self.pos += 5;
                Ok(false)
            }
            _ => Self::field(name, "expected a boolean"),
        }
    }

    /// The document: the `{"traceEvents":[…]}` object form, one key
    /// (unknown, duplicate and missing top-level keys refuse).
    fn parse_document(&mut self) -> Result<TraceReport, TraceJsonError> {
        self.expect(b'{')?;
        let mut events_slot: Option<Vec<EventRow>> = None;
        let mut first = true;
        while let Some(key) = self.next_key(first)? {
            first = false;
            match key.as_str() {
                "traceEvents" => {
                    let rows = self.parse_events()?;
                    Self::set(&mut events_slot, "traceEvents", rows)?;
                }
                other => {
                    return Self::field(
                        other,
                        "unknown key (the trace object carries `traceEvents` alone)",
                    );
                }
            }
        }
        let events = Self::require(events_slot, "traceEvents")?;
        Self::assemble(events)
    }

    /// The `traceEvents` array: one event object per element (no
    /// trailing comma — the writer never emits one).
    fn parse_events(&mut self) -> Result<Vec<EventRow>, TraceJsonError> {
        self.expect(b'[')?;
        let mut out = Vec::new();
        loop {
            if self.peek()? == b']' {
                self.pos += 1;
                return Ok(out);
            }
            if !out.is_empty() {
                self.expect(b',')?;
                if self.peek()? == b']' {
                    return Self::field("traceEvents", "trailing comma in array");
                }
            }
            out.push(self.parse_event()?);
        }
    }

    /// One event object: the fields the `ph` names, exactly (unknown and
    /// duplicate keys refuse; the metadata and timeline rows carry
    /// different field sets, and the `ph` picks the schema).
    fn parse_event(&mut self) -> Result<EventRow, TraceJsonError> {
        self.expect(b'{')?;
        let mut name: Option<String> = None;
        let mut cat: Option<String> = None;
        let mut ph: Option<String> = None;
        let mut ts: Option<u64> = None;
        let mut dur: Option<u64> = None;
        let mut pid: Option<u64> = None;
        let mut tid: Option<u64> = None;
        let mut args: Option<ArgsRow> = None;
        let mut first = true;
        while let Some(key) = self.next_key(first)? {
            first = false;
            match key.as_str() {
                "name" => Self::set(&mut name, "name", self.parse_string()?)?,
                "cat" => Self::set(&mut cat, "cat", self.parse_string()?)?,
                "ph" => Self::set(&mut ph, "ph", self.parse_string()?)?,
                "ts" => Self::set(&mut ts, "ts", self.u64_field("ts")?)?,
                "dur" => Self::set(&mut dur, "dur", self.u64_field("dur")?)?,
                "pid" => Self::set(&mut pid, "pid", self.u64_field("pid")?)?,
                "tid" => Self::set(&mut tid, "tid", self.u64_field("tid")?)?,
                "args" => Self::set(&mut args, "args", self.parse_args()?)?,
                other => return Self::field(other, "unknown key in the trace event"),
            }
        }
        let ph = Self::require(ph, "ph")?;
        let name = Self::require(name, "name")?;
        let pid = Self::require(pid, "pid")?;
        if pid != 1 {
            return Self::field("pid", "the trace carries one process (pid 1)");
        }
        match ph.as_str() {
            "M" => {
                let args = Self::require(args, "args")?;
                match name.as_str() {
                    "process_name" => {
                        if tid.is_some() {
                            return Self::field("tid", "the process row names no lane");
                        }
                        let ArgsRow::Name(label) = args else {
                            return Self::field(
                                "args",
                                "the process row's args carry the name alone",
                            );
                        };
                        if label.is_empty() {
                            return Self::field("args", "the process name is empty");
                        }
                        Ok(EventRow::ProcessName)
                    }
                    "thread_name" => {
                        let tid = Self::require(tid, "tid")?;
                        let ArgsRow::Name(label) = args else {
                            return Self::field("args", "the thread row's args carry the name");
                        };
                        if label.is_empty() {
                            return Self::field("args", "the lane name is empty");
                        }
                        Ok(EventRow::ThreadName { tid, name: label })
                    }
                    other => Self::field("name", format!("unknown metadata row `{other}`")),
                }
            }
            "X" | "i" => {
                let cat = Self::require(cat, "cat")?;
                if cat != TRACE_CAT {
                    return Self::field("cat", format!("expected `{TRACE_CAT}`"));
                }
                let ts = Self::require(ts, "ts")?;
                let tid = Self::require(tid, "tid")?;
                let args = Self::require(args, "args")?;
                if ph == "X" {
                    let dur = Self::require(dur, "dur")?;
                    let Some(phase) = phase_from_token(&name) else {
                        return Self::field(
                            "name",
                            format!(
                                "unknown phase token `{name}` (the timeline names the M54 \
                                 seam's phases)"
                            ),
                        );
                    };
                    match args {
                        ArgsRow::Detail(detail) => Ok(EventRow::Span {
                            phase,
                            detail,
                            ts,
                            dur,
                            tid,
                        }),
                        ArgsRow::Task(label) => Ok(EventRow::Task {
                            phase,
                            label,
                            ts,
                            dur,
                            tid,
                        }),
                        _ => Self::field(
                            "args",
                            "the span's args carry the phase detail or the task label",
                        ),
                    }
                } else {
                    if dur.is_some() {
                        return Self::field("dur", "the instant row carries no duration");
                    }
                    // Validated here, once: the assembled row carries the
                    // schema's own token (no re-validation, no panic path
                    // in the reader).
                    let Some(kind) = NOTE_KINDS.iter().find(|k| **k == name.as_str()).copied()
                    else {
                        return Self::field("name", format!("unknown note kind `{name}`"));
                    };
                    let ArgsRow::Reason(reason) = args else {
                        return Self::field("args", "the instant's args carry the reason");
                    };
                    Ok(EventRow::Note {
                        kind,
                        reason,
                        ts,
                        tid,
                    })
                }
            }
            other => Self::field("ph", format!("unknown trace event ph `{other}`")),
        }
    }

    /// The `args` object: three shapes share the parser — the phase
    /// detail (`kind` plus its own counts), the metadata's `name`, the
    /// instant's `reason`, and the M63 task's `kind`+`name` pair.
    /// Exactly one marker rides (a mix is the malformed shape).
    fn parse_args(&mut self) -> Result<ArgsRow, TraceJsonError> {
        self.expect(b'{')?;
        let mut kind: Option<String> = None;
        let mut name: Option<String> = None;
        let mut reason: Option<String> = None;
        let mut inputs: Option<u64> = None;
        let mut pulled: Option<u64> = None;
        let mut interned: Option<u64> = None;
        let mut reused: Option<bool> = None;
        let mut active: Option<bool> = None;
        let mut folded: Option<u64> = None;
        let mut segments: Option<u64> = None;
        let mut sections: Option<u64> = None;
        let mut pages: Option<u64> = None;
        let mut tiles: Option<u64> = None;
        let mut dirty: Option<u64> = None;
        let mut bytes: Option<u64> = None;
        let mut healed: Option<bool> = None;
        let mut issues: Option<u64> = None;
        let mut first = true;
        while let Some(key) = self.next_key(first)? {
            first = false;
            match key.as_str() {
                "kind" => Self::set(&mut kind, "kind", self.parse_string()?)?,
                "name" => Self::set(&mut name, "name", self.parse_string()?)?,
                "reason" => Self::set(&mut reason, "reason", self.parse_string()?)?,
                "inputs" => Self::set(&mut inputs, "inputs", self.u64_field("inputs")?)?,
                "pulled" => Self::set(&mut pulled, "pulled", self.u64_field("pulled")?)?,
                "interned" => Self::set(&mut interned, "interned", self.u64_field("interned")?)?,
                "reused" => Self::set(&mut reused, "reused", self.bool_field("reused")?)?,
                "active" => Self::set(&mut active, "active", self.bool_field("active")?)?,
                "folded" => Self::set(&mut folded, "folded", self.u64_field("folded")?)?,
                "segments" => Self::set(&mut segments, "segments", self.u64_field("segments")?)?,
                "sections" => Self::set(&mut sections, "sections", self.u64_field("sections")?)?,
                "pages" => Self::set(&mut pages, "pages", self.u64_field("pages")?)?,
                "tiles" => Self::set(&mut tiles, "tiles", self.u64_field("tiles")?)?,
                "dirty" => Self::set(&mut dirty, "dirty", self.u64_field("dirty")?)?,
                "bytes" => Self::set(&mut bytes, "bytes", self.u64_field("bytes")?)?,
                "healed" => Self::set(&mut healed, "healed", self.bool_field("healed")?)?,
                "issues" => Self::set(&mut issues, "issues", self.u64_field("issues")?)?,
                other => return Self::field(other, "unknown key in the trace args"),
            }
        }
        if let Some(kind) = kind {
            if kind == "task" {
                // The M63 task shape: the kind and the label alone (a
                // count key beside it is the malformed mix).
                if reason.is_some()
                    || inputs.is_some()
                    || pulled.is_some()
                    || interned.is_some()
                    || reused.is_some()
                    || active.is_some()
                    || folded.is_some()
                    || segments.is_some()
                    || sections.is_some()
                    || pages.is_some()
                    || tiles.is_some()
                    || dirty.is_some()
                    || bytes.is_some()
                    || healed.is_some()
                    || issues.is_some()
                {
                    return Self::field("args", "the task args carry the kind and the label");
                }
                let label = Self::require(name, "name")?;
                return Ok(ArgsRow::Task(label));
            }
            if name.is_some() || reason.is_some() {
                return Self::field("args", "the detail args carry the kind and its counts");
            }
            let detail = match kind.as_str() {
                "objects" => PhaseDetail::Objects {
                    inputs: usize::try_from(Self::require(inputs, "inputs")?).unwrap_or(usize::MAX),
                },
                "members" => PhaseDetail::Members {
                    pulled: usize::try_from(Self::require(pulled, "pulled")?).unwrap_or(usize::MAX),
                },
                "names" => PhaseDetail::Names {
                    interned: usize::try_from(Self::require(interned, "interned")?)
                        .unwrap_or(usize::MAX),
                },
                "winners" => PhaseDetail::Winners {
                    reused: Self::require(reused, "reused")?,
                },
                "live" => PhaseDetail::Live {
                    active: Self::require(active, "active")?,
                },
                "folded" => PhaseDetail::Folded {
                    folded: usize::try_from(Self::require(folded, "folded")?).unwrap_or(usize::MAX),
                },
                "planned" => PhaseDetail::Planned {
                    segments: usize::try_from(Self::require(segments, "segments")?)
                        .unwrap_or(usize::MAX),
                    sections: usize::try_from(Self::require(sections, "sections")?)
                        .unwrap_or(usize::MAX),
                },
                "reloc" => PhaseDetail::Reloc {
                    inputs: usize::try_from(Self::require(inputs, "inputs")?).unwrap_or(usize::MAX),
                },
                "gate" => PhaseDetail::Gate {
                    pages: usize::try_from(Self::require(pages, "pages")?).unwrap_or(usize::MAX),
                },
                "plan" => PhaseDetail::Plan {
                    tiles: usize::try_from(Self::require(tiles, "tiles")?).unwrap_or(usize::MAX),
                    dirty: usize::try_from(Self::require(dirty, "dirty")?).unwrap_or(usize::MAX),
                },
                "patch" => PhaseDetail::Patch {
                    bytes: Self::require(bytes, "bytes")?,
                    tiles: usize::try_from(Self::require(tiles, "tiles")?).unwrap_or(usize::MAX),
                },
                "audit" => PhaseDetail::Audit {
                    healed: Self::require(healed, "healed")?,
                    issues: usize::try_from(Self::require(issues, "issues")?).unwrap_or(usize::MAX),
                },
                other => {
                    return Self::field("kind", format!("unknown detail kind `{other}`"));
                }
            };
            return Ok(ArgsRow::Detail(detail));
        }
        if let Some(label) = name {
            if reason.is_some() {
                return Self::field("args", "the metadata args carry the name alone");
            }
            return Ok(ArgsRow::Name(label));
        }
        if let Some(reason) = reason {
            return Ok(ArgsRow::Reason(reason));
        }
        Self::field("args", "the args carry one of `kind`, `name` or `reason`")
    }

    /// Assembles the report: the metadata rows fill the named lane
    /// registry (ascending tids refused — the writer sorts; M64 the
    /// labels ride the registry), the timeline rows cross-check their
    /// lane against it.
    fn assemble(events: Vec<EventRow>) -> Result<TraceReport, TraceJsonError> {
        let mut lanes: Vec<TraceLane> = Vec::new();
        for row in &events {
            if let EventRow::ThreadName { tid, name } = row {
                if lanes.iter().any(|l| l.id == *tid) {
                    return Self::field("tid", "duplicate thread_name row");
                }
                if lanes.last().is_some_and(|last| last.id > *tid) {
                    return Self::field("tid", "the thread_name rows ride ascending");
                }
                lanes.push(TraceLane {
                    id: *tid,
                    name: name.clone(),
                });
            }
        }
        let mut spans = Vec::new();
        let mut tasks = Vec::new();
        let mut notes = Vec::new();
        for row in events {
            match row {
                EventRow::ProcessName | EventRow::ThreadName { .. } => {}
                EventRow::Span {
                    phase,
                    detail,
                    ts,
                    dur,
                    tid,
                } => {
                    if !lanes.iter().any(|l| l.id == tid) {
                        return Self::field(
                            "tid",
                            format!("the span names lane {tid}, no thread_name declares it"),
                        );
                    }
                    spans.push(TraceSpan {
                        phase,
                        detail,
                        lane: tid,
                        start_us: ts,
                        dur_us: dur,
                    });
                }
                EventRow::Task {
                    phase,
                    label,
                    ts,
                    dur,
                    tid,
                } => {
                    if !lanes.iter().any(|l| l.id == tid) {
                        return Self::field(
                            "tid",
                            format!("the task names lane {tid}, no thread_name declares it"),
                        );
                    }
                    tasks.push(TraceTask {
                        phase,
                        label,
                        lane: tid,
                        start_us: ts,
                        dur_us: dur,
                    });
                }
                EventRow::Note {
                    kind,
                    reason,
                    ts,
                    tid,
                } => {
                    if !lanes.iter().any(|l| l.id == tid) {
                        return Self::field(
                            "tid",
                            format!("the note names lane {tid}, no thread_name declares it"),
                        );
                    }
                    notes.push(TraceNote {
                        kind,
                        reason,
                        lane: tid,
                        at_us: ts,
                    });
                }
            }
        }
        Ok(TraceReport {
            spans,
            tasks,
            notes,
            lanes,
        })
    }
}

/// One parsed event's shape (the `ph`-keyed union the event parser
/// returns; [`TraceJsonReader::assemble`] splits it into the report).
enum EventRow {
    /// The `process_name` metadata row.
    ProcessName,
    /// The `thread_name` metadata row (one per lane, ascending).
    ThreadName {
        /// The lane it names.
        tid: u64,
        /// The lane's own label (M64: the data the registry carries).
        name: String,
    },
    /// A phase span (`ph: "X"`).
    Span {
        /// The phase the name restored.
        phase: Phase,
        /// The shape the args restored.
        detail: PhaseDetail,
        /// The µs start.
        ts: u64,
        /// The µs wall.
        dur: u64,
        /// The lane.
        tid: u64,
    },
    /// A task span (`ph: "X"`, the M63 task args — a parse the pool's
    /// worker carried).
    Task {
        /// The phase the task rode in.
        phase: Phase,
        /// The task's label.
        label: String,
        /// The µs start.
        ts: u64,
        /// The µs wall.
        dur: u64,
        /// The lane.
        tid: u64,
    },
    /// A note instant (`ph: "i"`).
    Note {
        /// The note's token from the schema's own acceptance set.
        kind: &'static str,
        /// The note's reason.
        reason: String,
        /// The µs instant.
        ts: u64,
        /// The lane.
        tid: u64,
    },
}

/// The `args` object's shape (the detail union, the task label, or the
/// metadata/instant strings the two metadata rows carry).
#[derive(Debug, PartialEq, Eq)]
enum ArgsRow {
    /// A phase detail (the `kind`-token union).
    Detail(PhaseDetail),
    /// A task span's label (the M63 `kind: "task"` shape).
    Task(String),
    /// The instant's reason.
    Reason(String),
    /// A metadata row's `name` (the process/lane label).
    Name(String),
}
