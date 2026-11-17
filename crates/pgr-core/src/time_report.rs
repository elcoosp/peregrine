//! M58 — the per-pass time report: the TDD's instrumentation spec
//! ("`--time` prints a per-pass table: parse, intern, resolve, layout,
//! emit/fixups, hashes, flush") and the roadmap's §9.3 budgets ("per-pass
//! wall … enforced from `--time` JSON output") name a measurement surface
//! the M54 observation seam already serves the raw material for — the
//! typed [`crate::observe::PhaseEvent`]s carry each Pass 1–3 phase's
//! completion and wall time. This module is the consumer that turns those
//! events *as data* into the report: [`TimeCollector`] subscribes to the
//! seam (an [`crate::observe::LinkObserver`] impl), [`TimeReport`] renders
//! the answer as a deterministic text table and a compact JSON interchange
//! line — the M55/M56/M57 convention (fixed key order, one line, the
//! report-JSON escape rules).
//!
//! The report is a measurement, not a layout product: the row set and the
//! columns are deterministic, the wall times are what the clock said. The
//! emit and total bands are the caller's (`Some` when the caller measured
//! them — the driver times the fused tile emit and the pipeline wall; a
//! library consumer may leave them `None`) and render as `null` in the
//! interchange when absent. The ladder's silent-correct rungs ride the
//! report as [`crate::observe::LinkNote`] lines — the "silent-correct, not
//! silent-blind" contract names its decisions, and a phase table that hid
//! the resolve-reuse fallback would misread the resolve row's price.
//!
//! The share column is integer math (permille over the measured rows plus
//! the emit band — never over the total, whose band the seams do not
//! cover), so the table carries no float rounding; the walls render µs
//! below a millisecond, ms with three decimals below a second, seconds
//! beyond.

use std::time::Duration;

use crate::observe::{LinkNote, LinkObserver, PhaseDetail, PhaseEvent};

/// The M58 time-report collector: subscribes to the observation seam and
/// keeps every phase event (arrival order — link order) and every note's
/// reason. Feed it to [`crate::link_observed`] /
/// [`crate::link_reloc_observed`] (the observed pipelines), then
/// [`TimeCollector::report`] into a [`TimeReport`]; the caller may fill
/// the report's `emit`/`total` bands (the driver times the fused emit and
/// the pipeline wall) before rendering.
#[derive(Debug, Default)]
pub struct TimeCollector {
    phases: Vec<PhaseEvent>,
    notes: Vec<String>,
}

impl LinkObserver for TimeCollector {
    fn on_phase(&mut self, event: PhaseEvent) {
        self.phases.push(event);
    }

    fn on_note(&mut self, note: LinkNote) {
        // `LinkNote` is a one-variant enum today; when a later rung joins
        // as a new variant, this destructure stops compiling — the report
        // must name the new rung's own note (a match arm, not a skip).
        let LinkNote::ResolveReuseFallback { reason } = note;
        self.notes.push(reason);
    }
}

impl TimeCollector {
    /// Consumes the collection into the report. The phases stay in link
    /// order (the seam's own); the emit and total bands ride `None` —
    /// the caller's measurement, set on the report before rendering.
    #[must_use]
    pub fn report(self) -> TimeReport {
        TimeReport {
            phases: self.phases,
            emit: None,
            total: None,
            notes: self.notes,
        }
    }
}

/// The per-pass wall report: the phases the link ran (in link order,
/// each with its own detail and wall time), the caller-measured emit and
/// total bands, and the ladder's notes.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TimeReport {
    /// The phase rows, in link order (the M54 seam's own order — one
    /// event per phase, seven per segmented link).
    pub phases: Vec<PhaseEvent>,
    /// The emit band (Passes 4–5, the fused tile emit) — the caller's
    /// measurement, `None` when unmeasured.
    pub emit: Option<Duration>,
    /// The pipeline's total wall — the caller's measurement, `None`
    /// when unmeasured.
    pub total: Option<Duration>,
    /// The notes the ladder emitted (the resolve-reuse fallback's own
    /// wording, in arrival order).
    pub notes: Vec<String>,
}

/// The phase's detail, as the table's shape column renders it (the same
/// counts the M54 event carried — the report never re-derives a number
/// to show it).
fn detail_text(detail: &PhaseDetail) -> String {
    match detail {
        PhaseDetail::Objects { inputs } => format!("inputs={inputs}"),
        PhaseDetail::Members { pulled } => format!("pulled={pulled}"),
        PhaseDetail::Names { interned } => format!("interned={interned}"),
        PhaseDetail::Winners { reused } => {
            if *reused {
                "winners=replayed".to_string()
            } else {
                "winners=full".to_string()
            }
        }
        PhaseDetail::Live { active } => format!("live={active}"),
        PhaseDetail::Folded { folded } => format!("folded={folded}"),
        PhaseDetail::Planned { segments, sections } => {
            format!("segments={segments}, sections={sections}")
        }
        PhaseDetail::Reloc { inputs } => format!("reloc inputs={inputs}"),
    }
}

/// The wall time, as the table renders it: whole microseconds below a
/// millisecond, milliseconds with three decimals below a second, seconds
/// with three decimals beyond. Integer math on the nanoseconds — no
/// float rounding rides the table.
fn wall_text(elapsed: Duration) -> String {
    let ns = elapsed.as_nanos();
    if ns < 1_000 {
        format!("{ns} ns")
    } else if ns < 1_000_000 {
        format!("{} µs", ns / 1_000)
    } else if ns < 1_000_000_000 {
        format!("{}.{:03} ms", ns / 1_000_000, (ns % 1_000_000) / 1_000)
    } else {
        format!(
            "{}.{:03} s",
            ns / 1_000_000_000,
            (ns % 1_000_000_000) / 1_000_000
        )
    }
}

/// The row's share of the measured span (the phase rows plus the emit
/// band when present), in permille — `50.0%`-style text, integer math.
/// A zero span (every measured row at zero) reports `0.0%` rather than
/// dividing by zero.
fn share_text(permille_of: u128, span: u128) -> String {
    if span == 0 {
        return "0.0%".to_string();
    }
    let permille = permille_of * 1_000 / span;
    format!("{}.{:01}%", permille / 10, permille % 10)
}

impl TimeReport {
    /// Renders the report as the deterministic text table: the header,
    /// one row per phase in link order (the phase token, the detail
    /// shape, the wall time, the share of the measured span), the emit
    /// and total bands when present, then one line per note — a build
    /// system can diff two reports' shapes line by line (the walls are
    /// measurements; the rows and columns are not).
    #[must_use]
    pub fn render(&self) -> String {
        use std::fmt::Write as _;
        let span: u128 = self
            .phases
            .iter()
            .map(|e| e.elapsed.as_nanos())
            .chain(self.emit.map(|d| d.as_nanos()))
            .sum();
        let mut s = String::with_capacity(64 + self.phases.len() * 64);
        let _ = writeln!(s, "the per-pass wall report");
        for e in &self.phases {
            let _ = writeln!(
                s,
                "  {:<12} {:<24} {:>9} {:>7}",
                e.phase.as_str(),
                detail_text(&e.detail),
                wall_text(e.elapsed),
                share_text(e.elapsed.as_nanos(), span),
            );
        }
        if let Some(emit) = self.emit {
            let _ = writeln!(
                s,
                "  {:<12} {:<24} {:>9} {:>7}",
                "emit",
                "fused tile emit",
                wall_text(emit),
                share_text(emit.as_nanos(), span),
            );
        }
        if let Some(total) = self.total {
            let _ = writeln!(
                s,
                "  {:<12} {:<24} {:>9}",
                "total",
                "link wall",
                wall_text(total),
            );
        }
        for note in &self.notes {
            let _ = writeln!(s, "  note: {note}");
        }
        s
    }

    /// Renders the report as deterministic, compact JSON (M58): fixed
    /// key order, one line, the report-JSON escape rules — the house
    /// interchange writer, shared with the M55 map and the M56/M57
    /// provenance faces. The walls ride as whole microseconds
    /// (`elapsed_us`); the absent bands ride `null`.
    #[must_use]
    pub fn render_json(&self) -> String {
        use std::fmt::Write as _;
        let mut s = String::with_capacity(96 + self.phases.len() * 80);
        s.push_str("{\"phases\":[");
        for (i, e) in self.phases.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            let _ = write!(
                s,
                "{{\"phase\":\"{}\",\"detail\":{},\"elapsed_us\":{}}}",
                e.phase.as_str(),
                detail_json(&e.detail),
                e.elapsed.as_nanos() / 1_000,
            );
        }
        s.push_str("],\"emit_us\":");
        match self.emit {
            Some(d) => {
                let _ = write!(s, "{}", d.as_nanos() / 1_000);
            }
            None => s.push_str("null"),
        }
        s.push_str(",\"total_us\":");
        match self.total {
            Some(d) => {
                let _ = write!(s, "{}", d.as_nanos() / 1_000);
            }
            None => s.push_str("null"),
        }
        s.push_str(",\"notes\":[");
        for (i, note) in self.notes.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            let _ = write!(s, "{}", crate::map::escape_json(note));
        }
        s.push_str("]}");
        s
    }
}

/// The detail's interchange shape (the counts ride their own keys — the
/// M54 event's fields, verbatim).
fn detail_json(detail: &PhaseDetail) -> String {
    match detail {
        PhaseDetail::Objects { inputs } => format!("{{\"kind\":\"objects\",\"inputs\":{inputs}}}"),
        PhaseDetail::Members { pulled } => format!("{{\"kind\":\"members\",\"pulled\":{pulled}}}"),
        PhaseDetail::Names { interned } => {
            format!("{{\"kind\":\"names\",\"interned\":{interned}}}")
        }
        PhaseDetail::Winners { reused } => format!("{{\"kind\":\"winners\",\"reused\":{reused}}}"),
        PhaseDetail::Live { active } => format!("{{\"kind\":\"live\",\"active\":{active}}}"),
        PhaseDetail::Folded { folded } => format!("{{\"kind\":\"folded\",\"folded\":{folded}}}"),
        PhaseDetail::Planned { segments, sections } => {
            format!("{{\"kind\":\"planned\",\"segments\":{segments},\"sections\":{sections}}}")
        }
        PhaseDetail::Reloc { inputs } => format!("{{\"kind\":\"reloc\",\"inputs\":{inputs}}}"),
    }
}
