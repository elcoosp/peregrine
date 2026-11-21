//! M112 — the link-statistics report (`-print_statistics`): ld64's
//! link-statistics report, the counts a link's own passes already had in
//! hand, rendered to stderr at the end of the link. The report rides the
//! M54 observation seam and the link's product — the objects Pass 1
//! parsed and the names the interner batched (the phase events' own
//! details, [`StatsCollector`] reading them off the seam), the fixups
//! Pass 3 planned and the bytes the emit produced (the layout and the
//! image, the caller's product), and the wall time the run took (the
//! caller's clock).
//!
//! The report is a measurement, not a layout product: the row set and
//! columns are deterministic, the counts and the wall are what the run
//! reported — a build system can diff two reports' shapes line by line.
//! An observed run plans the identical layout (the parity gate is the
//! M54 seam's own contract, `tests/m54_observer.rs`); the resident lane's
//! warm pipeline computes the same counts (the M62 convention — the reply
//! tail carries them, the client prints the cold lane's face).

use std::time::Duration;

use crate::observe::{LinkObserver, Phase, PhaseDetail, PhaseEvent};

/// The M112 statistics collector: subscribes to the observation seam and
/// keeps the counts the phase events carry — the parse face's input
/// count (the `Parse` phase's own detail) and the interner batch's name
/// count (the `Intern` phase's own detail). Feed it to
/// [`crate::link_observed`] / [`crate::link_from_objects_observed`], then
/// [`StatsCollector::finish`] into a [`LinkStatistics`]; the caller fills
/// the product's own counts (the fixups planned, the bytes emitted) and
/// the wall time before rendering. A warm pipeline with no parse phase
/// (the resident session's POIs) reads its object count off the request
/// it served — the counts are the run's own, never re-derived.
#[derive(Debug, Default)]
pub struct StatsCollector {
    objects: usize,
    interned: usize,
}

impl LinkObserver for StatsCollector {
    fn on_phase(&mut self, event: PhaseEvent) {
        // The counts ride the phase events' own details (the seam never
        // re-derives a number to observe it); every other phase carries
        // nothing the report names.
        match (event.phase, event.detail) {
            // The parse face's own count (the segmented pipeline's
            // `Parse`, the object walk's `Reloc` — one body, the same
            // count either shape reports).
            (Phase::Parse, PhaseDetail::Objects { inputs })
            | (Phase::Reloc, PhaseDetail::Reloc { inputs }) => self.objects = inputs,
            (Phase::Intern, PhaseDetail::Names { interned }) => self.interned = interned,
            _ => {}
        }
    }
}

impl StatsCollector {
    /// Consumes the collection into the report: the seam-carried counts
    /// (objects parsed, symbols interned) beside the product's own (the
    /// fixups planned, the bytes emitted) and the wall time the caller
    /// measured.
    #[must_use]
    pub fn finish(self, fixup_slots: usize, bytes: u64, wall: Duration) -> LinkStatistics {
        LinkStatistics {
            objects: self.objects,
            interned: self.interned,
            fixup_slots,
            bytes,
            wall,
        }
    }
}

/// The link-statistics report (M112): the counts the link's passes
/// reported and the wall time the run took. The render is deterministic —
/// fixed row set, fixed order — so a build system can diff two reports'
/// shapes line by line (the counts and the wall are the run's own).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LinkStatistics {
    /// The inputs Pass 1 parsed (the parse phase's own count; the warm
    /// pipeline's request carried them).
    pub objects: usize,
    /// The names the interner batched (object symbols, dylib exports,
    /// the header names — the `Intern` phase's own count).
    pub interned: usize,
    /// The fixup slots Pass 3 planned (the layout's own count).
    pub fixup_slots: usize,
    /// The bytes the emit produced (the image's own size).
    pub bytes: u64,
    /// The wall time the run took (the caller's clock).
    pub wall: Duration,
}

/// The wall time, as the report renders it: whole microseconds below a
/// millisecond, milliseconds with three decimals below a second, seconds
/// with three decimals beyond (the M58 table's integer-math convention —
/// no float rounding rides the report).
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

impl LinkStatistics {
    /// Renders the report as the deterministic text block the driver
    /// prints to stderr at the end of the link — one line per count, in
    /// report order, the values the run reported.
    #[must_use]
    pub fn render(&self) -> String {
        use std::fmt::Write as _;
        let mut s = String::with_capacity(160);
        let _ = writeln!(s, "the link statistics");
        let _ = writeln!(s, "  objects parsed {}", self.objects);
        let _ = writeln!(s, "  symbols interned {}", self.interned);
        let _ = writeln!(s, "  fixups planned {}", self.fixup_slots);
        let _ = writeln!(s, "  bytes emitted {}", self.bytes);
        let _ = writeln!(s, "  wall time {}", wall_text(self.wall));
        s
    }
}
