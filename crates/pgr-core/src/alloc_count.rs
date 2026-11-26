//! The §9.3 per-PR allocation-count seam (the `pgr_core::alloc_count`
//! module) — the measurement infrastructure's allocation half.
//!
//! Plan fidelity: the performance architecture doc §9.3's first bullet —
//! "**Per-PR (noise-resistant):** instruction counts and cache-miss
//! counts on a fixed corpus (`perf stat` or valgrind-class tooling on
//! Linux), **plus allocation counts per pass**." — restated by §10.3's
//! M1 performance gate ("no allocation in Pass 1–4 hot loops (counted
//! in CI)") and the hot-path rules' first rule (§5: "No allocation in a
//! `par_iter` body except into pre-sized per-task arenas"). The
//! instruction and cache-miss counters stay the §9.1 rig job's (the
//! dev-class runners do not carry them); this module is the allocation
//! half a dev-class runner can carry: the seat a counting allocator
//! feeds, the per-pass attribution windows the M54 observation seam
//! provides, and the report faces the M55/M58 interchange conventions.
//!
//! Three pieces, one shape:
//!
//! * **The seat** ([`AllocSource`], [`SharedCounters`]) — where the
//!   cumulative counts come from. The named seat is DHAT (the
//!   valgrind-class tooling the plan names): its in-process Rust face
//!   is the `dhat::Alloc` counting allocator a *binary* installs, and
//!   the bridge from its `dhat::HeapStats` to this module's
//!   [`AllocSnapshot`] is the seat consumer's own glue — the library
//!   never links DHAT (the driver's dependency surface stays lean, perf
//!   doc §8), and the counting `unsafe` lives inside the seat crate,
//!   the tree's `unsafe_code = "forbid"` gate staying intact. Tests and
//!   consumers that count some other way ride [`SharedCounters`] (the
//!   safe atomics seat) instead; every seat answers one contract — a
//!   cumulative, monotonic-by-habit sample the windows subtract
//!   saturating.
//! * **The collector** ([`AllocCollector`]) — subscribes to the M54
//!   observation seam ([`crate::link_observed`] /
//!   [`crate::link_from_objects_observed`] /
//!   [`crate::link_reloc_observed`]) and samples the seat at every
//!   phase completion; the saturating difference between consecutive
//!   samples is that pass's window. The window convention is the
//!   report's: the allocations the process made between the previous
//!   phase's completion and this one's — the pass's worker threads
//!   included (the pipeline's phase barriers make the window the
//!   pass's body). The collector is read-only (an observed link plans
//!   the identical layout — the parity gate is the seam's own
//!   contract) and re-derives nothing: the counts are the seat's own,
//!   a measured zero rides zero, and a seat that moves backwards (a
//!   mid-run reset) saturates at zero rather than fabricating a
//!   negative window.
//! * **The report** ([`AllocReport`]) — one row per phase in link
//!   order beside the run's whole-window totals, rendered as the
//!   deterministic text table a build system diffs line by line and
//!   the one-line JSON interchange (fixed key order, whole numbers,
//!   the report-JSON escape rules — the M55/M58 faces).
//!
//! The ladder's notes and the parse pool's task events subscribe to
//! nothing here: the ladder's rungs arrive as phases in the M54
//! vocabulary, per-task attribution is the timeline's face (the M63
//! seam), and the reference trace is the M113 face — the per-pass
//! window is this module's only unit.

use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::observe::{LinkObserver, Phase, PhaseEvent};

/// One cumulative sample: the seat's totals since the process started.
/// The counters are monotonic by habit (a seat that resets saturates
/// the windows at zero — never negative, never fabricated); the
/// window arithmetic subtracts saturating.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AllocSnapshot {
    /// The blocks (allocations) counted so far.
    pub blocks: u64,
    /// The bytes counted so far.
    pub bytes: u64,
}

impl AllocSnapshot {
    /// The saturating window between two samples: this sample minus
    /// `base`, each field independently — a seat that moved backwards
    /// prices as zero rather than a negative window (the honesty rule:
    /// a count is never fabricated).
    #[must_use]
    pub fn window_since(self, base: Self) -> Self {
        Self {
            blocks: self.blocks.saturating_sub(base.blocks),
            bytes: self.bytes.saturating_sub(base.bytes),
        }
    }
}

/// Where the cumulative counts come from — the seat the collector
/// samples at every phase completion. The named seat is DHAT (the
/// valgrind-class tooling §9.3 names): the bridge is the seat
/// consumer's own glue, so the library stays DHAT-free (the driver's
/// dependency surface stays lean) and the tree's `unsafe_code = "forbid"`
/// gate stays intact. [`SharedCounters`] is the seat tests and
/// consumers count through.
pub trait AllocSource {
    /// The seat's current cumulative sample. `Relaxed` ordering is the
    /// contract (a measurement, never a synchronization edge); the
    /// sample is the seat's own totals, never re-derived.
    fn sample(&self) -> AllocSnapshot;
}

/// The shared-counters seat: the safe atomics a counting allocator (or
/// a test, or a consumer's own hook) records through. The seat carries
/// no allocator — filling it is the consumer's decision (the DHAT
/// bridge in the seat consumer's own glue is the named filler).
#[derive(Debug, Default)]
pub struct SharedCounters {
    /// The blocks recorded so far.
    blocks: AtomicU64,
    /// The bytes recorded so far.
    bytes: AtomicU64,
}

impl SharedCounters {
    /// An empty seat (the measured-zero baseline).
    #[must_use]
    pub const fn new() -> Self {
        Self {
            blocks: AtomicU64::new(0),
            bytes: AtomicU64::new(0),
        }
    }

    /// Records one allocation batch: `blocks` allocations of `bytes`
    /// bytes total (the caller's own units — the seat aggregates, it
    /// does not interpret).
    pub fn record(&self, blocks: u64, bytes: u64) {
        self.blocks.fetch_add(blocks, Ordering::Relaxed);
        self.bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Returns the seat to zero (a mid-run reset — the window
    /// arithmetic prices the backwards move at zero, never negative).
    pub fn reset(&self) {
        self.blocks.store(0, Ordering::Relaxed);
        self.bytes.store(0, Ordering::Relaxed);
    }

    /// The seat's current sample.
    #[must_use]
    pub fn snapshot(&self) -> AllocSnapshot {
        AllocSnapshot {
            blocks: self.blocks.load(Ordering::Relaxed),
            bytes: self.bytes.load(Ordering::Relaxed),
        }
    }
}

impl AllocSource for SharedCounters {
    fn sample(&self) -> AllocSnapshot {
        self.snapshot()
    }
}

/// One pass's allocation window (§9.3: "allocation counts per pass"):
/// the phase and the counts the seat recorded between the previous
/// phase's completion and this one's — the pass's workers included.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllocRow {
    /// The phase that completed (the M54 vocabulary — [`Phase::as_str`]
    /// is the token).
    pub phase: Phase,
    /// The window's allocation count (saturating: never negative).
    pub blocks: u64,
    /// The window's byte count (saturating: never negative).
    pub bytes: u64,
}

/// The per-pass allocation report: one row per phase completion, link
/// order, beside the run's whole-window totals — the §9.3 face a build
/// system renders, stores and diffs.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AllocReport {
    /// One row per phase event, in link order (the seam's own).
    pub rows: Vec<AllocRow>,
    /// The run's whole-window allocation count (the seat's own totals —
    /// the collector's window opens at collection and closes at
    /// `finish`).
    pub total_blocks: u64,
    /// The run's whole-window byte count.
    pub total_bytes: u64,
}

impl AllocReport {
    /// Renders the deterministic text table: the header, one row per
    /// phase, the totals — a build system diffs two reports' shapes
    /// line by line (the values are measurements; the rows and columns
    /// are not).
    #[must_use]
    pub fn render(&self) -> String {
        let mut s = String::with_capacity(32 + self.rows.len() * 48);
        let _ = writeln!(s, "allocation report:");
        for row in &self.rows {
            let _ = writeln!(
                s,
                "  {:<14} {:>6} blocks {:>8} bytes",
                row.phase.as_str(),
                row.blocks,
                row.bytes
            );
        }
        let _ = writeln!(
            s,
            "  {:<14} {:>6} blocks {:>8} bytes",
            "total", self.total_blocks, self.total_bytes
        );
        s
    }

    /// Renders the one-line JSON interchange: fixed key order (rows,
    /// then the totals), whole numbers only — the M55/M58 convention
    /// (the phase tokens are the vocabulary's own, the numbers carry
    /// no units in the keys).
    #[must_use]
    pub fn render_json(&self) -> String {
        let mut s = String::with_capacity(48 + self.rows.len() * 64);
        s.push_str("{\"rows\":[");
        for (i, row) in self.rows.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            let _ = write!(
                s,
                "{{\"phase\":\"{}\",\"blocks\":{},\"bytes\":{}}}",
                row.phase.as_str(),
                row.blocks,
                row.bytes
            );
        }
        let _ = write!(
            s,
            "],\"total_blocks\":{},\"total_bytes\":{}}}",
            self.total_blocks, self.total_bytes
        );
        s
    }
}

/// The allocation-count collector: samples the seat at every phase
/// completion and keeps the pass windows. Feed it to
/// [`crate::link_observed`] / [`crate::link_from_objects_observed`] /
/// [`crate::link_reloc_observed`] beside the face collectors it rides
/// with (an [`crate::observe::ObserverPair`] serves the time and
/// allocation faces together — one event stream, both faces), then
/// [`AllocCollector::finish`] into the report.
///
/// The collection is read-only: a counted link plans the identical
/// layout (the parity gate is the M54 seam's own contract), and the
/// counts are the seat's own — the collector samples, never re-derives.
pub struct AllocCollector<'a> {
    /// The seat the windows subtract over.
    source: &'a dyn AllocSource,
    /// The sample the previous window closed on (the first is the
    /// collection's own opening sample).
    prev: AllocSnapshot,
    /// The first sample — the whole-window total's base.
    first: AllocSnapshot,
    /// The windows so far, link order.
    rows: Vec<AllocRow>,
}

impl<'a> AllocCollector<'a> {
    /// Opens the collection on the seat's current sample — the window
    /// the first phase's body fills opens here, at the subscription.
    #[must_use]
    pub fn new(source: &'a dyn AllocSource) -> Self {
        let first = source.sample();
        Self {
            source,
            prev: first,
            first,
            rows: Vec::new(),
        }
    }

    /// Consumes the collection into the report: the rows stay in link
    /// order (the seam's own), the totals are the seat's whole-window
    /// difference (saturating — a seat that reset mid-run prices the
    /// backwards move at zero, the honesty rule).
    #[must_use]
    pub fn finish(self) -> AllocReport {
        let now = self.source.sample();
        let total = now.window_since(self.first);
        AllocReport {
            rows: self.rows,
            total_blocks: total.blocks,
            total_bytes: total.bytes,
        }
    }
}

impl LinkObserver for AllocCollector<'_> {
    fn on_phase(&mut self, event: PhaseEvent) {
        let now = self.source.sample();
        let window = now.window_since(self.prev);
        self.rows.push(AllocRow {
            phase: event.phase,
            blocks: window.blocks,
            bytes: window.bytes,
        });
        self.prev = now;
    }
}
