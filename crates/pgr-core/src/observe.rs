//! The typed link-pipeline observation seam (M54): the pass structure
//! Passes 1–3 already name on the tracing seam becomes a nameable, typed
//! surface a library consumer can subscribe to. A link reports each
//! phase's completion — [`Phase`] in link order, the phase's own shape as
//! [`PhaseDetail`] (the counts the pass already had in hand), the wall
//! time it took — and the §7.3 ladder's silent-correct rungs (the
//! resolve-reuse fallback) as explicit [`LinkNote`]s. The observer is
//! read-only: subscribing never changes the plan (the parity gate lives in
//! `tests/m54_observer.rs`), and the trait's default methods keep an
//! observer that subscribes to nothing cost-free.
//!
//! The seam follows the house observability convention: [`TracingObserver`]
//! bridges every event onto the `tracing` debug level, inert until a
//! subscriber installs — the binaries and the consumer examples install
//! one under their debug envs (`PGR_TRACING=1`), and a library consumer
//! keeps (or ships) its own. The typed surface is for the consumer that
//! wants the events *as data* — a build-system progress bar, a phase-time
//! report — without scraping formatted spans.

use std::time::Duration;

/// The pipeline phases the observer sees, in link order (the same pass
/// structure the tracing spans name: `link_reloc`, `objc_pull`,
/// `resolve_reuse_plan`/`install`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Phase {
    /// Pass 1: the inputs' Mach-O parse & atomize (POI-cache hits included —
    /// a cached parse is still a parse the consumer waited on).
    Parse,
    /// The S7 archive-pull fixpoint (M5): the members liveness added beyond
    /// the direct parse (zero when no archives ride the link).
    ArchivePull,
    /// The interner batch: object symbols, then dylib exports, then the
    /// header/alias names (the M2 two-level id order).
    Intern,
    /// Pass 2: symbol resolution — the full install or the resolve-reuse
    /// replay (the replay's refusal rides [`LinkNote::ResolveReuseFallback`]).
    Resolve,
    /// The D12 liveness fixpoint (M5): roots, mark, sweep (`active` names
    /// whether the strip engaged — without `-dead_strip` the set is live).
    Liveness,
    /// The ICF fold over the live text atoms (M6): the atoms folded onto a
    /// canonical copy.
    Fold,
    /// Pass 3: layout — synthesis, fixup planning, the segment/section plan.
    Layout,
    /// The `-r` relocatable shape's completion (Passes 1–2, no segment
    /// plan — the object bytes are `pgr-emit`'s `build_object_image`).
    Reloc,
}

impl Phase {
    /// The phase's stable token — the field name a subscriber records
    /// (`parse`, `archive_pull`, …), the same `snake_case` convention the
    /// tracing spans use.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Parse => "parse",
            Self::ArchivePull => "archive_pull",
            Self::Intern => "intern",
            Self::Resolve => "resolve",
            Self::Liveness => "liveness",
            Self::Fold => "fold",
            Self::Layout => "layout",
            Self::Reloc => "reloc",
        }
    }
}

/// The phase's own detail: the shape the pass already computed (the counts
/// ride for free — the seam never re-derives a number to observe it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PhaseDetail {
    /// Pass 1: the parsed direct inputs (cache hits included).
    Objects {
        /// The input count the parse produced.
        inputs: usize,
    },
    /// The archive pull: members liveness pulled beyond the direct parse.
    Members {
        /// The pulled member count.
        pulled: usize,
    },
    /// The interner batch: the symbol names interned.
    Names {
        /// The interned name count.
        interned: usize,
    },
    /// Pass 2: the winners installed. `reused` names the path — the
    /// resolve-reuse replay (`true`) or the full walk (`false`).
    Winners {
        /// Whether the resolution rode the recorded replay.
        reused: bool,
    },
    /// The liveness fixpoint: whether the dead-strip engaged.
    Live {
        /// True when `-dead_strip` (or the M11 order file) ran the fixpoint.
        active: bool,
    },
    /// The ICF fold: the atoms folded onto a canonical copy.
    Folded {
        /// The folded-atom count.
        folded: usize,
    },
    /// Pass 3: the planned shape.
    Planned {
        /// The planned segment count.
        segments: usize,
        /// The planned section count.
        sections: usize,
    },
    /// The `-r` shape: the inputs the front half parsed.
    Reloc {
        /// The input count the object-shape run consumed.
        inputs: usize,
    },
}

/// One phase completion: the phase, its shape, the wall time it took.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhaseEvent {
    /// The phase that completed.
    pub phase: Phase,
    /// The phase's own shape.
    pub detail: PhaseDetail,
    /// The wall time the phase took (measured at the seam — the sum is the
    /// link's Passes 1–3 wall time minus the seams' own overhead).
    pub elapsed: Duration,
}

/// A pipeline note: a rung the ladder answered on the consumer's behalf.
/// A note never changes the plan — it names the decision the "silent-correct,
/// not silent-blind" contract already made (the same wording the tracing
/// seam's debug events carry).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkNote {
    /// The shape-guarded resolve-reuse replay refused (`reason` names the
    /// moved shape, the `ReuseFallback` render) and the full resolve ran —
    /// the ladder's bottom rung: always available, always correct.
    ResolveReuseFallback {
        /// The refusal's own wording.
        reason: String,
    },
}

/// The link-pipeline observer: subscribes to the passes a link runs. Both
/// methods default to subscribing to nothing — an observer opts into the
/// phases and notes it wants, and the pipeline pays nothing for the
/// silence (the observed and unobserved links plan identical layouts).
pub trait LinkObserver {
    /// A phase completed (`event.elapsed` names its wall time).
    fn on_phase(&mut self, _event: PhaseEvent) {}
    /// A pipeline note (a fallback the ladder answered itself).
    fn on_note(&mut self, _note: LinkNote) {}
}

/// The tracing bridge: every event rides the house tracing seam (debug
/// level, inert until a subscriber installs). The bridge is the zero-config
/// observer — installing it keeps the library's own spans and events
/// exactly where they were, and adds the phase-level record a subscriber
/// can watch.
#[derive(Debug, Default, Clone, Copy)]
pub struct TracingObserver;

impl LinkObserver for TracingObserver {
    fn on_phase(&mut self, event: PhaseEvent) {
        tracing::debug!(
            phase = event.phase.as_str(),
            elapsed_us = event.elapsed.as_micros() as u64,
            "the link phase completed"
        );
    }

    fn on_note(&mut self, note: LinkNote) {
        // `LinkNote` is a one-variant enum today; when a later rung joins
        // as a new variant, this destructure stops compiling — the bridge
        // must name the new note's own event (a `match` arm, not a skip).
        let LinkNote::ResolveReuseFallback { reason } = note;
        tracing::debug!(
            fallback = %reason,
            "the resolve-reuse replay fell back to the full resolve"
        );
    }
}

/// Two observers behind one subscription (M61): the one-shot `--time` +
/// `--trace` shape — both faces read the one observed run, so the seam
/// hands each event to both collectors (the first a clone, the second
/// the original; the event is a `Duration` and an enum, the copy is the
/// seam's own price). The pair borrows its subscribers, so the caller's
/// collectors stay where it put them.
pub struct ObserverPair<'a, 'b> {
    first: &'a mut dyn LinkObserver,
    second: &'b mut dyn LinkObserver,
}

impl<'a, 'b> ObserverPair<'a, 'b> {
    /// Pairs two subscribers behind one [`LinkObserver`].
    #[must_use]
    pub fn new(first: &'a mut dyn LinkObserver, second: &'b mut dyn LinkObserver) -> Self {
        Self { first, second }
    }
}

impl LinkObserver for ObserverPair<'_, '_> {
    fn on_phase(&mut self, event: PhaseEvent) {
        self.first.on_phase(event.clone());
        self.second.on_phase(event);
    }

    fn on_note(&mut self, note: LinkNote) {
        self.first.on_note(note.clone());
        self.second.on_note(note);
    }
}
